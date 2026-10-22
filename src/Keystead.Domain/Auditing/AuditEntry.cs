using System;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Keystead.Domain.Auditing;

/// <summary>
/// One link in the tamper-evident audit chain.
/// </summary>
/// <remarks>
/// <para>
/// Each entry commits to the entry before it: <see cref="Hash"/> is the SHA-256 of this
/// entry's canonical content <em>including</em> <see cref="PreviousHash"/>. Changing or
/// removing any historical row therefore breaks every hash after it, which is what makes the
/// log evidence rather than a convention. An insider with database write access can still
/// rewrite rows, but they cannot do so without the chain failing verification.
/// </para>
/// <para>
/// The canonical form is length-prefixed, not delimited. Concatenating fields with a separator
/// invites an ambiguity attack: two different entries whose fields straddle the separator
/// differently would otherwise hash identically. Length prefixes make the encoding injective.
/// </para>
/// </remarks>
public sealed class AuditEntry
{
    /// <summary>The length of a chain hash, in bytes (SHA-256).</summary>
    public const int HashLength = 32;

    /// <summary>
    /// The hash recorded as the predecessor of the very first entry: 32 zero bytes.
    /// Having an explicit genesis value means entry 1 is verified by the same rule as every
    /// other entry, with no special case to get wrong.
    /// </summary>
    public static ReadOnlySpan<byte> GenesisHash => new byte[HashLength];

    /// <summary>Surrogate key.</summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// Position in the chain, starting at 1 and never reused. A gap in this sequence is itself
    /// evidence of deletion.
    /// </summary>
    public required long Seq { get; init; }

    /// <summary>The workspace the action belonged to, or null for installation-wide events.</summary>
    public Guid? WorkspaceId { get; init; }

    /// <summary>Whether the actor was a user, a service identity, the system, or anonymous.</summary>
    public required ActorType ActorType { get; init; }

    /// <summary>The actor identifier, or null when anonymous.</summary>
    public Guid? ActorId { get; init; }

    /// <summary>
    /// A display label for the actor captured at write time, so history survives the deletion
    /// of the principal. For a failed sign-in this is the submitted address, which is why the
    /// audit log is itself treated as sensitive and access to it is authorized.
    /// </summary>
    public required string ActorLabel { get; init; }

    /// <summary>What happened.</summary>
    public required AuditAction Action { get; init; }

    /// <summary>Whether it succeeded, was denied, or errored.</summary>
    public required AuditOutcome Outcome { get; init; }

    /// <summary>The kind of thing acted upon, for example <c>secret</c> or <c>vault</c>.</summary>
    public required string ResourceType { get; init; }

    /// <summary>The identifier of the thing acted upon, when there is one.</summary>
    public Guid? ResourceId { get; init; }

    /// <summary>
    /// A human-readable name for the resource, for example the secret name. Names are metadata
    /// and are safe to record; values never are.
    /// </summary>
    public string? ResourceLabel { get; init; }

    /// <summary>The address the request came from.</summary>
    public required string IpAddress { get; init; }

    /// <summary>The user agent string, truncated at storage time.</summary>
    public string? UserAgent { get; init; }

    /// <summary>The correlation id of the request, to tie an audit entry to its log lines.</summary>
    public string? CorrelationId { get; init; }

    /// <summary>
    /// Extra structured detail as JSON, for example the old and new role on a role change.
    /// </summary>
    /// <remarks>
    /// This field never carries a secret value. It is written only by call sites that pass
    /// metadata, and the redaction tests assert that a known secret value never reaches it.
    /// </remarks>
    public string? DataJson { get; init; }

    /// <summary>When the entry was written.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>The <see cref="Hash"/> of the preceding entry, or the genesis value for the first.</summary>
    public required byte[] PreviousHash { get; init; }

    /// <summary>SHA-256 over this entry's canonical content, including <see cref="PreviousHash"/>.</summary>
    public required byte[] Hash { get; init; }

    /// <summary>
    /// Computes the chain hash this entry should carry, given the hash of its predecessor.
    /// </summary>
    /// <param name="previousHash">
    /// The predecessor's <see cref="Hash"/>, or <see cref="GenesisHash"/> for the first entry.
    /// </param>
    /// <returns>The 32-byte SHA-256 chain hash.</returns>
    /// <exception cref="ArgumentException"><paramref name="previousHash"/> is the wrong length.</exception>
    public byte[] ComputeHash(ReadOnlySpan<byte> previousHash)
    {
        if (previousHash.Length != HashLength)
        {
            throw new ArgumentException(
                $"A chain hash must be {HashLength} bytes.",
                nameof(previousHash));
        }

        using var buffer = new MemoryStream(capacity: 512);
        Write(buffer, previousHash);
        WriteInt64(buffer, Seq);
        WriteString(buffer, Id.ToString("D", CultureInfo.InvariantCulture));
        WriteString(buffer, WorkspaceId?.ToString("D", CultureInfo.InvariantCulture));
        WriteInt64(buffer, (long)ActorType);
        WriteString(buffer, ActorId?.ToString("D", CultureInfo.InvariantCulture));
        WriteString(buffer, ActorLabel);
        WriteInt64(buffer, (long)Action);
        WriteInt64(buffer, (long)Outcome);
        WriteString(buffer, ResourceType);
        WriteString(buffer, ResourceId?.ToString("D", CultureInfo.InvariantCulture));
        WriteString(buffer, ResourceLabel);
        WriteString(buffer, IpAddress);
        WriteString(buffer, UserAgent);
        WriteString(buffer, CorrelationId);
        WriteString(buffer, DataJson);

        // Round-trip format ("O") so the hash is stable across machines and cultures, and
        // normalised to UTC so an offset change cannot alter the committed value.
        WriteString(buffer, CreatedUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));

        buffer.Position = 0;
        return SHA256.HashData(buffer.GetBuffer().AsSpan(0, (int)buffer.Length));
    }

    /// <summary>
    /// Whether this entry's recorded <see cref="Hash"/> matches a recomputation from its own
    /// content and the supplied predecessor hash.
    /// </summary>
    /// <param name="previousHash">The predecessor's hash, or <see cref="GenesisHash"/>.</param>
    /// <returns><see langword="true"/> when the link is intact.</returns>
    public bool VerifyAgainst(ReadOnlySpan<byte> previousHash)
    {
        if (Hash.Length != HashLength || PreviousHash.Length != HashLength)
        {
            return false;
        }

        // The stored predecessor must be the one we were handed, and the recomputed hash must
        // match what was stored. Both comparisons are fixed-time: verification output is
        // visible to a caller, so there is no reason to leak where a mismatch begins.
        if (!CryptographicOperations.FixedTimeEquals(PreviousHash, previousHash))
        {
            return false;
        }

        var expected = ComputeHash(previousHash);
        return CryptographicOperations.FixedTimeEquals(Hash, expected);
    }

    private static void Write(Stream destination, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(length, value.Length);
        destination.Write(length);
        destination.Write(value);
    }

    private static void WriteInt64(Stream destination, long value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(buffer, value);
        destination.Write(buffer);
    }

    private static void WriteString(Stream destination, string? value)
    {
        if (value is null)
        {
            // A null is distinguished from an empty string by a length of -1, so that
            // (null, "x") and ("", "x") cannot collide.
            Span<byte> marker = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(marker, -1);
            destination.Write(marker);
            return;
        }

        Write(destination, Encoding.UTF8.GetBytes(value));
    }
}
