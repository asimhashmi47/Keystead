using System;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Text;

namespace Keystead.Application.Cryptography;

/// <summary>
/// The context that a ciphertext is cryptographically bound to, serialised as AES-GCM
/// additional authenticated data.
/// </summary>
/// <remarks>
/// <para>
/// This type is the answer to a specific attack. Suppose an attacker can write to the database
/// but does not hold any key. Without binding, they could copy the ciphertext, nonce and tag
/// from a secret they <em>are</em> allowed to read into the row of a secret they are not, and
/// the server would decrypt it happily, because the key and the blob still match. The result
/// would be a read of privileged material through an unprivileged row.
/// </para>
/// <para>
/// Including the full path (workspace, vault, secret, version) plus the purpose and scheme in
/// the AAD closes that door: the tag only verifies when the blob is decrypted in exactly the
/// row it was sealed for. Any relocation turns a silent success into an
/// <see cref="System.Security.Cryptography.AuthenticationTagMismatchException"/>.
/// </para>
/// <para>
/// The encoding is length-prefixed rather than delimited, for the same injectivity reason as
/// the audit chain: a separator-joined encoding lets two different contexts produce identical
/// bytes.
/// </para>
/// </remarks>
public sealed class CryptoContext : IEquatable<CryptoContext>
{
    /// <summary>
    /// A version tag for the binding scheme itself. If the AAD layout ever changes, this
    /// changes with it, so old ciphertext cannot be reinterpreted under new rules.
    /// </summary>
    public const string Scheme = "keystead.aad.v1";

    private readonly byte[] _aad;

    private CryptoContext(
        CryptoPurpose purpose,
        Guid? workspaceId,
        Guid? vaultId,
        Guid? secretId,
        Guid? versionId,
        int keyVersion)
    {
        Purpose = purpose;
        WorkspaceId = workspaceId;
        VaultId = vaultId;
        SecretId = secretId;
        VersionId = versionId;
        KeyVersion = keyVersion;
        _aad = Build();
    }

    /// <summary>What this key use is for.</summary>
    public CryptoPurpose Purpose { get; }

    /// <summary>The owning workspace, when the protected item belongs to one.</summary>
    public Guid? WorkspaceId { get; }

    /// <summary>The owning vault, when the protected item belongs to one.</summary>
    public Guid? VaultId { get; }

    /// <summary>The owning secret, when the protected item belongs to one.</summary>
    public Guid? SecretId { get; }

    /// <summary>The owning secret version, when the protected item belongs to one.</summary>
    public Guid? VersionId { get; }

    /// <summary>The generation of the wrapping key, so a re-wrap cannot be rolled back.</summary>
    public int KeyVersion { get; }

    /// <summary>The serialised additional authenticated data.</summary>
    /// <returns>A read-only view; the backing array is never handed out.</returns>
    public ReadOnlySpan<byte> Aad => _aad;

    /// <summary>Context for a vault KEK sealed under the master key.</summary>
    /// <param name="workspaceId">The owning workspace.</param>
    /// <param name="vaultId">The vault whose KEK this is.</param>
    /// <param name="kekVersion">The KEK generation.</param>
    /// <param name="masterKeyVersion">The master key generation doing the wrapping.</param>
    public static CryptoContext ForVaultKek(
        Guid workspaceId,
        Guid vaultId,
        int kekVersion,
        int masterKeyVersion) =>
        new(
            CryptoPurpose.VaultKekWrap,
            workspaceId,
            vaultId,
            secretId: null,
            versionId: null,
            keyVersion: (masterKeyVersion * 1_000_000) + kekVersion);

    /// <summary>Context for a per-version DEK sealed under a vault KEK.</summary>
    /// <param name="workspaceId">The owning workspace.</param>
    /// <param name="vaultId">The owning vault.</param>
    /// <param name="secretId">The owning secret.</param>
    /// <param name="versionId">The version whose DEK this is.</param>
    /// <param name="kekVersion">The KEK generation doing the wrapping.</param>
    public static CryptoContext ForDataKey(
        Guid workspaceId,
        Guid vaultId,
        Guid secretId,
        Guid versionId,
        int kekVersion) =>
        new(CryptoPurpose.DataKeyWrap, workspaceId, vaultId, secretId, versionId, kekVersion);

    /// <summary>Context for a secret value sealed under its own DEK.</summary>
    /// <param name="workspaceId">The owning workspace.</param>
    /// <param name="vaultId">The owning vault.</param>
    /// <param name="secretId">The owning secret.</param>
    /// <param name="versionId">The version being sealed.</param>
    public static CryptoContext ForSecretValue(
        Guid workspaceId,
        Guid vaultId,
        Guid secretId,
        Guid versionId) =>
        new(CryptoPurpose.SecretValue, workspaceId, vaultId, secretId, versionId, keyVersion: 0);

    /// <summary>Context for a user TOTP seed sealed under the master key.</summary>
    /// <param name="userId">The user the seed belongs to.</param>
    /// <param name="masterKeyVersion">The master key generation doing the wrapping.</param>
    public static CryptoContext ForTotpSeed(Guid userId, int masterKeyVersion) =>
        new(
            CryptoPurpose.TotpSeed,
            workspaceId: null,
            vaultId: null,
            secretId: userId,
            versionId: null,
            keyVersion: masterKeyVersion);

    /// <summary>Context for a JWT signing key sealed under the master key.</summary>
    /// <param name="keyId">The signing key identifier.</param>
    /// <param name="masterKeyVersion">The master key generation doing the wrapping.</param>
    public static CryptoContext ForSigningKey(Guid keyId, int masterKeyVersion) =>
        new(
            CryptoPurpose.SigningKeyWrap,
            workspaceId: null,
            vaultId: null,
            secretId: keyId,
            versionId: null,
            keyVersion: masterKeyVersion);

    private byte[] Build()
    {
        using var buffer = new MemoryStream(capacity: 256);
        WriteString(buffer, Scheme);
        WriteInt64(buffer, (long)Purpose);
        WriteGuid(buffer, WorkspaceId);
        WriteGuid(buffer, VaultId);
        WriteGuid(buffer, SecretId);
        WriteGuid(buffer, VersionId);
        WriteInt64(buffer, KeyVersion);
        return buffer.ToArray();
    }

    private static void WriteGuid(Stream destination, Guid? value) =>
        WriteString(destination, value?.ToString("D", CultureInfo.InvariantCulture));

    private static void WriteInt64(Stream destination, long value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(buffer, value);
        destination.Write(buffer);
    }

    private static void WriteString(Stream destination, string? value)
    {
        Span<byte> length = stackalloc byte[4];

        if (value is null)
        {
            BinaryPrimitives.WriteInt32LittleEndian(length, -1);
            destination.Write(length);
            return;
        }

        var bytes = Encoding.UTF8.GetBytes(value);
        BinaryPrimitives.WriteInt32LittleEndian(length, bytes.Length);
        destination.Write(length);
        destination.Write(bytes);
    }

    /// <inheritdoc />
    public bool Equals(CryptoContext? other) =>
        other is not null && _aad.AsSpan().SequenceEqual(other._aad);

    /// <inheritdoc />
    public override bool Equals(object? obj) => Equals(obj as CryptoContext);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_aad);
        return hash.ToHashCode();
    }

    /// <summary>Equality operator.</summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    public static bool operator ==(CryptoContext? left, CryptoContext? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Inequality operator.</summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    public static bool operator !=(CryptoContext? left, CryptoContext? right) => !(left == right);
}
