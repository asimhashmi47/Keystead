using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Keystead.Application.Identity;

/// <summary>
/// The format of a service identity's client secret, and how one is generated and checked.
/// </summary>
/// <remarks>
/// <para>
/// Shape: <c>ksd_live_&lt;base32 of 256 random bits&gt;_&lt;checksum&gt;</c>. Three parts, each
/// earning its place.
/// </para>
/// <para>
/// The <c>ksd_live_</c> prefix makes the credential self-identifying. That is what lets a
/// secret scanner recognise one in a commit or a log and raise it, and it lets this server
/// reject something that is obviously not one of its credentials before spending an Argon2-free
/// but still non-zero hash on it. The <c>live</c> segment leaves room for <c>test</c> without
/// the two ever being confusable.
/// </para>
/// <para>
/// The checksum catches a truncated or mistyped credential locally, so a developer who pasted
/// 39 of 40 characters gets told the credential is malformed rather than that their
/// authentication failed. It is a typo guard and nothing more: it is computed from the public
/// part of the string, so it adds no secrecy and is not relied on for any.
/// </para>
/// <para>
/// Crockford's base32 alphabet, excluding I, L, O and U, because these get copied by hand more
/// often than anyone intends.
/// </para>
/// </remarks>
public static class ClientCredential
{
    /// <summary>The prefix on every live client secret.</summary>
    public const string LivePrefix = "ksd_live_";

    /// <summary>The prefix reserved for non-production credentials.</summary>
    public const string TestPrefix = "ksd_test_";

    /// <summary>The number of random bytes in a client secret.</summary>
    public const int EntropyBytes = 32;

    /// <summary>The number of characters in the checksum segment.</summary>
    public const int ChecksumLength = 6;

    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private const string HashLabel = "keystead.client_secret.v1";

    /// <summary>Generates a new client secret and the hash to store for it.</summary>
    /// <param name="prefix">
    /// <see cref="LivePrefix"/> or <see cref="TestPrefix"/>.
    /// </param>
    /// <returns>The plaintext secret, to show exactly once, and its digest.</returns>
    /// <exception cref="ArgumentException">The prefix is not one of the two known values.</exception>
    public static (string Secret, byte[] Hash) Create(string prefix = LivePrefix)
    {
        if (prefix is not (LivePrefix or TestPrefix))
        {
            throw new ArgumentException(
                $"A client secret prefix must be '{LivePrefix}' or '{TestPrefix}'.",
                nameof(prefix));
        }

        var entropy = RandomNumberGenerator.GetBytes(EntropyBytes);

        try
        {
            var body = prefix + Encode(entropy);
            var secret = body + "_" + Checksum(body);

            return (secret, Hash(secret));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    /// <summary>
    /// Whether a submitted string is shaped like a Keystead client secret with a valid checksum.
    /// </summary>
    /// <remarks>
    /// A cheap structural check, not an authentication decision. It exists so a malformed
    /// credential is reported as malformed, and so the token endpoint can refuse obvious
    /// rubbish without touching the database.
    /// </remarks>
    /// <param name="candidate">The submitted secret.</param>
    /// <returns><see langword="true"/> when the shape and checksum are right.</returns>
    public static bool IsWellFormed(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate))
        {
            return false;
        }

        var separator = candidate.LastIndexOf('_');

        if (separator <= 0 || candidate.Length - separator - 1 != ChecksumLength)
        {
            return false;
        }

        var body = candidate[..separator];
        var checksum = candidate[(separator + 1)..];

        if (!body.StartsWith(LivePrefix, StringComparison.Ordinal)
            && !body.StartsWith(TestPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        // Fixed-time comparison even here. The checksum is not secret, but comparing it in
        // variable time would still be a habit worth not forming in this file.
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(checksum),
            Encoding.ASCII.GetBytes(Checksum(body)));
    }

    /// <summary>
    /// Computes the digest stored for a client secret.
    /// </summary>
    /// <remarks>
    /// SHA-256, not Argon2id, and for the same reason as recovery codes: the input is 256 bits
    /// from the cryptographic generator, so there is nothing to brute force and a slow hash
    /// would only turn the token endpoint into a way to burn server CPU. The user's chosen
    /// password, which has far less entropy, does get Argon2id.
    /// </remarks>
    /// <param name="secret">The plaintext secret.</param>
    /// <returns>The 32-byte digest.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> is null.</exception>
    public static byte[] Hash(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);

        // Domain separated, so this digest can never collide with one computed elsewhere over
        // the same bytes for a different purpose.
        var payload = Encoding.UTF8.GetBytes(
            string.Create(CultureInfo.InvariantCulture, $"{HashLabel}:{secret}"));

        try
        {
            return SHA256.HashData(payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>Compares a candidate digest against a stored one in fixed time.</summary>
    /// <param name="candidate">The digest of the submitted secret.</param>
    /// <param name="stored">The stored digest.</param>
    /// <returns><see langword="true"/> when they match.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static bool Matches(byte[] candidate, byte[] stored)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(stored);

        return CryptographicOperations.FixedTimeEquals(candidate, stored);
    }

    /// <summary>
    /// Generates a public client identifier.
    /// </summary>
    /// <remarks>
    /// Not a secret, and deliberately shaped differently from the secret so the two cannot be
    /// mistaken for one another in configuration or in a support conversation.
    /// </remarks>
    /// <returns>An identifier such as <c>ksid_7F3K9QRTVW2XY4ZB</c>.</returns>
    public static string CreateClientId() =>
        "ksid_" + Encode(RandomNumberGenerator.GetBytes(10));

    private static string Encode(ReadOnlySpan<byte> bytes)
    {
        // Straightforward base32 over the 5-bit groups. Not RFC 4648 padding, because this is
        // an opaque token rather than something anyone needs to decode.
        var builder = new StringBuilder((bytes.Length * 8 / 5) + 1);
        var buffer = 0;
        var bitsHeld = 0;

        foreach (var value in bytes)
        {
            buffer = (buffer << 8) | value;
            bitsHeld += 8;

            while (bitsHeld >= 5)
            {
                builder.Append(Alphabet[(buffer >> (bitsHeld - 5)) & 31]);
                bitsHeld -= 5;
            }
        }

        if (bitsHeld > 0)
        {
            builder.Append(Alphabet[(buffer << (5 - bitsHeld)) & 31]);
        }

        return builder.ToString();
    }

    private static string Checksum(string body)
    {
        // A truncated SHA-256 over the body, rendered in the same alphabet. SHA-256 rather
        // than a CRC only because it is already here; the job is detecting a typo, and any
        // checksum would do. Nothing secret goes into it, and nothing relies on it for
        // secrecy: the body it covers is the part of the credential an attacker would already
        // have if they had the credential at all.
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(body));
        var seed = BinaryPrimitives.ReadUInt32LittleEndian(digest);

        var builder = new StringBuilder(ChecksumLength);

        for (var i = 0; i < ChecksumLength; i++)
        {
            builder.Append(Alphabet[(int)(seed >> (i * 5)) & 31]);
        }

        return builder.ToString();
    }
}
