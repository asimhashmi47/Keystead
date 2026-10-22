using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Keystead.Application.Identity;

namespace Keystead.Infrastructure.Identity;

/// <summary>
/// Issues and verifies single-use MFA recovery codes.
/// </summary>
/// <remarks>
/// <para>
/// A recovery code is a bearer credential that bypasses the second factor, so it is treated
/// like one: 100 bits of entropy from the cryptographic generator, stored only as SHA-256,
/// displayed exactly once, and consumed on use.
/// </para>
/// <para>
/// SHA-256 rather than Argon2id here, deliberately. The usual reason to use a slow hash is that
/// the input has little entropy and is therefore guessable offline. These codes are 100 random
/// bits, which is far beyond brute force, so the slow hash would buy nothing and would instead
/// let an attacker turn the recovery form into a cheap way to burn server CPU. The password,
/// which a human chose, does get Argon2id.
/// </para>
/// <para>
/// Crockford's base32 alphabet, excluding I, L, O and U: a code that gets read off a printout
/// and typed must not turn on telling 0 from O.
/// </para>
/// </remarks>
public sealed class RecoveryCodeService : IRecoveryCodeService
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private const int GroupLength = 5;
    private const int GroupCount = 4;
    private const string HashLabel = "keystead.recovery.v1";

    /// <inheritdoc />
    public int CodesPerUser => 10;

    /// <inheritdoc />
    public IReadOnlyList<GeneratedRecoveryCode> Generate()
    {
        var codes = new List<GeneratedRecoveryCode>(CodesPerUser);

        for (var i = 0; i < CodesPerUser; i++)
        {
            var code = GenerateOne();
            codes.Add(new GeneratedRecoveryCode(code, Hash(Normalise(code)!)));
        }

        return codes;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="code"/> is null.</exception>
    public byte[]? HashForComparison(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        var normalised = Normalise(code);

        return normalised is null ? null : Hash(normalised);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public bool Matches(byte[] candidate, byte[] stored)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(stored);

        return CryptographicOperations.FixedTimeEquals(candidate, stored);
    }

    private static string GenerateOne()
    {
        // 20 characters from a 32-symbol alphabet: 100 bits.
        var builder = new StringBuilder(GroupCount * (GroupLength + 1));

        for (var group = 0; group < GroupCount; group++)
        {
            if (group > 0)
            {
                builder.Append('-');
            }

            for (var i = 0; i < GroupLength; i++)
            {
                // Rejection-free selection from a 32-symbol alphabet because 32 divides the
                // generator's range evenly, so there is no modulo bias to correct.
                builder.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);
            }
        }

        return builder.ToString();
    }

    /// <summary>
    /// Reduces a submitted code to its canonical form, or returns null when it cannot be one.
    /// </summary>
    /// <remarks>
    /// Separators and casing are forgiven because a human is retyping this from paper. The
    /// commonly confused characters are folded to their alphabet equivalents for the same
    /// reason: refusing a code because someone typed O for 0 helps nobody.
    /// </remarks>
    private static string? Normalise(string code)
    {
        var builder = new StringBuilder(GroupCount * GroupLength);

        foreach (var character in code)
        {
            if (character is '-' or ' ' or '\t')
            {
                continue;
            }

            var upper = char.ToUpperInvariant(character);

            upper = upper switch
            {
                'O' => '0',
                'I' or 'L' => '1',
                'U' => 'V',
                _ => upper,
            };

            if (!Alphabet.Contains(upper, StringComparison.Ordinal))
            {
                return null;
            }

            builder.Append(upper);

            if (builder.Length > GroupCount * GroupLength)
            {
                return null;
            }
        }

        return builder.Length == GroupCount * GroupLength ? builder.ToString() : null;
    }

    private static byte[] Hash(string normalisedCode)
    {
        // Domain-separated so a recovery-code digest can never collide with a digest computed
        // for some other purpose that happens to use SHA-256 over the same bytes.
        var payload = Encoding.UTF8.GetBytes(
            string.Create(CultureInfo.InvariantCulture, $"{HashLabel}:{normalisedCode}"));

        try
        {
            return SHA256.HashData(payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }
}
