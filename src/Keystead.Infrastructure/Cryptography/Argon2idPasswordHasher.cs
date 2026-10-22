using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Keystead.Application.Abstractions;
using Keystead.Application.Cryptography;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Keystead.Infrastructure.Cryptography;

/// <summary>
/// Argon2id password hashing, with a per-user salt and an optional server-side pepper.
/// </summary>
/// <remarks>
/// <para>
/// Digests are stored in PHC string format, for example
/// <c>$argon2id$v=19$m=65536,t=3,p=1$&lt;salt&gt;$&lt;hash&gt;</c>. Carrying the parameters
/// inside the digest is what lets the cost be raised later without locking anyone out.
/// </para>
/// <para>
/// The pepper is supplied by <see cref="IMasterKeyProvider"/>, so it lives wherever the master
/// key lives rather than in the database. An attacker who exfiltrates only the database holds
/// salts and digests but is missing an input to the hash, which makes an offline dictionary
/// attack impossible rather than merely expensive.
/// </para>
/// </remarks>
public sealed class Argon2idPasswordHasher : IPasswordHasher
{
    private const string AlgorithmLabel = "argon2id";
    private const int ArgonVersion = 19;

    private readonly Argon2idOptions _options;
    private readonly IMasterKeyProvider _masterKeys;

    /// <summary>Creates the hasher.</summary>
    /// <param name="options">The cost parameters.</param>
    /// <param name="masterKeys">Supplies the optional password pepper.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public Argon2idPasswordHasher(IOptions<Argon2idOptions> options, IMasterKeyProvider masterKeys)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(masterKeys);

        _options = options.Value;
        _masterKeys = masterKeys;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(_options.SaltLength);
        var digest = Derive(
            password,
            salt,
            _options.MemoryKib,
            _options.Iterations,
            _options.Parallelism,
            _options.HashLength);

        try
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"${AlgorithmLabel}$v={ArgonVersion}$m={_options.MemoryKib},t={_options.Iterations},p={_options.Parallelism}${Convert.ToBase64String(salt)}${Convert.ToBase64String(digest)}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public PasswordVerificationResult Verify(string password, string encodedHash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(encodedHash);

        if (!TryParse(encodedHash, out var parsed))
        {
            // An unreadable digest is a failure, not an exception: a corrupt or hand-edited
            // row must not become a way to tell accounts apart.
            return PasswordVerificationResult.Failed;
        }

        var candidate = Derive(
            password,
            parsed.Salt,
            parsed.MemoryKib,
            parsed.Iterations,
            parsed.Parallelism,
            parsed.Hash.Length);

        try
        {
            if (!CryptographicOperations.FixedTimeEquals(candidate, parsed.Hash))
            {
                return PasswordVerificationResult.Failed;
            }

            var isCurrent =
                parsed.MemoryKib >= _options.MemoryKib
                && parsed.Iterations >= _options.Iterations
                && parsed.Parallelism == _options.Parallelism
                && parsed.Hash.Length >= _options.HashLength
                && parsed.Salt.Length >= _options.SaltLength;

            return isCurrent
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.SuccessRehashNeeded;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(candidate);
            CryptographicOperations.ZeroMemory(parsed.Hash);
        }
    }

    private byte[] Derive(
        string password,
        byte[] salt,
        int memoryKib,
        int iterations,
        int parallelism,
        int hashLength)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                MemorySize = memoryKib,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };

            var pepper = _masterKeys.GetPasswordPepper();

            if (!pepper.IsEmpty)
            {
                argon2.KnownSecret = pepper.ToArray();
            }

            return argon2.GetBytes(hashLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static bool TryParse(string encoded, out ParsedDigest parsed)
    {
        parsed = default;

        // $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
        var parts = encoded.Split('$');

        if (parts.Length != 6
            || parts[0].Length != 0
            || !string.Equals(parts[1], AlgorithmLabel, StringComparison.Ordinal)
            || !string.Equals(parts[2], $"v={ArgonVersion}", StringComparison.Ordinal))
        {
            return false;
        }

        var costs = parts[3].Split(',');

        if (costs.Length != 3
            || !TryReadCost(costs[0], "m=", out var memoryKib)
            || !TryReadCost(costs[1], "t=", out var iterations)
            || !TryReadCost(costs[2], "p=", out var parallelism))
        {
            return false;
        }

        byte[] salt;
        byte[] hash;

        try
        {
            salt = Convert.FromBase64String(parts[4]);
            hash = Convert.FromBase64String(parts[5]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (salt.Length == 0 || hash.Length == 0)
        {
            return false;
        }

        parsed = new ParsedDigest(salt, hash, memoryKib, iterations, parallelism);
        return true;
    }

    private static bool TryReadCost(string field, string prefix, out int value)
    {
        value = 0;

        return field.StartsWith(prefix, StringComparison.Ordinal)
            && int.TryParse(
                field.AsSpan(prefix.Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out value)
            && value > 0;
    }

    private readonly record struct ParsedDigest(
        byte[] Salt,
        byte[] Hash,
        int MemoryKib,
        int Iterations,
        int Parallelism);
}
