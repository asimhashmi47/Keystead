using System.ComponentModel.DataAnnotations;

namespace Keystead.Infrastructure.Cryptography;

/// <summary>
/// Argon2id cost parameters.
/// </summary>
/// <remarks>
/// <para>
/// The defaults are deliberately above the OWASP floor of 19 MiB / t=2 / p=1:
/// <c>64 MiB, t=3, p=1</c>. This is a secrets manager, so the password that unlocks a
/// human session guards every credential that human can reach, and a slow hash is the only
/// thing standing between a stolen database and an offline attack.
/// </para>
/// <para>
/// Parallelism stays at 1 on purpose. Raising it multiplies memory across concurrent sign-ins
/// and turns the login endpoint into a memory-exhaustion lever; the rate limiter bounds how
/// many hashes run at once, and single-threaded hashing keeps that bound meaningful.
/// </para>
/// <para>
/// These values are recorded inside every digest, so raising them later does not invalidate
/// existing hashes: verification reads the stored parameters, and
/// <see cref="Application.Abstractions.PasswordVerificationResult.SuccessRehashNeeded"/>
/// tells the caller to upgrade the digest while it still holds the plaintext.
/// </para>
/// </remarks>
public sealed class Argon2idOptions
{
    /// <summary>The configuration section these options bind to.</summary>
    public const string SectionName = "Keystead:PasswordHashing";

    /// <summary>Memory cost in kibibytes. Default 65536 (64 MiB).</summary>
    [Range(19_456, 1_048_576)]
    public int MemoryKib { get; set; } = 65_536;

    /// <summary>Time cost, in passes over memory. Default 3.</summary>
    [Range(2, 20)]
    public int Iterations { get; set; } = 3;

    /// <summary>Degree of parallelism (lanes). Default 1; see the remarks on this type.</summary>
    [Range(1, 16)]
    public int Parallelism { get; set; } = 1;

    /// <summary>Salt length in bytes. Default 16 (128 bits).</summary>
    [Range(16, 64)]
    public int SaltLength { get; set; } = 16;

    /// <summary>Derived key length in bytes. Default 32 (256 bits).</summary>
    [Range(32, 64)]
    public int HashLength { get; set; } = 32;
}
