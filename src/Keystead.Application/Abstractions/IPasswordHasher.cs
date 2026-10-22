namespace Keystead.Application.Abstractions;

/// <summary>Hashes and verifies user passwords with Argon2id.</summary>
public interface IPasswordHasher
{
    /// <summary>Hashes a password, generating a fresh random salt.</summary>
    /// <param name="password">The plaintext password.</param>
    /// <returns>
    /// An encoded digest carrying the algorithm, its parameters and the salt, so that stored
    /// hashes stay verifiable after the cost parameters are raised.
    /// </returns>
    string Hash(string password);

    /// <summary>Verifies a password against an encoded digest in fixed time.</summary>
    /// <param name="password">The submitted plaintext password.</param>
    /// <param name="encodedHash">The stored digest.</param>
    /// <returns>The outcome, including whether the stored hash should be upgraded.</returns>
    PasswordVerificationResult Verify(string password, string encodedHash);
}
