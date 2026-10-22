namespace Keystead.Application.Abstractions;

/// <summary>The outcome of verifying a password against a stored digest.</summary>
public enum PasswordVerificationResult
{
    /// <summary>The password does not match, or the stored digest is unreadable.</summary>
    Failed = 0,

    /// <summary>The password matches and the stored digest uses current parameters.</summary>
    Success = 1,

    /// <summary>
    /// The password matches but the digest was produced with weaker parameters than are now
    /// configured. The caller should re-hash and store the result while it holds the plaintext.
    /// </summary>
    SuccessRehashNeeded = 2,
}
