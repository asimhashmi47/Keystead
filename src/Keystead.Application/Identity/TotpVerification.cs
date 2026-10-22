namespace Keystead.Application.Identity;

/// <summary>The outcome of checking a TOTP code.</summary>
/// <param name="IsValid">Whether the code was correct and unused.</param>
/// <param name="Window">
/// The time step the code belonged to. Stored against the user on success so the same code
/// cannot be presented twice: a correct code is single-use, not valid for its whole window.
/// </param>
public sealed record TotpVerification(bool IsValid, long Window)
{
    /// <summary>A failed verification.</summary>
    public static TotpVerification Failed { get; } = new(false, 0);
}
