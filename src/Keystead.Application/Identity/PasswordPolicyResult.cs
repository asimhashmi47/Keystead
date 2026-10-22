namespace Keystead.Application.Identity;

/// <summary>Whether a proposed password is acceptable.</summary>
/// <param name="IsAcceptable">Whether it passed.</param>
/// <param name="Reason">
/// A message for the user when it failed. Shown on the form, so it explains the rule without
/// echoing the password back.
/// </param>
public sealed record PasswordPolicyResult(bool IsAcceptable, string? Reason)
{
    /// <summary>An acceptable password.</summary>
    public static PasswordPolicyResult Acceptable { get; } = new(true, null);

    /// <summary>A rejected password.</summary>
    /// <param name="reason">Why it was rejected.</param>
    public static PasswordPolicyResult Rejected(string reason) => new(false, reason);
}
