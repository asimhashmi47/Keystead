namespace Keystead.Application.Authorization;

/// <summary>
/// The result of an authorization check.
/// </summary>
/// <param name="IsAllowed">Whether the action may proceed.</param>
/// <param name="NeedsStepUp">
/// Whether the only thing standing in the way is a stale step-up re-authentication. Separated
/// from a flat denial so the user interface can offer the step-up modal instead of a dead end.
/// </param>
/// <param name="Reason">
/// Why it was refused. Written for the audit log and for a generic user-facing message; it
/// never reveals whether a resource the caller cannot reach exists.
/// </param>
public sealed record AccessDecision(bool IsAllowed, bool NeedsStepUp, string? Reason)
{
    /// <summary>The action may proceed.</summary>
    public static AccessDecision Allowed { get; } = new(true, false, null);

    /// <summary>The action is refused.</summary>
    /// <param name="reason">Why, for the audit entry.</param>
    public static AccessDecision Denied(string reason) => new(false, false, reason);

    /// <summary>The action needs a fresh step-up re-authentication first.</summary>
    /// <param name="reason">Which action demanded it.</param>
    public static AccessDecision StepUp(string reason) => new(false, true, reason);
}
