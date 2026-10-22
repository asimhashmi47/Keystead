using System;

namespace Keystead.Application.Identity;

/// <summary>
/// What happened on a sign-in attempt.
/// </summary>
/// <remarks>
/// <see cref="Failed"/> carries no detail about why, and the caller must not add any. "No such
/// account", "wrong password" and "locked out" are the same answer to anyone outside, because
/// telling them apart turns the sign-in form into a way to discover who has an account here.
/// </remarks>
public enum SignInStatus
{
    /// <summary>Rejected. The reason is in the audit log, never in the response.</summary>
    Failed = 0,

    /// <summary>Password accepted; a TOTP code is now required.</summary>
    MfaRequired = 1,

    /// <summary>
    /// Password accepted, but this account holds a role that mandates MFA and has not enrolled.
    /// The user is sent to enrolment rather than let in.
    /// </summary>
    MfaEnrolmentRequired = 2,

    /// <summary>Fully authenticated; a session has been created.</summary>
    Succeeded = 3,
}

/// <summary>The result of a sign-in step.</summary>
/// <param name="Status">What happened.</param>
/// <param name="UserId">
/// The account, when the password step succeeded. Needed to carry the pending MFA challenge,
/// and never put anywhere the user could edit it.
/// </param>
/// <param name="SessionId">The new session, when sign-in completed.</param>
/// <param name="Email">
/// The account's address, carried so the caller can put a display name in the cookie without
/// querying for it. Only populated on success.
/// </param>
public sealed record SignInOutcome(
    SignInStatus Status,
    Guid? UserId,
    Guid? SessionId,
    string? Email)
{
    /// <summary>A rejected attempt.</summary>
    public static SignInOutcome Failed { get; } = new(SignInStatus.Failed, null, null, null);

    /// <summary>The password was accepted and a TOTP code is required.</summary>
    /// <param name="userId">The account being signed in to.</param>
    public static SignInOutcome MfaRequired(Guid userId) =>
        new(SignInStatus.MfaRequired, userId, null, null);

    /// <summary>The account must enrol in MFA before it can be used.</summary>
    /// <param name="userId">The account being signed in to.</param>
    public static SignInOutcome MfaEnrolmentRequired(Guid userId) =>
        new(SignInStatus.MfaEnrolmentRequired, userId, null, null);

    /// <summary>Sign-in completed.</summary>
    /// <param name="userId">The account.</param>
    /// <param name="sessionId">The new session.</param>
    /// <param name="email">The account's address, for the cookie's display name.</param>
    public static SignInOutcome Succeeded(Guid userId, Guid sessionId, string email) =>
        new(SignInStatus.Succeeded, userId, sessionId, email);
}
