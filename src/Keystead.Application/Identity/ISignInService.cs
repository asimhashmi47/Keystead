using System;
using System.Threading;
using System.Threading.Tasks;

namespace Keystead.Application.Identity;

/// <summary>Drives the interactive sign-in flow and session lifecycle.</summary>
public interface ISignInService
{
    /// <summary>Checks an email and password, the first step of sign-in.</summary>
    /// <param name="email">The submitted address.</param>
    /// <param name="password">The submitted password.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>
    /// The outcome. A failure says nothing about why, by design: see <see cref="SignInStatus"/>.
    /// </returns>
    Task<SignInOutcome> AuthenticateAsync(
        string email,
        string password,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Completes sign-in with a TOTP code.</summary>
    /// <param name="userId">The account from the pending challenge.</param>
    /// <param name="code">The submitted six-digit code.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The outcome.</returns>
    Task<SignInOutcome> VerifyMfaAsync(
        Guid userId,
        string code,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Completes sign-in by consuming a single-use recovery code.</summary>
    /// <param name="userId">The account from the pending challenge.</param>
    /// <param name="code">The submitted recovery code.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The outcome.</returns>
    Task<SignInOutcome> UseRecoveryCodeAsync(
        Guid userId,
        string code,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Re-confirms a signed-in user's identity for a high-privilege action, and records the
    /// step-up against their session.
    /// </summary>
    /// <param name="userId">The signed-in account.</param>
    /// <param name="sessionId">Their current session.</param>
    /// <param name="password">The submitted password.</param>
    /// <param name="totpCode">A TOTP code, when the account has MFA enrolled.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns><see langword="true"/> when the step-up succeeded.</returns>
    Task<bool> StepUpAsync(
        Guid userId,
        Guid sessionId,
        string password,
        string? totpCode,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Ends one session.</summary>
    /// <param name="userId">The owning account.</param>
    /// <param name="sessionId">The session to revoke.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A task that completes when the session is revoked.</returns>
    Task SignOutAsync(
        Guid userId,
        Guid sessionId,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Ends every session for an account.</summary>
    /// <param name="userId">The owning account.</param>
    /// <param name="exceptSessionId">A session to keep, normally the current one.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>How many sessions were revoked.</returns>
    Task<int> SignOutEverywhereAsync(
        Guid userId,
        Guid? exceptSessionId,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Confirms that a session is still valid and refreshes its last-seen time.
    /// </summary>
    /// <remarks>
    /// Called on every authenticated request. A cookie alone is not enough: the session must
    /// still exist, be unrevoked, and be inside both timeouts, which is what makes
    /// "sign out everywhere" take effect immediately rather than when the cookie expires.
    /// </remarks>
    /// <param name="userId">The account from the cookie.</param>
    /// <param name="sessionId">The session from the cookie.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns><see langword="true"/> when the session may continue.</returns>
    Task<bool> TouchSessionAsync(
        Guid userId,
        Guid sessionId,
        CancellationToken cancellationToken);
}
