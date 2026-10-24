using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Domain.Common;

namespace Keystead.Application.Identity;

/// <summary>What a signed-in person can change about their own account.</summary>
public interface IProfileService
{
    /// <summary>
    /// Changes the signed-in user's password.
    /// </summary>
    /// <remarks>
    /// Requires the current password, even though the session is already authenticated. A
    /// session left open on an unlocked machine must not be enough to take the account over,
    /// and knowing the old password is the one thing the person at the keyboard can prove.
    /// Every other session is revoked on success.
    /// </remarks>
    /// <param name="userId">The signed-in account.</param>
    /// <param name="currentSessionId">The session to keep alive.</param>
    /// <param name="currentPassword">The existing password.</param>
    /// <param name="newPassword">The proposed password.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>How many other sessions were revoked, or the reason it was refused.</returns>
    Task<Result<int>> ChangePasswordAsync(
        Guid userId,
        Guid currentSessionId,
        string currentPassword,
        string newPassword,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Clears the user's TOTP enrolment so they can set up a new authenticator.
    /// </summary>
    /// <remarks>
    /// Needs the current password and, when one is enrolled, a current code or a recovery
    /// code. Allowing a signed-in session to drop the second factor unchallenged would make
    /// the second factor worth nothing once a session existed.
    /// </remarks>
    /// <param name="userId">The signed-in account.</param>
    /// <param name="currentPassword">The existing password.</param>
    /// <param name="totpOrRecoveryCode">A current code, or a recovery code.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> ResetMfaAsync(
        Guid userId,
        string currentPassword,
        string? totpOrRecoveryCode,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Reads the signed-in user's own profile.</summary>
    /// <param name="userId">The signed-in account.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Their profile.</returns>
    Task<Result<ProfileView>> GetAsync(Guid userId, CancellationToken cancellationToken);
}

/// <summary>A user's own profile.</summary>
/// <param name="Email">Their sign-in address.</param>
/// <param name="DisplayName">Their display name.</param>
/// <param name="MfaEnabled">Whether a second factor is enrolled.</param>
/// <param name="RequiresMfa">Whether any role they hold makes it mandatory.</param>
/// <param name="RecoveryCodesRemaining">How many unused recovery codes are left.</param>
/// <param name="PasswordChangedUtc">When the password was last changed.</param>
/// <param name="ActiveSessionCount">How many sessions are currently live.</param>
public sealed record ProfileView(
    string Email,
    string DisplayName,
    bool MfaEnabled,
    bool RequiresMfa,
    int RecoveryCodesRemaining,
    DateTimeOffset PasswordChangedUtc,
    int ActiveSessionCount);
