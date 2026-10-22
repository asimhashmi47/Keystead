using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Keystead.Infrastructure.Identity;
using Keystead.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Keystead.Web.Pages;

/// <summary>
/// The security centre: MFA status and the session list.
/// </summary>
/// <remarks>
/// Requires authentication through the fallback policy, so there is no attribute here. Each
/// query is scoped to the signed-in user, and the revoke handlers take the session id from the
/// form but match it against that user, so a crafted post cannot revoke someone else's session.
/// </remarks>
public sealed class SecurityModel : KeysteadPageModel
{
    private readonly KeysteadDbContext _db;
    private readonly ISignInService _signIn;
    private readonly SessionOptions _sessions;

    /// <summary>Creates the page model.</summary>
    /// <param name="db">The database.</param>
    /// <param name="signIn">The sign-in service, for revocation.</param>
    /// <param name="sessions">Session lifetimes, for the idle calculation.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public SecurityModel(
        KeysteadDbContext db,
        ISignInService signIn,
        IOptions<SessionOptions> sessions)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(signIn);
        ArgumentNullException.ThrowIfNull(sessions);

        _db = db;
        _signIn = signIn;
        _sessions = sessions.Value;
    }

    /// <summary>Whether the signed-in account has TOTP enrolled.</summary>
    public bool MfaEnabled { get; private set; }

    /// <summary>How many unused recovery codes remain.</summary>
    public int RecoveryCodesRemaining { get; private set; }

    /// <summary>The account's sessions, newest first.</summary>
    public IReadOnlyList<SessionRow> Sessions { get; private set; } = [];

    /// <summary>A session as shown in the list.</summary>
    /// <param name="Id">The session identifier.</param>
    /// <param name="IsCurrent">Whether this is the session making the request.</param>
    /// <param name="CreatedUtc">When it began.</param>
    /// <param name="LastSeenUtc">When it was last active.</param>
    /// <param name="CreatedIp">The address it was created from.</param>
    /// <param name="UserAgent">The user agent captured at sign-in.</param>
    public sealed record SessionRow(
        Guid Id,
        bool IsCurrent,
        DateTimeOffset CreatedUtc,
        DateTimeOffset LastSeenUtc,
        string CreatedIp,
        string UserAgent);

    /// <summary>Loads the page.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        await LoadAsync(cancellationToken).ConfigureAwait(false);
        return Page();
    }

    /// <summary>Revokes one session.</summary>
    /// <param name="sessionId">The session to revoke.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostRevokeAsync(
        Guid sessionId,
        CancellationToken cancellationToken)
    {
        if (CurrentUserId is not { } userId)
        {
            return RedirectToPage("/SignIn");
        }

        // The service matches the session against this user, so a session id belonging to
        // someone else simply does not match and nothing is revoked.
        await _signIn
            .SignOutAsync(userId, sessionId, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        return RedirectToPage();
    }

    /// <summary>Revokes every session except the current one.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostRevokeAllAsync(CancellationToken cancellationToken)
    {
        if (CurrentUserId is not { } userId)
        {
            return RedirectToPage("/SignIn");
        }

        // Keeps this session alive on purpose: signing the user out of the page they are
        // using to secure their account is a hostile way to handle a suspected compromise.
        await _signIn
            .SignOutEverywhereAsync(userId, CurrentSessionId, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        return RedirectToPage();
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        if (CurrentUserId is not { } userId)
        {
            return;
        }

        var user = await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new
            {
                u.MfaEnrolledUtc,
                HasSeed = u.MfaSecretCiphertext != null,
                Remaining = u.RecoveryCodes.Count(c => c.UsedUtc == null),
            })
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (user is null)
        {
            return;
        }

        MfaEnabled = user.MfaEnrolledUtc is not null && user.HasSeed;
        RecoveryCodesRemaining = user.Remaining;

        var cutoff = DateTimeOffset.UtcNow - _sessions.IdleTimeout;

        Sessions = await _db.UserSessions
            .AsNoTracking()
            .Where(s => s.UserId == userId
                && s.RevokedUtc == null
                && s.LastSeenUtc > cutoff)
            .OrderByDescending(s => s.LastSeenUtc)
            .Select(s => new SessionRow(
                s.Id,
                s.Id == CurrentSessionId,
                s.CreatedUtc,
                s.LastSeenUtc,
                s.CreatedIp,
                s.UserAgent))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
    }
}
