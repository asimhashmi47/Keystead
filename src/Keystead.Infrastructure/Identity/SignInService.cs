using System;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Identity;
using Keystead.Domain.Auditing;
using Keystead.Domain.Identity;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Keystead.Infrastructure.Identity;

/// <summary>
/// The interactive sign-in flow.
/// </summary>
/// <remarks>
/// <para>
/// Three properties this class exists to hold, none of which survive being added later:
/// </para>
/// <para>
/// <b>No user enumeration.</b> An unknown address runs the same Argon2id verification as a
/// known one, against a decoy digest generated at construction. Skipping the hash when the
/// account does not exist would make the response measurably faster, and the sign-in form
/// would become a way to test whether an address has an account here. The decoy also means a
/// deactivated or locked account costs the same as a live one.
/// </para>
/// <para>
/// <b>Every attempt is audited before the caller is answered.</b> A failure the log never saw
/// is a failure nobody can investigate, and the entry joins the hash chain so it cannot be
/// quietly removed afterwards.
/// </para>
/// <para>
/// <b>MFA is not optional for privileged roles.</b> An Owner or Admin who has not enrolled is
/// sent to enrolment, not let in. Checking at sign-in rather than at enrolment time means a
/// role promotion cannot leave a privileged account without a second factor.
/// </para>
/// </remarks>
public sealed class SignInService : ISignInService
{
    private readonly KeysteadDbContext _db;
    private readonly IPasswordHasher _passwords;
    private readonly ITotpService _totp;
    private readonly IRecoveryCodeService _recoveryCodes;
    private readonly IAuditChain _audit;
    private readonly IClock _clock;
    private readonly SessionOptions _sessions;
    private readonly string _decoyPasswordHash;

    /// <summary>Creates the service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="passwords">The password hasher.</param>
    /// <param name="totp">The TOTP service.</param>
    /// <param name="recoveryCodes">The recovery code service.</param>
    /// <param name="audit">The audit chain.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="sessions">Session lifetimes.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public SignInService(
        KeysteadDbContext db,
        IPasswordHasher passwords,
        ITotpService totp,
        IRecoveryCodeService recoveryCodes,
        IAuditChain audit,
        IClock clock,
        IOptions<SessionOptions> sessions)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(passwords);
        ArgumentNullException.ThrowIfNull(totp);
        ArgumentNullException.ThrowIfNull(recoveryCodes);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(sessions);

        _db = db;
        _passwords = passwords;
        _totp = totp;
        _recoveryCodes = recoveryCodes;
        _audit = audit;
        _clock = clock;
        _sessions = sessions.Value;

        // The decoy digest. Verified against when no account matches, so the work done is
        // indistinguishable from a real verification. Its plaintext is a random value that is
        // thrown away, so no submitted password can ever match it.
        _decoyPasswordHash = _passwords.Hash(Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<SignInOutcome> AuthenticateAsync(
        string email,
        string password,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(context);

        var normalisedEmail = email.Trim().ToLowerInvariant();
        var now = _clock.UtcNow;

        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Email == normalisedEmail, cancellationToken)
            .ConfigureAwait(false);

        // Always verify something. See the remarks on this class.
        var storedHash = user?.PasswordHash ?? _decoyPasswordHash;
        var verification = _passwords.Verify(password, storedHash);

        if (user is null)
        {
            await AuditAsync(
                context,
                AuditAction.SignInFailed,
                AuditOutcome.Denied,
                actorId: null,
                actorLabel: normalisedEmail,
                detail: "No account with that address.",
                cancellationToken).ConfigureAwait(false);

            return SignInOutcome.Failed;
        }

        if (user.IsLockedOut(now))
        {
            await AuditAsync(
                context,
                AuditAction.SignInFailed,
                AuditOutcome.Denied,
                user.Id,
                user.Email,
                "Account is locked out.",
                cancellationToken).ConfigureAwait(false);

            return SignInOutcome.Failed;
        }

        if (!user.IsActive)
        {
            await AuditAsync(
                context,
                AuditAction.SignInFailed,
                AuditOutcome.Denied,
                user.Id,
                user.Email,
                "Account is deactivated.",
                cancellationToken).ConfigureAwait(false);

            return SignInOutcome.Failed;
        }

        if (verification is PasswordVerificationResult.Failed)
        {
            user.RegisterFailedSignIn(now);

            var lockedOutNow = user.IsLockedOut(_clock.UtcNow);

            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            await AuditAsync(
                context,
                AuditAction.SignInFailed,
                AuditOutcome.Denied,
                user.Id,
                user.Email,
                $"Incorrect password (consecutive failures: {user.FailedSignInCount}).",
                cancellationToken).ConfigureAwait(false);

            if (lockedOutNow)
            {
                await AuditAsync(
                    context,
                    AuditAction.AccountLockedOut,
                    AuditOutcome.Denied,
                    user.Id,
                    user.Email,
                    $"Locked out until {user.LockoutEndUtc:O}.",
                    cancellationToken).ConfigureAwait(false);
            }

            return SignInOutcome.Failed;
        }

        // Correct password. Upgrade the digest now, while the plaintext is still in hand: this
        // is the only moment it can be re-hashed at the current cost parameters.
        if (verification is PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = _passwords.Hash(password);
        }

        var mustUseMfa = await RequiresMfaAsync(user.Id, cancellationToken).ConfigureAwait(false);

        if (user.MfaEnabled)
        {
            // The failure counter is not cleared yet. The second factor has not been presented,
            // so this attempt is not yet a success, and clearing it here would let an attacker
            // with the password alone reset the lockout indefinitely.
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            return SignInOutcome.MfaRequired(user.Id);
        }

        if (mustUseMfa)
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            await AuditAsync(
                context,
                AuditAction.SignInFailed,
                AuditOutcome.Denied,
                user.Id,
                user.Email,
                "Role requires multi-factor authentication, which is not enrolled.",
                cancellationToken).ConfigureAwait(false);

            return SignInOutcome.MfaEnrolmentRequired(user.Id);
        }

        return await CompleteSignInAsync(user, context, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<SignInOutcome> VerifyMfaAsync(
        Guid userId,
        string code,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(context);

        var now = _clock.UtcNow;

        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken)
            .ConfigureAwait(false);

        if (user is null || !user.IsActive || user.IsLockedOut(now) || !user.MfaEnabled)
        {
            await AuditAsync(
                context,
                AuditAction.MfaFailed,
                AuditOutcome.Denied,
                userId,
                user?.Email ?? userId.ToString("D", CultureInfo.InvariantCulture),
                "No pending challenge for this account.",
                cancellationToken).ConfigureAwait(false);

            return SignInOutcome.Failed;
        }

        var seed = new StoredTotpSeed(
            user.MfaSecretCiphertext!,
            user.MfaSecretNonce!,
            user.MfaSecretTag!,
            user.MfaSeedMasterKeyVersion);

        var result = _totp.Verify(user.Id, seed, code, user.LastUsedTotpWindow);

        if (!result.IsValid)
        {
            // A wrong second factor counts towards lockout. Without this, an attacker holding
            // the password could grind the six-digit code without limit.
            user.RegisterFailedSignIn(now);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            await AuditAsync(
                context,
                AuditAction.MfaFailed,
                AuditOutcome.Denied,
                user.Id,
                user.Email,
                "Incorrect or already-used code.",
                cancellationToken).ConfigureAwait(false);

            return SignInOutcome.Failed;
        }

        // Burn the time step so this code cannot be presented again.
        user.LastUsedTotpWindow = result.Window;

        await AuditAsync(
            context,
            AuditAction.MfaSucceeded,
            AuditOutcome.Success,
            user.Id,
            user.Email,
            null,
            cancellationToken).ConfigureAwait(false);

        return await CompleteSignInAsync(user, context, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<SignInOutcome> UseRecoveryCodeAsync(
        Guid userId,
        string code,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(context);

        var now = _clock.UtcNow;

        var user = await _db.Users
            .Include(u => u.RecoveryCodes)
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken)
            .ConfigureAwait(false);

        if (user is null || !user.IsActive || user.IsLockedOut(now))
        {
            await AuditAsync(
                context,
                AuditAction.MfaFailed,
                AuditOutcome.Denied,
                userId,
                user?.Email ?? userId.ToString("D", CultureInfo.InvariantCulture),
                "No pending challenge for this account.",
                cancellationToken).ConfigureAwait(false);

            return SignInOutcome.Failed;
        }

        var candidate = _recoveryCodes.HashForComparison(code);

        // Every unused code is compared, with no early exit, so the time taken does not reveal
        // how many codes the account has left or which position matched.
        UserRecoveryCode? matched = null;

        foreach (var stored in user.RecoveryCodes.Where(c => c.IsUnused))
        {
            if (candidate is not null && _recoveryCodes.Matches(candidate, stored.CodeHash))
            {
                matched = stored;
            }
        }

        if (matched is null)
        {
            user.RegisterFailedSignIn(now);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            await AuditAsync(
                context,
                AuditAction.MfaFailed,
                AuditOutcome.Denied,
                user.Id,
                user.Email,
                "Recovery code not recognised.",
                cancellationToken).ConfigureAwait(false);

            return SignInOutcome.Failed;
        }

        matched.UsedUtc = now;

        var remaining = user.RecoveryCodes.Count(c => c.IsUnused) - 1;

        await AuditAsync(
            context,
            AuditAction.RecoveryCodeUsed,
            AuditOutcome.Success,
            user.Id,
            user.Email,
            $"Recovery code consumed; {remaining} remaining.",
            cancellationToken).ConfigureAwait(false);

        return await CompleteSignInAsync(user, context, cancellationToken).ConfigureAwait(false);
    }

    private async Task<SignInOutcome> CompleteSignInAsync(
        User user,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;

        user.RegisterSuccessfulSignIn();

        var seenBefore = await _db.UserSessions
            .AsNoTracking()
            .AnyAsync(
                s => s.UserId == user.Id && s.CreatedIp == context.IpAddress,
                cancellationToken)
            .ConfigureAwait(false);

        var session = new UserSession
        {
            Id = Guid.CreateVersion7(),
            UserId = user.Id,
            CreatedUtc = now,
            LastSeenUtc = now,
            AbsoluteExpiryUtc = now + _sessions.AbsoluteLifetime,
            CreatedIp = Cap(context.IpAddress, 64),
            UserAgent = Cap(context.UserAgent ?? "unknown", 512),

            // Signing in is itself a proof of identity, so the session starts with a fresh
            // step-up. Demanding another one immediately would be theatre, not security.
            LastStepUpUtc = now,
        };

        _db.UserSessions.Add(session);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            context,
            AuditAction.SignInSucceeded,
            AuditOutcome.Success,
            user.Id,
            user.Email,
            null,
            cancellationToken,
            resourceId: session.Id,
            resourceType: "session").ConfigureAwait(false);

        if (!seenBefore)
        {
            // Surfaced in the audit log and the security centre. A sign-in from an unfamiliar
            // address is not blocked, because a legitimate user travels, but it is recorded so
            // it can be noticed.
            await AuditAsync(
                context,
                AuditAction.SignInFromNewAddress,
                AuditOutcome.Success,
                user.Id,
                user.Email,
                "First sign-in seen from this address.",
                cancellationToken,
                resourceId: session.Id,
                resourceType: "session").ConfigureAwait(false);
        }

        return SignInOutcome.Succeeded(user.Id, session.Id, user.Email);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<bool> StepUpAsync(
        Guid userId,
        Guid sessionId,
        string password,
        string? totpCode,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(context);

        var now = _clock.UtcNow;

        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken)
            .ConfigureAwait(false);

        var session = await _db.UserSessions
            .FirstOrDefaultAsync(
                s => s.Id == sessionId && s.UserId == userId,
                cancellationToken)
            .ConfigureAwait(false);

        if (user is null || session is null || session.RevokedUtc is not null
            || !user.IsActive || user.IsLockedOut(now))
        {
            await AuditStepUpFailureAsync(context, userId, user?.Email, "Session or account is not usable.", cancellationToken)
                .ConfigureAwait(false);

            return false;
        }

        if (_passwords.Verify(password, user.PasswordHash) is PasswordVerificationResult.Failed)
        {
            user.RegisterFailedSignIn(now);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            await AuditStepUpFailureAsync(context, userId, user.Email, "Incorrect password.", cancellationToken)
                .ConfigureAwait(false);

            return false;
        }

        // When MFA is enrolled it is part of the step-up too. A step-up that only asked for the
        // password would be weaker than the sign-in it is re-confirming.
        if (user.MfaEnabled)
        {
            var seed = new StoredTotpSeed(
                user.MfaSecretCiphertext!,
                user.MfaSecretNonce!,
                user.MfaSecretTag!,
                user.MfaSeedMasterKeyVersion);

            var result = _totp.Verify(user.Id, seed, totpCode ?? string.Empty, user.LastUsedTotpWindow);

            if (!result.IsValid)
            {
                user.RegisterFailedSignIn(now);
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

                await AuditStepUpFailureAsync(context, userId, user.Email, "Incorrect or already-used code.", cancellationToken)
                    .ConfigureAwait(false);

                return false;
            }

            user.LastUsedTotpWindow = result.Window;
        }

        user.RegisterSuccessfulSignIn();
        session.LastStepUpUtc = now;
        session.LastSeenUtc = now;

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            context,
            AuditAction.StepUpSucceeded,
            AuditOutcome.Success,
            userId,
            user.Email,
            null,
            cancellationToken,
            resourceId: sessionId,
            resourceType: "session").ConfigureAwait(false);

        return true;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public async Task SignOutAsync(
        Guid userId,
        Guid sessionId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var session = await _db.UserSessions
            .FirstOrDefaultAsync(
                s => s.Id == sessionId && s.UserId == userId,
                cancellationToken)
            .ConfigureAwait(false);

        if (session is null || session.RevokedUtc is not null)
        {
            return;
        }

        session.RevokedUtc = _clock.UtcNow;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        var email = await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => u.Email)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        await AuditAsync(
            context,
            AuditAction.SignedOut,
            AuditOutcome.Success,
            userId,
            email ?? userId.ToString("D", CultureInfo.InvariantCulture),
            null,
            cancellationToken,
            resourceId: sessionId,
            resourceType: "session").ConfigureAwait(false);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public async Task<int> SignOutEverywhereAsync(
        Guid userId,
        Guid? exceptSessionId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var now = _clock.UtcNow;

        var sessions = await _db.UserSessions
            .Where(s => s.UserId == userId
                && s.RevokedUtc == null
                && (exceptSessionId == null || s.Id != exceptSessionId))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        foreach (var session in sessions)
        {
            session.RevokedUtc = now;
        }

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        var email = await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => u.Email)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        await AuditAsync(
            context,
            AuditAction.SessionRevoked,
            AuditOutcome.Success,
            userId,
            email ?? userId.ToString("D", CultureInfo.InvariantCulture),
            $"Signed out everywhere; {sessions.Count} session(s) revoked.",
            cancellationToken,
            resourceType: "session").ConfigureAwait(false);

        return sessions.Count;
    }

    /// <inheritdoc />
    public async Task<bool> TouchSessionAsync(
        Guid userId,
        Guid sessionId,
        CancellationToken cancellationToken)
    {
        var session = await _db.UserSessions
            .FirstOrDefaultAsync(
                s => s.Id == sessionId && s.UserId == userId,
                cancellationToken)
            .ConfigureAwait(false);

        if (session is null)
        {
            return false;
        }

        var now = _clock.UtcNow;

        if (!session.IsActive(now, _sessions.IdleTimeout))
        {
            // Expired by idle or absolute timeout. Recorded as revoked so the session list
            // shows why it ended rather than leaving a row that looks live but is not.
            if (session.RevokedUtc is null)
            {
                session.RevokedUtc = now;
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }

            return false;
        }

        session.LastSeenUtc = now;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return true;
    }

    private async Task<bool> RequiresMfaAsync(Guid userId, CancellationToken cancellationToken)
    {
        var roles = await _db.WorkspaceMemberships
            .AsNoTracking()
            .Where(m => m.UserId == userId)
            .Select(m => m.Role)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        // Any privileged role anywhere mandates MFA. A user who is a Reader in one workspace
        // and an Admin in another is still an Admin, and the account is only as strong as its
        // weakest sign-in.
        return roles.Exists(RoleCapabilities.RequiresMfa);
    }

    private Task AuditStepUpFailureAsync(
        RequestContext context,
        Guid userId,
        string? email,
        string detail,
        CancellationToken cancellationToken) =>
        AuditAsync(
            context,
            AuditAction.StepUpFailed,
            AuditOutcome.Denied,
            userId,
            email ?? userId.ToString("D", CultureInfo.InvariantCulture),
            detail,
            cancellationToken);

    // Returns Task rather than Task<long>: these call sites have no use for the chain
    // position, and awaiting-and-discarding here keeps every caller free of a value it would
    // only ignore.
    private async Task AuditAsync(
        RequestContext context,
        AuditAction action,
        AuditOutcome outcome,
        Guid? actorId,
        string actorLabel,
        string? detail,
        CancellationToken cancellationToken,
        Guid? resourceId = null,
        string resourceType = "user") =>
        _ = await _audit.AppendAsync(
            new AuditRecord
            {
                WorkspaceId = null,
                ActorType = actorId is null ? ActorType.Anonymous : ActorType.User,
                ActorId = actorId,
                ActorLabel = actorLabel,
                Action = action,
                Outcome = outcome,
                ResourceType = resourceType,
                ResourceId = resourceId ?? actorId,
                ResourceLabel = null,
                IpAddress = context.IpAddress,
                UserAgent = context.UserAgent,
                CorrelationId = context.CorrelationId,

                // The detail says which rule was broken, never what was submitted. A password
                // or a code must not reach the audit log any more than it reaches a log line.
                DataJson = detail is null
                    ? null
                    : System.Text.Json.JsonSerializer.Serialize(new { reason = detail }),
            },
            cancellationToken).ConfigureAwait(false);

    private static string Cap(string value, int max) =>
        value.Length <= max ? value : value[..max];
}
