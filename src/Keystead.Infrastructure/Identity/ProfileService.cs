using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Identity;
using Keystead.Domain.Auditing;
using Keystead.Domain.Common;
using Keystead.Domain.Identity;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Keystead.Infrastructure.Identity;

/// <summary>Self-service account changes.</summary>
public sealed class ProfileService : IProfileService
{
    private readonly KeysteadDbContext _db;
    private readonly IPasswordHasher _passwords;
    private readonly IPasswordPolicy _policy;
    private readonly ITotpService _totp;
    private readonly IRecoveryCodeService _recoveryCodes;
    private readonly IAuditChain _audit;
    private readonly IClock _clock;
    private readonly SessionOptions _sessions;

    /// <summary>Creates the service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="passwords">The password hasher.</param>
    /// <param name="policy">The password policy.</param>
    /// <param name="totp">The TOTP service.</param>
    /// <param name="recoveryCodes">The recovery code service.</param>
    /// <param name="audit">The audit chain.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="sessions">Session lifetimes.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public ProfileService(
        KeysteadDbContext db,
        IPasswordHasher passwords,
        IPasswordPolicy policy,
        ITotpService totp,
        IRecoveryCodeService recoveryCodes,
        IAuditChain audit,
        IClock clock,
        IOptions<SessionOptions> sessions)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(passwords);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(totp);
        ArgumentNullException.ThrowIfNull(recoveryCodes);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(sessions);

        _db = db;
        _passwords = passwords;
        _policy = policy;
        _totp = totp;
        _recoveryCodes = recoveryCodes;
        _audit = audit;
        _clock = clock;
        _sessions = sessions.Value;
    }

    /// <inheritdoc />
    public async Task<Result<ProfileView>> GetAsync(
        Guid userId,
        CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var cutoff = now - _sessions.IdleTimeout;

        var profile = await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new
            {
                u.Email,
                u.DisplayName,
                u.MfaEnrolledUtc,
                HasSeed = u.MfaSecretCiphertext != null,
                u.PasswordChangedUtc,
                Remaining = u.RecoveryCodes.Count(c => c.UsedUtc == null),
                Sessions = u.Sessions.Count(s => s.RevokedUtc == null && s.LastSeenUtc > cutoff),
                Roles = u.Memberships.Select(m => m.Role).ToList(),
            })
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (profile is null)
        {
            return Result<ProfileView>.Fail(
                DomainError.NotFound("profile.not_found", "No such account."));
        }

        return Result<ProfileView>.Ok(new ProfileView(
            profile.Email,
            profile.DisplayName,
            profile.MfaEnrolledUtc is not null && profile.HasSeed,
            profile.Roles.Exists(RoleCapabilities.RequiresMfa),
            profile.Remaining,
            profile.PasswordChangedUtc,
            profile.Sessions));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<int>> ChangePasswordAsync(
        Guid userId,
        Guid currentSessionId,
        string currentPassword,
        string newPassword,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(newPassword);
        ArgumentNullException.ThrowIfNull(context);

        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken)
            .ConfigureAwait(false);

        if (user is null || !user.IsActive)
        {
            return Result<int>.Fail(
                DomainError.NotFound("profile.not_found", "No such account."));
        }

        var now = _clock.UtcNow;

        if (user.IsLockedOut(now))
        {
            return Result<int>.Fail(
                DomainError.Forbidden("profile.locked_out", "Too many failed attempts. Try again shortly."));
        }

        if (_passwords.Verify(currentPassword, user.PasswordHash) is PasswordVerificationResult.Failed)
        {
            // Counts towards lockout. Otherwise this form would be an unlimited oracle for
            // guessing the password of an account whose session has been left open.
            user.RegisterFailedSignIn(now);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            await AuditAsync(
                user, AuditAction.PasswordChanged, AuditOutcome.Denied,
                "Current password incorrect.", context, cancellationToken).ConfigureAwait(false);

            return Result<int>.Fail(
                DomainError.Forbidden("profile.wrong_password", "That is not your current password."));
        }

        var check = _policy.Check(newPassword, user.Email);

        if (!check.IsAcceptable)
        {
            return Result<int>.Fail(DomainError.Invalid("profile.weak_password", check.Reason!));
        }

        if (_passwords.Verify(newPassword, user.PasswordHash) is not PasswordVerificationResult.Failed)
        {
            return Result<int>.Fail(
                DomainError.Invalid(
                    "profile.password_unchanged",
                    "That is already your password. Choose a different one."));
        }

        user.PasswordHash = _passwords.Hash(newPassword);
        user.PasswordChangedUtc = now;
        user.RegisterSuccessfulSignIn();

        // Every other session ends. If the password was changed because it may have leaked,
        // leaving other sessions alive would leave the intruder signed in.
        var others = await _db.UserSessions
            .Where(s => s.UserId == userId && s.RevokedUtc == null && s.Id != currentSessionId)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        foreach (var session in others)
        {
            session.RevokedUtc = now;
        }

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            user, AuditAction.PasswordChanged, AuditOutcome.Success,
            $"{others.Count} other session(s) revoked.", context, cancellationToken)
            .ConfigureAwait(false);

        return Result<int>.Ok(others.Count);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> ResetMfaAsync(
        Guid userId,
        string currentPassword,
        string? totpOrRecoveryCode,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(context);

        var user = await _db.Users
            .Include(u => u.RecoveryCodes)
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken)
            .ConfigureAwait(false);

        if (user is null || !user.IsActive)
        {
            return Result<bool>.Fail(
                DomainError.NotFound("profile.not_found", "No such account."));
        }

        var now = _clock.UtcNow;

        if (user.IsLockedOut(now))
        {
            return Result<bool>.Fail(
                DomainError.Forbidden("profile.locked_out", "Too many failed attempts. Try again shortly."));
        }

        if (_passwords.Verify(currentPassword, user.PasswordHash) is PasswordVerificationResult.Failed)
        {
            user.RegisterFailedSignIn(now);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            return Result<bool>.Fail(
                DomainError.Forbidden("profile.wrong_password", "That is not your current password."));
        }

        if (user.MfaEnabled)
        {
            var seed = new StoredTotpSeed(
                user.MfaSecretCiphertext!,
                user.MfaSecretNonce!,
                user.MfaSecretTag!,
                user.MfaSeedMasterKeyVersion);

            var code = totpOrRecoveryCode ?? string.Empty;
            var verification = _totp.Verify(user.Id, seed, code, user.LastUsedTotpWindow);
            var accepted = verification.IsValid;

            if (verification.IsValid)
            {
                user.LastUsedTotpWindow = verification.Window;
            }
            else
            {
                // A recovery code also works here. Someone who has lost their authenticator
                // is exactly the person who needs to re-enrol, and refusing them would make
                // the recovery codes useless for the case they exist for.
                var candidate = _recoveryCodes.HashForComparison(code);
                UserRecoveryCode? matched = null;

                foreach (var stored in user.RecoveryCodes.Where(c => c.IsUnused))
                {
                    if (candidate is not null && _recoveryCodes.Matches(candidate, stored.CodeHash))
                    {
                        matched = stored;
                    }
                }

                if (matched is not null)
                {
                    matched.UsedUtc = now;
                    accepted = true;
                }
            }

            if (!accepted)
            {
                user.RegisterFailedSignIn(now);
                await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

                return Result<bool>.Fail(
                    DomainError.Forbidden(
                        "profile.bad_second_factor",
                        "Enter a current code from your authenticator, or one of your recovery codes."));
            }
        }

        // Clear the seed and the enrolment together, and drop the old recovery codes: a
        // printout from the previous enrolment must not keep bypassing the new factor.
        user.MfaSecretCiphertext = null;
        user.MfaSecretNonce = null;
        user.MfaSecretTag = null;
        user.MfaSeedMasterKeyVersion = 0;
        user.MfaEnrolledUtc = null;
        user.LastUsedTotpWindow = null;
        user.RegisterSuccessfulSignIn();

        foreach (var stored in user.RecoveryCodes.ToList())
        {
            _db.UserRecoveryCodes.Remove(stored);
        }

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            user, AuditAction.MfaEnrolled, AuditOutcome.Success,
            "Enrolment cleared so a new authenticator can be set up.",
            context, cancellationToken).ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    private async Task AuditAsync(
        User user,
        AuditAction action,
        AuditOutcome outcome,
        string? detail,
        RequestContext context,
        CancellationToken cancellationToken) =>
        _ = await _audit.AppendAsync(
            new AuditRecord
            {
                WorkspaceId = null,
                ActorType = ActorType.User,
                ActorId = user.Id,
                ActorLabel = user.Email,
                Action = action,
                Outcome = outcome,
                ResourceType = "user",
                ResourceId = user.Id,
                IpAddress = context.IpAddress,
                UserAgent = context.UserAgent,
                CorrelationId = context.CorrelationId,
                DataJson = detail is null
                    ? null
                    : System.Text.Json.JsonSerializer.Serialize(new { reason = detail }),
            },
            cancellationToken).ConfigureAwait(false);
}
