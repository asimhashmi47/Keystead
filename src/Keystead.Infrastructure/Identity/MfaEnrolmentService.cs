using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Identity;
using Keystead.Domain.Auditing;
using Keystead.Domain.Identity;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Identity;

/// <summary>Enrols a user in TOTP, and issues their recovery codes.</summary>
public sealed class MfaEnrolmentService : IMfaEnrolmentService
{
    private readonly KeysteadDbContext _db;
    private readonly ITotpService _totp;
    private readonly IRecoveryCodeService _recoveryCodes;
    private readonly IAuditChain _audit;
    private readonly IClock _clock;

    /// <summary>Creates the service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="totp">The TOTP service.</param>
    /// <param name="recoveryCodes">The recovery code service.</param>
    /// <param name="audit">The audit chain.</param>
    /// <param name="clock">The clock.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public MfaEnrolmentService(
        KeysteadDbContext db,
        ITotpService totp,
        IRecoveryCodeService recoveryCodes,
        IAuditChain audit,
        IClock clock)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(totp);
        ArgumentNullException.ThrowIfNull(recoveryCodes);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(clock);

        _db = db;
        _totp = totp;
        _recoveryCodes = recoveryCodes;
        _audit = audit;
        _clock = clock;
    }

    /// <inheritdoc />
    public async Task<TotpEnrolment?> BeginAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken)
            .ConfigureAwait(false);

        if (user is null || !user.IsActive)
        {
            return null;
        }

        if (user.MfaEnabled)
        {
            // Re-enrolling would silently invalidate the authenticator the user already has.
            // Changing an enrolled second factor is a separate, step-up-protected operation.
            return null;
        }

        var enrolment = _totp.CreateEnrolment(user.Id, user.Email);

        user.MfaSecretCiphertext = enrolment.Seed.Ciphertext;
        user.MfaSecretNonce = enrolment.Seed.Nonce;
        user.MfaSecretTag = enrolment.Seed.Tag;
        user.MfaSeedMasterKeyVersion = enrolment.Seed.MasterKeyVersion;

        // Deliberately not set: MfaEnrolledUtc stays null, so MfaEnabled is false until a
        // code has been proved. A seed without an enrolment timestamp cannot lock anyone out.
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return enrolment;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<IReadOnlyList<string>?> CompleteAsync(
        Guid userId,
        string code,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(context);

        var user = await _db.Users
            .Include(u => u.RecoveryCodes)
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken)
            .ConfigureAwait(false);

        if (user is null
            || !user.IsActive
            || user.MfaSecretCiphertext is null
            || user.MfaSecretNonce is null
            || user.MfaSecretTag is null)
        {
            return null;
        }

        var seed = new StoredTotpSeed(
            user.MfaSecretCiphertext,
            user.MfaSecretNonce,
            user.MfaSecretTag,
            user.MfaSeedMasterKeyVersion);

        var verification = _totp.Verify(user.Id, seed, code, user.LastUsedTotpWindow);

        if (!verification.IsValid)
        {
            await _audit.AppendAsync(
                Record(user, AuditAction.MfaFailed, AuditOutcome.Denied, context, "Enrolment code incorrect."),
                cancellationToken).ConfigureAwait(false);

            return null;
        }

        var now = _clock.UtcNow;

        user.MfaEnrolledUtc = now;
        user.LastUsedTotpWindow = verification.Window;

        // Replace any previous codes outright. Leaving old ones usable alongside a new set
        // would mean a printout from a previous enrolment still bypassed the new factor.
        foreach (var existing in user.RecoveryCodes.ToList())
        {
            _db.UserRecoveryCodes.Remove(existing);
        }

        var generated = _recoveryCodes.Generate();

        foreach (var entry in generated)
        {
            _db.UserRecoveryCodes.Add(new UserRecoveryCode
            {
                Id = Guid.CreateVersion7(),
                UserId = user.Id,
                CodeHash = entry.Hash,
            });
        }

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await _audit.AppendAsync(
            Record(user, AuditAction.MfaEnrolled, AuditOutcome.Success, context, null),
            cancellationToken).ConfigureAwait(false);

        // The only moment these exist in plaintext. The caller shows them once and does not
        // store them anywhere.
        return generated.Select(c => c.PlaintextCode).ToList();
    }

    private static AuditRecord Record(
        User user,
        AuditAction action,
        AuditOutcome outcome,
        RequestContext context,
        string? detail) => new()
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
        };
}
