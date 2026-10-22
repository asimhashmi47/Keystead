using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Authorization;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Identity;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Keystead.Infrastructure.Authorization;

/// <summary>
/// Resolves authorization questions against the database.
/// </summary>
/// <remarks>
/// <para>
/// Two obligations, discharged separately on every call. First the resource is scoped: a vault
/// is only considered if it belongs to the workspace the caller named. Second the principal is
/// authorized: role, then explicit grant, then the role's ceiling.
/// </para>
/// <para>
/// Doing only the first would let a member of workspace A reach vault B by id. Doing only the
/// second would let an Admin of A authorize against a vault in B, because their role lookup
/// would succeed and the vault lookup would never check whose it was. Both, every time.
/// </para>
/// <para>
/// Denials never distinguish "no such vault" from "not yours". The decision reason is written
/// for the audit log, and the user-facing message is generic, because telling someone that a
/// vault exists but is not theirs is itself a disclosure.
/// </para>
/// </remarks>
public sealed class AccessPolicy : IAccessPolicy
{
    private readonly KeysteadDbContext _db;
    private readonly IClock _clock;
    private readonly SessionOptions _sessions;

    /// <summary>Creates the policy.</summary>
    /// <param name="db">The database.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="sessions">Session and step-up lifetimes.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public AccessPolicy(KeysteadDbContext db, IClock clock, IOptions<SessionOptions> sessions)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(sessions);

        _db = db;
        _clock = clock;
        _sessions = sessions.Value;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="principal"/> is null.</exception>
    public async Task<AccessDecision> AuthorizeWorkspaceAsync(
        Principal principal,
        Guid workspaceId,
        WorkspaceCapability capability,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        // A service identity holds vault scopes, never workspace administration. Letting a
        // machine credential manage members or rotate keys would mean a leaked client secret
        // could escalate to owning the tenant.
        if (principal.Type is not SubjectType.User)
        {
            return AccessDecision.Denied(
                "Workspace administration is not available to service identities.");
        }

        var role = await ResolveRoleAsync(principal.Id, workspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (role is null)
        {
            return AccessDecision.Denied("Not a member of this workspace.");
        }

        if (!RoleCapabilities.Allows(role.Value, capability))
        {
            return AccessDecision.Denied(
                $"Role {role.Value} does not permit {capability}.");
        }

        return AccessDecision.Allowed;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="principal"/> is null.</exception>
    public async Task<AccessDecision> AuthorizeVaultAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        VaultPermission required,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        // Obligation one: scoping. The vault must exist, belong to this workspace, and not be
        // soft deleted. Anything else is indistinguishable from "no such vault".
        var vaultExists = await _db.Vaults
            .AsNoTracking()
            .AnyAsync(
                v => v.Id == vaultId
                    && v.WorkspaceId == workspaceId
                    && v.SoftDeletedUtc == null,
                cancellationToken)
            .ConfigureAwait(false);

        if (!vaultExists)
        {
            return AccessDecision.Denied("No such vault in this workspace.");
        }

        // Obligation two: authorization.
        if (principal.Type is SubjectType.ServiceIdentity)
        {
            return await AuthorizeServiceIdentityVaultAsync(
                principal, workspaceId, vaultId, required, cancellationToken)
                .ConfigureAwait(false);
        }

        var role = await ResolveRoleAsync(principal.Id, workspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (role is null)
        {
            return AccessDecision.Denied("Not a member of this workspace.");
        }

        var ceiling = RoleCapabilities.Ceiling(role.Value);

        if (required > ceiling)
        {
            return AccessDecision.Denied(
                $"Role {role.Value} is capped at {ceiling} access.");
        }

        if (RoleCapabilities.HasImplicitVaultAccess(role.Value))
        {
            return AccessDecision.Allowed;
        }

        var granted = await _db.VaultAssignments
            .AsNoTracking()
            .Where(a =>
                a.VaultId == vaultId
                && a.SubjectId == principal.Id
                && a.SubjectType == SubjectType.User)
            .Select(a => (VaultPermission?)a.Permission)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (granted is null)
        {
            return AccessDecision.Denied("No grant on this vault.");
        }

        return granted.Value >= required
            ? AccessDecision.Allowed
            : AccessDecision.Denied($"Grant is {granted.Value}, {required} required.");
    }

    private async Task<AccessDecision> AuthorizeServiceIdentityVaultAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        VaultPermission required,
        CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;

        // The identity must still be live. Checked here as well as at token issuance, because
        // a token already in the wild outlives the moment it was minted: disabling an identity
        // has to take effect on the next call, not on the next token request.
        var identity = await _db.ServiceIdentities
            .AsNoTracking()
            .Where(i => i.Id == principal.Id && i.WorkspaceId == workspaceId)
            .Select(i => new { i.IsActive, i.ExpiresUtc })
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (identity is null)
        {
            return AccessDecision.Denied("No such service identity in this workspace.");
        }

        if (!identity.IsActive)
        {
            return AccessDecision.Denied("Service identity is disabled.");
        }

        if (identity.ExpiresUtc is { } expires && now >= expires)
        {
            return AccessDecision.Denied("Service identity has expired.");
        }

        // No implicit access for machines, ever. A service identity reaches exactly the vaults
        // it was granted, which is what makes a leaked client secret a bounded incident.
        var granted = await _db.VaultAssignments
            .AsNoTracking()
            .Where(a =>
                a.VaultId == vaultId
                && a.SubjectId == principal.Id
                && a.SubjectType == SubjectType.ServiceIdentity)
            .Select(a => (VaultPermission?)a.Permission)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (granted is null)
        {
            return AccessDecision.Denied("Service identity has no grant on this vault.");
        }

        return granted.Value >= required
            ? AccessDecision.Allowed
            : AccessDecision.Denied($"Grant is {granted.Value}, {required} required.");
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="principal"/> is null.</exception>
    public async Task<AccessDecision> RequireFreshStepUpAsync(
        Principal principal,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.Type is not SubjectType.User || principal.SessionId is null)
        {
            // A machine cannot step up: there is nobody at the keyboard. Operations that
            // demand step-up are therefore closed to service identities by construction.
            return AccessDecision.Denied(
                "This action requires an interactive session and cannot be performed by a service identity.");
        }

        var session = await _db.UserSessions
            .AsNoTracking()
            .Where(s => s.Id == principal.SessionId.Value && s.UserId == principal.Id)
            .Select(s => new { s.LastStepUpUtc, s.RevokedUtc })
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (session is null || session.RevokedUtc is not null)
        {
            return AccessDecision.Denied("Session is no longer valid.");
        }

        var fresh = session.LastStepUpUtc is { } at
            && _clock.UtcNow - at < _sessions.StepUpWindow;

        return fresh
            ? AccessDecision.Allowed
            : AccessDecision.StepUp("This action requires you to confirm your identity again.");
    }

    private async Task<WorkspaceRole?> ResolveRoleAsync(
        Guid userId,
        Guid workspaceId,
        CancellationToken cancellationToken)
    {
        // A unique index on (WorkspaceId, UserId) guarantees at most one row, so there is no
        // "highest of several roles" ambiguity to resolve here.
        var role = await _db.WorkspaceMemberships
            .AsNoTracking()
            .Where(m => m.UserId == userId && m.WorkspaceId == workspaceId)
            .Select(m => (WorkspaceRole?)m.Role)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (role is null)
        {
            return null;
        }

        // A deactivated account keeps its membership row but loses every capability, so
        // disabling a user takes effect without having to unpick their grants.
        var isActive = await _db.Users
            .AsNoTracking()
            .AnyAsync(u => u.Id == userId && u.IsActive, cancellationToken)
            .ConfigureAwait(false);

        return isActive ? role : null;
    }
}
