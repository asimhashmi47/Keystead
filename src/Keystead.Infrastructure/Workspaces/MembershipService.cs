using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Application.Workspaces;
using Keystead.Domain.Auditing;
using Keystead.Domain.Common;
using Keystead.Domain.Identity;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Workspaces;

/// <summary>Manages workspace membership, roles and per-user vault grants.</summary>
public sealed class MembershipService : IMembershipService
{
    private const string PasswordAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";

    private readonly KeysteadDbContext _db;
    private readonly IAccessPolicy _access;
    private readonly IPasswordHasher _passwords;
    private readonly IAuditChain _audit;
    private readonly IClock _clock;

    /// <summary>Creates the service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="access">The authorization policy.</param>
    /// <param name="passwords">Hashes the generated one-time password.</param>
    /// <param name="audit">The audit chain.</param>
    /// <param name="clock">The clock.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public MembershipService(
        KeysteadDbContext db,
        IAccessPolicy access,
        IPasswordHasher passwords,
        IAuditChain audit,
        IClock clock)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(passwords);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(clock);

        _db = db;
        _access = access;
        _passwords = passwords;
        _audit = audit;
        _clock = clock;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="principal"/> is null.</exception>
    public async Task<Result<IReadOnlyList<MemberSummary>>> ListAsync(
        Principal principal,
        Guid workspaceId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (!await CanManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            return Result<IReadOnlyList<MemberSummary>>.Fail(Forbidden());
        }

        var members = await _db.WorkspaceMemberships
            .AsNoTracking()
            .Where(m => m.WorkspaceId == workspaceId)
            .Select(m => new
            {
                m.UserId,
                m.Role,
                Email = m.User!.Email,
                m.User.DisplayName,
                m.User.IsActive,
                m.User.CreatedUtc,
                HasSeed = m.User.MfaSecretCiphertext != null,
                m.User.MfaEnrolledUtc,
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var userIds = members.Select(m => m.UserId).ToList();

        var grants = await _db.VaultAssignments
            .AsNoTracking()
            .Where(a => userIds.Contains(a.SubjectId)
                && a.SubjectType == SubjectType.User
                && a.Vault!.WorkspaceId == workspaceId
                && a.Vault.SoftDeletedUtc == null)
            .Select(a => new
            {
                a.SubjectId,
                a.VaultId,
                a.Permission,
                VaultName = a.Vault!.Name,
                VaultSlug = a.Vault.Slug,
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var summaries = members
            .OrderByDescending(m => m.Role)
            .ThenBy(m => m.Email, StringComparer.Ordinal)
            .Select(m => new MemberSummary(
                m.UserId,
                m.Email,
                m.DisplayName,
                m.Role,
                m.IsActive,
                m.MfaEnrolledUtc is not null && m.HasSeed,
                RoleCapabilities.RequiresMfa(m.Role),
                m.CreatedUtc,
                grants
                    .Where(g => g.SubjectId == m.UserId)
                    .Select(g => new GrantedScope(
                        g.VaultId, g.VaultName, g.VaultSlug, g.Permission))
                    .ToList(),
                RoleCapabilities.HasImplicitVaultAccess(m.Role)))
            .ToList();

        return Result<IReadOnlyList<MemberSummary>>.Ok(summaries);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<AddedMember>> AddAsync(
        Principal principal,
        Guid workspaceId,
        string email,
        string displayName,
        WorkspaceRole role,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(context);

        if (!await CanManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.RoleChanged, AuditOutcome.Denied,
                null, email, "Not permitted.", context, cancellationToken).ConfigureAwait(false);

            return Result<AddedMember>.Fail(Forbidden());
        }

        var normalised = email.Trim().ToLowerInvariant();

        if (normalised.Length == 0 || !normalised.Contains('@', StringComparison.Ordinal))
        {
            return Result<AddedMember>.Fail(
                DomainError.Invalid("member.bad_email", "Enter a valid email address."));
        }

        // Only an Owner may create another Owner. An Admin who could would be able to promote
        // themselves to Owner in two steps, which makes the distinction meaningless.
        if (role is WorkspaceRole.Owner
            && !await IsOwnerAsync(principal.Id, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            return Result<AddedMember>.Fail(
                DomainError.Forbidden("member.owner_requires_owner", "Only an owner can add an owner."));
        }

        var existing = await _db.Users
            .FirstOrDefaultAsync(u => u.Email == normalised, cancellationToken)
            .ConfigureAwait(false);

        var now = _clock.UtcNow;
        var password = GeneratePassword();
        Guid userId;

        if (existing is null)
        {
            userId = Guid.CreateVersion7();

            _db.Users.Add(new User
            {
                Id = userId,
                Email = normalised,
                DisplayName = string.IsNullOrWhiteSpace(displayName)
                    ? normalised
                    : displayName.Trim(),
                PasswordHash = _passwords.Hash(password),
                PasswordChangedUtc = now,
                FailedSignInCount = 0,
                CreatedUtc = now,
                IsActive = true,
            });
        }
        else
        {
            userId = existing.Id;

            var alreadyHere = await _db.WorkspaceMemberships
                .AsNoTracking()
                .AnyAsync(
                    m => m.WorkspaceId == workspaceId && m.UserId == userId,
                    cancellationToken)
                .ConfigureAwait(false);

            if (alreadyHere)
            {
                return Result<AddedMember>.Fail(
                    DomainError.Conflict(
                        "member.already_present",
                        "That person is already a member of this workspace."));
            }
        }

        _db.WorkspaceMemberships.Add(new WorkspaceMembership
        {
            Id = Guid.CreateVersion7(),
            WorkspaceId = workspaceId,
            UserId = userId,
            Role = role,
            GrantedUtc = now,
        });

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.RoleChanged, AuditOutcome.Success,
            userId, normalised,
            existing is null
                ? $"Account created and added as {role}."
                : $"Existing account added as {role}.",
            context, cancellationToken).ConfigureAwait(false);

        var listed = await ListAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false);
        var member = listed.Value.First(m => m.UserId == userId);

        // An existing account keeps its own password; the generated one is meaningless then,
        // so it is not handed back and cannot be mistaken for a working credential.
        return Result<AddedMember>.Ok(
            new AddedMember(member, existing is null ? password : string.Empty));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> ChangeRoleAsync(
        Principal principal,
        Guid workspaceId,
        Guid userId,
        WorkspaceRole role,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        if (!await CanManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.RoleChanged, AuditOutcome.Denied,
                userId, null, "Not permitted.", context, cancellationToken).ConfigureAwait(false);

            return Result<bool>.Fail(Forbidden());
        }

        var membership = await _db.WorkspaceMemberships
            .FirstOrDefaultAsync(
                m => m.WorkspaceId == workspaceId && m.UserId == userId,
                cancellationToken)
            .ConfigureAwait(false);

        if (membership is null)
        {
            return NotFound<bool>();
        }

        var isOwner = await IsOwnerAsync(principal.Id, workspaceId, cancellationToken)
            .ConfigureAwait(false);

        // Granting or removing Owner is an Owner's decision. Letting an Admin do either would
        // let them promote themselves, or strip the only person who can stop them.
        if ((role is WorkspaceRole.Owner || membership.Role is WorkspaceRole.Owner) && !isOwner)
        {
            return Result<bool>.Fail(
                DomainError.Forbidden(
                    "member.owner_requires_owner",
                    "Only an owner can change an owner's role."));
        }

        if (membership.Role is WorkspaceRole.Owner && role is not WorkspaceRole.Owner)
        {
            var otherOwners = await _db.WorkspaceMemberships
                .AsNoTracking()
                .CountAsync(
                    m => m.WorkspaceId == workspaceId
                        && m.Role == WorkspaceRole.Owner
                        && m.UserId != userId,
                    cancellationToken)
                .ConfigureAwait(false);

            if (otherOwners == 0)
            {
                return Result<bool>.Fail(
                    DomainError.Conflict(
                        "member.last_owner",
                        "This is the only owner. Promote someone else to owner first, or the workspace would be left with nobody who can manage it."));
            }
        }

        var previous = membership.Role;

        if (previous == role)
        {
            return Result<bool>.Ok(true);
        }

        membership.Role = role;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        var email = await EmailOfAsync(userId, cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.RoleChanged, AuditOutcome.Success,
            userId, email, $"{previous} to {role}.", context, cancellationToken)
            .ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> RemoveAsync(
        Principal principal,
        Guid workspaceId,
        Guid userId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        if (!await CanManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            return Result<bool>.Fail(Forbidden());
        }

        var membership = await _db.WorkspaceMemberships
            .FirstOrDefaultAsync(
                m => m.WorkspaceId == workspaceId && m.UserId == userId,
                cancellationToken)
            .ConfigureAwait(false);

        if (membership is null)
        {
            return NotFound<bool>();
        }

        if (membership.Role is WorkspaceRole.Owner)
        {
            var otherOwners = await _db.WorkspaceMemberships
                .AsNoTracking()
                .CountAsync(
                    m => m.WorkspaceId == workspaceId
                        && m.Role == WorkspaceRole.Owner
                        && m.UserId != userId,
                    cancellationToken)
                .ConfigureAwait(false);

            if (otherOwners == 0)
            {
                return Result<bool>.Fail(
                    DomainError.Conflict(
                        "member.last_owner",
                        "This is the only owner and cannot be removed."));
            }
        }

        // The grants go with the membership. Leaving them behind would mean re-adding the
        // person silently restored access someone had deliberately taken away.
        var vaultIds = await _db.Vaults
            .AsNoTracking()
            .Where(v => v.WorkspaceId == workspaceId)
            .Select(v => v.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        await _db.VaultAssignments
            .Where(a => a.SubjectId == userId
                && a.SubjectType == SubjectType.User
                && vaultIds.Contains(a.VaultId))
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);

        _db.WorkspaceMemberships.Remove(membership);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        var email = await EmailOfAsync(userId, cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.RoleChanged, AuditOutcome.Success,
            userId, email, "Removed from the workspace; vault grants revoked.",
            context, cancellationToken).ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> GrantVaultAsync(
        Principal principal,
        Guid workspaceId,
        Guid userId,
        Guid vaultId,
        VaultPermission permission,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        if (!await CanManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.VaultAccessGranted, AuditOutcome.Denied,
                userId, null, "Not permitted.", context, cancellationToken).ConfigureAwait(false);

            return Result<bool>.Fail(Forbidden());
        }

        var isMember = await _db.WorkspaceMemberships
            .AsNoTracking()
            .AnyAsync(
                m => m.WorkspaceId == workspaceId && m.UserId == userId,
                cancellationToken)
            .ConfigureAwait(false);

        // Both the member and the vault must belong to this workspace. Checking only one would
        // let an admin grant a stranger access, or grant a member a vault from another tenant.
        var vaultBelongs = await _db.Vaults
            .AsNoTracking()
            .AnyAsync(
                v => v.Id == vaultId && v.WorkspaceId == workspaceId && v.SoftDeletedUtc == null,
                cancellationToken)
            .ConfigureAwait(false);

        if (!isMember || !vaultBelongs)
        {
            return NotFound<bool>();
        }

        var existing = await _db.VaultAssignments
            .FirstOrDefaultAsync(
                a => a.VaultId == vaultId
                    && a.SubjectId == userId
                    && a.SubjectType == SubjectType.User,
                cancellationToken)
            .ConfigureAwait(false);

        if (existing is null)
        {
            _db.VaultAssignments.Add(new VaultAssignment
            {
                Id = Guid.CreateVersion7(),
                VaultId = vaultId,
                SubjectId = userId,
                SubjectType = SubjectType.User,
                Permission = permission,
                GrantedUtc = _clock.UtcNow,
            });
        }
        else
        {
            existing.Permission = permission;
        }

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        var email = await EmailOfAsync(userId, cancellationToken).ConfigureAwait(false);
        var vaultName = await VaultNameAsync(vaultId, cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.VaultAccessGranted, AuditOutcome.Success,
            userId, email, $"{permission} on {vaultName}.", context, cancellationToken)
            .ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> RevokeVaultAsync(
        Principal principal,
        Guid workspaceId,
        Guid userId,
        Guid vaultId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        if (!await CanManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            return Result<bool>.Fail(Forbidden());
        }

        var vaultBelongs = await _db.Vaults
            .AsNoTracking()
            .AnyAsync(v => v.Id == vaultId && v.WorkspaceId == workspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (!vaultBelongs)
        {
            return NotFound<bool>();
        }

        var removed = await _db.VaultAssignments
            .Where(a => a.VaultId == vaultId
                && a.SubjectId == userId
                && a.SubjectType == SubjectType.User)
            .ExecuteDeleteAsync(cancellationToken)
            .ConfigureAwait(false);

        if (removed == 0)
        {
            return NotFound<bool>();
        }

        var email = await EmailOfAsync(userId, cancellationToken).ConfigureAwait(false);
        var vaultName = await VaultNameAsync(vaultId, cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.VaultAccessRevoked, AuditOutcome.Success,
            userId, email, $"Access to {vaultName} revoked.", context, cancellationToken)
            .ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// Generates a readable one-time password that satisfies the installation's own policy.
    /// </summary>
    /// <remarks>
    /// Four groups of five from an alphabet with the ambiguous characters removed, which gives
    /// about 116 bits and is still readable over the phone. Twenty-three characters clears the
    /// twelve-character floor, and the random alphabet means it will not appear in the deny
    /// list.
    /// </remarks>
    private static string GeneratePassword()
    {
        var builder = new StringBuilder(23);

        for (var group = 0; group < 4; group++)
        {
            if (group > 0)
            {
                builder.Append('-');
            }

            for (var i = 0; i < 5; i++)
            {
                builder.Append(PasswordAlphabet[
                    RandomNumberGenerator.GetInt32(PasswordAlphabet.Length)]);
            }
        }

        return builder.ToString();
    }

    private async Task<bool> CanManageAsync(
        Principal principal,
        Guid workspaceId,
        CancellationToken cancellationToken)
    {
        var decision = await _access
            .AuthorizeWorkspaceAsync(
                principal, workspaceId, WorkspaceCapability.ManageMembers, cancellationToken)
            .ConfigureAwait(false);

        return decision.IsAllowed;
    }

    private Task<bool> IsOwnerAsync(
        Guid userId,
        Guid workspaceId,
        CancellationToken cancellationToken) =>
        _db.WorkspaceMemberships
            .AsNoTracking()
            .AnyAsync(
                m => m.WorkspaceId == workspaceId
                    && m.UserId == userId
                    && m.Role == WorkspaceRole.Owner,
                cancellationToken);

    private async Task<string> EmailOfAsync(Guid userId, CancellationToken cancellationToken) =>
        await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => u.Email)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false)
        ?? userId.ToString("D", System.Globalization.CultureInfo.InvariantCulture);

    private async Task<string> VaultNameAsync(Guid vaultId, CancellationToken cancellationToken) =>
        await _db.Vaults
            .AsNoTracking()
            .Where(v => v.Id == vaultId)
            .Select(v => v.Name)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false)
        ?? "a vault";

    private static DomainError Forbidden() =>
        DomainError.Forbidden("member.manage_denied", "You cannot manage members here.");

    private static Result<T> NotFound<T>() =>
        Result<T>.Fail(DomainError.NotFound("member.not_found", "No such member."));

    private async Task AuditAsync(
        Principal principal,
        Guid workspaceId,
        AuditAction action,
        AuditOutcome outcome,
        Guid? userId,
        string? label,
        string? detail,
        RequestContext context,
        CancellationToken cancellationToken) =>
        _ = await _audit.AppendAsync(
            new AuditRecord
            {
                WorkspaceId = workspaceId,
                ActorType = ActorType.User,
                ActorId = principal.Id,
                ActorLabel = principal.Label,
                Action = action,
                Outcome = outcome,
                ResourceType = "member",
                ResourceId = userId,
                ResourceLabel = label,
                IpAddress = context.IpAddress,
                UserAgent = context.UserAgent,
                CorrelationId = context.CorrelationId,
                DataJson = detail is null
                    ? null
                    : System.Text.Json.JsonSerializer.Serialize(new { reason = detail }),
            },
            cancellationToken).ConfigureAwait(false);
}
