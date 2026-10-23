using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Application.Vaults;
using Keystead.Domain.Auditing;
using Keystead.Domain.Common;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Vaults;

/// <summary>Vault use cases, authorized and audited.</summary>
public sealed class VaultService : IVaultService
{
    private static readonly TimeSpan ExpiringSoonWindow = TimeSpan.FromDays(30);

    private readonly KeysteadDbContext _db;
    private readonly IAccessPolicy _access;
    private readonly IVaultKeyService _vaultKeys;
    private readonly IAuditChain _audit;
    private readonly IClock _clock;

    /// <summary>Creates the service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="access">The authorization policy.</param>
    /// <param name="vaultKeys">Creates the vault key on creation.</param>
    /// <param name="audit">The audit chain.</param>
    /// <param name="clock">The clock.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public VaultService(
        KeysteadDbContext db,
        IAccessPolicy access,
        IVaultKeyService vaultKeys,
        IAuditChain audit,
        IClock clock)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(vaultKeys);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(clock);

        _db = db;
        _access = access;
        _vaultKeys = vaultKeys;
        _audit = audit;
        _clock = clock;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="principal"/> is null.</exception>
    public async Task<Result<IReadOnlyList<VaultSummary>>> ListAsync(
        Principal principal,
        Guid workspaceId,
        bool includeDeleted,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var now = _clock.UtcNow;
        var soonCutoff = now + ExpiringSoonWindow;

        var candidates = await _db.Vaults
            .AsNoTracking()
            .Where(v => v.WorkspaceId == workspaceId
                && (includeDeleted || v.SoftDeletedUtc == null))
            .OrderBy(v => v.Name)
            .Select(v => new
            {
                v.Id,
                v.Name,
                v.Slug,
                v.Description,
                v.ColorToken,
                v.CreatedUtc,
                v.SoftDeletedUtc,
                v.PurgeProtection,
            })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var vaultIds = candidates.Select(v => v.Id).ToList();

        // Counted with their own grouped queries, keyed off the vault ids already in hand,
        // rather than as correlated subqueries or through a navigation. Two extra round trips
        // in exchange for SQL that translates: both of the tidier-looking forms defeat the
        // provider, one on the correlated projection and one on the join inside a GroupBy.
        var secretCounts = await _db.Secrets
            .AsNoTracking()
            .Where(s => vaultIds.Contains(s.VaultId) && s.SoftDeletedUtc == null)
            .GroupBy(s => s.VaultId)
            .Select(g => new { VaultId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.VaultId, x => x.Count, cancellationToken)
            .ConfigureAwait(false);

        var expiringCounts = await _db.Secrets
            .AsNoTracking()
            .Where(s => vaultIds.Contains(s.VaultId)
                && s.SoftDeletedUtc == null
                && s.ExpiresUtc != null
                && s.ExpiresUtc > now
                && s.ExpiresUtc <= soonCutoff)
            .GroupBy(s => s.VaultId)
            .Select(g => new { VaultId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.VaultId, x => x.Count, cancellationToken)
            .ConfigureAwait(false);

        var visible = new List<VaultSummary>(candidates.Count);

        // Authorization per vault rather than one blanket check. A Reader sees only the vaults
        // they hold a grant on, so the list itself must not reveal that the others exist.
        foreach (var candidate in candidates)
        {
            var read = await _access
                .AuthorizeVaultAsync(
                    principal, workspaceId, candidate.Id, VaultPermission.Read, cancellationToken)
                .ConfigureAwait(false);

            if (!read.IsAllowed)
            {
                continue;
            }

            var write = await _access
                .AuthorizeVaultAsync(
                    principal, workspaceId, candidate.Id, VaultPermission.Write, cancellationToken)
                .ConfigureAwait(false);

            visible.Add(new VaultSummary(
                candidate.Id,
                candidate.Name,
                candidate.Slug,
                candidate.Description,
                candidate.ColorToken,
                secretCounts.GetValueOrDefault(candidate.Id),
                expiringCounts.GetValueOrDefault(candidate.Id),
                candidate.CreatedUtc,
                candidate.SoftDeletedUtc,
                candidate.PurgeProtection,
                write.IsAllowed ? VaultPermission.Write : VaultPermission.Read));
        }

        return Result<IReadOnlyList<VaultSummary>>.Ok(visible);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<VaultSummary>> GetBySlugAsync(
        Principal principal,
        Guid workspaceId,
        string slug,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(slug);

        var all = await ListAsync(principal, workspaceId, includeDeleted: true, cancellationToken)
            .ConfigureAwait(false);

        var match = all.Value.FirstOrDefault(
            v => string.Equals(v.Slug, slug, StringComparison.Ordinal));

        return match is null
            ? NotFound<VaultSummary>()
            : Result<VaultSummary>.Ok(match);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<VaultSummary>> CreateAsync(
        Principal principal,
        Guid workspaceId,
        CreateVaultRequest request,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        var authorized = await _access
            .AuthorizeWorkspaceAsync(
                principal, workspaceId, WorkspaceCapability.ManageVaults, cancellationToken)
            .ConfigureAwait(false);

        if (!authorized.IsAllowed)
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.VaultCreated, AuditOutcome.Denied,
                null, request.Name, authorized.Reason, context, cancellationToken)
                .ConfigureAwait(false);

            return Result<VaultSummary>.Fail(
                DomainError.Forbidden("vault.create_denied", "You cannot create vaults here."));
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return Result<VaultSummary>.Fail(
                DomainError.Invalid("vault.name_required", "Give the vault a name."));
        }

        if (!VaultColorTokens.IsValid(request.ColorToken))
        {
            // An allow-list, not a sanitiser: the token reaches a CSS custom property name in
            // the view, so anything not on the list is refused outright.
            return Result<VaultSummary>.Fail(
                DomainError.Invalid("vault.bad_color", "Choose one of the available colours."));
        }

        var slug = Slugify(request.Name);

        var slugTaken = await _db.Vaults
            .AsNoTracking()
            .AnyAsync(v => v.WorkspaceId == workspaceId && v.Slug == slug, cancellationToken)
            .ConfigureAwait(false);

        if (slugTaken)
        {
            return Result<VaultSummary>.Fail(
                DomainError.Conflict(
                    "vault.name_taken",
                    "A vault with a similar name already exists in this workspace."));
        }

        var now = _clock.UtcNow;
        var vaultId = Guid.CreateVersion7();

        var vault = new Vault
        {
            Id = vaultId,
            WorkspaceId = workspaceId,
            Name = request.Name.Trim(),
            Slug = slug,
            Description = string.IsNullOrWhiteSpace(request.Description)
                ? null
                : request.Description.Trim(),
            ColorToken = request.ColorToken,
            CreatedUtc = now,
            RecoveryWindowDays = Math.Clamp(request.RecoveryWindowDays, 1, 365),
            PurgeProtection = request.PurgeProtection,
        };

        _db.Vaults.Add(vault);

        // The vault and its key are created in one SaveChanges. A vault without a key could
        // never hold a secret, and a key without a vault is orphaned key material.
        _db.VaultKeks.Add(_vaultKeys.CreateInitialKek(workspaceId, vaultId));

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.VaultCreated, AuditOutcome.Success,
            vaultId, vault.Name, null, context, cancellationToken)
            .ConfigureAwait(false);

        return Result<VaultSummary>.Ok(new VaultSummary(
            vaultId,
            vault.Name,
            vault.Slug,
            vault.Description,
            vault.ColorToken,
            SecretCount: 0,
            ExpiringSoonCount: 0,
            now,
            SoftDeletedUtc: null,
            vault.PurgeProtection,
            VaultPermission.Write));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> SoftDeleteAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        var authorized = await RequireManageVaultsAsync(
            principal, workspaceId, vaultId, AuditAction.VaultSoftDeleted, context, cancellationToken)
            .ConfigureAwait(false);

        if (authorized.Error is not null)
        {
            return authorized;
        }

        var vault = await FindAsync(workspaceId, vaultId, cancellationToken).ConfigureAwait(false);

        if (vault is null)
        {
            return NotFound<bool>();
        }

        vault.SoftDelete(_clock.UtcNow);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.VaultSoftDeleted, AuditOutcome.Success,
            vaultId, vault.Name,
            $"Recoverable for {vault.RecoveryWindowDays} days.", context, cancellationToken)
            .ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> RecoverAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        var authorized = await RequireManageVaultsAsync(
            principal, workspaceId, vaultId, AuditAction.VaultRecovered, context, cancellationToken)
            .ConfigureAwait(false);

        if (authorized.Error is not null)
        {
            return authorized;
        }

        var vault = await FindAsync(workspaceId, vaultId, cancellationToken).ConfigureAwait(false);

        if (vault is null)
        {
            return NotFound<bool>();
        }

        if (!vault.IsDeleted)
        {
            return Result<bool>.Fail(
                DomainError.Conflict("vault.not_deleted", "That vault is not deleted."));
        }

        vault.Recover();
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.VaultRecovered, AuditOutcome.Success,
            vaultId, vault.Name, null, context, cancellationToken)
            .ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> PurgeAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        // Purging is a separate capability from managing vaults, and an Owner-only one. It is
        // the only operation in the product that destroys key material irreversibly.
        var authorized = await _access
            .AuthorizeWorkspaceAsync(
                principal, workspaceId, WorkspaceCapability.PurgeData, cancellationToken)
            .ConfigureAwait(false);

        if (!authorized.IsAllowed)
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.VaultPurged, AuditOutcome.Denied,
                vaultId, null, authorized.Reason, context, cancellationToken)
                .ConfigureAwait(false);

            return Result<bool>.Fail(
                DomainError.Forbidden("vault.purge_denied", "You cannot purge data here."));
        }

        var vault = await FindAsync(workspaceId, vaultId, cancellationToken).ConfigureAwait(false);

        if (vault is null)
        {
            return NotFound<bool>();
        }

        if (vault.PurgeProtection)
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.VaultPurged, AuditOutcome.Denied,
                vaultId, vault.Name, "Purge protection is enabled.", context, cancellationToken)
                .ConfigureAwait(false);

            return Result<bool>.Fail(
                DomainError.Conflict(
                    "vault.purge_protected",
                    "Purge protection is on for this vault. Turn it off first, which is itself an audited change."));
        }

        if (!vault.CanPurge(_clock.UtcNow))
        {
            var reason = vault.IsDeleted
                ? $"Its recovery window has not elapsed; it ends {vault.SoftDeletedUtc!.Value.AddDays(vault.RecoveryWindowDays):d MMM yyyy}."
                : "It must be deleted first.";

            await AuditAsync(
                principal, workspaceId, AuditAction.VaultPurged, AuditOutcome.Denied,
                vaultId, vault.Name, reason, context, cancellationToken)
                .ConfigureAwait(false);

            return Result<bool>.Fail(DomainError.Conflict("vault.purge_too_soon", reason));
        }

        var secretCount = await _db.Secrets
            .AsNoTracking()
            .CountAsync(s => s.VaultId == vaultId, cancellationToken)
            .ConfigureAwait(false);

        // Audited before the delete, not after. Once the rows are gone there is nothing left
        // to name, and an audit write that failed afterwards would leave no trace at all.
        await AuditAsync(
            principal, workspaceId, AuditAction.VaultPurged, AuditOutcome.Success,
            vaultId, vault.Name,
            $"Permanently destroyed {secretCount} secret(s) and their keys.",
            context, cancellationToken)
            .ConfigureAwait(false);

        // Cascades to keys, secrets, tags and versions through the foreign keys, which is why
        // the pragma enabling them is applied per connection.
        _db.Vaults.Remove(vault);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    private async Task<Result<bool>> RequireManageVaultsAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        AuditAction action,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        var authorized = await _access
            .AuthorizeWorkspaceAsync(
                principal, workspaceId, WorkspaceCapability.ManageVaults, cancellationToken)
            .ConfigureAwait(false);

        if (authorized.IsAllowed)
        {
            return Result<bool>.Ok(true);
        }

        await AuditAsync(
            principal, workspaceId, action, AuditOutcome.Denied,
            vaultId, null, authorized.Reason, context, cancellationToken)
            .ConfigureAwait(false);

        return Result<bool>.Fail(
            DomainError.Forbidden("vault.manage_denied", "You cannot manage vaults here."));
    }

    private Task<Vault?> FindAsync(
        Guid workspaceId,
        Guid vaultId,
        CancellationToken cancellationToken) =>
        _db.Vaults.FirstOrDefaultAsync(
            v => v.Id == vaultId && v.WorkspaceId == workspaceId,
            cancellationToken);

    /// <summary>
    /// The one not-found error used for every unreachable vault.
    /// </summary>
    /// <remarks>
    /// A vault in another workspace, a vault the caller has no grant on, and a vault that was
    /// never created all produce this. Distinguishing them would confirm the existence of
    /// something the caller is not allowed to know about.
    /// </remarks>
    private static Result<T> NotFound<T>() =>
        Result<T>.Fail(DomainError.NotFound("vault.not_found", "No such vault."));

    private async Task AuditAsync(
        Principal principal,
        Guid workspaceId,
        AuditAction action,
        AuditOutcome outcome,
        Guid? vaultId,
        string? vaultName,
        string? detail,
        RequestContext context,
        CancellationToken cancellationToken) =>
        _ = await _audit.AppendAsync(
            new AuditRecord
            {
                WorkspaceId = workspaceId,
                ActorType = principal.Type is SubjectType.User
                    ? ActorType.User
                    : ActorType.ServiceIdentity,
                ActorId = principal.Id,
                ActorLabel = principal.Label,
                Action = action,
                Outcome = outcome,
                ResourceType = "vault",
                ResourceId = vaultId,
                ResourceLabel = vaultName,
                IpAddress = context.IpAddress,
                UserAgent = context.UserAgent,
                CorrelationId = context.CorrelationId,
                DataJson = detail is null
                    ? null
                    : System.Text.Json.JsonSerializer.Serialize(new { reason = detail }),
            },
            cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Reduces a name to a URL-safe slug using an allow-list.
    /// </summary>
    private static string Slugify(string name)
    {
        var builder = new StringBuilder(name.Length);
        var lastWasHyphen = false;

        foreach (var character in name.Trim().ToLowerInvariant())
        {
            if (char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character))
            {
                builder.Append(character);
                lastWasHyphen = false;
            }
            else if (!lastWasHyphen && builder.Length > 0)
            {
                builder.Append('-');
                lastWasHyphen = true;
            }
        }

        var slug = builder.ToString().Trim('-');

        return slug.Length == 0
            ? "vault-" + Guid.CreateVersion7().ToString("N")[..12]
            : slug[..Math.Min(slug.Length, 100)];
    }
}
