using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Domain.Auditing;
using Keystead.Domain.Common;
using Keystead.Domain.Identity;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Identity;

/// <summary>Manages machine principals, authorized and audited.</summary>
public sealed class ServiceIdentityService : IServiceIdentityService
{
    private readonly KeysteadDbContext _db;
    private readonly IAccessPolicy _access;
    private readonly IAuditChain _audit;
    private readonly IClock _clock;

    /// <summary>Creates the service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="access">The authorization policy.</param>
    /// <param name="audit">The audit chain.</param>
    /// <param name="clock">The clock.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public ServiceIdentityService(
        KeysteadDbContext db,
        IAccessPolicy access,
        IAuditChain audit,
        IClock clock)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(clock);

        _db = db;
        _access = access;
        _audit = audit;
        _clock = clock;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="principal"/> is null.</exception>
    public async Task<Result<IReadOnlyList<ServiceIdentitySummary>>> ListAsync(
        Principal principal,
        Guid workspaceId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var allowed = await RequireManageAsync(principal, workspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (!allowed)
        {
            return Result<IReadOnlyList<ServiceIdentitySummary>>.Fail(Forbidden());
        }

        var identities = await _db.ServiceIdentities
            .AsNoTracking()
            .Where(i => i.WorkspaceId == workspaceId)
            .OrderBy(i => i.Name)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var ids = identities.Select(i => i.Id).ToList();

        var grants = await _db.VaultAssignments
            .AsNoTracking()
            .Where(a => ids.Contains(a.SubjectId)
                && a.SubjectType == SubjectType.ServiceIdentity)
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

        var now = _clock.UtcNow;

        var summaries = identities
            .Select(i => new ServiceIdentitySummary(
                i.Id,
                i.Name,
                i.ClientId,
                i.IsActive,
                i.ExpiresUtc,
                i.CreatedUtc,
                i.LastUsedUtc,
                [.. i.IpAllowlist],
                i.PreviousSecretUsable(now),
                i.PreviousSecretExpiresUtc,
                grants
                    .Where(g => g.SubjectId == i.Id)
                    .Select(g => new GrantedScope(
                        g.VaultId, g.VaultName, g.VaultSlug, g.Permission))
                    .ToList()))
            .ToList();

        return Result<IReadOnlyList<ServiceIdentitySummary>>.Ok(summaries);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<CreatedServiceIdentity>> CreateAsync(
        Principal principal,
        Guid workspaceId,
        CreateServiceIdentityRequest request,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        if (!await RequireManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.ServiceIdentityCreated, AuditOutcome.Denied,
                null, request.Name, "Not permitted.", context, cancellationToken)
                .ConfigureAwait(false);

            return Result<CreatedServiceIdentity>.Fail(Forbidden());
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return Result<CreatedServiceIdentity>.Fail(
                DomainError.Invalid("identity.name_required", "Give the identity a name."));
        }

        foreach (var entry in request.IpAllowlist)
        {
            if (!LooksLikeAddressOrRange(entry))
            {
                return Result<CreatedServiceIdentity>.Fail(
                    DomainError.Invalid(
                        "identity.bad_allowlist",
                        $"'{entry}' is not an address or CIDR range."));
            }
        }

        // Every requested vault must exist in this workspace. Without this check an admin
        // could mint an identity scoped to a vault id from another tenant; the grant would
        // never resolve, but the scope string would claim otherwise and be misleading.
        var requestedVaultIds = request.Scopes.Select(s => s.VaultId).Distinct().ToList();

        var validVaultIds = await _db.Vaults
            .AsNoTracking()
            .Where(v => v.WorkspaceId == workspaceId
                && requestedVaultIds.Contains(v.Id)
                && v.SoftDeletedUtc == null)
            .Select(v => v.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        if (validVaultIds.Count != requestedVaultIds.Count)
        {
            return Result<CreatedServiceIdentity>.Fail(
                DomainError.Invalid(
                    "identity.bad_scope",
                    "One of the chosen vaults is not in this workspace."));
        }

        var now = _clock.UtcNow;
        var identityId = Guid.CreateVersion7();
        var (secret, hash) = ClientCredential.Create();

        var identity = new ServiceIdentity
        {
            Id = identityId,
            WorkspaceId = workspaceId,
            Name = request.Name.Trim(),
            ClientId = ClientCredential.CreateClientId(),
            ClientSecretHash = hash,
            ExpiresUtc = request.ExpiresUtc,
            CreatedUtc = now,
            IsActive = true,
            IpAllowlist = [.. request.IpAllowlist.Select(e => e.Trim()).Where(e => e.Length > 0)],
        };

        _db.ServiceIdentities.Add(identity);

        foreach (var scope in request.Scopes.DistinctBy(s => s.VaultId))
        {
            _db.VaultAssignments.Add(new VaultAssignment
            {
                Id = Guid.CreateVersion7(),
                VaultId = scope.VaultId,
                SubjectId = identityId,
                SubjectType = SubjectType.ServiceIdentity,
                Permission = scope.Permission,
                GrantedUtc = now,
            });
        }

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.ServiceIdentityCreated, AuditOutcome.Success,
            identityId, identity.Name,
            $"Client {identity.ClientId}, {request.Scopes.Count} scope(s).",
            context, cancellationToken).ConfigureAwait(false);

        var listed = await ListAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false);
        var summary = listed.Value.First(i => i.Id == identityId);

        return Result<CreatedServiceIdentity>.Ok(new CreatedServiceIdentity(summary, secret));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<string>> RotateSecretAsync(
        Principal principal,
        Guid workspaceId,
        Guid identityId,
        TimeSpan overlap,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        if (!await RequireManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.ServiceIdentitySecretRotated,
                AuditOutcome.Denied, identityId, null, "Not permitted.", context, cancellationToken)
                .ConfigureAwait(false);

            return Result<string>.Fail(Forbidden());
        }

        var identity = await FindAsync(workspaceId, identityId, cancellationToken)
            .ConfigureAwait(false);

        if (identity is null)
        {
            return NotFound<string>();
        }

        var now = _clock.UtcNow;
        var (secret, hash) = ClientCredential.Create();

        // The outgoing secret becomes the previous one, with a deadline. Deployments move to
        // the new secret inside that window; after it, only the new one works.
        identity.PreviousClientSecretHash = identity.ClientSecretHash;
        identity.PreviousSecretExpiresUtc = now + Clamp(overlap);
        identity.ClientSecretHash = hash;

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.ServiceIdentitySecretRotated,
            AuditOutcome.Success, identityId, identity.Name,
            $"Previous secret works until {identity.PreviousSecretExpiresUtc:O}.",
            context, cancellationToken).ConfigureAwait(false);

        return Result<string>.Ok(secret);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<bool>> RevokeAsync(
        Principal principal,
        Guid workspaceId,
        Guid identityId,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(context);

        if (!await RequireManageAsync(principal, workspaceId, cancellationToken).ConfigureAwait(false))
        {
            await AuditAsync(
                principal, workspaceId, AuditAction.ServiceIdentityRevoked, AuditOutcome.Denied,
                identityId, null, "Not permitted.", context, cancellationToken)
                .ConfigureAwait(false);

            return Result<bool>.Fail(Forbidden());
        }

        var identity = await FindAsync(workspaceId, identityId, cancellationToken)
            .ConfigureAwait(false);

        if (identity is null)
        {
            return NotFound<bool>();
        }

        identity.IsActive = false;

        // Both digests cleared. Leaving the previous one usable would mean a revoked identity
        // could still authenticate for the rest of its overlap window.
        identity.PreviousClientSecretHash = null;
        identity.PreviousSecretExpiresUtc = null;

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            principal, workspaceId, AuditAction.ServiceIdentityRevoked, AuditOutcome.Success,
            identityId, identity.Name,
            "Disabled; takes effect on the next call, including for tokens already issued.",
            context, cancellationToken).ConfigureAwait(false);

        return Result<bool>.Ok(true);
    }

    private static TimeSpan Clamp(TimeSpan overlap) =>
        overlap < TimeSpan.Zero ? TimeSpan.Zero
        : overlap > TimeSpan.FromDays(30) ? TimeSpan.FromDays(30)
        : overlap;

    private static bool LooksLikeAddressOrRange(string entry) =>
        IpAllowlist.IsAllowed([entry], "203.0.113.1")
        || IpAllowlist.IsAllowed([entry], "2001:db8::1")
        || System.Net.IPAddress.TryParse(entry.Split('/')[0], out _);

    private async Task<bool> RequireManageAsync(
        Principal principal,
        Guid workspaceId,
        CancellationToken cancellationToken)
    {
        var decision = await _access
            .AuthorizeWorkspaceAsync(
                principal,
                workspaceId,
                WorkspaceCapability.ManageServiceIdentities,
                cancellationToken)
            .ConfigureAwait(false);

        return decision.IsAllowed;
    }

    private Task<ServiceIdentity?> FindAsync(
        Guid workspaceId,
        Guid identityId,
        CancellationToken cancellationToken) =>
        _db.ServiceIdentities.FirstOrDefaultAsync(
            i => i.Id == identityId && i.WorkspaceId == workspaceId,
            cancellationToken);

    private static DomainError Forbidden() =>
        DomainError.Forbidden(
            "identity.manage_denied",
            "You cannot manage service identities here.");

    private static Result<T> NotFound<T>() =>
        Result<T>.Fail(DomainError.NotFound("identity.not_found", "No such service identity."));

    private async Task AuditAsync(
        Principal principal,
        Guid workspaceId,
        AuditAction action,
        AuditOutcome outcome,
        Guid? identityId,
        string? label,
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
                ResourceType = "service_identity",
                ResourceId = identityId,
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
