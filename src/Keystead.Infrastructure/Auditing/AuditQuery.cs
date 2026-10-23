using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Auditing;
using Keystead.Application.Authorization;
using Keystead.Domain.Common;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Auditing;

/// <summary>Reads and verifies the audit log, authorized per workspace.</summary>
public sealed class AuditQuery : IAuditQuery
{
    private const int MaxPageSize = 500;

    private readonly KeysteadDbContext _db;
    private readonly IAccessPolicy _access;
    private readonly IAuditChain _chain;

    /// <summary>Creates the query service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="access">The authorization policy.</param>
    /// <param name="chain">The chain, for verification.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public AuditQuery(KeysteadDbContext db, IAccessPolicy access, IAuditChain chain)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(access);
        ArgumentNullException.ThrowIfNull(chain);

        _db = db;
        _access = access;
        _chain = chain;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<AuditPage>> ListAsync(
        Principal principal,
        Guid workspaceId,
        AuditFilter filter,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(filter);

        var allowed = await _access
            .AuthorizeWorkspaceAsync(
                principal, workspaceId, WorkspaceCapability.ViewAudit, cancellationToken)
            .ConfigureAwait(false);

        if (!allowed.IsAllowed)
        {
            return Result<AuditPage>.Fail(
                DomainError.Forbidden(
                    "audit.view_denied",
                    "You cannot view the audit log for this workspace."));
        }

        var query = _db.AuditEntries
            .AsNoTracking()
            .Where(e => e.WorkspaceId == workspaceId);

        if (filter.Action is { } action)
        {
            query = query.Where(e => e.Action == action);
        }

        if (filter.Outcome is { } outcome)
        {
            query = query.Where(e => e.Outcome == outcome);
        }

        if (!string.IsNullOrWhiteSpace(filter.Search))
        {
            var search = filter.Search.Trim();

            query = query.Where(e =>
                EF.Functions.Like(e.ActorLabel, $"%{search}%")
                || (e.ResourceLabel != null && EF.Functions.Like(e.ResourceLabel, $"%{search}%")));
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);

        var entries = await query
            .OrderByDescending(e => e.Seq)
            .Skip(Math.Max(filter.Skip, 0))
            .Take(Math.Clamp(filter.Take, 1, MaxPageSize))
            .Select(e => new AuditEntryView(
                e.Seq,
                e.CreatedUtc,
                e.ActorLabel,
                e.Action,
                e.Outcome,
                e.ResourceType,
                e.ResourceLabel,
                e.IpAddress,
                e.DataJson))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return Result<AuditPage>.Ok(new AuditPage(entries, total));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="principal"/> is null.</exception>
    public async Task<Result<AuditChainVerification>> VerifyAsync(
        Principal principal,
        Guid workspaceId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var allowed = await _access
            .AuthorizeWorkspaceAsync(
                principal, workspaceId, WorkspaceCapability.ViewAudit, cancellationToken)
            .ConfigureAwait(false);

        if (!allowed.IsAllowed)
        {
            return Result<AuditChainVerification>.Fail(
                DomainError.Forbidden("audit.view_denied", "You cannot verify this log."));
        }

        // Verifies the whole chain, not just this workspace's slice. The chain is installation
        // wide by design: a per-workspace chain could be truncated by deleting a workspace's
        // entries without anything else noticing.
        var result = await _chain.VerifyAsync(cancellationToken).ConfigureAwait(false);

        return Result<AuditChainVerification>.Ok(result);
    }
}
