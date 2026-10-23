using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Authorization;
using Keystead.Domain.Auditing;
using Keystead.Domain.Common;

namespace Keystead.Application.Auditing;

/// <summary>
/// Reads the audit log.
/// </summary>
/// <remarks>
/// Authorized like anything else, and not readable by every member. The log records who read
/// which secret and when, which makes it a map of who holds what; that is sensitive in its own
/// right, so reading it needs the ViewAudit capability.
/// </remarks>
public interface IAuditQuery
{
    /// <summary>Lists audit entries for a workspace, newest first.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="filter">How to narrow the list.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The matching entries.</returns>
    Task<Result<AuditPage>> ListAsync(
        Principal principal,
        Guid workspaceId,
        AuditFilter filter,
        CancellationToken cancellationToken);

    /// <summary>Verifies the whole chain, for the integrity badge.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The verification outcome.</returns>
    Task<Result<AuditChainVerification>> VerifyAsync(
        Principal principal,
        Guid workspaceId,
        CancellationToken cancellationToken);
}

/// <summary>How an audit listing is narrowed.</summary>
/// <param name="Action">A specific action, or null for all.</param>
/// <param name="Outcome">A specific outcome, or null for all.</param>
/// <param name="Search">Free text matched against actor and resource labels.</param>
/// <param name="Take">How many entries to return.</param>
/// <param name="Skip">How many to skip, for paging.</param>
public sealed record AuditFilter(
    AuditAction? Action = null,
    AuditOutcome? Outcome = null,
    string? Search = null,
    int Take = 100,
    int Skip = 0);

/// <summary>A page of audit entries.</summary>
/// <param name="Entries">The entries, newest first.</param>
/// <param name="TotalCount">How many match the filter in total.</param>
public sealed record AuditPage(IReadOnlyList<AuditEntryView> Entries, int TotalCount);

/// <summary>An audit entry as shown in the log.</summary>
/// <param name="Seq">Its position in the chain.</param>
/// <param name="CreatedUtc">When it was written.</param>
/// <param name="ActorLabel">Who did it.</param>
/// <param name="Action">What happened.</param>
/// <param name="Outcome">Whether it succeeded.</param>
/// <param name="ResourceType">The kind of thing acted upon.</param>
/// <param name="ResourceLabel">Its name, when there is one.</param>
/// <param name="IpAddress">Where the request came from.</param>
/// <param name="Detail">Extra context, which never contains a secret value.</param>
public sealed record AuditEntryView(
    long Seq,
    DateTimeOffset CreatedUtc,
    string ActorLabel,
    AuditAction Action,
    AuditOutcome Outcome,
    string ResourceType,
    string? ResourceLabel,
    string IpAddress,
    string? Detail);
