using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Auditing;
using Keystead.Application.Workspaces;
using Keystead.Domain.Auditing;
using Keystead.Web.Tables;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>
/// The audit log, with its chain integrity badge and a download.
/// </summary>
/// <remarks>
/// The one table in the application whose rows are filtered and paged by the query rather than
/// in memory. Every other list here is a workspace-scoped set the page has already loaded; this
/// one grows for as long as the installation is used, so reading all of it to render a page of
/// twenty-five would get slower every day it ran.
/// </remarks>
public sealed class AuditModel : KeysteadPageModel
{
    private readonly IAuditQuery _audit;
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="audit">The audit query service.</param>
    /// <param name="workspaces">Resolves the acting workspace.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public AuditModel(IAuditQuery audit, ICurrentWorkspace workspaces)
    {
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(workspaces);

        _audit = audit;
        _workspaces = workspaces;
    }

    /// <summary>The page of entries.</summary>
    public AuditPage? Entries { get; private set; }

    /// <summary>The chain verification result.</summary>
    public AuditChainVerification? Verification { get; private set; }

    /// <summary>The table chrome around the entries.</summary>
    public TableView<AuditEntryView>? Table { get; private set; }

    /// <summary>An error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>Loads the log.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (CurrentPrincipal is not { } principal)
        {
            return RedirectToPage("/SignIn");
        }

        var workspace = await _workspaces
            .ResolveAsync(principal.Id, RequestedWorkspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (workspace is null)
        {
            return RedirectToPage("/SignIn");
        }

        var query = TableQuery.FromRequest(Request);

        var listed = await _audit.ListAsync(
            principal,
            workspace.WorkspaceId,
            Filter(query, query.PageSize, (query.Page - 1) * query.PageSize),
            cancellationToken).ConfigureAwait(false);

        if (listed.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        Entries = listed.Value;

        // A page past the end of the result is an empty table under a toolbar reporting rows,
        // which reads as a bug in the product rather than a stale link. The in-memory tables
        // clamp this before they page; here the count is only known once the query has run, so
        // the clamp costs a second query in the one case that needs it.
        var pageCount = Math.Max(1, (Entries.TotalCount + query.PageSize - 1) / query.PageSize);

        if (query.Page > pageCount)
        {
            query = query.OnPage(pageCount);

            var clamped = await _audit.ListAsync(
                principal,
                workspace.WorkspaceId,
                Filter(query, query.PageSize, (query.Page - 1) * query.PageSize),
                cancellationToken).ConfigureAwait(false);

            if (clamped.IsSuccess)
            {
                Entries = clamped.Value;
            }
        }

        Table = TableEngine.FromServer(
            Entries.Entries,
            Columns(),
            query,
            id: "audit",
            label: "entries",
            path: Request.Path,
            filteredCount: Entries.TotalCount,

            // The query counts what matches, not what exists, and counting the whole log on
            // every page view to fill in the difference would be a second full scan for one
            // word in a sentence. When nothing is filtered the two are the same number, which
            // is the only case where the difference would be shown.
            totalCount: Entries.TotalCount);

        var verified = await _audit
            .VerifyAsync(principal, workspace.WorkspaceId, cancellationToken)
            .ConfigureAwait(false);

        Verification = verified.IsSuccess ? verified.Value : null;

        return Page();
    }

    /// <summary>
    /// Exports the filtered entries.
    /// </summary>
    /// <param name="format">The format, <c>xlsx</c> or <c>csv</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A file, or a redirect when unauthorized.</returns>
    /// <remarks>
    /// <para>
    /// The same filter as the screen, without its paging: an export of a filtered log is the
    /// whole filtered log, up to the ceiling in <see cref="TableExport.MaxRows"/>.
    /// </para>
    /// <para>
    /// The CSV form prefixes any field opening with <c>=</c>, <c>+</c>, <c>-</c> or <c>@@</c>,
    /// because a spreadsheet would otherwise treat it as a formula. These fields carry user
    /// agents and resource labels that a caller chooses, and the audit log is precisely the
    /// file a security reviewer opens. The workbook form writes string cells, which are never
    /// evaluated, so it needs no such apology.
    /// </para>
    /// </remarks>
    public async Task<IActionResult> OnGetExportAsync(
        string? format,
        CancellationToken cancellationToken)
    {
        if (CurrentPrincipal is not { } principal)
        {
            return RedirectToPage("/SignIn");
        }

        var workspace = await _workspaces
            .ResolveAsync(principal.Id, RequestedWorkspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (workspace is null)
        {
            return RedirectToPage("/SignIn");
        }

        var query = TableQuery.FromRequest(Request);

        var listed = await _audit.ListAsync(
            principal,
            workspace.WorkspaceId,
            Filter(query, TableExport.MaxRows, 0),
            cancellationToken).ConfigureAwait(false);

        if (!listed.IsSuccess)
        {
            return Forbid();
        }

        var view = TableEngine.FromServer(
            listed.Value.Entries,
            Columns(),
            query,
            id: "audit",
            label: "entries",
            path: Request.Path,
            filteredCount: listed.Value.TotalCount,
            totalCount: listed.Value.TotalCount);

        return TableExport.ToFile(view, TableExport.ParseFormat(format), "Audit log");
    }

    /// <summary>
    /// Turns the table's query into the service's filter.
    /// </summary>
    /// <remarks>
    /// The column keys are the contract between the two. An unparseable action or outcome
    /// becomes no filter rather than an error, for the same reason the rest of the query is
    /// clamped: a table is a read, and a URL someone edited should show a table.
    /// </remarks>
    private static AuditFilter Filter(TableQuery query, int take, int skip) =>
        new(
            Action: Parse<AuditAction>(query.TermFor("action")),
            Outcome: Parse<AuditOutcome>(query.TermFor("outcome")),
            Search: query.Search ?? query.TermFor("who"),
            Take: take,
            Skip: skip);

    private static TEnum? Parse<TEnum>(string? value)
        where TEnum : struct, Enum =>
        Enum.TryParse<TEnum>(value, ignoreCase: true, out var parsed) ? parsed : null;

    /// <summary>
    /// The columns.
    /// </summary>
    /// <remarks>
    /// None of them sort. The log has one meaningful order, newest first, and it is the order
    /// the chain is written in; offering to sort by actor would mean sorting a page of
    /// twenty-five rows out of a history of thousands, which answers a question nobody asked.
    /// </remarks>
    private static IReadOnlyList<TableColumn<AuditEntryView>> Columns() =>
    [
        new TableColumn<AuditEntryView>
        {
            Key = "seq",
            Header = "#",
            Text = e => e.Seq.ToString(CultureInfo.InvariantCulture),
            Sortable = false,
            Searchable = false,
            Align = TableAlign.End,
            Numeric = true,
            Hint = "Position in the hash chain",
        },
        new TableColumn<AuditEntryView>
        {
            Key = "when",
            Header = "When",
            Text = e => e.CreatedUtc.ToString("u", CultureInfo.InvariantCulture),
            Sortable = false,
            Searchable = false,
        },
        new TableColumn<AuditEntryView>
        {
            Key = "who",
            Header = "Who",
            Text = e => e.ActorLabel,
            Sortable = false,
        },
        new TableColumn<AuditEntryView>
        {
            Key = "action",
            Header = "What",
            Text = e => e.Action.ToString(),
            Sortable = false,
            Options = [.. Enum.GetNames<AuditAction>().Select(name => new TableOption(name, Spaced(name)))],
        },
        new TableColumn<AuditEntryView>
        {
            Key = "outcome",
            Header = "Outcome",
            Text = e => e.Outcome.ToString(),
            Sortable = false,
            Options = [.. Enum.GetNames<AuditOutcome>().Select(name => new TableOption(name, name))],
        },
        new TableColumn<AuditEntryView>
        {
            Key = "resource",
            Header = "Resource",
            Text = e => string.IsNullOrEmpty(e.ResourceLabel) ? e.ResourceType : e.ResourceLabel,
            Sortable = false,
            Searchable = false,
            Priority = TablePriority.Secondary,
        },
        new TableColumn<AuditEntryView>
        {
            Key = "from",
            Header = "From",
            Text = e => e.IpAddress,
            Sortable = false,
            Searchable = false,
            Priority = TablePriority.Secondary,
        },
        new TableColumn<AuditEntryView>
        {
            Key = "detail",
            Header = "Detail",
            Text = e => e.Detail ?? string.Empty,
            Sortable = false,
            Searchable = false,

            Priority = TablePriority.Hidden,
        },
    ];

    /// <summary>Turns an enum name into words, for a filter label.</summary>
    private static string Spaced(string name)
    {
        var spaced = new System.Text.StringBuilder(name.Length + 6);

        foreach (var character in name)
        {
            if (char.IsUpper(character) && spaced.Length > 0)
            {
                spaced.Append(' ');
            }

            spaced.Append(character);
        }

        return spaced.ToString();
    }
}
