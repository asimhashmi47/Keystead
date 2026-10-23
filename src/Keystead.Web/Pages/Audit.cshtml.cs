using System;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Auditing;
using Keystead.Application.Workspaces;
using Keystead.Domain.Auditing;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>The audit log, with its chain integrity badge and a CSV export.</summary>
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

    /// <summary>An error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>Action filter.</summary>
    [BindProperty(SupportsGet = true, Name = "action")]
    public AuditAction? ActionFilter { get; set; }

    /// <summary>Outcome filter.</summary>
    [BindProperty(SupportsGet = true, Name = "outcome")]
    public AuditOutcome? OutcomeFilter { get; set; }

    /// <summary>Free-text filter over actor and resource labels.</summary>
    [BindProperty(SupportsGet = true, Name = "q")]
    public string? Search { get; set; }

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
            .ResolveAsync(principal.Id, null, cancellationToken)
            .ConfigureAwait(false);

        if (workspace is null)
        {
            return RedirectToPage("/SignIn");
        }

        var listed = await _audit.ListAsync(
            principal,
            workspace.WorkspaceId,
            new AuditFilter(ActionFilter, OutcomeFilter, Search),
            cancellationToken).ConfigureAwait(false);

        if (listed.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        Entries = listed.Value;

        var verified = await _audit
            .VerifyAsync(principal, workspace.WorkspaceId, cancellationToken)
            .ConfigureAwait(false);

        Verification = verified.IsSuccess ? verified.Value : null;

        return Page();
    }

    /// <summary>
    /// Exports the filtered entries as CSV.
    /// </summary>
    /// <remarks>
    /// Every field is quoted and its quotes doubled. A leading <c>=</c>, <c>+</c>, <c>-</c> or
    /// <c>@</c> is also prefixed with an apostrophe: without that, a spreadsheet treats the
    /// cell as a formula, and an attacker who can influence an audit label (a user agent, say)
    /// could get code to run in the reviewer's spreadsheet. The audit log is exactly the file
    /// a security reviewer opens, which makes it the worst place to leave that open.
    /// </remarks>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A CSV file, or a redirect when unauthorized.</returns>
    public async Task<IActionResult> OnGetExportAsync(CancellationToken cancellationToken)
    {
        if (CurrentPrincipal is not { } principal)
        {
            return RedirectToPage("/SignIn");
        }

        var workspace = await _workspaces
            .ResolveAsync(principal.Id, null, cancellationToken)
            .ConfigureAwait(false);

        if (workspace is null)
        {
            return RedirectToPage("/SignIn");
        }

        var listed = await _audit.ListAsync(
            principal,
            workspace.WorkspaceId,
            new AuditFilter(ActionFilter, OutcomeFilter, Search, Take: 500),
            cancellationToken).ConfigureAwait(false);

        if (!listed.IsSuccess)
        {
            return Forbid();
        }

        var csv = new StringBuilder();
        csv.AppendLine("Seq,Timestamp,Actor,Action,Outcome,ResourceType,Resource,IpAddress,Detail");

        foreach (var entry in listed.Value.Entries)
        {
            csv.Append(entry.Seq.ToString(CultureInfo.InvariantCulture)).Append(',');
            csv.Append(Csv(entry.CreatedUtc.ToString("O", CultureInfo.InvariantCulture))).Append(',');
            csv.Append(Csv(entry.ActorLabel)).Append(',');
            csv.Append(Csv(entry.Action.ToString())).Append(',');
            csv.Append(Csv(entry.Outcome.ToString())).Append(',');
            csv.Append(Csv(entry.ResourceType)).Append(',');
            csv.Append(Csv(entry.ResourceLabel)).Append(',');
            csv.Append(Csv(entry.IpAddress)).Append(',');
            csv.AppendLine(Csv(entry.Detail));
        }

        return File(
            Encoding.UTF8.GetBytes(csv.ToString()),
            "text/csv",
            $"keystead-audit-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.csv");
    }

    private static string Csv(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "\"\"";
        }

        // Formula injection guard. See the remarks on the export handler.
        var guarded = value[0] is '=' or '+' or '-' or '@' or '\t' or '\r'
            ? "'" + value
            : value;

        return "\"" + guarded.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
