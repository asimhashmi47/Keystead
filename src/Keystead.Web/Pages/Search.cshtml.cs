using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Secrets;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>
/// Search across the vaults and secrets this person can reach.
/// </summary>
/// <remarks>
/// <para>
/// Searches names only. A secret value is never searchable, and could not be even in
/// principle: values are sealed under per-version keys, so matching text against them would
/// mean decrypting every secret in the workspace on every keystroke. That the design makes it
/// impossible rather than merely forbidden is the point.
/// </para>
/// <para>
/// Results come from the authorized list calls, so a Reader sees only what they have been
/// granted. Searching is not a way around an access check.
/// </para>
/// </remarks>
public sealed class SearchModel : KeysteadPageModel
{
    private const int MaxResults = 25;

    private readonly IVaultService _vaults;
    private readonly ISecretService _secrets;
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="vaults">The vault service.</param>
    /// <param name="secrets">The secret service.</param>
    /// <param name="workspaces">Resolves the acting workspace.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public SearchModel(
        IVaultService vaults,
        ISecretService secrets,
        ICurrentWorkspace workspaces)
    {
        ArgumentNullException.ThrowIfNull(vaults);
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(workspaces);

        _vaults = vaults;
        _secrets = secrets;
        _workspaces = workspaces;
    }

    /// <summary>The search term.</summary>
    [BindProperty(SupportsGet = true, Name = "q")]
    public string? Query { get; set; }

    /// <summary>The matches.</summary>
    public IReadOnlyList<SearchHit> Hits { get; private set; } = [];

    /// <summary>One search result.</summary>
    /// <param name="Kind">Either <c>vault</c> or <c>secret</c>.</param>
    /// <param name="Title">What to show as the result's name.</param>
    /// <param name="Subtitle">Context, such as the owning vault and environment.</param>
    /// <param name="Url">Where the result links to.</param>
    public sealed record SearchHit(string Kind, string Title, string Subtitle, string Url);

    /// <summary>Renders the search page.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        Hits = await FindAsync(Query, cancellationToken).ConfigureAwait(false);
        return Page();
    }

    /// <summary>Returns matches as JSON for the command palette.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The matches.</returns>
    public async Task<IActionResult> OnGetQueryAsync(CancellationToken cancellationToken)
    {
        var hits = await FindAsync(Query, cancellationToken).ConfigureAwait(false);

        // Names are metadata, but the response still gets no-store: a cached list of a
        // workspace's secret names is a map of what is worth attacking.
        Response.Headers.CacheControl = "no-store";

        return new JsonResult(hits);
    }

    private async Task<IReadOnlyList<SearchHit>> FindAsync(
        string? query,
        CancellationToken cancellationToken)
    {
        if (CurrentPrincipal is not { } principal || string.IsNullOrWhiteSpace(query))
        {
            return [];
        }

        var workspace = await _workspaces
            .ResolveAsync(principal.Id, RequestedWorkspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (workspace is null)
        {
            return [];
        }

        var term = query.Trim();

        var vaults = await _vaults
            .ListAsync(principal, workspace.WorkspaceId, includeDeleted: false, cancellationToken)
            .ConfigureAwait(false);

        if (!vaults.IsSuccess)
        {
            return [];
        }

        var hits = new List<SearchHit>();

        foreach (var vault in vaults.Value)
        {
            if (vault.Name.Contains(term, StringComparison.OrdinalIgnoreCase))
            {
                hits.Add(new SearchHit(
                    "vault",
                    vault.Name,
                    $"{vault.SecretCount} secret(s)",
                    $"/vaults/{vault.Slug}"));
            }
        }

        foreach (var vault in vaults.Value)
        {
            if (hits.Count >= MaxResults)
            {
                break;
            }

            var secrets = await _secrets.ListAsync(
                principal,
                workspace.WorkspaceId,
                vault.Id,
                new SecretFilter(Search: term),
                cancellationToken).ConfigureAwait(false);

            if (!secrets.IsSuccess)
            {
                continue;
            }

            foreach (var secret in secrets.Value.Take(MaxResults - hits.Count))
            {
                hits.Add(new SearchHit(
                    "secret",
                    secret.Name,
                    $"{vault.Name} / {secret.Environment}",
                    $"/vaults/{vault.Slug}/secrets/{secret.Id}"));
            }
        }

        return hits;
    }
}
