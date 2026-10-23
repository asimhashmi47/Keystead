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
/// The workspace dashboard.
/// </summary>
/// <remarks>
/// Every count here is derived from what this principal may actually see, by going through the
/// same authorized list calls the vault pages use. A dashboard that counted straight from the
/// database would tell a Reader how many secrets exist in vaults they cannot open, which is a
/// small but real disclosure.
/// </remarks>
public sealed class IndexModel : KeysteadPageModel
{
    private static readonly TimeSpan ExpiringSoonWindow = TimeSpan.FromDays(30);

    private readonly IVaultService _vaults;
    private readonly ISecretService _secrets;
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="vaults">The vault service.</param>
    /// <param name="secrets">The secret service.</param>
    /// <param name="workspaces">Resolves the acting workspace.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public IndexModel(
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

    /// <summary>The acting workspace.</summary>
    public WorkspaceMembershipView? Workspace { get; private set; }

    /// <summary>How many vaults this principal can reach.</summary>
    public int VaultCount { get; private set; }

    /// <summary>How many secrets those vaults hold.</summary>
    public int SecretCount { get; private set; }

    /// <summary>How many of those expire within 30 days.</summary>
    public int ExpiringSoonCount { get; private set; }

    /// <summary>How many have already expired.</summary>
    public int ExpiredCount { get; private set; }

    /// <summary>The vaults, for the overview list.</summary>
    public IReadOnlyList<VaultSummary> Vaults { get; private set; } = [];

    /// <summary>Secrets needing attention, soonest expiry first.</summary>
    public IReadOnlyList<SecretAttention> NeedsAttention { get; private set; } = [];

    /// <summary>A secret that expires soon or has expired.</summary>
    /// <param name="VaultSlug">The owning vault's slug, for the link.</param>
    /// <param name="VaultName">The owning vault's name.</param>
    /// <param name="Secret">The secret's metadata.</param>
    public sealed record SecretAttention(string VaultSlug, string VaultName, SecretSummary Secret);

    /// <summary>Loads the dashboard.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (CurrentPrincipal is not { } principal)
        {
            return RedirectToPage("/SignIn");
        }

        Workspace = await _workspaces
            .ResolveAsync(principal.Id, null, cancellationToken)
            .ConfigureAwait(false);

        if (Workspace is null)
        {
            return RedirectToPage("/SignIn");
        }

        var listed = await _vaults
            .ListAsync(principal, Workspace.WorkspaceId, includeDeleted: false, cancellationToken)
            .ConfigureAwait(false);

        Vaults = listed.IsSuccess ? listed.Value : [];
        VaultCount = Vaults.Count;

        var now = DateTimeOffset.UtcNow;
        var attention = new List<SecretAttention>();

        foreach (var vault in Vaults)
        {
            var secrets = await _secrets.ListAsync(
                principal,
                Workspace.WorkspaceId,
                vault.Id,
                new SecretFilter(),
                cancellationToken).ConfigureAwait(false);

            if (!secrets.IsSuccess)
            {
                continue;
            }

            SecretCount += secrets.Value.Count;

            foreach (var secret in secrets.Value)
            {
                if (secret.IsExpired(now))
                {
                    ExpiredCount++;
                    attention.Add(new SecretAttention(vault.Slug, vault.Name, secret));
                }
                else if (secret.IsExpiringSoon(now, ExpiringSoonWindow))
                {
                    ExpiringSoonCount++;
                    attention.Add(new SecretAttention(vault.Slug, vault.Name, secret));
                }
            }
        }

        NeedsAttention = attention
            .OrderBy(a => a.Secret.ExpiresUtc)
            .Take(10)
            .ToList();

        return Page();
    }
}
