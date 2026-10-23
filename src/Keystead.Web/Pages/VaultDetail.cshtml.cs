using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Secrets;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Domain.Vaults;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>One vault: its secrets, and the form to add one.</summary>
public sealed class VaultDetailModel : KeysteadPageModel
{
    private readonly IVaultService _vaults;
    private readonly ISecretService _secrets;
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="vaults">The vault service.</param>
    /// <param name="secrets">The secret service.</param>
    /// <param name="workspaces">Resolves the acting workspace.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public VaultDetailModel(
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

    /// <summary>The vault slug from the route.</summary>
    [BindProperty(SupportsGet = true)]
    public string Slug { get; set; } = string.Empty;

    /// <summary>Free-text search over secret names.</summary>
    [BindProperty(SupportsGet = true, Name = "q")]
    public string? Search { get; set; }

    /// <summary>Environment filter.</summary>
    [BindProperty(SupportsGet = true, Name = "env")]
    public string? EnvironmentFilter { get; set; }

    /// <summary>Whether soft-deleted secrets are shown.</summary>
    [BindProperty(SupportsGet = true, Name = "deleted")]
    public bool ShowDeleted { get; set; }

    /// <summary>The vault.</summary>
    public VaultSummary? Vault { get; private set; }

    /// <summary>The acting workspace.</summary>
    public WorkspaceMembershipView? Workspace { get; private set; }

    /// <summary>The secrets in this vault, as metadata only.</summary>
    public IReadOnlyList<SecretSummary> Secrets { get; private set; } = [];

    /// <summary>The distinct environment labels present, for the filter.</summary>
    public IReadOnlyList<string> Environments { get; private set; } = [];

    /// <summary>Whether this principal may write here.</summary>
    public bool CanWrite => Vault?.Permission == VaultPermission.Write;

    /// <summary>The add-secret form.</summary>
    [BindProperty]
    public CreateSecretInput Input { get; set; } = new();

    /// <summary>An error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>A confirmation message, or null.</summary>
    [TempData]
    public string? Notice { get; set; }

    /// <summary>The current time, for expiry badges.</summary>
    public DateTimeOffset Now { get; private set; }

    /// <summary>Loads the vault and its secrets.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, or a redirect when the vault is unreachable.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var loaded = await LoadAsync(cancellationToken).ConfigureAwait(false);

        return loaded ? Page() : NotFound();
    }

    /// <summary>Creates a secret in this vault.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect on success, or the page with an error.</returns>
    public async Task<IActionResult> OnPostCreateAsync(CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Vault is null
            || Workspace is null)
        {
            return NotFound();
        }

        if (!ModelState.IsValid)
        {
            Error = "Check the details below.";
            return Page();
        }

        // The plaintext exists as bytes only for the length of this call, and is zeroed in the
        // finally block whether or not sealing succeeded.
        var value = Encoding.UTF8.GetBytes(Input.Value);

        try
        {
            var tags = new Dictionary<string, string>(StringComparer.Ordinal);

            if (!string.IsNullOrWhiteSpace(Input.TagKey))
            {
                tags[Input.TagKey.Trim()] = (Input.TagValue ?? string.Empty).Trim();
            }

            var created = await _secrets.CreateAsync(
                principal,
                Workspace.WorkspaceId,
                Vault.Id,
                new CreateSecretRequest(
                    Input.Name,
                    Input.Environment,
                    value,
                    Input.ContentType,
                    Input.ExpiresUtc,
                    Input.RotationReminderDays,
                    tags),
                RequestContext,
                cancellationToken).ConfigureAwait(false);

            if (created.Error is { } error)
            {
                Error = error.Message;
                return Page();
            }

            Notice = $"Stored {created.Value.Name} in {Vault.Name}.";

            return RedirectToPage("/VaultDetail", new { slug = Slug });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private async Task<bool> LoadAsync(CancellationToken cancellationToken)
    {
        if (CurrentPrincipal is not { } principal)
        {
            return false;
        }

        Now = DateTimeOffset.UtcNow;

        Workspace = await _workspaces
            .ResolveAsync(principal.Id, null, cancellationToken)
            .ConfigureAwait(false);

        if (Workspace is null)
        {
            return false;
        }

        var found = await _vaults
            .GetBySlugAsync(principal, Workspace.WorkspaceId, Slug, cancellationToken)
            .ConfigureAwait(false);

        if (!found.IsSuccess)
        {
            return false;
        }

        Vault = found.Value;

        var listed = await _secrets.ListAsync(
            principal,
            Workspace.WorkspaceId,
            Vault.Id,
            new SecretFilter(
                Search: Search,
                Environment: EnvironmentFilter,
                IncludeDeleted: ShowDeleted),
            cancellationToken).ConfigureAwait(false);

        Secrets = listed.IsSuccess ? listed.Value : [];

        // Built from an unfiltered listing so the environment filter does not hide its own
        // other options once one is applied.
        var all = await _secrets.ListAsync(
            principal,
            Workspace.WorkspaceId,
            Vault.Id,
            new SecretFilter(IncludeDeleted: true),
            cancellationToken).ConfigureAwait(false);

        if (all.IsSuccess)
        {
            var environments = new SortedSet<string>(StringComparer.Ordinal);

            foreach (var secret in all.Value)
            {
                environments.Add(secret.Environment);
            }

            Environments = [.. environments];
        }

        return true;
    }
}

/// <summary>The add-secret form's fields.</summary>
public sealed class CreateSecretInput
{
    /// <summary>The lookup name.</summary>
    [Required]
    [StringLength(256, MinimumLength = 1)]
    public string Name { get; set; } = string.Empty;

    /// <summary>Environment label.</summary>
    [Required]
    [StringLength(64, MinimumLength = 1)]
    public string Environment { get; set; } = "prod";

    /// <summary>
    /// The secret value.
    /// </summary>
    /// <remarks>
    /// Bound as a string because that is what a form posts. The page model converts it to
    /// bytes, hands those to the service, and zeroes them; the string itself is left to the
    /// garbage collector, which is a real limitation of model binding and is recorded in
    /// THREATMODEL.md rather than papered over.
    /// </remarks>
    [Required]
    [StringLength(64 * 1024, MinimumLength = 1)]
    public string Value { get; set; } = string.Empty;

    /// <summary>Optional content type hint.</summary>
    [StringLength(128)]
    public string? ContentType { get; set; }

    /// <summary>When the value stops being valid, if it expires.</summary>
    public DateTimeOffset? ExpiresUtc { get; set; }

    /// <summary>How many days before expiry to surface a reminder.</summary>
    [Range(1, 365)]
    public int? RotationReminderDays { get; set; }

    /// <summary>An optional tag key.</summary>
    [StringLength(64)]
    public string? TagKey { get; set; }

    /// <summary>An optional tag value.</summary>
    [StringLength(256)]
    public string? TagValue { get; set; }
}
