using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Domain.Workspaces;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>The vault list, and the form to create one.</summary>
public sealed class VaultsModel : KeysteadPageModel
{
    private readonly IVaultService _vaults;
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="vaults">The vault service.</param>
    /// <param name="workspaces">Resolves the acting workspace.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public VaultsModel(IVaultService vaults, ICurrentWorkspace workspaces)
    {
        ArgumentNullException.ThrowIfNull(vaults);
        ArgumentNullException.ThrowIfNull(workspaces);

        _vaults = vaults;
        _workspaces = workspaces;
    }

    /// <summary>The vaults this principal may see.</summary>
    public IReadOnlyList<VaultSummary> Items { get; private set; } = [];

    /// <summary>The acting workspace.</summary>
    public WorkspaceMembershipView? Workspace { get; private set; }

    /// <summary>Whether this principal may create a vault here.</summary>
    public bool CanCreate { get; private set; }

    /// <summary>Whether soft-deleted vaults are shown.</summary>
    [BindProperty(SupportsGet = true, Name = "deleted")]
    public bool ShowDeleted { get; set; }

    /// <summary>The create form.</summary>
    [BindProperty]
    public CreateVaultInput Input { get; set; } = new();

    /// <summary>An error from the create form, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>A confirmation message, or null.</summary>
    [TempData]
    public string? Notice { get; set; }

    /// <summary>Loads the list.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var loaded = await LoadAsync(cancellationToken).ConfigureAwait(false);

        return loaded ? Page() : RedirectToPage("/SignIn");
    }

    /// <summary>Creates a vault.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect on success, or the page with an error.</returns>
    public async Task<IActionResult> OnPostCreateAsync(CancellationToken cancellationToken)
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

        if (!ModelState.IsValid)
        {
            Error = "Check the details below.";
            await LoadAsync(cancellationToken).ConfigureAwait(false);
            return Page();
        }

        var created = await _vaults.CreateAsync(
            principal,
            workspace.WorkspaceId,
            new CreateVaultRequest(
                Input.Name,
                Input.Description,
                Input.ColorToken,
                Input.RecoveryWindowDays,
                Input.PurgeProtection),
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (created.Error is { } error)
        {
            Error = error.Message;
            await LoadAsync(cancellationToken).ConfigureAwait(false);
            return Page();
        }

        Notice = $"Created the vault {created.Value.Name}.";

        return RedirectToPage("/VaultDetail", new { slug = created.Value.Slug });
    }

    private async Task<bool> LoadAsync(CancellationToken cancellationToken)
    {
        if (CurrentPrincipal is not { } principal)
        {
            return false;
        }

        Workspace = await _workspaces
            .ResolveAsync(principal.Id, null, cancellationToken)
            .ConfigureAwait(false);

        if (Workspace is null)
        {
            return false;
        }

        CanCreate = RoleCapabilities.Allows(Workspace.Role, WorkspaceCapability.ManageVaults);

        var listed = await _vaults
            .ListAsync(principal, Workspace.WorkspaceId, ShowDeleted, cancellationToken)
            .ConfigureAwait(false);

        Items = listed.IsSuccess ? listed.Value : [];

        return true;
    }
}

/// <summary>The create-vault form's fields.</summary>
public sealed class CreateVaultInput
{
    /// <summary>Display name.</summary>
    [Required]
    [StringLength(200, MinimumLength = 2)]
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional description.</summary>
    [StringLength(1000)]
    public string? Description { get; set; }

    /// <summary>
    /// Badge colour token. Validated against the allow-list by the service as well, because a
    /// form value is never trusted on its own.
    /// </summary>
    [Required]
    public string ColorToken { get; set; } = VaultColorTokens.Default;

    /// <summary>How long a soft-deleted vault stays recoverable.</summary>
    [Range(1, 365)]
    public int RecoveryWindowDays { get; set; } = 30;

    /// <summary>Whether the vault may ever be purged.</summary>
    public bool PurgeProtection { get; set; }
}
