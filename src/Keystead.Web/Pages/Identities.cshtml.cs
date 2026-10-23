using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>
/// Service identities: the machine principals that let applications read secrets.
/// </summary>
/// <remarks>
/// A newly issued client secret is shown on exactly one response and never stored in plaintext.
/// It is deliberately not put in TempData: that would survive a redirect, which means it would
/// also survive a refresh and sit in a cookie or in server-side session state for longer than
/// the one render that needs it.
/// </remarks>
public sealed class IdentitiesModel : KeysteadPageModel
{
    private readonly IServiceIdentityService _identities;
    private readonly IVaultService _vaults;
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="identities">The service identity service.</param>
    /// <param name="vaults">Lists vaults to scope against.</param>
    /// <param name="workspaces">Resolves the acting workspace.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public IdentitiesModel(
        IServiceIdentityService identities,
        IVaultService vaults,
        ICurrentWorkspace workspaces)
    {
        ArgumentNullException.ThrowIfNull(identities);
        ArgumentNullException.ThrowIfNull(vaults);
        ArgumentNullException.ThrowIfNull(workspaces);

        _identities = identities;
        _vaults = vaults;
        _workspaces = workspaces;
    }

    /// <summary>The workspace's identities.</summary>
    public IReadOnlyList<ServiceIdentitySummary> Items { get; private set; } = [];

    /// <summary>The vaults available to scope against.</summary>
    public IReadOnlyList<VaultSummary> Vaults { get; private set; } = [];

    /// <summary>The acting workspace.</summary>
    public WorkspaceMembershipView? Workspace { get; private set; }

    /// <summary>Whether this principal may manage identities here.</summary>
    public bool CanManage { get; private set; }

    /// <summary>The create form.</summary>
    [BindProperty]
    public CreateIdentityInput Input { get; set; } = new();

    /// <summary>
    /// A newly issued client secret, shown on this response only.
    /// </summary>
    public string? IssuedSecret { get; private set; }

    /// <summary>The client id the new secret belongs to.</summary>
    public string? IssuedClientId { get; private set; }

    /// <summary>Whether the issued secret came from a rotation rather than a creation.</summary>
    public bool IssuedByRotation { get; private set; }

    /// <summary>An error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>A confirmation message, or null.</summary>
    [TempData]
    public string? Notice { get; set; }

    /// <summary>The current time, for expiry and overlap badges.</summary>
    public DateTimeOffset Now { get; private set; }

    /// <summary>Loads the list.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken) =>
        await LoadAsync(cancellationToken).ConfigureAwait(false)
            ? Page()
            : RedirectToPage("/SignIn");

    /// <summary>Creates an identity and shows its one-time secret.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, carrying the secret.</returns>
    public async Task<IActionResult> OnPostCreateAsync(CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Workspace is null)
        {
            return RedirectToPage("/SignIn");
        }

        if (!ModelState.IsValid)
        {
            Error = "Check the details below.";
            return Page();
        }

        var scopes = new List<RequestedScope>();

        foreach (var selected in Input.ScopedVaultIds ?? [])
        {
            if (Guid.TryParse(selected, out var vaultId))
            {
                scopes.Add(new RequestedScope(
                    vaultId,
                    Input.GrantWrite ? VaultPermission.Write : VaultPermission.Read));
            }
        }

        var allowlist = (Input.IpAllowlist ?? string.Empty)
            .Split([',', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        var created = await _identities.CreateAsync(
            principal,
            Workspace.WorkspaceId,
            new CreateServiceIdentityRequest(Input.Name, Input.ExpiresUtc, allowlist, scopes),
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (created.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        // Rendered on this response and never again.
        IssuedSecret = created.Value.ClientSecret;
        IssuedClientId = created.Value.Identity.ClientId;

        await LoadAsync(cancellationToken).ConfigureAwait(false);

        return Page();
    }

    /// <summary>Rotates an identity's secret, keeping the old one briefly usable.</summary>
    /// <param name="identityId">The identity to rotate.</param>
    /// <param name="overlapHours">How long the previous secret keeps working.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, carrying the new secret.</returns>
    public async Task<IActionResult> OnPostRotateAsync(
        Guid identityId,
        int overlapHours,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Workspace is null)
        {
            return RedirectToPage("/SignIn");
        }

        var rotated = await _identities.RotateSecretAsync(
            principal,
            Workspace.WorkspaceId,
            identityId,
            TimeSpan.FromHours(Math.Clamp(overlapHours, 0, 720)),
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (rotated.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        IssuedSecret = rotated.Value;
        IssuedByRotation = true;
        IssuedClientId = Items.FirstOrDefault(i => i.Id == identityId)?.ClientId;

        await LoadAsync(cancellationToken).ConfigureAwait(false);

        return Page();
    }

    /// <summary>Revokes an identity.</summary>
    /// <param name="identityId">The identity to revoke.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostRevokeAsync(
        Guid identityId,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Workspace is null)
        {
            return RedirectToPage("/SignIn");
        }

        var revoked = await _identities.RevokeAsync(
            principal, Workspace.WorkspaceId, identityId, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        Notice = revoked.IsSuccess
            ? "Revoked. It stops working on its next call, including with tokens already issued."
            : null;

        if (revoked.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        return RedirectToPage();
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

        CanManage = RoleCapabilities.Allows(
            Workspace.Role, WorkspaceCapability.ManageServiceIdentities);

        var listed = await _identities
            .ListAsync(principal, Workspace.WorkspaceId, cancellationToken)
            .ConfigureAwait(false);

        Items = listed.IsSuccess ? listed.Value : [];

        var vaults = await _vaults
            .ListAsync(principal, Workspace.WorkspaceId, includeDeleted: false, cancellationToken)
            .ConfigureAwait(false);

        Vaults = vaults.IsSuccess ? vaults.Value : [];

        return true;
    }
}

/// <summary>The create-identity form's fields.</summary>
public sealed class CreateIdentityInput
{
    /// <summary>Display name.</summary>
    [Required]
    [StringLength(200, MinimumLength = 2)]
    public string Name { get; set; } = string.Empty;

    /// <summary>When the identity stops working, if it expires.</summary>
    public DateTimeOffset? ExpiresUtc { get; set; }

    /// <summary>Addresses and CIDR ranges, comma or newline separated.</summary>
    [StringLength(2048)]
    public string? IpAllowlist { get; set; }

    /// <summary>The vaults to grant.</summary>
    public IReadOnlyList<string>? ScopedVaultIds { get; set; }

    /// <summary>
    /// Whether to grant write rather than read.
    /// </summary>
    /// <remarks>
    /// One choice for the whole identity rather than per vault, deliberately: an identity that
    /// needs write on one vault and read on another is two identities, and splitting them
    /// keeps the blast radius of a leaked secret smaller.
    /// </remarks>
    public bool GrantWrite { get; set; }
}
