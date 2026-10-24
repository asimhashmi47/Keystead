using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>
/// Members and roles, and which vaults each person can reach.
/// </summary>
/// <remarks>
/// Role and permission are taken from named handler parameters, never model-bound onto an
/// entity. Binding a role straight onto a membership row is the textbook mass-assignment
/// escalation, and CLAUDE.md forbids it for exactly this page.
/// </remarks>
public sealed class MembersModel : KeysteadPageModel
{
    private readonly IMembershipService _members;
    private readonly IVaultService _vaults;
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="members">The membership service.</param>
    /// <param name="vaults">Lists vaults to grant against.</param>
    /// <param name="workspaces">Resolves the acting workspace.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public MembersModel(
        IMembershipService members,
        IVaultService vaults,
        ICurrentWorkspace workspaces)
    {
        ArgumentNullException.ThrowIfNull(members);
        ArgumentNullException.ThrowIfNull(vaults);
        ArgumentNullException.ThrowIfNull(workspaces);

        _members = members;
        _vaults = vaults;
        _workspaces = workspaces;
    }

    /// <summary>The workspace's members.</summary>
    public IReadOnlyList<MemberSummary> Items { get; private set; } = [];

    /// <summary>The vaults available to grant.</summary>
    public IReadOnlyList<VaultSummary> Vaults { get; private set; } = [];

    /// <summary>The acting workspace.</summary>
    public WorkspaceMembershipView? Workspace { get; private set; }

    /// <summary>Whether this principal holds the Owner role here.</summary>
    public bool IsOwner => Workspace?.Role is WorkspaceRole.Owner;

    /// <summary>The add-member form.</summary>
    [BindProperty]
    public AddMemberInput Input { get; set; } = new();

    /// <summary>A generated one-time password, shown on this response only.</summary>
    public string? OneTimePassword { get; private set; }

    /// <summary>The address the one-time password belongs to.</summary>
    public string? OneTimePasswordFor { get; private set; }

    /// <summary>An error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>A confirmation message, or null.</summary>
    [TempData]
    public string? Notice { get; set; }

    /// <summary>Loads the member list.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, or a redirect when unauthorized.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false))
        {
            return RedirectToPage("/Forbidden");
        }

        return Page();
    }

    /// <summary>Adds a member.</summary>
    /// <param name="role">The role to grant, from a named field rather than a bound entity.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, carrying any one-time password.</returns>
    public async Task<IActionResult> OnPostAddAsync(
        WorkspaceRole role,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Workspace is null)
        {
            return RedirectToPage("/Forbidden");
        }

        if (!ModelState.IsValid)
        {
            Error = "Check the details below.";
            return Page();
        }

        var added = await _members.AddAsync(
            principal,
            Workspace.WorkspaceId,
            Input.Email,
            Input.DisplayName,
            role,
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (added.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        if (added.Value.OneTimePassword.Length > 0)
        {
            OneTimePassword = added.Value.OneTimePassword;
            OneTimePasswordFor = added.Value.Member.Email;
        }
        else
        {
            Notice = $"{added.Value.Member.Email} was added. They sign in with their existing password.";
        }

        await LoadAsync(cancellationToken).ConfigureAwait(false);

        return Page();
    }

    /// <summary>Changes a member's role.</summary>
    /// <param name="userId">The member.</param>
    /// <param name="role">The new role.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostChangeRoleAsync(
        Guid userId,
        WorkspaceRole role,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Workspace is null)
        {
            return RedirectToPage("/Forbidden");
        }

        var changed = await _members.ChangeRoleAsync(
            principal, Workspace.WorkspaceId, userId, role, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        if (changed.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        Notice = "Role updated.";
        return RedirectToPage();
    }

    /// <summary>Removes a member.</summary>
    /// <param name="userId">The member.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostRemoveAsync(
        Guid userId,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Workspace is null)
        {
            return RedirectToPage("/Forbidden");
        }

        var removed = await _members.RemoveAsync(
            principal, Workspace.WorkspaceId, userId, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        if (removed.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        Notice = "Member removed and their vault access revoked.";
        return RedirectToPage();
    }

    /// <summary>Grants a member access to a vault.</summary>
    /// <param name="userId">The member.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="permission">Read or write.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostGrantAsync(
        Guid userId,
        Guid vaultId,
        VaultPermission permission,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Workspace is null)
        {
            return RedirectToPage("/Forbidden");
        }

        var granted = await _members.GrantVaultAsync(
            principal, Workspace.WorkspaceId, userId, vaultId, permission,
            RequestContext, cancellationToken).ConfigureAwait(false);

        if (granted.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        Notice = "Access granted.";
        return RedirectToPage();
    }

    /// <summary>Revokes a member's access to a vault.</summary>
    /// <param name="userId">The member.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostRevokeGrantAsync(
        Guid userId,
        Guid vaultId,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Workspace is null)
        {
            return RedirectToPage("/Forbidden");
        }

        var revoked = await _members.RevokeVaultAsync(
            principal, Workspace.WorkspaceId, userId, vaultId, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        if (revoked.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        Notice = "Access revoked.";
        return RedirectToPage();
    }

    private async Task<bool> LoadAsync(CancellationToken cancellationToken)
    {
        if (CurrentPrincipal is not { } principal)
        {
            return false;
        }

        Workspace = await _workspaces
            .ResolveAsync(principal.Id, RequestedWorkspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (Workspace is null)
        {
            return false;
        }

        var listed = await _members
            .ListAsync(principal, Workspace.WorkspaceId, cancellationToken)
            .ConfigureAwait(false);

        if (!listed.IsSuccess)
        {
            return false;
        }

        Items = listed.Value;

        var vaults = await _vaults
            .ListAsync(principal, Workspace.WorkspaceId, includeDeleted: false, cancellationToken)
            .ConfigureAwait(false);

        Vaults = vaults.IsSuccess ? vaults.Value : [];

        return true;
    }
}

/// <summary>The add-member form's fields.</summary>
/// <remarks>
/// Note what is absent: the role. It arrives as a separate handler parameter so that it can
/// never be set by binding onto something that reaches an entity.
/// </remarks>
public sealed class AddMemberInput
{
    /// <summary>The new member's address.</summary>
    [Required]
    [EmailAddress]
    [StringLength(320)]
    public string Email { get; set; } = string.Empty;

    /// <summary>Their display name.</summary>
    [Required]
    [StringLength(200, MinimumLength = 2)]
    public string DisplayName { get; set; } = string.Empty;
}
