using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Web.Tables;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>
/// Members and roles, and which vaults each person can reach.
/// </summary>
/// <remarks>
/// <para>
/// Role and permission are taken from named handler parameters, never model-bound onto an
/// entity. Binding a role straight onto a membership row is the textbook mass-assignment
/// escalation, and CLAUDE.md forbids it for exactly this page.
/// </para>
/// <para>
/// The page is a list beside a panel. It used to be one table carrying a role select, a
/// two-factor state, a chip per vault grant and a grant form on every row, which needed a
/// horizontal scrollbar at 1440 px and put five controls in front of someone who came to read
/// one. The list now answers "who is here"; the panel answers "what can this person do", for
/// one person at a time. Which person is a query value, so the panel is part of the URL: it
/// survives a sort, a filter and a page, and it can be sent to someone.
/// </para>
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

    /// <summary>The query value naming the member shown in the detail panel.</summary>
    public const string SelectionKey = "member";

    /// <summary>The workspace's members.</summary>
    public IReadOnlyList<MemberSummary> Items { get; private set; } = [];

    /// <summary>The searched, sorted and paged table.</summary>
    public TableView<MemberSummary>? Table { get; private set; }

    /// <summary>The vaults available to grant.</summary>
    public IReadOnlyList<VaultSummary> Vaults { get; private set; } = [];

    /// <summary>The acting workspace.</summary>
    public WorkspaceMembershipView? Workspace { get; private set; }

    /// <summary>Whether this principal holds the Owner role here.</summary>
    public bool IsOwner => Workspace?.Role is WorkspaceRole.Owner;

    /// <summary>The member whose detail panel is open, or null.</summary>
    public MemberSummary? Selected { get; private set; }

    /// <summary>The add-member form.</summary>
    [BindProperty]
    public AddMemberInput Input { get; set; } = new();

    /// <summary>Whether the add-member form should be open on this response.</summary>
    /// <remarks>
    /// Open when it was just used and refused, so the details are still there to correct, and
    /// when the person asked for it. Otherwise a page about reading who is here does not lead
    /// with a form about adding someone.
    /// </remarks>
    public bool AddOpen { get; private set; }

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

        AddOpen = Request.Query["add"] == "1";

        return Page();
    }

    /// <summary>Downloads the filtered member list.</summary>
    /// <param name="format">The format, <c>xlsx</c> or <c>csv</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A file, or a redirect when unauthorized.</returns>
    /// <remarks>
    /// The same authorization, the same filter and the same columns as the page: the export is
    /// built from the view the page would have rendered, so a spreadsheet can never hold a row
    /// or a column the screen would not have shown.
    /// </remarks>
    public async Task<IActionResult> OnGetExportAsync(
        string? format,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false) || Table is null)
        {
            return RedirectToPage("/Forbidden");
        }

        return TableExport.ToFile(Table, TableExport.ParseFormat(format), "Members");
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

        AddOpen = true;

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

        // The form is closed again and the new member's panel is opened instead, because the
        // next thing anyone does after adding someone is grant them a vault.
        AddOpen = false;
        Input = new AddMemberInput();

        await LoadAsync(cancellationToken, added.Value.Member.UserId).ConfigureAwait(false);

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
        if (!await LoadAsync(cancellationToken, userId).ConfigureAwait(false)
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
        return Reload(userId);
    }

    /// <summary>Removes a member.</summary>
    /// <param name="userId">The member.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostRemoveAsync(
        Guid userId,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken, userId).ConfigureAwait(false)
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

        // No selection: the person the panel was about is gone.
        return Reload(null);
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
        if (!await LoadAsync(cancellationToken, userId).ConfigureAwait(false)
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
        return Reload(userId);
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
        if (!await LoadAsync(cancellationToken, userId).ConfigureAwait(false)
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
        return Reload(userId);
    }

    /// <summary>
    /// Redirects back to this page, keeping the table's query and the open panel.
    /// </summary>
    /// <remarks>
    /// A redirect rather than a rendered page, so the browser's reload does not repeat the
    /// action. Keeping the query means granting a vault to the fourth person on a filtered page
    /// three leaves you looking at the fourth person on filtered page three.
    /// </remarks>
    private RedirectToPageResult Reload(Guid? selected)
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);

        foreach (var pair in Request.Query)
        {
            if (!string.Equals(pair.Key, "handler", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(pair.Key, SelectionKey, StringComparison.OrdinalIgnoreCase))
            {
                values[pair.Key] = pair.Value.ToString();
            }
        }

        if (selected is { } id)
        {
            values[SelectionKey] = id.ToString("D", CultureInfo.InvariantCulture);
        }

        return RedirectToPage("/Members", pageHandler: null, routeValues: values);
    }

    private async Task<bool> LoadAsync(
        CancellationToken cancellationToken,
        Guid? selectedOverride = null)
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

        var selected = selectedOverride
            ?? (Guid.TryParse(Request.Query[SelectionKey], out var parsed) ? parsed : null);

        // Resolved against the list the person is allowed to see, so naming a member of
        // another workspace in the URL selects nobody rather than disclosing that they exist.
        Selected = selected is { } id ? Items.FirstOrDefault(m => m.UserId == id) : null;

        Table = TableEngine.Build(
            Items,
            Columns(),
            TableQuery.FromRequest(Request),
            id: "members",
            label: "members",
            path: Request.Path,
            preserved: Selected is { } member
                ? new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    [SelectionKey] = member.UserId.ToString("D", CultureInfo.InvariantCulture),
                }
                : null);

        return true;
    }

    /// <summary>
    /// The columns, declared once and used for the header, the filters, the sort and the export.
    /// </summary>
    private static IReadOnlyList<TableColumn<MemberSummary>> Columns() =>
    [
        new TableColumn<MemberSummary>
        {
            Key = "person",
            Header = "Person",

            // Both halves of the cell, so searching finds a person by either and an export
            // carries what the cell showed.
            Text = m => $"{m.DisplayName} ({m.Email})",
            SortBy = m => m.DisplayName,
        },
        new TableColumn<MemberSummary>
        {
            Key = "role",
            Header = "Role",
            Text = m => m.Role.ToString(),

            // Ordered by privilege rather than alphabetically: a role column sorted
            // "Admin, Contributor, Owner, Reader" is sorted by nothing anyone cares about.
            SortBy = m => (int)m.Role,
            Options = [.. Enum.GetValues<WorkspaceRole>()
                .Select(role => new TableOption(role.ToString(), role.ToString()))],
        },
        new TableColumn<MemberSummary>
        {
            Key = "mfa",
            Header = "Two-factor",
            Text = MfaText,
            Options =
            [
                new TableOption("Enrolled", "Enrolled"),
                new TableOption("Required, not set up", "Required, not set up"),
                new TableOption("Optional", "Optional"),
            ],
            Hint = "Whether this person has a second factor, and whether their role demands one",
        },
        new TableColumn<MemberSummary>
        {
            Key = "vaults",
            Header = "Vault access",
            Text = VaultAccessText,
            SortBy = m => m.HasImplicitVaultAccess ? int.MaxValue : m.Grants.Count,
            Align = TableAlign.End,
            Numeric = true,
            Priority = TablePriority.Secondary,
        },
        new TableColumn<MemberSummary>
        {
            Key = "status",
            Header = "Status",
            Text = m => m.IsActive ? "Active" : "Deactivated",
            Options =
            [
                new TableOption("Active", "Active"),
                new TableOption("Deactivated", "Deactivated"),
            ],
            Priority = TablePriority.Secondary,
        },
    ];

    /// <summary>The two-factor state as a word, for search, sort and export.</summary>
    internal static string MfaText(MemberSummary member) => member switch
    {
        { MfaEnabled: true } => "Enrolled",
        { RequiresMfa: true } => "Required, not set up",
        _ => "Optional",
    };

    /// <summary>What a member can open, as text.</summary>
    internal static string VaultAccessText(MemberSummary member)
    {
        if (member.HasImplicitVaultAccess)
        {
            return "Every vault";
        }

        return member.Grants.Count switch
        {
            0 => "No vaults",
            1 => "1 vault",
            var count => string.Create(CultureInfo.InvariantCulture, $"{count} vaults"),
        };
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
