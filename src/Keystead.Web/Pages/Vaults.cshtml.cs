using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Web.Tables;
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

    /// <summary>The searched, sorted and paged table.</summary>
    public TableView<VaultSummary>? Table { get; private set; }

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

    /// <summary>Downloads the filtered vault list.</summary>
    /// <param name="format">The format, <c>xlsx</c> or <c>csv</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A file, or a redirect when unauthorized.</returns>
    public async Task<IActionResult> OnGetExportAsync(
        string? format,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false) || Table is null)
        {
            return RedirectToPage("/SignIn");
        }

        return TableExport.ToFile(Table, TableExport.ParseFormat(format), "Vaults");
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
            .ResolveAsync(principal.Id, RequestedWorkspaceId, cancellationToken)
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
            .ResolveAsync(principal.Id, RequestedWorkspaceId, cancellationToken)
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

        Table = TableEngine.Build(
            Items,
            Columns(),
            TableQuery.FromRequest(Request),
            id: "vaults",
            label: "vaults",
            path: Request.Path,

            // The deleted toggle is the page's own, not the table's, so it has to be carried
            // through every sort, page and filter link the table builds.
            preserved: ShowDeleted
                ? new Dictionary<string, string?>(StringComparer.Ordinal) { ["deleted"] = "true" }
                : null);

        return true;
    }

    /// <summary>
    /// The columns, declared once and used for the header, the filters, the sort and the export.
    /// </summary>
    private static IReadOnlyList<TableColumn<VaultSummary>> Columns() =>
    [
        new TableColumn<VaultSummary>
        {
            Key = "vault",
            Header = "Vault",

            // The description as well as the name, because that is what the cell shows and
            // what someone searching for "payments" expects to match.
            Text = v => string.IsNullOrEmpty(v.Description) ? v.Name : $"{v.Name} - {v.Description}",
            SortBy = v => v.Name,
        },
        new TableColumn<VaultSummary>
        {
            Key = "secrets",
            Header = "Secrets",
            Text = v => v.SecretCount.ToString(CultureInfo.InvariantCulture),
            SortBy = v => v.SecretCount,
            Align = TableAlign.End,
            Numeric = true,
            Searchable = false,
        },
        new TableColumn<VaultSummary>
        {
            Key = "expiring",
            Header = "Expiring soon",
            Text = v => v.ExpiringSoonCount.ToString(CultureInfo.InvariantCulture),
            SortBy = v => v.ExpiringSoonCount,
            Align = TableAlign.End,
            Numeric = true,
            Searchable = false,
            Hint = "Secrets in this vault whose expiry is within the warning window",
        },
        new TableColumn<VaultSummary>
        {
            Key = "access",
            Header = "Access",
            Text = v => v.Permission == VaultPermission.Write ? "Read and write" : "Read only",
            Options =
            [
                new TableOption("Read and write", "Read and write"),
                new TableOption("Read only", "Read only"),
            ],
        },
        new TableColumn<VaultSummary>
        {
            Key = "status",
            Header = "Status",
            Text = Status,
            Options =
            [
                new TableOption("Active", "Active"),
                new TableOption("Purge protected", "Purge protected"),
                new TableOption("Deleted", "Deleted"),
            ],
            Priority = TablePriority.Secondary,
        },
        new TableColumn<VaultSummary>
        {
            Key = "created",
            Header = "Created",
            Text = v => v.CreatedUtc.ToString("d MMM yyyy", CultureInfo.InvariantCulture),

            // The instant, not the formatted date, or "1 Feb" would sort before "20 Jan".
            SortBy = v => v.CreatedUtc,
            Align = TableAlign.End,
            Priority = TablePriority.Secondary,
        },
    ];

    /// <summary>A vault's state as one word, for search, filter and export.</summary>
    internal static string Status(VaultSummary vault) => vault switch
    {
        { SoftDeletedUtc: not null } => "Deleted",
        { PurgeProtection: true } => "Purge protected",
        _ => "Active",
    };
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
