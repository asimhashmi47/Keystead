using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Secrets;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Domain.Vaults;
using Keystead.Web.Tables;
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

    /// <summary>Whether soft-deleted secrets are shown.</summary>
    [BindProperty(SupportsGet = true, Name = "deleted")]
    public bool ShowDeleted { get; set; }

    /// <summary>The vault.</summary>
    public VaultSummary? Vault { get; private set; }

    /// <summary>The acting workspace.</summary>
    public WorkspaceMembershipView? Workspace { get; private set; }

    /// <summary>The secrets in this vault, as metadata only.</summary>
    /// <remarks>
    /// Metadata, and never a value. A list is the one place where loading values would be
    /// invisible and catastrophic: nothing on screen would change, and every secret in the
    /// vault would have been decrypted to render a page about their names.
    /// </remarks>
    public IReadOnlyList<SecretSummary> Secrets { get; private set; } = [];

    /// <summary>The searched, sorted and paged table.</summary>
    public TableView<SecretSummary>? Table { get; private set; }

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

    /// <summary>
    /// Downloads the filtered secret list as metadata.
    /// </summary>
    /// <param name="format">The format, <c>xlsx</c> or <c>csv</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A file, or 404 when the vault is unreachable.</returns>
    /// <remarks>
    /// Names, environments, versions, states and dates. No values: the page model never loads
    /// one, so there is none here to write. That is a property of where the export is built
    /// from, not a filter applied to it, which is the only version of this that stays true.
    /// </remarks>
    public async Task<IActionResult> OnGetExportAsync(
        string? format,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false) || Table is null)
        {
            return NotFound();
        }

        return TableExport.ToFile(
            Table,
            TableExport.ParseFormat(format),
            $"{Vault?.Name ?? "Vault"} secrets");
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
            .ResolveAsync(principal.Id, RequestedWorkspaceId, cancellationToken)
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

        // One listing, filtered in the page rather than in the query. Searching and sorting
        // belong to the table, which already has to hold every row it might page through; the
        // service keeps the one filter that changes what may be read at all.
        var listed = await _secrets.ListAsync(
            principal,
            Workspace.WorkspaceId,
            Vault.Id,
            new SecretFilter(IncludeDeleted: ShowDeleted),
            cancellationToken).ConfigureAwait(false);

        Secrets = listed.IsSuccess ? listed.Value : [];

        var environments = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var secret in Secrets)
        {
            environments.Add(secret.Environment);
        }

        Environments = [.. environments];

        Table = TableEngine.Build(
            Secrets,
            Columns(Environments, Now),
            TableQuery.FromRequest(Request),
            id: "secrets",
            label: "secrets",
            path: Request.Path,
            preserved: ShowDeleted
                ? new Dictionary<string, string?>(StringComparer.Ordinal) { ["deleted"] = "true" }
                : null);

        return true;
    }

    /// <summary>
    /// The columns, declared once and used for the header, the filters, the sort and the export.
    /// </summary>
    /// <param name="environments">The environment labels present, for that column's filter.</param>
    /// <param name="now">The instant expiry is judged against.</param>
    /// <returns>The columns.</returns>
    private static IReadOnlyList<TableColumn<SecretSummary>> Columns(
        IReadOnlyList<string> environments,
        DateTimeOffset now) =>
    [
        new TableColumn<SecretSummary>
        {
            Key = "name",
            Header = "Name",

            // The tags too: they are how people label ownership here, and "owner: payments"
            // is a search someone will type.
            Text = s => s.Tags.Count == 0
                ? s.Name
                : $"{s.Name} {string.Join(' ', s.Tags.Select(t => $"{t.Key}: {t.Value}"))}",
            SortBy = s => s.Name,
        },
        new TableColumn<SecretSummary>
        {
            Key = "environment",
            Header = "Environment",
            Text = s => s.Environment,
            Options = [.. environments.Select(e => new TableOption(e, e))],
        },
        new TableColumn<SecretSummary>
        {
            Key = "versions",
            Header = "Versions",
            Text = s => string.Create(CultureInfo.InvariantCulture, $"v{s.LatestVersion} of {s.VersionCount}"),
            SortBy = s => s.VersionCount,
            Align = TableAlign.End,
            Numeric = true,
            Searchable = false,
        },
        new TableColumn<SecretSummary>
        {
            Key = "status",
            Header = "Status",
            Text = s => Status(s, now),
            Options =
            [
                new TableOption("Active", "Active"),
                new TableOption("Expiring soon", "Expiring soon"),
                new TableOption("Expired", "Expired"),
                new TableOption("Disabled", "Disabled"),
                new TableOption("Deleted", "Deleted"),
            ],
        },
        new TableColumn<SecretSummary>
        {
            Key = "updated",
            Header = "Updated",
            Text = s => s.UpdatedUtc.ToString("d MMM yyyy", CultureInfo.InvariantCulture),
            SortBy = s => s.UpdatedUtc,
            Align = TableAlign.End,
            Priority = TablePriority.Secondary,
        },
    ];

    /// <summary>
    /// A secret's state as one word, in the order that matters.
    /// </summary>
    /// <remarks>
    /// Deleted beats disabled beats expired beats expiring. A secret can be several of these at
    /// once, and the cell, the filter and the export all have to agree on which one it is
    /// called, which is why there is one function rather than a chain of conditions in the
    /// markup.
    /// </remarks>
    internal static string Status(SecretSummary secret, DateTimeOffset now) => secret switch
    {
        { SoftDeletedUtc: not null } => "Deleted",
        { Enabled: false } => "Disabled",
        _ when secret.IsExpired(now) => "Expired",
        _ when secret.IsExpiringSoon(now, ExpiryWarning) => "Expiring soon",
        _ => "Active",
    };

    /// <summary>How far ahead an expiry counts as soon.</summary>
    internal static readonly TimeSpan ExpiryWarning = TimeSpan.FromDays(30);
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
