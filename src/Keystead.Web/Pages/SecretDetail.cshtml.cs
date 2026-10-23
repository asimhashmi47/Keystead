using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Secrets;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Domain.Common;
using Keystead.Domain.Vaults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>
/// One secret: its metadata, its version timeline, and the reveal flow.
/// </summary>
/// <remarks>
/// <para>
/// The value is never rendered into this page. The <c>GET</c> response contains only metadata
/// and a masked placeholder; the value is fetched separately by the reveal handler, which is
/// <c>POST</c> only, antiforgery protected, step-up protected, and returns
/// <c>Cache-Control: no-store</c>. That combination is what keeps a secret out of the browser
/// history, out of any shared cache, and out of a page someone leaves open.
/// </para>
/// <para>
/// <c>POST</c> for a read looks odd until you consider the alternative: a <c>GET</c> that
/// returns a secret puts it in a URL-keyed cache, a referrer, and a server log line, and makes
/// it fetchable by anything that can cause a navigation.
/// </para>
/// </remarks>
public sealed class SecretDetailModel : KeysteadPageModel
{
    private readonly IVaultService _vaults;
    private readonly ISecretService _secrets;
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="vaults">The vault service.</param>
    /// <param name="secrets">The secret service.</param>
    /// <param name="workspaces">Resolves the acting workspace.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public SecretDetailModel(
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

    /// <summary>The secret id from the route.</summary>
    [BindProperty(SupportsGet = true)]
    public Guid SecretId { get; set; }

    /// <summary>The owning vault.</summary>
    public VaultSummary? Vault { get; private set; }

    /// <summary>The secret's metadata. Never its value.</summary>
    public SecretSummary? Secret { get; private set; }

    /// <summary>The version timeline, newest first.</summary>
    public IReadOnlyList<SecretVersionSummary> Versions { get; private set; } = [];

    /// <summary>Whether this principal may write here.</summary>
    public bool CanWrite => Vault?.Permission == VaultPermission.Write;

    /// <summary>The new-value form.</summary>
    [BindProperty]
    public NewVersionInput Input { get; set; } = new();

    /// <summary>An error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>A confirmation message, or null.</summary>
    [TempData]
    public string? Notice { get; set; }

    /// <summary>The current time, for expiry badges.</summary>
    public DateTimeOffset Now { get; private set; }

    /// <summary>Loads the secret.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, or 404 when it is unreachable.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken) =>
        await LoadAsync(cancellationToken).ConfigureAwait(false) ? Page() : NotFound();

    /// <summary>
    /// Decrypts and returns the value, as JSON, for the page script to display.
    /// </summary>
    /// <param name="version">A specific version, or null for the latest.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>
    /// The value on success, a 403 carrying a step-up challenge when one is needed, or 404.
    /// </returns>
    public async Task<IActionResult> OnPostRevealAsync(
        int? version,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Vault is null
            || Workspace is null)
        {
            return NotFound();
        }

        var revealed = await _secrets.RevealAsync(
            principal,
            Workspace.WorkspaceId,
            Vault.Id,
            SecretId,
            version,
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (revealed.Error is { } error)
        {
            // A stale step-up is answerable, so it is reported distinctly from a flat refusal:
            // the script sends the viewer to the step-up form rather than a dead end.
            if (error.Kind is DomainErrorKind.StepUpRequired)
            {
                Response.StatusCode = StatusCodes.Status403Forbidden;

                return new JsonResult(new
                {
                    stepUpRequired = true,
                    message = error.Message,
                    stepUpUrl = $"/step-up?next={Uri.EscapeDataString(Request.Path + Request.QueryString)}",
                });
            }

            Response.StatusCode = error.Kind is DomainErrorKind.NotFound
                ? StatusCodes.Status404NotFound
                : StatusCodes.Status403Forbidden;

            return new JsonResult(new { message = error.Message });
        }

        using var value = revealed.Value;

        // Belt and braces over the global header: this response in particular must never be
        // stored by anything.
        Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0";
        Response.Headers["Pragma"] = "no-cache";

        return new JsonResult(new
        {
            value = Encoding.UTF8.GetString(value.Value),
            version = value.Version,
            contentType = value.ContentType,

            // Drives the auto-hide countdown in the page, so the timing is stated by the
            // server rather than hardcoded in two places.
            autoHideSeconds = 30,
        });
    }

    /// <summary>Appends a new version with a new value.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect on success, or the page with an error.</returns>
    public async Task<IActionResult> OnPostNewVersionAsync(CancellationToken cancellationToken)
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
            Error = "Enter a value.";
            return Page();
        }

        var value = Encoding.UTF8.GetBytes(Input.Value);

        try
        {
            var written = await _secrets.SetValueAsync(
                principal, Workspace.WorkspaceId, Vault.Id, SecretId,
                value, RequestContext, cancellationToken).ConfigureAwait(false);

            if (written.Error is { } error)
            {
                Error = error.Message;
                return Page();
            }

            Notice = $"Stored version {written.Value}.";

            return RedirectToPage("/SecretDetail", new { slug = Slug, secretId = SecretId });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    /// <summary>Rolls the secret back to an earlier version.</summary>
    /// <param name="targetVersion">The version to restore.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostRollbackAsync(
        int targetVersion,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Vault is null
            || Workspace is null)
        {
            return NotFound();
        }

        var rolled = await _secrets.RollbackAsync(
            principal, Workspace.WorkspaceId, Vault.Id, SecretId,
            targetVersion, RequestContext, cancellationToken).ConfigureAwait(false);

        Notice = rolled.IsSuccess
            ? $"Rolled back to version {targetVersion}, stored as version {rolled.Value}."
            : null;

        if (rolled.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        return RedirectToPage("/SecretDetail", new { slug = Slug, secretId = SecretId });
    }

    /// <summary>Enables or disables the secret.</summary>
    /// <param name="enabled">The new state.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostSetEnabledAsync(
        bool enabled,
        CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Vault is null
            || Workspace is null)
        {
            return NotFound();
        }

        var changed = await _secrets.SetEnabledAsync(
            principal, Workspace.WorkspaceId, Vault.Id, SecretId,
            enabled, RequestContext, cancellationToken).ConfigureAwait(false);

        Notice = changed.IsSuccess
            ? enabled ? "Secret enabled." : "Secret disabled."
            : null;

        return RedirectToPage("/SecretDetail", new { slug = Slug, secretId = SecretId });
    }

    /// <summary>Soft deletes the secret.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect to the vault.</returns>
    public async Task<IActionResult> OnPostDeleteAsync(CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Vault is null
            || Workspace is null)
        {
            return NotFound();
        }

        var deleted = await _secrets.SoftDeleteAsync(
            principal, Workspace.WorkspaceId, Vault.Id, SecretId,
            RequestContext, cancellationToken).ConfigureAwait(false);

        if (deleted.IsSuccess)
        {
            Notice = $"Deleted {Secret?.Name}. It stays recoverable.";
            return RedirectToPage("/VaultDetail", new { slug = Slug });
        }

        Error = deleted.Error.Message;
        return Page();
    }

    /// <summary>Restores a soft-deleted secret.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back to this page.</returns>
    public async Task<IActionResult> OnPostRecoverAsync(CancellationToken cancellationToken)
    {
        if (!await LoadAsync(cancellationToken).ConfigureAwait(false)
            || CurrentPrincipal is not { } principal
            || Vault is null
            || Workspace is null)
        {
            return NotFound();
        }

        await _secrets.RecoverAsync(
            principal, Workspace.WorkspaceId, Vault.Id, SecretId,
            RequestContext, cancellationToken).ConfigureAwait(false);

        Notice = "Recovered.";

        return RedirectToPage("/SecretDetail", new { slug = Slug, secretId = SecretId });
    }

    /// <summary>The acting workspace.</summary>
    public WorkspaceMembershipView? Workspace { get; private set; }

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

        var vault = await _vaults
            .GetBySlugAsync(principal, Workspace.WorkspaceId, Slug, cancellationToken)
            .ConfigureAwait(false);

        if (!vault.IsSuccess)
        {
            return false;
        }

        Vault = vault.Value;

        var listed = await _secrets.ListAsync(
            principal,
            Workspace.WorkspaceId,
            Vault.Id,
            new SecretFilter(IncludeDeleted: true),
            cancellationToken).ConfigureAwait(false);

        if (!listed.IsSuccess)
        {
            return false;
        }

        Secret = listed.Value.FirstOrDefault(s => s.Id == SecretId);

        if (Secret is null)
        {
            return false;
        }

        var versions = await _secrets
            .ListVersionsAsync(principal, Workspace.WorkspaceId, Vault.Id, SecretId, cancellationToken)
            .ConfigureAwait(false);

        Versions = versions.IsSuccess ? versions.Value : [];

        return true;
    }
}

/// <summary>The new-version form's fields.</summary>
public sealed class NewVersionInput
{
    /// <summary>The new secret value.</summary>
    [Required]
    [StringLength(64 * 1024, MinimumLength = 1)]
    public string Value { get; set; } = string.Empty;
}
