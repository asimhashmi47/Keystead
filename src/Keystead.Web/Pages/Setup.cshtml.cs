using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Keystead.Web.Pages;

/// <summary>
/// The first-run wizard: creates the first workspace and its owner.
/// </summary>
/// <remarks>
/// Necessarily anonymous, because there is nobody to authenticate as yet. Both the page and
/// the service refuse once any user exists: a setup route that stayed open would be a
/// permanent unauthenticated way to create an Owner account, which would undo the whole
/// authorization model.
/// </remarks>
[AllowAnonymous]
[EnableRateLimiting("sign-in")]
public sealed class SetupModel : KeysteadPageModel
{
    private readonly IInstallationService _installation;

    /// <summary>Creates the page model.</summary>
    /// <param name="installation">The installation service.</param>
    /// <exception cref="ArgumentNullException"><paramref name="installation"/> is null.</exception>
    public SetupModel(IInstallationService installation)
    {
        ArgumentNullException.ThrowIfNull(installation);
        _installation = installation;
    }

    /// <summary>The submitted form.</summary>
    [BindProperty]
    public SetupInput Input { get; set; } = new();

    /// <summary>The error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>
    /// The master key fingerprint, shown once on the recovery kit after a successful setup.
    /// </summary>
    public string? MasterKeyCheckValue { get; private set; }

    /// <summary>Shows the wizard.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, or a redirect when setup is already done.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken) =>
        await _installation.IsInitialisedAsync(cancellationToken).ConfigureAwait(false)
            ? RedirectToPage("/SignIn")
            : Page();

    /// <summary>Creates the workspace and owner.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The recovery kit on success, or the form with an error.</returns>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (await _installation.IsInitialisedAsync(cancellationToken).ConfigureAwait(false))
        {
            return RedirectToPage("/SignIn");
        }

        if (!ModelState.IsValid)
        {
            Error = "Check the details below and try again.";
            return Page();
        }

        var result = await _installation.InitialiseAsync(
            new InitialisationRequest(
                Input.WorkspaceName,
                Input.Email,
                Input.DisplayName,
                Input.Password),
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            Error = result.Error;
            return Page();
        }

        // The recovery kit is shown on this response and never again. It is not stored in
        // TempData or a cookie, so a refresh does not reproduce it.
        MasterKeyCheckValue = result.MasterKeyCheckValue;

        return Page();
    }
}
