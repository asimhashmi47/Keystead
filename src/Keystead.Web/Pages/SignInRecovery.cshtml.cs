using System;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Keystead.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Keystead.Web.Pages;

/// <summary>
/// Signing in with a single-use recovery code instead of a TOTP code.
/// </summary>
/// <remarks>
/// Still behind the password step: a recovery code replaces the second factor, never the first.
/// Reaching this page without the half-authenticated cookie redirects back to the password form.
/// </remarks>
[AllowAnonymous]
[EnableRateLimiting("mfa")]
public sealed class SignInRecoveryModel : KeysteadPageModel
{
    private readonly ISignInService _signIn;

    /// <summary>Creates the page model.</summary>
    /// <param name="signIn">The sign-in service.</param>
    /// <exception cref="ArgumentNullException"><paramref name="signIn"/> is null.</exception>
    public SignInRecoveryModel(ISignInService signIn)
    {
        ArgumentNullException.ThrowIfNull(signIn);
        _signIn = signIn;
    }

    /// <summary>The submitted code.</summary>
    [BindProperty]
    public RecoveryCodeInput Input { get; set; } = new();

    /// <summary>The error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>Shows the form.</summary>
    /// <returns>The page, or a redirect back to the password step.</returns>
    public async Task<IActionResult> OnGetAsync() =>
        await GetPendingUserIdAsync().ConfigureAwait(false) is null
            ? RedirectToPage("/SignIn")
            : Page();

    /// <summary>Consumes the recovery code.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The next step in the flow.</returns>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var pending = await GetPendingUserIdAsync().ConfigureAwait(false);

        if (pending is null)
        {
            return RedirectToPage("/SignIn");
        }

        if (!ModelState.IsValid)
        {
            Error = "Enter one of the recovery codes you were given when you set up two-factor authentication.";
            return Page();
        }

        var outcome = await _signIn
            .UseRecoveryCodeAsync(pending.Value, Input.Code, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        if (outcome.Status is not SignInStatus.Succeeded)
        {
            Error = "That recovery code was not accepted. Each code can only be used once.";
            return Page();
        }

        await HttpContext.SignOutAsync(KeysteadSchemes.MfaPending).ConfigureAwait(false);

        var identity = new ClaimsIdentity(
            KeysteadClaims.For(outcome.UserId!.Value, outcome.SessionId!.Value, outcome.Email!),
            CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity)).ConfigureAwait(false);

        // Straight to the security centre, not the dashboard. Someone who just burned a
        // recovery code needs to re-enrol an authenticator, and this is the moment they will
        // actually do it.
        return RedirectToPage("/Security");
    }

    private async Task<Guid?> GetPendingUserIdAsync()
    {
        var result = await HttpContext
            .AuthenticateAsync(KeysteadSchemes.MfaPending)
            .ConfigureAwait(false);

        return result.Succeeded ? KeysteadClaims.GetUserId(result.Principal) : null;
    }
}
