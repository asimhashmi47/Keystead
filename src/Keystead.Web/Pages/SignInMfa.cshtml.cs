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
/// The second factor step.
/// </summary>
/// <remarks>
/// Reached only with the half-authenticated cookie from the password step, so a client cannot
/// arrive here naming an account it has not proved a password for. Like the password step, one
/// generic error and a per-address rate limit on top of the per-account lockout.
/// </remarks>
[AllowAnonymous]
[EnableRateLimiting("mfa")]
public sealed class SignInMfaModel : KeysteadPageModel
{
    private readonly ISignInService _signIn;

    /// <summary>Creates the page model.</summary>
    /// <param name="signIn">The sign-in service.</param>
    /// <exception cref="ArgumentNullException"><paramref name="signIn"/> is null.</exception>
    public SignInMfaModel(ISignInService signIn)
    {
        ArgumentNullException.ThrowIfNull(signIn);
        _signIn = signIn;
    }

    /// <summary>The submitted code.</summary>
    [BindProperty]
    public MfaCodeInput Input { get; set; } = new();

    /// <summary>The error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>Where to go after a successful sign-in.</summary>
    [BindProperty(SupportsGet = true)]
    public string? Next { get; set; }

    /// <summary>Shows the form.</summary>
    /// <returns>The page, or a redirect back to the password step.</returns>
    public async Task<IActionResult> OnGetAsync()
    {
        var pending = await GetPendingUserIdAsync().ConfigureAwait(false);

        return pending is null ? RedirectToPage("/SignIn") : Page();
    }

    /// <summary>Verifies the code.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The next step in the flow.</returns>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var pending = await GetPendingUserIdAsync().ConfigureAwait(false);

        if (pending is null)
        {
            // The five-minute pending window elapsed, or the cookie was never issued.
            return RedirectToPage("/SignIn");
        }

        if (!ModelState.IsValid)
        {
            Error = "Enter the six-digit code from your authenticator app.";
            return Page();
        }

        var outcome = await _signIn
            .VerifyMfaAsync(pending.Value, Input.Code, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        if (outcome.Status is not SignInStatus.Succeeded)
        {
            Error = "That code was not accepted. Codes expire after 30 seconds, and each one can only be used once.";
            return Page();
        }

        await SignInCompletedAsync(outcome).ConfigureAwait(false);

        return !string.IsNullOrEmpty(Next) && Url.IsLocalUrl(Next)
            ? Redirect(Next)
            : RedirectToPage("/Index");
    }

    private async Task<Guid?> GetPendingUserIdAsync()
    {
        var result = await HttpContext
            .AuthenticateAsync(KeysteadSchemes.MfaPending)
            .ConfigureAwait(false);

        return result.Succeeded ? KeysteadClaims.GetUserId(result.Principal) : null;
    }

    private async Task SignInCompletedAsync(SignInOutcome outcome)
    {
        // Drop the half-authenticated cookie before issuing the real one, so a stale
        // pending-MFA cookie cannot be replayed.
        await HttpContext.SignOutAsync(KeysteadSchemes.MfaPending).ConfigureAwait(false);

        var identity = new ClaimsIdentity(
            KeysteadClaims.For(
                outcome.UserId!.Value,
                outcome.SessionId!.Value,
                outcome.Email!),
            CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity)).ConfigureAwait(false);
    }
}
