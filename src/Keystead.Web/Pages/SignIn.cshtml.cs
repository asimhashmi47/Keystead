using System;
using System.Collections.Generic;
using System.Globalization;
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
/// The sign-in form.
/// </summary>
/// <remarks>
/// <para>
/// One error message for every failure. "No such account", "wrong password", "locked out" and
/// "deactivated" all produce the same sentence, because telling them apart turns this form
/// into a way to discover who has an account here, and then into a way to confirm when a
/// password guess was close.
/// </para>
/// <para>
/// Rate limited per client address on top of the per-account progressive lockout. The lockout
/// alone would not stop one guess against each of a thousand accounts.
/// </para>
/// </remarks>
[AllowAnonymous]
[EnableRateLimiting("sign-in")]
public sealed class SignInModel : KeysteadPageModel
{
    private const string GenericFailure =
        "That email address and password combination was not accepted.";

    private readonly ISignInService _signIn;
    private readonly IInstallationService _installation;

    /// <summary>Creates the page model.</summary>
    /// <param name="signIn">The sign-in service.</param>
    /// <param name="installation">Used to redirect to setup on a fresh installation.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public SignInModel(ISignInService signIn, IInstallationService installation)
    {
        ArgumentNullException.ThrowIfNull(signIn);
        ArgumentNullException.ThrowIfNull(installation);

        _signIn = signIn;
        _installation = installation;
    }

    /// <summary>
    /// The submitted form.
    /// </summary>
    /// <remarks>
    /// A separate input model, never an entity. Model-binding onto <c>User</c> would let a
    /// crafted form post set a role or a password hash (CLAUDE.md: separate input models).
    /// </remarks>
    [BindProperty]
    public SignInInput Input { get; set; } = new();

    /// <summary>The error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>Shows the form.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, or a redirect to setup on a fresh installation.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (!await _installation.IsInitialisedAsync(cancellationToken).ConfigureAwait(false))
        {
            return RedirectToPage("/Setup");
        }

        return Page();
    }

    /// <summary>Checks the submitted credentials.</summary>
    /// <param name="next">Where to go on success, validated as a local URL.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The next step in the flow.</returns>
    public async Task<IActionResult> OnPostAsync(string? next, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            Error = GenericFailure;
            return Page();
        }

        var outcome = await _signIn
            .AuthenticateAsync(Input.Email, Input.Password, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        switch (outcome.Status)
        {
            case SignInStatus.Succeeded:
                await IssueSessionCookieAsync(
                    outcome.UserId!.Value,
                    outcome.SessionId!.Value,
                    outcome.Email!).ConfigureAwait(false);

                return RedirectToLocalOrHome(next);

            case SignInStatus.MfaRequired:
                await IssuePendingCookieAsync(outcome.UserId!.Value).ConfigureAwait(false);
                return RedirectToPage("/SignInMfa", new { next });

            case SignInStatus.MfaEnrolmentRequired:
                await IssuePendingCookieAsync(outcome.UserId!.Value).ConfigureAwait(false);
                return RedirectToPage("/MfaEnrol");

            case SignInStatus.Failed:
            default:
                Error = GenericFailure;
                return Page();
        }
    }

    private async Task IssueSessionCookieAsync(Guid userId, Guid sessionId, string email)
    {
        // Drop the half-authenticated cookie the moment the full one is issued, so a stale
        // pending-MFA cookie cannot be reused later.
        await HttpContext.SignOutAsync(KeysteadSchemes.MfaPending).ConfigureAwait(false);

        var identity = new ClaimsIdentity(
            KeysteadClaims.For(userId, sessionId, email),
            CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity)).ConfigureAwait(false);
    }

    private Task IssuePendingCookieAsync(Guid userId)
    {
        // Carries the user id and nothing else, on a scheme no authorization policy accepts.
        var identity = new ClaimsIdentity(
            new List<Claim>
            {
                new(KeysteadClaims.UserId, userId.ToString("D", CultureInfo.InvariantCulture)),
            },
            KeysteadSchemes.MfaPending);

        return HttpContext.SignInAsync(
            KeysteadSchemes.MfaPending,
            new ClaimsPrincipal(identity));
    }

    /// <summary>
    /// Redirects to the requested page only when it is local.
    /// </summary>
    /// <remarks>
    /// An unchecked redirect parameter is an open redirect: an attacker sends a sign-in link
    /// whose next value points at their own host, and the user lands on a convincing copy of
    /// this page having just proved they will type their password into it.
    /// </remarks>
    private IActionResult RedirectToLocalOrHome(string? next) =>
        !string.IsNullOrEmpty(next) && Url.IsLocalUrl(next)
            ? Redirect(next)
            : RedirectToPage("/Index");
}
