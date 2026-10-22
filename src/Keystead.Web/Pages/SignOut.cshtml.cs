using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Keystead.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Keystead.Web.Pages;

/// <summary>
/// Signing out.
/// </summary>
/// <remarks>
/// POST only for the actual sign-out, with an antiforgery token. A GET that ended the session
/// would let any page on the internet sign a user out with an image tag, which is a nuisance
/// rather than a breach but is trivially avoidable.
/// </remarks>
[AllowAnonymous]
public sealed class SignOutModel : KeysteadPageModel
{
    private readonly ISignInService _signIn;

    /// <summary>Creates the page model.</summary>
    /// <param name="signIn">The sign-in service.</param>
    /// <exception cref="ArgumentNullException"><paramref name="signIn"/> is null.</exception>
    public SignOutModel(ISignInService signIn)
    {
        ArgumentNullException.ThrowIfNull(signIn);
        _signIn = signIn;
    }

    /// <summary>Shows the confirmation form.</summary>
    /// <returns>The page.</returns>
    public PageResult OnGet() => Page();

    /// <summary>Revokes the session and clears the cookies.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect to the sign-in page.</returns>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (CurrentUserId is { } userId && CurrentSessionId is { } sessionId)
        {
            // Revoke server-side first. Clearing the cookie alone would leave a session row
            // that still validates if the cookie were replayed from somewhere else.
            await _signIn
                .SignOutAsync(userId, sessionId, RequestContext, cancellationToken)
                .ConfigureAwait(false);
        }

        await HttpContext
            .SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme)
            .ConfigureAwait(false);

        await HttpContext.SignOutAsync(KeysteadSchemes.MfaPending).ConfigureAwait(false);

        return RedirectToPage("/SignIn");
    }
}
