using System;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Keystead.Web.Security;

/// <summary>
/// Re-checks the server-side session on every authenticated request.
/// </summary>
/// <remarks>
/// <para>
/// Without this, the cookie alone would be the authority, and a cookie is a bearer token the
/// server cannot take back. "Sign out everywhere" would mean "stop being signed in once the
/// cookie expires", which is not what it says and not what someone reaching for it after a
/// laptop theft needs.
/// </para>
/// <para>
/// The cost is one indexed lookup per request. That is the price of being able to revoke a
/// session, and it is the right trade for an application whose whole job is holding secrets.
/// </para>
/// </remarks>
public static class SessionCookieValidator
{
    /// <summary>
    /// Validates the principal carried by the cookie, rejecting it when the session has been
    /// revoked or has timed out.
    /// </summary>
    /// <param name="context">The cookie validation context.</param>
    /// <returns>A task that completes when validation finishes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var userId = KeysteadClaims.GetUserId(context.Principal);
        var sessionId = KeysteadClaims.GetSessionId(context.Principal);

        if (userId is null || sessionId is null)
        {
            // A cookie without the claims we issue is not one of ours, or has been tampered
            // with. Data protection would normally have caught that, so this is belt and
            // braces rather than the primary check.
            context.RejectPrincipal();
            return;
        }

        var sessions = context.HttpContext.RequestServices
            .GetRequiredService<ISignInService>();

        var stillValid = await sessions
            .TouchSessionAsync(userId.Value, sessionId.Value, context.HttpContext.RequestAborted)
            .ConfigureAwait(false);

        if (!stillValid)
        {
            context.RejectPrincipal();

            await context.HttpContext
                .SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme)
                .ConfigureAwait(false);
        }
    }
}
