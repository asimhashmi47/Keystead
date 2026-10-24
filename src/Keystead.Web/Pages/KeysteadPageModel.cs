using System;
using System.Diagnostics;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Web.Security;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Keystead.Web.Pages;

/// <summary>
/// Shared base for Keystead page models.
/// </summary>
/// <remarks>
/// Exists only to stop every page re-deriving the request context and the principal, which is
/// the sort of duplication where one page eventually forgets to pass the real client address
/// and quietly audits every action as coming from the proxy.
/// </remarks>
public abstract class KeysteadPageModel : PageModel
{
    /// <summary>
    /// Where this request came from, for audit entries and session records.
    /// </summary>
    /// <remarks>
    /// The address is whatever the forwarded-headers middleware resolved. That middleware
    /// trusts only the configured proxies, so this is not a client-controlled value unless an
    /// operator has widened the proxy list incorrectly.
    /// </remarks>
    protected RequestContext RequestContext => new(
        HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        Request.Headers.UserAgent.ToString() is { Length: > 0 } agent ? agent : null,
        Activity.Current?.Id ?? HttpContext.TraceIdentifier);

    /// <summary>The signed-in principal, or null when this request is not authenticated.</summary>
    protected Principal? CurrentPrincipal => KeysteadClaims.ToPrincipal(User);

    /// <summary>The signed-in user's identifier.</summary>
    protected Guid? CurrentUserId => KeysteadClaims.GetUserId(User);

    /// <summary>The current session's identifier.</summary>
    protected Guid? CurrentSessionId => KeysteadClaims.GetSessionId(User);

    /// <summary>The name of the cookie holding the chosen workspace.</summary>
    internal const string WorkspaceCookie = "__Host-keystead-ws";

    /// <summary>
    /// The workspace the person has selected, if any.
    /// </summary>
    /// <remarks>
    /// Only a hint. <c>ICurrentWorkspace.ResolveAsync</c> looks it up inside the user's own
    /// memberships and falls back to their first workspace if it does not match, so a value
    /// edited in the cookie cannot select a tenant they do not belong to. That is why this can
    /// safely be a plain cookie rather than something signed.
    /// </remarks>
    protected Guid? RequestedWorkspaceId =>
        Request.Cookies.TryGetValue(WorkspaceCookie, out var value)
            && Guid.TryParse(value, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
                ? parsed
                : null;
}
