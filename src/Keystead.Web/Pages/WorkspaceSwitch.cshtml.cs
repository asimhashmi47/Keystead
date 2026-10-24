using System;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Workspaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Pages;

/// <summary>
/// Switches which workspace the person is acting in.
/// </summary>
/// <remarks>
/// Writes a cookie and redirects. The cookie is only a hint: the resolver looks the value up
/// inside the user's own memberships, so a value edited by hand simply does not match and
/// their default workspace is used instead.
/// </remarks>
public sealed class WorkspaceSwitchModel : KeysteadPageModel
{
    private readonly ICurrentWorkspace _workspaces;

    /// <summary>Creates the page model.</summary>
    /// <param name="workspaces">Resolves and lists workspaces.</param>
    /// <exception cref="ArgumentNullException"><paramref name="workspaces"/> is null.</exception>
    public WorkspaceSwitchModel(ICurrentWorkspace workspaces)
    {
        ArgumentNullException.ThrowIfNull(workspaces);
        _workspaces = workspaces;
    }

    /// <summary>Selects a workspace.</summary>
    /// <param name="workspaceId">The workspace to switch to.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect to the dashboard.</returns>
    public async Task<IActionResult> OnPostAsync(
        Guid workspaceId,
        CancellationToken cancellationToken)
    {
        if (CurrentUserId is not { } userId)
        {
            return RedirectToPage("/SignIn");
        }

        var memberships = await _workspaces
            .ListForUserAsync(userId, cancellationToken)
            .ConfigureAwait(false);

        // Checked here as well as in the resolver. Writing a cookie for a workspace the person
        // does not belong to would achieve nothing, but it would also be a confusing thing to
        // leave in their browser.
        if (memberships.Any(m => m.WorkspaceId == workspaceId))
        {
            Response.Cookies.Append(
                WorkspaceCookie,
                workspaceId.ToString("D", CultureInfo.InvariantCulture),
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Path = "/",
                    IsEssential = true,
                });
        }

        return RedirectToPage("/Index");
    }
}
