using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Keystead.Web.Pages;

/// <summary>
/// Shown when an authenticated user lacks the permission for something.
/// </summary>
/// <remarks>
/// Deliberately vague. It does not say which permission was missing or whether the resource
/// exists, because either detail helps someone map out what they cannot see.
/// </remarks>
[AllowAnonymous]
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
public sealed class ForbiddenModel : PageModel
{
    /// <summary>Shows the page.</summary>
    public void OnGet()
    {
        // Nothing to load: the page is static by design.
    }
}
