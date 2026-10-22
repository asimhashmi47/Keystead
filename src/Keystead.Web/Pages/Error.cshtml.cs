using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Keystead.Web.Pages;

/// <summary>
/// The safe error page.
/// </summary>
/// <remarks>
/// It shows a correlation id and nothing else. The exception type, message and stack trace stay
/// in the server log where only an operator sees them: an error page that explains which query
/// failed is a free map of the application's internals.
/// </remarks>
[AllowAnonymous]
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
[IgnoreAntiforgeryToken]
public sealed class ErrorModel : PageModel
{
    /// <summary>
    /// The correlation id for this request, which an operator can match against the log.
    /// </summary>
    public string? CorrelationId { get; private set; }

    /// <summary>Loads the error page.</summary>
    public void OnGet() =>
        CorrelationId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
}
