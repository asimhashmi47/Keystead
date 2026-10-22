using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Keystead.Web.Pages;

/// <summary>
/// The workspace dashboard.
/// </summary>
/// <remarks>
/// The counts are placeholders until the vault and secret use cases land in M4. They are
/// typed and surfaced now so the shell, the layout and the design system can be exercised
/// against a real page rather than a blank one.
/// </remarks>
public sealed class IndexModel : PageModel
{
    /// <summary>How many secrets this workspace holds.</summary>
    public int SecretCount { get; private set; }

    /// <summary>How many vaults this workspace holds.</summary>
    public int VaultCount { get; private set; }

    /// <summary>How many secrets expire within 30 days.</summary>
    public int ExpiringSoonCount { get; private set; }

    /// <summary>How many secret values were read today.</summary>
    public int ReadsToday { get; private set; }

    /// <summary>How many sign-in attempts failed in the last 24 hours.</summary>
    public int FailedSignInsToday { get; private set; }

    /// <summary>Loads the dashboard.</summary>
    public void OnGet()
    {
        // Intentionally empty until the query handlers exist. Left as a real handler rather
        // than removed so the route, the layout and the authorization policy are all live.
    }
}
