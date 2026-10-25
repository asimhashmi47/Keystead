using System;

namespace Keystead.Web.Tables;

/// <summary>
/// Turns a user agent string into the few words someone can actually use.
/// </summary>
/// <remarks>
/// <para>
/// The security centre asks one question: do you recognise these sessions? A row reading
/// <c>Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
/// Chrome/131.0.0.0 Safari/537.36</c> wraps across two lines and does not answer it. "Chrome on
/// Windows" does.
/// </para>
/// <para>
/// This is deliberately crude, and it is allowed to be. User agent strings are a thicket of
/// historical lies — every browser claims to be Mozilla, Edge claims to be Chrome, Chrome
/// claims to be Safari — so the order of the checks matters more than the checks themselves,
/// and the specific ones have to come before the ones they impersonate. It is also only ever
/// used as a label: nothing is authorized, refused or counted on the strength of it, and the
/// exact string is kept and exported beside the summary for anyone who needs the truth.
/// </para>
/// </remarks>
public static class DeviceSummary
{
    /// <summary>Shown when the agent is missing or unrecognisable.</summary>
    public const string Unknown = "Unknown device";

    /// <summary>Describes a user agent in a few words.</summary>
    /// <param name="userAgent">The raw header value.</param>
    /// <returns>Something like "Chrome on Windows", never null or empty.</returns>
    public static string Describe(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return Unknown;
        }

        var browser = Browser(userAgent);
        var platform = Platform(userAgent);

        return (browser, platform) switch
        {
            (null, null) => Unknown,
            (null, { } os) => os,
            ({ } name, null) => name,
            var (name, os) => $"{name} on {os}",
        };
    }

    private static string? Browser(string agent)
    {
        // Order matters, and every line of it is load-bearing: Edge and Opera both carry
        // "Chrome", Chrome carries "Safari", and most things carry "Mozilla".
        if (Has(agent, "Edg/") || Has(agent, "Edge/"))
        {
            return "Edge";
        }

        if (Has(agent, "OPR/") || Has(agent, "Opera"))
        {
            return "Opera";
        }

        if (Has(agent, "Chrome/") || Has(agent, "CriOS/"))
        {
            return "Chrome";
        }

        if (Has(agent, "Firefox/") || Has(agent, "FxiOS/"))
        {
            return "Firefox";
        }

        if (Has(agent, "Safari/"))
        {
            return "Safari";
        }

        // Not a browser at all, which is worth saying plainly: a session created by a script
        // is the kind of thing someone scanning this page should notice.
        if (Has(agent, "curl/"))
        {
            return "curl";
        }

        return Has(agent, "python") || Has(agent, "httpx") || Has(agent, "requests")
            ? "A script"
            : null;
    }

    private static string? Platform(string agent)
    {
        if (Has(agent, "Windows"))
        {
            return "Windows";
        }

        // iPhone and iPad before Mac: an iOS agent also says "like Mac OS X".
        if (Has(agent, "iPhone"))
        {
            return "iPhone";
        }

        if (Has(agent, "iPad"))
        {
            return "iPad";
        }

        // Android before Linux, for the same reason.
        if (Has(agent, "Android"))
        {
            return "Android";
        }

        if (Has(agent, "Mac OS X") || Has(agent, "Macintosh"))
        {
            return "macOS";
        }

        return Has(agent, "Linux") || Has(agent, "X11") ? "Linux" : null;
    }

    private static bool Has(string agent, string token) =>
        agent.Contains(token, StringComparison.OrdinalIgnoreCase);
}
