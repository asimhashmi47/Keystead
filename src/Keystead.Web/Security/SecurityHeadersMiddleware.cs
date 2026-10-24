using System;
using System.Globalization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Keystead.Web.Security;

/// <summary>
/// Writes the response headers that make up Keystead's browser-side hardening.
/// </summary>
/// <remarks>
/// <para>
/// Every header set here is asserted by a test in <c>Keystead.SecurityTests</c>. A security
/// claim that is not tested is a security claim that quietly stops being true the first time
/// someone reorders the middleware pipeline.
/// </para>
/// <para>
/// The policy starts from <c>default-src 'none'</c> and names each source explicitly. Starting
/// from <c>'self'</c> looks tidier but silently permits whatever source types are added to the
/// CSP specification later; denying everything and opting in is the only version that stays
/// correct as browsers gain features.
/// </para>
/// </remarks>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>Creates the middleware.</summary>
    /// <param name="next">The next stage in the pipeline.</param>
    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;

    /// <summary>Adds the headers and invokes the rest of the pipeline.</summary>
    /// <param name="context">The current request.</param>
    /// <param name="nonce">This request's CSP nonce.</param>
    /// <returns>A task that completes when the pipeline completes.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public Task InvokeAsync(HttpContext context, CspNonce nonce)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(nonce);

        var headers = context.Response.Headers;

        // Built before the response starts, so a handler cannot accidentally emit a body first
        // and lose the headers.
        headers["Content-Security-Policy"] = BuildCsp(nonce.Value);

        headers["X-Content-Type-Options"] = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";
        headers["Cross-Origin-Embedder-Policy"] = "require-corp";
        headers["X-Frame-Options"] = "DENY";

        // Everything the application does not use is switched off rather than left to the
        // browser's default, which varies and tends to loosen over time.
        headers["Permissions-Policy"] = string.Join(
            ", ",
            "accelerometer=()",
            "ambient-light-sensor=()",
            "autoplay=()",
            "battery=()",
            "camera=()",
            "display-capture=()",
            "document-domain=()",
            "encrypted-media=()",
            "fullscreen=()",
            "gamepad=()",
            "geolocation=()",
            "gyroscope=()",
            "hid=()",
            "idle-detection=()",
            "local-fonts=()",
            "magnetometer=()",
            "microphone=()",
            "midi=()",
            "payment=()",
            "picture-in-picture=()",
            "publickey-credentials-get=()",
            "screen-wake-lock=()",
            "serial=()",
            "usb=()",
            "xr-spatial-tracking=()");

        // Nothing Keystead generates is safe to cache. A secret rendered into a page that a
        // shared proxy or a browser's back-forward cache retains is a disclosure, so no-store
        // is the default for every response rather than only for the ones that obviously carry
        // secret material.
        //
        // The exemption is the static asset tree, and it is written this way round on purpose:
        // the rule is "no-store unless the path is one of these", never "no-store if the path
        // looks sensitive". A new page is covered by default; a new asset directory has to be
        // named here, where the decision is visible.
        if (IsVersionedAsset(context.Request.Path))
        {
            // Safe for two reasons. The stylesheet and the scripts are referenced with a
            // content hash in the query, which the layout appends, so a changed file is a
            // changed URL and a year-long lifetime cannot serve a stale one. The two fonts are
            // referenced from inside the stylesheet, which cannot be versioned that way, so
            // their names are the version: replacing a font means a new filename, and the
            // source rule suite fails if the stylesheet names a font file that is not present.
            //
            // None of these files holds secret material, which is the property that actually
            // permits a shared cache to keep them.
            headers["Cache-Control"] = "public, max-age=31536000, immutable";
        }
        else
        {
            headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0";
            headers["Pragma"] = "no-cache";
            headers["Expires"] = "0";
        }

        // Kestrel announces itself by default. Version banners only help someone matching the
        // host against a list of known issues.
        headers.Remove("Server");
        headers.Remove("X-Powered-By");
        headers.Remove("X-AspNet-Version");

        return _next(context);
    }

    /// <summary>
    /// Whether a path is a static asset served under a content-hashed URL.
    /// </summary>
    /// <param name="path">The request path.</param>
    /// <returns>True when the response may be cached.</returns>
    /// <remarks>
    /// A closed list of prefixes, matched case-insensitively because the comparison decides
    /// whether <c>no-store</c> is dropped and the filesystem underneath is not always
    /// case-sensitive. <c>/favicon.ico</c> is named exactly: it is requested without a version
    /// query by browsers that guess at it, and it is one file, not a tree.
    /// </remarks>
    public static bool IsVersionedAsset(PathString path)
    {
        if (!path.HasValue)
        {
            return false;
        }

        return path.StartsWithSegments("/css", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/js", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/fonts", StringComparison.OrdinalIgnoreCase)
            || string.Equals(path.Value, "/favicon.ico", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Builds the Content Security Policy for a request.
    /// </summary>
    /// <param name="nonce">The per-request nonce.</param>
    /// <returns>The policy string.</returns>
    public static string BuildCsp(string nonce)
    {
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        return string.Format(
            CultureInfo.InvariantCulture,
            // 'strict-dynamic' is deliberately absent: it would let a nonced script load
            // further scripts without a nonce, which is convenient for bundlers and exactly
            // the hole this policy is meant to close.
            "default-src 'none'; " +
            "script-src 'self' 'nonce-{0}'; " +
            "style-src 'self' 'nonce-{0}'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "form-action 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'none'; " +
            "object-src 'none'; " +
            "manifest-src 'self'; " +
            "worker-src 'none'; " +
            "upgrade-insecure-requests; " +
            "report-uri /csp-report; " +
            "report-to keystead-csp",
            nonce);
    }
}
