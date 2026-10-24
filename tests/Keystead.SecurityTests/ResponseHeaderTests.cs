using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace Keystead.SecurityTests;

/// <summary>
/// Asserts every response header the README and the specification promise.
/// </summary>
/// <remarks>
/// A security claim written in a readme and not asserted anywhere is a claim that quietly
/// stops being true the first time someone reorders the middleware pipeline. These tests are
/// the reason the claims in the README can be read as statements of fact.
/// </remarks>
[Collection(nameof(HostedAppCollection))]
public sealed class ResponseHeaderTests
{
    private readonly KeysteadTestFactory _factory;

    /// <summary>Creates the fixture.</summary>
    /// <param name="factory">The hosted application.</param>
    /// <exception cref="ArgumentNullException"><paramref name="factory"/> is null.</exception>
    public ResponseHeaderTests(KeysteadTestFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        _factory = factory;
    }

    private static IEnumerable<string> Values(
        System.Net.Http.HttpResponseMessage response,
        string name) =>
        response.Headers.TryGetValues(name, out var values)
            ? values
            : response.Content.Headers.TryGetValues(name, out var content)
                ? content
                : [];

    private static string? First(System.Net.Http.HttpResponseMessage response, string name) =>
        Values(response, name).FirstOrDefault();

    /// <summary>
    /// The page the header assertions probe.
    /// </summary>
    /// <remarks>
    /// Not <c>/sign-in</c>. That page is capped at ten requests per five minutes, and this
    /// class issues around forty, so later tests would intermittently see 429 and the suite
    /// would look flaky when the rate limiter was in fact working. <c>/forbidden</c> is
    /// anonymous, Razor-rendered through the same layout and pipeline, and carries only the
    /// global limit.
    /// </remarks>
    private const string HeaderProbePath = "/forbidden";

    [Theory]
    [InlineData("/forbidden")]
    [InlineData("/healthz")]
    [InlineData("/vaults")]
    [InlineData("/readyz")]
    public async Task EveryResponseCarriesTheHardeningHeaders(string path)
    {
        // Checked on an anonymous page, an authenticated one that redirects, and the health
        // endpoint, because a header applied by only part of the pipeline is the usual bug.
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(path);

        Assert.Equal("nosniff", First(response, "X-Content-Type-Options"));
        Assert.Equal("no-referrer", First(response, "Referrer-Policy"));
        Assert.Equal("same-origin", First(response, "Cross-Origin-Opener-Policy"));
        Assert.Equal("same-origin", First(response, "Cross-Origin-Resource-Policy"));
        Assert.Equal("require-corp", First(response, "Cross-Origin-Embedder-Policy"));
        Assert.Equal("DENY", First(response, "X-Frame-Options"));
        Assert.NotNull(First(response, "Permissions-Policy"));
        Assert.NotNull(First(response, "Content-Security-Policy"));
    }

    [Fact]
    public async Task NothingIsCacheable()
    {
        // Every response, not just the ones that obviously carry a secret. A secret rendered
        // into a page that a shared proxy or the back-forward cache retains is a disclosure.
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(HeaderProbePath);

        var cacheControl = First(response, "Cache-Control") ?? string.Empty;

        Assert.Contains("no-store", cacheControl, StringComparison.Ordinal);
        Assert.Contains("no-cache", cacheControl, StringComparison.Ordinal);
        Assert.Equal("no-cache", First(response, "Pragma"));
    }

    [Fact]
    public async Task TheServerDoesNotAnnounceItself()
    {
        // A version banner only helps someone matching the host against a list of known
        // issues.
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(HeaderProbePath);

        Assert.Empty(Values(response, "Server"));
        Assert.Empty(Values(response, "X-Powered-By"));
        Assert.Empty(Values(response, "X-AspNet-Version"));
    }

    [Fact]
    public async Task ThePermissionsPolicyDisablesEveryFeatureTheApplicationDoesNotUse()
    {
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(HeaderProbePath);

        var policy = First(response, "Permissions-Policy") ?? string.Empty;

        foreach (var feature in new[]
        {
            "camera", "microphone", "geolocation", "payment", "usb", "serial",
            "display-capture", "midi", "hid", "idle-detection",
        })
        {
            Assert.Contains($"{feature}=()", policy, StringComparison.Ordinal);
        }
    }

    // -----------------------------------------------------------------------
    // Content Security Policy
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ThePolicyStartsFromDenyingEverything()
    {
        // Starting from 'self' looks tidier and silently permits whatever source types the
        // CSP specification gains later. Denying everything and opting in stays correct.
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(HeaderProbePath);

        var csp = First(response, "Content-Security-Policy") ?? string.Empty;

        Assert.Contains("default-src 'none'", csp, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("frame-ancestors 'none'")]
    [InlineData("base-uri 'none'")]
    [InlineData("object-src 'none'")]
    [InlineData("form-action 'self'")]
    [InlineData("img-src 'self' data:")]
    [InlineData("font-src 'self'")]
    [InlineData("connect-src 'self'")]
    [InlineData("upgrade-insecure-requests")]
    [InlineData("report-uri /csp-report")]
    public async Task ThePolicyContainsEveryPromisedDirective(string directive)
    {
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(HeaderProbePath);

        var csp = First(response, "Content-Security-Policy") ?? string.Empty;

        Assert.Contains(directive, csp, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ThePolicyPermitsNoUnsafeSources()
    {
        // 'unsafe-inline' or 'unsafe-eval' would undo the whole policy. 'strict-dynamic' is
        // also absent on purpose: it lets a nonced script load further scripts without one.
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(HeaderProbePath);

        var csp = First(response, "Content-Security-Policy") ?? string.Empty;

        Assert.DoesNotContain("unsafe-inline", csp, StringComparison.Ordinal);
        Assert.DoesNotContain("unsafe-eval", csp, StringComparison.Ordinal);
        Assert.DoesNotContain("strict-dynamic", csp, StringComparison.Ordinal);
        Assert.DoesNotContain("*", csp, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ScriptAndStyleAreNonced()
    {
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(HeaderProbePath);

        var csp = First(response, "Content-Security-Policy") ?? string.Empty;

        Assert.Matches(@"script-src 'self' 'nonce-[A-Za-z0-9+/=]+'", csp);
        Assert.Matches(@"style-src 'self' 'nonce-[A-Za-z0-9+/=]+'", csp);
    }

    [Fact]
    public async Task EveryRequestGetsADifferentNonce()
    {
        // A predictable or reused nonce is worth nothing: an attacker who can guess it can
        // inject a script tag the policy will happily execute.
        using var client = _factory.CreateApiClient();

        var nonces = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < 25; i++)
        {
            using var response = await client.GetAsync(HeaderProbePath);
            var csp = First(response, "Content-Security-Policy") ?? string.Empty;

            var match = System.Text.RegularExpressions.Regex.Match(
                csp,
                @"'nonce-([A-Za-z0-9+/=]+)'");

            Assert.True(match.Success, "The policy carried no nonce.");
            Assert.True(nonces.Add(match.Groups[1].Value), "A nonce was reused across requests.");
        }

        Assert.Equal(25, nonces.Count);
    }

    [Fact]
    public async Task TheNonceInThePolicyMatchesTheOneInThePage()
    {
        // The header and the markup are produced in different places. If they ever disagree,
        // the policy blocks the application's own scripts and the UI silently stops working.
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(HeaderProbePath);

        var csp = First(response, "Content-Security-Policy") ?? string.Empty;
        var body = await response.Content.ReadAsStringAsync();

        var headerNonce = System.Text.RegularExpressions.Regex
            .Match(csp, @"script-src 'self' 'nonce-([A-Za-z0-9+/=]+)'")
            .Groups[1].Value;

        Assert.False(string.IsNullOrEmpty(headerNonce));

        // The sign-in page renders no script of its own, so the nonce need not appear in the
        // body; where a script is rendered, it must carry exactly this value.
        if (body.Contains("<script", StringComparison.Ordinal))
        {
            Assert.Contains($"nonce=\"{headerNonce}\"", body, StringComparison.Ordinal);
        }
    }

    // -----------------------------------------------------------------------
    // Cookies
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TheAntiforgeryCookieIsHostPrefixedAndLockedDown()
    {
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync("/setup");

        var cookies = Values(response, "Set-Cookie").ToList();

        var csrf = cookies.FirstOrDefault(c =>
            c.StartsWith("__Host-keystead-csrf", StringComparison.Ordinal));

        Assert.NotNull(csrf);

        // The __Host- prefix is the strongest binding a browser offers: it requires Secure,
        // requires Path=/, and forbids a Domain attribute, so a sibling subdomain cannot set
        // or overwrite it.
        Assert.Contains("secure", csrf, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", csrf, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", csrf, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", csrf, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", csrf, StringComparison.OrdinalIgnoreCase);
    }

    // -----------------------------------------------------------------------
    // Deny by default
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("/")]
    [InlineData("/vaults")]
    [InlineData("/audit")]
    [InlineData("/members")]
    [InlineData("/identities")]
    [InlineData("/security")]
    [InlineData("/profile")]
    [InlineData("/search")]
    [InlineData("/step-up")]
    public async Task EveryAuthenticatedPageRefusesAnAnonymousCaller(string path)
    {
        // The authorization fallback policy, which is what makes a handler that forgets to
        // declare a policy fail closed rather than open.
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains(
            "/sign-in",
            response.Headers.Location?.ToString() ?? string.Empty,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/setup")]
    [InlineData("/sign-in")]
    [InlineData("/healthz")]
    [InlineData("/readyz")]
    [InlineData("/forbidden")]
    public async Task ThePagesThatMustBeAnonymousAre(string path)
    {
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(path);

        // 429 counts as reaching the page: it means the rate limiter answered, not that
        // authorization refused. The point of this test is that none of these redirects to
        // sign-in with a return URL, which is what an authorization failure looks like.
        Assert.True(
            response.StatusCode is HttpStatusCode.OK
                or HttpStatusCode.Found
                or HttpStatusCode.TooManyRequests,
            $"{path} returned {(int)response.StatusCode}.");

        if (response.StatusCode is HttpStatusCode.Found)
        {
            // Setup redirects once an installation exists; it must never redirect to sign-in
            // because it was refused by authorization.
            Assert.DoesNotContain(
                "next=",
                response.Headers.Location?.ToString() ?? string.Empty,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task TheMachineApiRefusesAnUnauthenticatedCaller()
    {
        using var client = _factory.CreateApiClient();

        using var response = await client.GetAsync(
            $"/api/v1/vaults/{Guid.NewGuid():D}/secrets");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(
            "Bearer",
            First(response, "WWW-Authenticate") ?? string.Empty,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnApiFailureIsAProblemDocument()
    {
        using var client = _factory.CreateApiClient();

        using var response = await client.GetAsync(
            $"/api/v1/vaults/{Guid.NewGuid():D}/secrets");

        Assert.Equal(
            "application/problem+json",
            response.Content.Headers.ContentType?.MediaType);

        var body = await response.Content.ReadAsStringAsync();

        // Carries a correlation id so an operator can find the audit entry, and nothing about
        // the internals.
        Assert.Contains("\"instance\"", body, StringComparison.Ordinal);
        Assert.DoesNotContain("StackTrace", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Keystead.Infrastructure", body, StringComparison.Ordinal);
    }
}
