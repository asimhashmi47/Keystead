using System;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace Keystead.SecurityTests;

/// <summary>
/// What the sign-in rate limiter counts, and what it must not count.
/// </summary>
/// <remarks>
/// <para>
/// A rate limit is a security control, and like any control it can be aimed at the wrong
/// thing. <c>[EnableRateLimiting]</c> on a Razor page covers every handler on that page, so
/// the sign-in policy originally counted the <c>GET</c> that renders the form as well as the
/// <c>POST</c> that submits it. Ten page views in five minutes — a few reloads, a browser
/// prefetch, a password manager opening the page — spent the whole budget, and the sign-in
/// that followed was refused with a 429.
/// </para>
/// <para>
/// That is a denial of service against the user rather than the attacker, and it is worth a
/// test of its own because it looks like the control working. The guessing that the limit
/// exists to bound happens on the <c>POST</c>, so that is what it counts.
/// </para>
/// </remarks>
[Collection(nameof(HostedAppCollection))]
public sealed class RateLimitTests
{
    private readonly KeysteadTestFactory _factory;

    /// <summary>Creates the fixture.</summary>
    /// <param name="factory">The hosted application.</param>
    /// <exception cref="ArgumentNullException"><paramref name="factory"/> is null.</exception>
    public RateLimitTests(KeysteadTestFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        _factory = factory;
    }

    [Fact]
    public async Task ViewingTheSignInPageRepeatedly_IsNeverRefused()
    {
        using var client = _factory.CreateApiClient();

        // Comfortably past the ten-attempt budget. Every one of these is a page view.
        for (var attempt = 1; attempt <= 25; attempt++)
        {
            using var response = await client.GetAsync(new Uri("/sign-in", UriKind.Relative));

            Assert.True(
                response.StatusCode != HttpStatusCode.TooManyRequests,
                $"View {attempt} of the sign-in page was rate limited. Reading a form is not an attempt at anything, and refusing it locks the user out of signing in.");
        }
    }

    [Fact]
    public async Task ViewingTheRecoveryAndSetupPages_IsNeverRefused()
    {
        using var client = _factory.CreateApiClient();

        foreach (var path in new[] { "/sign-in/recovery", "/setup" })
        {
            for (var attempt = 1; attempt <= 15; attempt++)
            {
                using var response = await client.GetAsync(new Uri(path, UriKind.Relative));

                Assert.True(
                    response.StatusCode != HttpStatusCode.TooManyRequests,
                    $"View {attempt} of {path} was rate limited.");
            }
        }
    }
}
