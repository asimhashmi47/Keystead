using System.Net;
using Keystead.Web.Security;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Keystead.SecurityTests;

/// <summary>
/// How requests are grouped for rate limiting.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of a measured failure, not a hypothetical one. A load run put a
/// thousand machine reads through eight distinct service identities from one address, and 872
/// of them were refused: the limiter partitioned by address, so the eight shared one budget.
/// Behind a load balancer or a NAT gateway that is every application in the estate sharing one
/// budget, and the symptom — a 429 on a correctly credentialled request — looks like the
/// caller's fault.
/// </para>
/// <para>
/// The property these tests hold is that two callers are two buckets, and that the boundary
/// key is still the one the caller cannot choose.
/// </para>
/// </remarks>
public sealed class RateLimitKeyTests
{
    private static DefaultHttpContext Request(string address, string? bearer = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(address);

        if (bearer is not null)
        {
            context.Request.Headers.Authorization = $"Bearer {bearer}";
        }

        return context;
    }

    [Fact]
    public void TwoServiceIdentitiesFromOneAddress_GetTwoBuckets()
    {
        var first = RateLimitKeys.Caller(Request("203.0.113.9", "token-for-billing"));
        var second = RateLimitKeys.Caller(Request("203.0.113.9", "token-for-search"));

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void OneServiceIdentity_KeepsOneBucketAcrossAddresses()
    {
        // A client that reconnects, or sits behind a pool of outbound addresses, is still one
        // caller and should still spend one budget.
        var first = RateLimitKeys.Caller(Request("203.0.113.9", "token-for-billing"));
        var second = RateLimitKeys.Caller(Request("198.51.100.4", "token-for-billing"));

        Assert.Equal(first, second);
    }

    [Fact]
    public void TheKey_NeverContainsTheToken()
    {
        // The key reaches logs, metrics and diagnostics. The token is a live credential.
        const string Token = "eyJhbGciOiJFUzI1NiJ9.payload.signature";

        var key = RateLimitKeys.Caller(Request("203.0.113.9", Token));

        Assert.DoesNotContain(Token, key, System.StringComparison.Ordinal);
        Assert.DoesNotContain("signature", key, System.StringComparison.Ordinal);
    }

    [Fact]
    public void WithoutACredential_TheKeyIsTheAddress()
    {
        var context = Request("203.0.113.9");

        Assert.Equal(RateLimitKeys.Address(context), RateLimitKeys.Caller(context));
    }

    [Fact]
    public void AnEmptyBearerHeader_FallsBackToTheAddress()
    {
        // "Authorization: Bearer " with nothing after it must not become a bucket of its own,
        // or it would be a free shared budget for anyone who sent it.
        var context = Request("203.0.113.9", bearer: "   ");

        Assert.Equal(RateLimitKeys.Address(context), RateLimitKeys.Caller(context));
    }

    [Fact]
    public void TheAddressKey_IgnoresThePresentedCredential()
    {
        // The outer limiter is the boundary, so its key must not be influenced by anything the
        // caller chose to send.
        var withToken = RateLimitKeys.Address(Request("203.0.113.9", "anything-at-all"));
        var without = RateLimitKeys.Address(Request("203.0.113.9"));

        Assert.Equal(without, withToken);
    }
}
