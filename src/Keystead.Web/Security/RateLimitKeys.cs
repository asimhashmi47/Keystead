using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace Keystead.Web.Security;

/// <summary>
/// Builds the partition keys the rate limiter counts against.
/// </summary>
/// <remarks>
/// <para>
/// Two keys, with two different jobs, and the difference matters.
/// </para>
/// <para>
/// <see cref="Caller"/> answers "who is asking", and it exists for fairness. It is what the
/// per-feature policies partition by, so that one busy caller spends its own budget rather than
/// everybody's. Behind a load balancer, a NAT gateway or a corporate network every caller
/// arrives from one address, so an address-only key means one chatty deployment starves every
/// other application in the estate — and the symptom, a 429 on a correctly credentialled
/// request, looks like the caller's fault.
/// </para>
/// <para>
/// <see cref="Address"/> answers "where is it coming from", and it exists as the boundary. It
/// is what the outer global limiter partitions by, and it is not forgeable by the caller: the
/// address comes from the connection, or from a forwarded header the operator explicitly
/// trusted.
/// </para>
/// <para>
/// The reason there are two is that <see cref="Caller"/> deliberately reads a credential the
/// limiter has not verified yet. The machine API resolves its bearer token inside the endpoint,
/// after the limiter has run, so at partition time the only thing available is the raw header.
/// A fabricated token therefore gets its own fairness bucket — which is why the outer
/// address-keyed limiter is there, and why <see cref="Caller"/> must never be treated as an
/// authentication decision. It groups requests; it does not admit them. A fabricated token
/// still fails at the endpoint with a 401 before it reaches a vault.
/// </para>
/// <para>
/// The token is never used as the key itself. It is a live credential, and a key reaches logs,
/// metrics and diagnostics; a truncated SHA-256 of it is stable for the token's lifetime and
/// discloses nothing.
/// </para>
/// </remarks>
public static class RateLimitKeys
{
    private const string BearerPrefix = "Bearer ";

    /// <summary>
    /// The per-caller key: the authenticated principal, else the bearer token presented, else
    /// the source address.
    /// </summary>
    /// <param name="context">The request.</param>
    /// <returns>The partition key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public static string Caller(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.User.Identity?.IsAuthenticated == true)
        {
            return $"user:{context.User.Identity.Name}";
        }

        var presented = BearerToken(context);

        return presented is null
            ? Address(context)
            : $"token:{Fingerprint(presented)}";
    }

    /// <summary>The per-address key.</summary>
    /// <param name="context">The request.</param>
    /// <returns>The partition key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public static string Address(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return $"ip:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
    }

    /// <summary>
    /// Reads the bearer token from the <c>Authorization</c> header, or null when there is none.
    /// </summary>
    /// <param name="context">The request.</param>
    /// <returns>The token, or null.</returns>
    private static string? BearerToken(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(header)
            || !header.StartsWith(BearerPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var token = header[BearerPrefix.Length..].Trim();

        return token.Length == 0 ? null : token;
    }

    /// <summary>
    /// A short, stable, non-reversible label for a token.
    /// </summary>
    /// <param name="token">The presented token.</param>
    /// <returns>Sixteen hex characters.</returns>
    /// <remarks>
    /// Sixty-four bits of a SHA-256. This is a grouping label, not a security claim: a
    /// collision would put two callers in one fairness bucket, which is the behaviour an
    /// address key has for every caller anyway.
    /// </remarks>
    private static string Fingerprint(string token)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(token));

        return BinaryPrimitives.ReadUInt64BigEndian(digest).ToString("x16", CultureInfo.InvariantCulture);
    }
}
