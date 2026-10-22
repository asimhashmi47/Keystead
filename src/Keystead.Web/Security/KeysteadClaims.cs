using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Keystead.Application.Authorization;
using Keystead.Domain.Vaults;

namespace Keystead.Web.Security;

/// <summary>
/// The claims Keystead puts in the authentication cookie, and how to read them back.
/// </summary>
/// <remarks>
/// Only identifiers go in the cookie. Role and vault permission are deliberately absent: a
/// claim is a snapshot taken at sign-in, so a role baked into a cookie keeps working after the
/// role is taken away. Authorization is resolved from the database on every request instead,
/// which is the only way revocation takes effect immediately.
/// </remarks>
public static class KeysteadClaims
{
    /// <summary>The user identifier claim.</summary>
    public const string UserId = "keystead:uid";

    /// <summary>The session identifier claim, used to validate and revoke the session.</summary>
    public const string SessionId = "keystead:sid";

    /// <summary>Builds the claims for a newly signed-in user.</summary>
    /// <param name="userId">The account.</param>
    /// <param name="sessionId">The session just created.</param>
    /// <param name="email">The sign-in address, used as the display name.</param>
    /// <returns>The claims to put in the cookie.</returns>
    /// <exception cref="ArgumentException"><paramref name="email"/> is null or empty.</exception>
    public static IReadOnlyList<Claim> For(Guid userId, Guid sessionId, string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        return
        [
            new Claim(UserId, userId.ToString("D", CultureInfo.InvariantCulture)),
            new Claim(SessionId, sessionId.ToString("D", CultureInfo.InvariantCulture)),
            new Claim(ClaimTypes.Name, email),
            new Claim(ClaimTypes.NameIdentifier, userId.ToString("D", CultureInfo.InvariantCulture)),
        ];
    }

    /// <summary>Reads the user identifier from a principal.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>The identifier, or null when absent or malformed.</returns>
    public static Guid? GetUserId(ClaimsPrincipal? principal) =>
        ParseGuid(principal?.FindFirst(UserId)?.Value);

    /// <summary>Reads the session identifier from a principal.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>The identifier, or null when absent or malformed.</returns>
    public static Guid? GetSessionId(ClaimsPrincipal? principal) =>
        ParseGuid(principal?.FindFirst(SessionId)?.Value);

    /// <summary>
    /// Builds the application's principal record from a signed-in user's claims.
    /// </summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>The principal, or null when the cookie does not carry a usable identity.</returns>
    public static Principal? ToPrincipal(ClaimsPrincipal? principal)
    {
        var userId = GetUserId(principal);
        var sessionId = GetSessionId(principal);

        if (userId is null || sessionId is null)
        {
            return null;
        }

        return new Principal(
            SubjectType.User,
            userId.Value,
            principal?.Identity?.Name ?? userId.Value.ToString("D", CultureInfo.InvariantCulture),
            sessionId.Value);
    }

    private static Guid? ParseGuid(string? value) =>
        Guid.TryParse(value, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
}
