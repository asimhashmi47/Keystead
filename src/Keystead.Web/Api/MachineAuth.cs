using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Application.Tokens;
using Keystead.Domain.Vaults;
using Microsoft.AspNetCore.Http;

namespace Keystead.Web.Api;

/// <summary>
/// Resolves the machine principal behind an API request.
/// </summary>
/// <remarks>
/// The bearer token is read from the <c>Authorization</c> header only. Accepting one from a
/// query string would be convenient for curl and would put a live credential into every
/// access log and browser history it passed through, so it is not accepted.
/// </remarks>
public static class MachineAuth
{
    private const string BearerPrefix = "Bearer ";

    /// <summary>
    /// Validates the request's bearer token.
    /// </summary>
    /// <param name="context">The current request.</param>
    /// <param name="tokens">The token issuer.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The principal, or null when the request is not authenticated.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static async Task<MachinePrincipal?> ResolveAsync(
        HttpContext context,
        ITokenIssuer tokens,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(tokens);

        var header = context.Request.Headers.Authorization.ToString();

        if (string.IsNullOrEmpty(header)
            || !header.StartsWith(BearerPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var token = header[BearerPrefix.Length..].Trim();

        if (token.Length == 0)
        {
            return null;
        }

        var validated = await tokens
            .ValidateAsync(token, context.ToRequestContext(), cancellationToken)
            .ConfigureAwait(false);

        return validated.IsSuccess ? validated.Value : null;
    }

    /// <summary>Converts a machine principal into the application's principal type.</summary>
    /// <param name="machine">The validated machine principal.</param>
    /// <returns>The application principal, with no session, so it can never step up.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="machine"/> is null.</exception>
    public static Principal ToPrincipal(this MachinePrincipal machine)
    {
        ArgumentNullException.ThrowIfNull(machine);

        return new Principal(
            SubjectType.ServiceIdentity,
            machine.ServiceIdentityId,
            machine.Name,
            SessionId: null);
    }

    /// <summary>Builds the audit request context from the current request.</summary>
    /// <param name="context">The current request.</param>
    /// <returns>The context.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public static RequestContext ToRequestContext(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return new RequestContext(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            context.Request.Headers.UserAgent.ToString() is { Length: > 0 } agent ? agent : null,
            System.Diagnostics.Activity.Current?.Id ?? context.TraceIdentifier);
    }
}
