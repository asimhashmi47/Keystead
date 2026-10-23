using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Keystead.Domain.Common;

namespace Keystead.Application.Tokens;

/// <summary>Issues and validates short-lived machine access tokens.</summary>
public interface ITokenIssuer
{
    /// <summary>
    /// Exchanges client credentials for a token.
    /// </summary>
    /// <remarks>
    /// Every failure returns the same error, for the same reason sign-in does: distinguishing
    /// an unknown client id from a wrong secret turns this endpoint into a way to enumerate
    /// which identities exist.
    /// </remarks>
    /// <param name="clientId">The public client identifier.</param>
    /// <param name="clientSecret">The client secret.</param>
    /// <param name="context">Where the request came from, for the IP allowlist and audit.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The token, or a single generic failure.</returns>
    Task<Result<MachineToken>> IssueAsync(
        string clientId,
        string clientSecret,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Validates a bearer token and resolves the identity behind it.
    /// </summary>
    /// <param name="token">The bearer token from the request.</param>
    /// <param name="context">Where the request came from, for the IP allowlist.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The principal, or a failure.</returns>
    Task<Result<MachinePrincipal>> ValidateAsync(
        string token,
        RequestContext context,
        CancellationToken cancellationToken);
}
