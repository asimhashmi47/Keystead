using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Keystead.Application.Identity;

/// <summary>Enrols a user in TOTP multi-factor authentication.</summary>
public interface IMfaEnrolmentService
{
    /// <summary>
    /// Starts enrolment: generates a seed, stores it sealed, and returns the display data.
    /// </summary>
    /// <remarks>
    /// The sealed seed is persisted immediately, but the enrolment timestamp is left unset, so
    /// <c>MfaEnabled</c> stays false until a code has been proved. This avoids carrying the
    /// plaintext secret between two requests in a cookie or in server-side session state, and
    /// it means an abandoned enrolment leaves the account exactly as it was.
    /// </remarks>
    /// <param name="userId">The account enrolling.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The enrolment, whose plaintext secret is shown exactly once.</returns>
    Task<TotpEnrolment?> BeginAsync(Guid userId, CancellationToken cancellationToken);

    /// <summary>
    /// Completes enrolment by proving a code, and issues the recovery codes.
    /// </summary>
    /// <param name="userId">The account enrolling.</param>
    /// <param name="code">A current code from the authenticator app.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>
    /// The recovery codes to display exactly once, or null when the code was wrong.
    /// </returns>
    Task<IReadOnlyList<string>?> CompleteAsync(
        Guid userId,
        string code,
        RequestContext context,
        CancellationToken cancellationToken);
}
