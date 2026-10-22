using System.Threading;
using System.Threading.Tasks;

namespace Keystead.Application.Identity;

/// <summary>Handles first-run initialisation of a fresh installation.</summary>
public interface IInstallationService
{
    /// <summary>Whether the installation already has a workspace and an owner.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns><see langword="true"/> when setup has already been completed.</returns>
    Task<bool> IsInitialisedAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Creates the first workspace and its owner.
    /// </summary>
    /// <remarks>
    /// Refuses if the installation is already initialised. Without that check the setup page
    /// would be a permanent unauthenticated route to creating an Owner account, which is the
    /// worst possible hole in a product like this.
    /// </remarks>
    /// <param name="request">The details collected by the wizard.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The outcome.</returns>
    Task<InitialisationResult> InitialiseAsync(
        InitialisationRequest request,
        RequestContext context,
        CancellationToken cancellationToken);
}
