using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;

namespace Keystead.Application.Authorization;

/// <summary>
/// Decides whether a principal may do something. The single entry point for every
/// authorization question in the application.
/// </summary>
/// <remarks>
/// Every method takes the workspace explicitly. That is not redundant with the resource id:
/// scoping by workspace and checking authorization are two separate obligations
/// (CLAUDE.md rule 8), and passing the workspace in means a caller cannot accidentally
/// authorize against a resource from a different tenant.
/// </remarks>
public interface IAccessPolicy
{
    /// <summary>Checks a workspace-level capability.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace the action targets.</param>
    /// <param name="capability">What is being attempted.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The decision.</returns>
    Task<AccessDecision> AuthorizeWorkspaceAsync(
        Principal principal,
        Guid workspaceId,
        WorkspaceCapability capability,
        CancellationToken cancellationToken);

    /// <summary>Checks access to a single vault.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace the vault must belong to.</param>
    /// <param name="vaultId">The vault being reached.</param>
    /// <param name="required">The permission needed.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The decision.</returns>
    Task<AccessDecision> AuthorizeVaultAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        VaultPermission required,
        CancellationToken cancellationToken);

    /// <summary>
    /// Checks that a user's session carries a recent enough step-up re-authentication for a
    /// high-privilege action.
    /// </summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The decision, which may ask for a step-up.</returns>
    Task<AccessDecision> RequireFreshStepUpAsync(
        Principal principal,
        CancellationToken cancellationToken);
}
