using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Domain.Common;

namespace Keystead.Application.Vaults;

/// <summary>
/// Vault use cases.
/// </summary>
/// <remarks>
/// Every method takes the principal and the workspace, and every method authorizes and audits
/// before returning. There is no unchecked overload for internal callers, because that is how
/// an unauthorized path eventually gets reached from a handler.
/// </remarks>
public interface IVaultService
{
    /// <summary>Lists the vaults the principal can reach in a workspace.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="includeDeleted">Whether to include soft-deleted vaults.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Only the vaults this principal may see.</returns>
    Task<Result<IReadOnlyList<VaultSummary>>> ListAsync(
        Principal principal,
        Guid workspaceId,
        bool includeDeleted,
        CancellationToken cancellationToken);

    /// <summary>Finds one vault by slug.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="slug">The vault slug.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>
    /// The vault, or a not-found error. A vault in another workspace produces the same error as
    /// one that does not exist.
    /// </returns>
    Task<Result<VaultSummary>> GetBySlugAsync(
        Principal principal,
        Guid workspaceId,
        string slug,
        CancellationToken cancellationToken);

    /// <summary>Creates a vault and its first key-encryption key.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="request">The vault details.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The new vault.</returns>
    Task<Result<VaultSummary>> CreateAsync(
        Principal principal,
        Guid workspaceId,
        CreateVaultRequest request,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Soft deletes a vault, leaving it recoverable.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> SoftDeleteAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Restores a soft-deleted vault.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> RecoverAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Permanently destroys a soft-deleted vault and everything in it.
    /// </summary>
    /// <remarks>
    /// Refused unless the vault is soft deleted, its recovery window has elapsed, and purge
    /// protection is off. Irreversible, so it is Owner-only and step-up protected at the edge.
    /// </remarks>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> PurgeAsync(
        Principal principal,
        Guid workspaceId,
        Guid vaultId,
        RequestContext context,
        CancellationToken cancellationToken);
}
