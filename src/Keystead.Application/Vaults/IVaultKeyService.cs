using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Domain.Vaults;

namespace Keystead.Application.Vaults;

/// <summary>Manages the middle tier of the key hierarchy: per-vault key-encryption keys.</summary>
public interface IVaultKeyService
{
    /// <summary>
    /// Creates the first key-encryption key for a new vault, already wrapped under the active
    /// master key.
    /// </summary>
    /// <param name="workspaceId">The owning workspace, bound into the wrap as AAD.</param>
    /// <param name="vaultId">The new vault, bound into the wrap as AAD.</param>
    /// <returns>The entity to persist alongside the vault.</returns>
    VaultKek CreateInitialKek(Guid workspaceId, Guid vaultId);

    /// <summary>Borrows the vault's current key-encryption key.</summary>
    /// <param name="workspaceId">The owning workspace.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A lease the caller must dispose.</returns>
    Task<VaultKeyLease> LeaseActiveAsync(
        Guid workspaceId,
        Guid vaultId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Borrows a specific key-encryption key generation, needed to read versions written
    /// before a rotation.
    /// </summary>
    /// <param name="workspaceId">The owning workspace.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="version">The generation to borrow.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A lease the caller must dispose.</returns>
    Task<VaultKeyLease> LeaseAsync(
        Guid workspaceId,
        Guid vaultId,
        int version,
        CancellationToken cancellationToken);
}
