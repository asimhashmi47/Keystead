using System;

namespace Keystead.Domain.Vaults;

/// <summary>
/// One generation of a vault's key-encryption key, stored only in wrapped form.
/// </summary>
/// <remarks>
/// The KEK itself is a 256-bit random value that exists in plaintext only inside a zeroed
/// buffer for the duration of a single wrap or unwrap. What is persisted is the KEK sealed
/// under the master key with AES-256-GCM, bound by AAD to its workspace, vault and version.
/// </remarks>
public sealed class VaultKek
{
    /// <summary>Surrogate key.</summary>
    public required Guid Id { get; init; }

    /// <summary>The vault this key belongs to.</summary>
    public required Guid VaultId { get; init; }

    /// <summary>Monotonic version within the vault, starting at 1.</summary>
    public required int Version { get; init; }

    /// <summary>The KEK sealed under the master key (nonce and tag included in the envelope).</summary>
    public required byte[] WrappedKek { get; set; }

    /// <summary>Which master key generation sealed this KEK.</summary>
    public required int MasterKeyVersion { get; set; }

    /// <summary>When this KEK generation was created.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>When this generation stopped being used for new wraps.</summary>
    public DateTimeOffset? RetiredUtc { get; set; }

    /// <summary>Navigation to the owning vault.</summary>
    public Vault? Vault { get; init; }

    /// <summary>Whether new DEKs should be wrapped with this generation.</summary>
    public bool IsActive => RetiredUtc is null;
}
