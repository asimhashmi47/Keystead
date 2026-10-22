namespace Keystead.Domain.Vaults;

/// <summary>
/// The level of access a subject (user or service identity) holds on a single vault.
/// Vault permission is granted explicitly; workspace role alone never implies vault access
/// for a Reader or Contributor.
/// </summary>
public enum VaultPermission
{
    /// <summary>Read secret metadata and reveal secret values.</summary>
    Read = 10,

    /// <summary>Read, plus create new secrets and new versions of existing secrets.</summary>
    Write = 20,
}
