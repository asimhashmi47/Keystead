namespace Keystead.Application.Cryptography;

/// <summary>
/// What a key is being used to protect. The purpose is mixed into the AAD so that a blob
/// sealed for one job cannot be presented as a blob for another.
/// </summary>
/// <remarks>
/// Without this, a wrapped DEK and a sealed secret value are both "AES-GCM output under a key
/// in this vault". Separating them by purpose means an attacker who can write to the database
/// cannot move a wrapped-DEK blob into the ciphertext column (or the reverse) and have it
/// authenticate.
/// </remarks>
public enum CryptoPurpose
{
    /// <summary>A vault key-encryption key sealed under the master key.</summary>
    VaultKekWrap = 1,

    /// <summary>A per-version data-encryption key sealed under a vault KEK.</summary>
    DataKeyWrap = 2,

    /// <summary>A secret value sealed under its own data-encryption key.</summary>
    SecretValue = 3,

    /// <summary>A user TOTP shared secret sealed under the master key.</summary>
    TotpSeed = 4,

    /// <summary>A JWT signing key sealed under the master key.</summary>
    SigningKeyWrap = 5,
}
