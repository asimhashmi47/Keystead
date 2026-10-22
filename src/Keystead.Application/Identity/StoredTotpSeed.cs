namespace Keystead.Application.Identity;

/// <summary>
/// A user's TOTP shared secret as it is stored: sealed under the master key, never plaintext.
/// </summary>
/// <param name="Ciphertext">The sealed seed.</param>
/// <param name="Nonce">The AES-GCM nonce.</param>
/// <param name="Tag">The AES-GCM authentication tag.</param>
/// <param name="MasterKeyVersion">Which master key generation sealed it.</param>
public sealed record StoredTotpSeed(
    byte[] Ciphertext,
    byte[] Nonce,
    byte[] Tag,
    int MasterKeyVersion);
