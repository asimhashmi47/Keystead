using System;

namespace Keystead.Application.Cryptography;

/// <summary>
/// Authenticated encryption with associated data. The single cryptographic primitive every
/// other part of Keystead builds on.
/// </summary>
/// <remarks>
/// Deliberately narrow: AES-256-GCM, a fresh random nonce per seal, and a mandatory context.
/// There is no overload that omits the context, because an unbound ciphertext is the bug this
/// interface exists to prevent.
/// </remarks>
public interface IAeadCipher
{
    /// <summary>Seals plaintext under a key, bound to a context.</summary>
    /// <param name="key">The 256-bit key.</param>
    /// <param name="plaintext">The bytes to protect.</param>
    /// <param name="context">The context the ciphertext is bound to.</param>
    /// <returns>The ciphertext with its nonce and authentication tag.</returns>
    SealedBlob Seal(KeyMaterial key, ReadOnlySpan<byte> plaintext, CryptoContext context);

    /// <summary>Opens a sealed blob, verifying its context.</summary>
    /// <param name="key">The 256-bit key.</param>
    /// <param name="blob">The ciphertext, nonce and tag.</param>
    /// <param name="context">The context the ciphertext must have been sealed for.</param>
    /// <returns>The recovered plaintext.</returns>
    /// <exception cref="System.Security.Cryptography.AuthenticationTagMismatchException">
    /// The ciphertext, nonce, tag or context does not match, or the key is wrong. The caller
    /// cannot tell which, by design.
    /// </exception>
    byte[] Open(KeyMaterial key, SealedBlob blob, CryptoContext context);
}
