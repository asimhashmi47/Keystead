using System;
using System.Security.Cryptography;
using Keystead.Application.Cryptography;

namespace Keystead.Infrastructure.Cryptography;

/// <summary>
/// AES-256-GCM, the only cipher Keystead uses for secret material.
/// </summary>
/// <remarks>
/// <para>
/// Nonces come from <see cref="RandomNumberGenerator"/>, never from a counter. A counter is
/// attractive because it makes reuse impossible within one process, but it is wrong here: the
/// same database can be served by several processes, restored from a backup, or replicated, and
/// any of those resets a counter. A repeated nonce under the same key is catastrophic for
/// GCM, so the only safe source is 96 random bits per operation.
/// </para>
/// <para>
/// 96-bit random nonces carry a birthday bound: collision probability stays below 2^-32 up to
/// roughly 2^32 seals under one key. Keystead never approaches that, because a DEK encrypts
/// exactly one secret version, and a KEK wraps one DEK per version rather than encrypting
/// bulk data. The bound is documented in THREATMODEL.md rather than left implicit.
/// </para>
/// </remarks>
public sealed class AesGcmCipher : IAeadCipher
{
    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    public SealedBlob Seal(KeyMaterial key, ReadOnlySpan<byte> plaintext, CryptoContext context)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(context);

        var nonce = RandomNumberGenerator.GetBytes(SealedBlob.NonceLength);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[SealedBlob.TagLength];

        using var aes = new AesGcm(key.Span, SealedBlob.TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, context.Aad);

        return new SealedBlob(ciphertext, nonce, tag);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    public byte[] Open(KeyMaterial key, SealedBlob blob, CryptoContext context)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(blob);
        ArgumentNullException.ThrowIfNull(context);

        var plaintext = new byte[blob.Ciphertext.Length];

        using var aes = new AesGcm(key.Span, SealedBlob.TagLength);

        try
        {
            // Throws AuthenticationTagMismatchException when the ciphertext, nonce, tag, AAD
            // or key is wrong. We deliberately do not catch and translate it: every one of
            // those causes means "this blob is not what it claims to be", and distinguishing
            // them for the caller would hand an attacker an oracle.
            aes.Decrypt(blob.Nonce, blob.Ciphertext, blob.Tag, plaintext, context.Aad);
        }
        catch
        {
            // Never leave a partially written plaintext buffer behind for the GC to hand out.
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }

        return plaintext;
    }
}
