using System;

namespace Keystead.Application.Cryptography;

/// <summary>
/// The output of one AES-256-GCM seal: ciphertext, the nonce it was sealed with, and the
/// authentication tag.
/// </summary>
/// <remarks>
/// All three parts are stored. The nonce is not a secret and is never reused; the tag is what
/// makes tampering detectable. Keeping them together in one type means a caller cannot
/// accidentally persist a ciphertext without the tag that authenticates it.
/// </remarks>
public sealed class SealedBlob
{
    /// <summary>The AES-GCM nonce length used throughout Keystead, in bytes.</summary>
    public const int NonceLength = 12;

    /// <summary>The AES-GCM authentication tag length used throughout Keystead, in bytes.</summary>
    public const int TagLength = 16;

    /// <summary>Creates a sealed blob from its three parts.</summary>
    /// <param name="ciphertext">The encrypted bytes.</param>
    /// <param name="nonce">The 12-byte nonce.</param>
    /// <param name="tag">The 16-byte authentication tag.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    /// <exception cref="ArgumentException">The nonce or tag is the wrong length.</exception>
    public SealedBlob(byte[] ciphertext, byte[] nonce, byte[] tag)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(nonce);
        ArgumentNullException.ThrowIfNull(tag);

        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException(
                $"An AES-GCM nonce must be {NonceLength} bytes.",
                nameof(nonce));
        }

        if (tag.Length != TagLength)
        {
            throw new ArgumentException(
                $"An AES-GCM tag must be {TagLength} bytes.",
                nameof(tag));
        }

        Ciphertext = ciphertext;
        Nonce = nonce;
        Tag = tag;
    }

    /// <summary>The encrypted bytes.</summary>
    public byte[] Ciphertext { get; }

    /// <summary>The nonce the ciphertext was sealed with.</summary>
    public byte[] Nonce { get; }

    /// <summary>The authentication tag over the ciphertext and its AAD.</summary>
    public byte[] Tag { get; }
}
