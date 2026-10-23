using System;

namespace Keystead.Application.Cryptography;

/// <summary>
/// Packs a <see cref="SealedBlob"/> into one opaque column value, and unpacks it again.
/// </summary>
/// <remarks>
/// <para>
/// Layout: nonce, then tag, then ciphertext. Both header parts are fixed length, so no length
/// prefix is needed and the format stays unambiguous.
/// </para>
/// <para>
/// One blob rather than three columns, for wrapped keys. Three columns invites a row where the
/// ciphertext was written and the tag was not, and a missing tag turns authenticated encryption
/// into unauthenticated encryption without anything failing loudly. One column cannot be
/// half-written.
/// </para>
/// <para>
/// Secret versions keep their value's nonce and tag in separate columns on purpose: those are
/// indexed and inspected during key rotation, where being able to see the parts matters more
/// than the atomicity does.
/// </para>
/// </remarks>
public static class SealedBlobPacking
{
    /// <summary>The number of leading bytes taken by the nonce and tag.</summary>
    public const int HeaderLength = SealedBlob.NonceLength + SealedBlob.TagLength;

    /// <summary>Packs a sealed blob into a single byte array.</summary>
    /// <param name="blob">The blob to pack.</param>
    /// <returns>The packed bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="blob"/> is null.</exception>
    public static byte[] Pack(SealedBlob blob)
    {
        ArgumentNullException.ThrowIfNull(blob);

        var packed = new byte[HeaderLength + blob.Ciphertext.Length];

        blob.Nonce.CopyTo(packed, 0);
        blob.Tag.CopyTo(packed, SealedBlob.NonceLength);
        blob.Ciphertext.CopyTo(packed, HeaderLength);

        return packed;
    }

    /// <summary>Unpacks bytes written by <see cref="Pack"/>.</summary>
    /// <param name="packed">The packed bytes.</param>
    /// <returns>The recovered blob.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="packed"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// The input is too short to contain a nonce and a tag, which means the row is corrupt or
    /// was not written by Keystead. Reported as a malformed input rather than allowed to
    /// surface later as an authentication failure, so the two causes stay distinguishable to
    /// an operator.
    /// </exception>
    public static SealedBlob Unpack(byte[] packed)
    {
        ArgumentNullException.ThrowIfNull(packed);

        if (packed.Length < HeaderLength)
        {
            throw new ArgumentException(
                $"A packed sealed blob must be at least {HeaderLength} bytes; got {packed.Length}.",
                nameof(packed));
        }

        return new SealedBlob(
            packed[HeaderLength..],
            packed[..SealedBlob.NonceLength],
            packed[SealedBlob.NonceLength..HeaderLength]);
    }
}
