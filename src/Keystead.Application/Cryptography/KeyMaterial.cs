using System;
using System.Security.Cryptography;

namespace Keystead.Application.Cryptography;

/// <summary>
/// A 256-bit symmetric key held in memory for as short a time as possible.
/// </summary>
/// <remarks>
/// <para>
/// Disposing this type zeroes the key bytes. That is the whole point of it: a
/// <c>byte[]</c> key dropped on the floor stays in managed memory until the garbage collector
/// happens to reuse the page, and may be copied around by compaction in the meantime. A key in
/// a <c>using</c> block has a defined end of life.
/// </para>
/// <para>
/// This is mitigation, not a guarantee. The CLR may still have copied the array during a
/// compacting collection, and nothing here defends against a process memory dump taken while
/// the key is live. It bounds the window; it does not remove it. That limit is recorded in
/// THREATMODEL.md rather than hidden.
/// </para>
/// </remarks>
public sealed class KeyMaterial : IDisposable
{
    /// <summary>The key length used for every symmetric key in Keystead, in bytes.</summary>
    public const int KeyLength = 32;

    private readonly byte[] _key;
    private bool _disposed;

    private KeyMaterial(byte[] key) => _key = key;

    /// <summary>
    /// Takes ownership of an existing 32-byte key array. The caller must not use the array
    /// afterwards: it will be zeroed when this instance is disposed.
    /// </summary>
    /// <param name="key">The key bytes, which become owned by the returned instance.</param>
    /// <returns>A key handle that zeroes the array on disposal.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not 32 bytes.</exception>
    public static KeyMaterial Adopt(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeyLength)
        {
            throw new ArgumentException(
                $"A Keystead key must be exactly {KeyLength} bytes (256 bits); got {key.Length}.",
                nameof(key));
        }

        return new KeyMaterial(key);
    }

    /// <summary>Copies the supplied bytes into a new key handle.</summary>
    /// <param name="key">The key bytes to copy.</param>
    /// <returns>A key handle holding its own copy.</returns>
    /// <exception cref="ArgumentException"><paramref name="key"/> is not 32 bytes.</exception>
    public static KeyMaterial CopyFrom(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException(
                $"A Keystead key must be exactly {KeyLength} bytes (256 bits); got {key.Length}.",
                nameof(key));
        }

        var copy = new byte[KeyLength];
        key.CopyTo(copy);
        return new KeyMaterial(copy);
    }

    /// <summary>Generates a fresh key from the cryptographic random number generator.</summary>
    /// <returns>A new random 256-bit key.</returns>
    public static KeyMaterial CreateRandom() =>
        new(RandomNumberGenerator.GetBytes(KeyLength));

    /// <summary>The key bytes.</summary>
    /// <exception cref="ObjectDisposedException">The key has been disposed and zeroed.</exception>
    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _key;
        }
    }

    /// <summary>Zeroes the key bytes. Safe to call more than once.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_key);
        _disposed = true;
    }
}
