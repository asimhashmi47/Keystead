using System;
using Keystead.Application.Cryptography;

namespace Keystead.Application.Vaults;

/// <summary>
/// A borrowed vault key-encryption key, unwrapped for the duration of one operation.
/// </summary>
/// <remarks>
/// A lease rather than a cached key. Disposing it zeroes the unwrapped KEK, so the plaintext
/// key exists only inside the <c>using</c> block that needs it. Holding unwrapped KEKs in a
/// cache would make every vault readable from a process memory dump for as long as the
/// process lived, which defeats the point of wrapping them in the first place.
/// </remarks>
public sealed class VaultKeyLease : IDisposable
{
    private readonly KeyMaterial _key;

    /// <summary>Creates the lease.</summary>
    /// <param name="key">The unwrapped key, which this lease takes ownership of.</param>
    /// <param name="version">The generation this key is.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    public VaultKeyLease(KeyMaterial key, int version)
    {
        ArgumentNullException.ThrowIfNull(key);

        _key = key;
        Version = version;
    }

    /// <summary>The KEK generation.</summary>
    public int Version { get; }

    /// <summary>The unwrapped key.</summary>
    public KeyMaterial Key => _key;

    /// <summary>Zeroes the unwrapped key.</summary>
    public void Dispose() => _key.Dispose();
}
