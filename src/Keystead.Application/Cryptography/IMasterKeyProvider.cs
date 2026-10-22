using System;

namespace Keystead.Application.Cryptography;

/// <summary>
/// Supplies the root of the key hierarchy. Every vault KEK is sealed under a master key, and
/// nothing above this interface ever learns where the key came from.
/// </summary>
/// <remarks>
/// Implementations exist for an environment variable or mounted file, and for a
/// platform-protected local file (DPAPI on Windows, mode 0600 elsewhere). The shape also
/// admits a remote KMS: an implementation may hold no key bytes at all and instead delegate
/// wrapping, which is why callers receive a disposable handle rather than a raw array.
/// </remarks>
public interface IMasterKeyProvider
{
    /// <summary>The generation that new wrap operations should use.</summary>
    int ActiveVersion { get; }

    /// <summary>
    /// A non-secret fingerprint of the active key, used to detect a wrong or swapped key at
    /// startup without storing the key itself.
    /// </summary>
    string ActiveKeyCheckValue { get; }

    /// <summary>Borrows the active master key. The caller disposes it, which zeroes it.</summary>
    /// <returns>A handle to the active master key.</returns>
    KeyMaterial GetActiveKey();

    /// <summary>
    /// Borrows a specific master key generation, needed while a rotation is in flight and some
    /// rows are still wrapped under the previous generation.
    /// </summary>
    /// <param name="version">The generation to retrieve.</param>
    /// <returns>A handle to that generation, or null when it is not available.</returns>
    KeyMaterial? TryGetKey(int version);

    /// <summary>
    /// A pepper mixed into password hashing, held with the master key rather than the database.
    /// </summary>
    /// <remarks>
    /// This is defence in depth, not a replacement for a per-user salt. A stolen database
    /// without the pepper cannot be attacked offline even with a weak password, because the
    /// attacker is missing an input the hash depends on.
    /// </remarks>
    /// <returns>The pepper bytes, or null when none is configured.</returns>
    ReadOnlySpan<byte> GetPasswordPepper();
}
