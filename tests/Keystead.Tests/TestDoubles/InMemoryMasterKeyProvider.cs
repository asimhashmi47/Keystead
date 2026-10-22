using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Keystead.Application.Cryptography;

namespace Keystead.Tests.TestDoubles;

/// <summary>
/// A master key provider backed by keys held in the test, so crypto tests never touch the
/// environment or the file system.
/// </summary>
internal sealed class InMemoryMasterKeyProvider : IMasterKeyProvider, IDisposable
{
    private readonly Dictionary<int, byte[]> _keys = [];
    private readonly byte[] _pepper;

    public InMemoryMasterKeyProvider(int activeVersion = 1, byte[]? pepper = null)
    {
        ActiveVersion = activeVersion;
        _keys[activeVersion] = RandomNumberGenerator.GetBytes(KeyMaterial.KeyLength);
        _pepper = pepper ?? [];
        ActiveKeyCheckValue = Convert.ToHexStringLower(
            SHA256.HashData(_keys[activeVersion]).AsSpan(0, 8));
    }

    public int ActiveVersion { get; private set; }

    public string ActiveKeyCheckValue { get; private set; }

    /// <summary>Adds a new generation and makes it active, as a master key rotation would.</summary>
    public int RotateToNewVersion()
    {
        var next = ActiveVersion + 1;
        _keys[next] = RandomNumberGenerator.GetBytes(KeyMaterial.KeyLength);
        ActiveVersion = next;
        ActiveKeyCheckValue = Convert.ToHexStringLower(SHA256.HashData(_keys[next]).AsSpan(0, 8));
        return next;
    }

    public KeyMaterial GetActiveKey() => KeyMaterial.CopyFrom(_keys[ActiveVersion]);

    public KeyMaterial? TryGetKey(int version) =>
        _keys.TryGetValue(version, out var key) ? KeyMaterial.CopyFrom(key) : null;

    public ReadOnlySpan<byte> GetPasswordPepper() => _pepper;

    public void Dispose()
    {
        foreach (var key in _keys.Values)
        {
            CryptographicOperations.ZeroMemory(key);
        }

        _keys.Clear();
    }
}
