using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Keystead.Application.Cryptography;
using Microsoft.Extensions.Options;

namespace Keystead.Infrastructure.Cryptography;

/// <summary>
/// Loads the master key from an environment variable, a mounted file, or a platform-protected
/// local file, according to <see cref="MasterKeyOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// The key is read once at construction and held for the process lifetime. That is a
/// deliberate trade: re-reading per operation would shorten the window the key sits in memory,
/// but it would also mean the application keeps running after an operator deletes the key file
/// and only fails much later, on an unpredictable request. Failing at startup is louder and
/// easier to diagnose.
/// </para>
/// <para>
/// Nothing in this class logs or formats the key. The only derived value it exposes is a key
/// check value, which is a truncated hash over a domain-separated label and the key: enough to
/// tell "a different key was supplied" from "the right key was supplied", and useless for
/// recovering the key.
/// </para>
/// </remarks>
public sealed class ConfiguredMasterKeyProvider : IMasterKeyProvider, IDisposable
{
    private const string KeyCheckLabel = "keystead.kcv.v1";

    private readonly Dictionary<int, byte[]> _keysByVersion = [];
    private readonly byte[] _pepper;
    private bool _disposed;

    /// <summary>Loads and validates the configured key material.</summary>
    /// <param name="options">Where to find the key.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="MasterKeyUnavailableException">
    /// The key is missing, not valid base64, or not 256 bits.
    /// </exception>
    public ConfiguredMasterKeyProvider(IOptions<MasterKeyOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var settings = options.Value;
        ActiveVersion = settings.ActiveVersion;

        var active = LoadActive(settings);
        _keysByVersion[ActiveVersion] = active;

        foreach (var (version, location) in settings.PreviousVersions)
        {
            if (version == ActiveVersion)
            {
                continue;
            }

            var raw = ReadFromEnvironmentOrFile(location);

            if (raw is not null)
            {
                _keysByVersion[version] = Decode(raw, $"master key version {version}");
            }
        }

        ActiveKeyCheckValue = ComputeKeyCheckValue(active);
        _pepper = LoadPepper(settings);
    }

    /// <inheritdoc />
    public int ActiveVersion { get; }

    /// <inheritdoc />
    public string ActiveKeyCheckValue { get; }

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">The provider has been disposed.</exception>
    public KeyMaterial GetActiveKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // A copy, because the caller owns the handle and disposing it zeroes the buffer.
        // Handing out the stored array would destroy the key on the first caller's dispose.
        return KeyMaterial.CopyFrom(_keysByVersion[ActiveVersion]);
    }

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">The provider has been disposed.</exception>
    public KeyMaterial? TryGetKey(int version)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _keysByVersion.TryGetValue(version, out var key)
            ? KeyMaterial.CopyFrom(key)
            : null;
    }

    /// <inheritdoc />
    public ReadOnlySpan<byte> GetPasswordPepper()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _pepper;
    }

    /// <summary>Zeroes every key held in memory.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        foreach (var key in _keysByVersion.Values)
        {
            CryptographicOperations.ZeroMemory(key);
        }

        CryptographicOperations.ZeroMemory(_pepper);
        _keysByVersion.Clear();
        _disposed = true;
    }

    /// <summary>
    /// Computes the non-secret fingerprint used to detect a swapped or mistyped key.
    /// </summary>
    /// <param name="key">The key to fingerprint.</param>
    /// <returns>A 16-character lower-case hex string.</returns>
    public static string ComputeKeyCheckValue(ReadOnlySpan<byte> key)
    {
        var label = Encoding.UTF8.GetBytes(KeyCheckLabel);
        var buffer = new byte[label.Length + key.Length];

        try
        {
            label.CopyTo(buffer.AsSpan());
            key.CopyTo(buffer.AsSpan(label.Length));

            var digest = SHA256.HashData(buffer);

            // Truncated to 64 bits: enough to detect a wrong key, far too short to be a
            // useful target for anyone trying to confirm a guess at the key itself.
            return Convert.ToHexStringLower(digest.AsSpan(0, 8));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static byte[] LoadActive(MasterKeyOptions settings)
    {
        var raw = settings.Source switch
        {
            MasterKeySource.Environment =>
                Environment.GetEnvironmentVariable(settings.EnvironmentVariable),

            MasterKeySource.File => ReadFile(settings.FilePath, settings.Source),

            MasterKeySource.ProtectedFile => ReadProtectedFile(settings.FilePath),

            _ => throw new MasterKeyUnavailableException(
                $"Unknown master key source '{settings.Source}'."),
        };

        if (string.IsNullOrWhiteSpace(raw))
        {
            throw new MasterKeyUnavailableException(
                settings.Source == MasterKeySource.Environment
                    ? $"No master key found. Set the '{settings.EnvironmentVariable}' environment variable to a base64-encoded 256-bit key, or run the first-run setup wizard to generate one."
                    : $"No master key found at '{settings.FilePath}'. Mount a file containing a base64-encoded 256-bit key, or run the first-run setup wizard to generate one.");
        }

        return Decode(raw, "master key");
    }

    private static byte[] LoadPepper(MasterKeyOptions settings)
    {
        var raw = Environment.GetEnvironmentVariable(settings.PepperEnvironmentVariable);

        if (string.IsNullOrWhiteSpace(raw) && !string.IsNullOrWhiteSpace(settings.PepperFilePath))
        {
            raw = File.Exists(settings.PepperFilePath)
                ? File.ReadAllText(settings.PepperFilePath)
                : null;
        }

        // The pepper is optional. Absent means password hashing relies on the per-user salt
        // alone, which is still correct, just without the extra offline-attack barrier.
        if (string.IsNullOrWhiteSpace(raw))
        {
            return [];
        }

        try
        {
            return Convert.FromBase64String(raw.Trim());
        }
        catch (FormatException ex)
        {
            throw new MasterKeyUnavailableException(
                "The configured password pepper is not valid base64.",
                ex);
        }
    }

    private static string? ReadFromEnvironmentOrFile(string location)
    {
        var fromEnvironment = Environment.GetEnvironmentVariable(location);

        if (!string.IsNullOrWhiteSpace(fromEnvironment))
        {
            return fromEnvironment;
        }

        return File.Exists(location) ? File.ReadAllText(location) : null;
    }

    private static string ReadFile(string? path, MasterKeySource source)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new MasterKeyUnavailableException(
                $"Master key source is '{source}' but no FilePath is configured.");
        }

        if (!File.Exists(path))
        {
            throw new MasterKeyUnavailableException($"No master key file at '{path}'.");
        }

        WarnIfWorldReadable(path);
        return File.ReadAllText(path);
    }

    private static string ReadProtectedFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new MasterKeyUnavailableException(
                "Master key source is 'ProtectedFile' but no FilePath is configured.");
        }

        if (!File.Exists(path))
        {
            throw new MasterKeyUnavailableException($"No master key file at '{path}'.");
        }

        if (!OperatingSystem.IsWindows())
        {
            // On Unix the protection is the file mode, so the content is plain base64.
            WarnIfWorldReadable(path);
            return File.ReadAllText(path);
        }

        var protectedBytes = File.ReadAllBytes(path);
        byte[]? plaintext = null;

        try
        {
            plaintext = ProtectedData.Unprotect(
                protectedBytes,
                optionalEntropy: Encoding.UTF8.GetBytes(KeyCheckLabel),
                scope: DataProtectionScope.CurrentUser);

            return Encoding.UTF8.GetString(plaintext);
        }
        catch (CryptographicException ex)
        {
            throw new MasterKeyUnavailableException(
                $"The master key file at '{path}' could not be unprotected. A DPAPI-protected key can only be read by the Windows user account that wrote it.",
                ex);
        }
        finally
        {
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private static void WarnIfWorldReadable(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var mode = File.GetUnixFileMode(path);
        const UnixFileMode TooOpen =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        if ((mode & TooOpen) != 0)
        {
            throw new MasterKeyUnavailableException(
                $"The master key file at '{path}' is readable beyond its owner (mode {mode}). Set it to 0600 before starting Keystead.");
        }
    }

    private static byte[] Decode(string raw, string what)
    {
        byte[] decoded;

        try
        {
            decoded = Convert.FromBase64String(raw.Trim());
        }
        catch (FormatException ex)
        {
            throw new MasterKeyUnavailableException(
                $"The configured {what} is not valid base64.",
                ex);
        }

        if (decoded.Length != KeyMaterial.KeyLength)
        {
            var length = decoded.Length.ToString(CultureInfo.InvariantCulture);
            CryptographicOperations.ZeroMemory(decoded);

            throw new MasterKeyUnavailableException(
                $"The configured {what} decodes to {length} bytes; Keystead requires exactly {KeyMaterial.KeyLength} bytes (256 bits).");
        }

        return decoded;
    }
}
