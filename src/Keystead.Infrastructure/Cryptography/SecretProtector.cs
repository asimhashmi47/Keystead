using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Cryptography;
using Keystead.Application.Secrets;
using Keystead.Application.Vaults;

namespace Keystead.Infrastructure.Cryptography;

/// <summary>
/// The inner tier of the key hierarchy: a unique data-encryption key per secret version.
/// </summary>
/// <remarks>
/// <para>
/// One key per version, never reused. That is what makes two versions of the same secret
/// cryptographically unrelated, and it is why a nonce collision cannot matter: a data key
/// encrypts exactly one value, once, so there is no second message under the same key for a
/// repeated nonce to compromise.
/// </para>
/// <para>
/// Both the value and its data key are bound by AAD to the full path. The value is bound with
/// <see cref="CryptoPurpose.SecretValue"/> and the key with
/// <see cref="CryptoPurpose.DataKeyWrap"/>, so the two blobs cannot be swapped for each other
/// even though both are AES-GCM output under keys in the same vault.
/// </para>
/// </remarks>
public sealed class SecretProtector : ISecretProtector
{
    private readonly IVaultKeyService _vaultKeys;
    private readonly IAeadCipher _cipher;

    /// <summary>Creates the protector.</summary>
    /// <param name="vaultKeys">Supplies the vault key-encryption key.</param>
    /// <param name="cipher">The AEAD primitive.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public SecretProtector(IVaultKeyService vaultKeys, IAeadCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(vaultKeys);
        ArgumentNullException.ThrowIfNull(cipher);

        _vaultKeys = vaultKeys;
        _cipher = cipher;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<ProtectedSecretValue> ProtectAsync(
        SecretPath path,
        byte[] plaintext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(plaintext);

        using var kekLease = await _vaultKeys
            .LeaseActiveAsync(path.WorkspaceId, path.VaultId, cancellationToken)
            .ConfigureAwait(false);

        using var dek = KeyMaterial.CreateRandom();

        var valueContext = CryptoContext.ForSecretValue(
            path.WorkspaceId,
            path.VaultId,
            path.SecretId,
            path.VersionId);

        var sealedValue = _cipher.Seal(dek, plaintext, valueContext);

        var keyContext = CryptoContext.ForDataKey(
            path.WorkspaceId,
            path.VaultId,
            path.SecretId,
            path.VersionId,
            kekLease.Version);

        var sealedDek = _cipher.Seal(kekLease.Key, dek.Span, keyContext);

        return new ProtectedSecretValue(
            sealedValue.Ciphertext,
            sealedValue.Nonce,
            sealedValue.Tag,
            SealedBlobPacking.Pack(sealedDek),
            kekLease.Version);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<byte[]> UnprotectAsync(
        SecretPath path,
        ProtectedSecretValue value,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(value);

        // The generation recorded on the row, not the active one. A version written before a
        // rotation is still readable, which is what lets rotation run without downtime.
        using var kekLease = await _vaultKeys
            .LeaseAsync(path.WorkspaceId, path.VaultId, value.KekVersion, cancellationToken)
            .ConfigureAwait(false);

        var keyContext = CryptoContext.ForDataKey(
            path.WorkspaceId,
            path.VaultId,
            path.SecretId,
            path.VersionId,
            value.KekVersion);

        byte[]? dekBytes = null;

        try
        {
            dekBytes = _cipher.Open(
                kekLease.Key,
                SealedBlobPacking.Unpack(value.WrappedDek),
                keyContext);

            using var dek = KeyMaterial.Adopt(dekBytes);
            dekBytes = null;

            var valueContext = CryptoContext.ForSecretValue(
                path.WorkspaceId,
                path.VaultId,
                path.SecretId,
                path.VersionId);

            return _cipher.Open(
                dek,
                new SealedBlob(value.Ciphertext, value.Nonce, value.Tag),
                valueContext);
        }
        finally
        {
            if (dekBytes is not null)
            {
                CryptographicOperations.ZeroMemory(dekBytes);
            }
        }
    }
}
