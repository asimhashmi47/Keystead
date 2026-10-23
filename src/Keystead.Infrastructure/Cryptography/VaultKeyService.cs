using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Cryptography;
using Keystead.Application.Vaults;
using Keystead.Domain.Vaults;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Cryptography;

/// <summary>
/// The middle tier of the key hierarchy: a per-vault key-encryption key, sealed under the
/// master key.
/// </summary>
/// <remarks>
/// <para>
/// Why a middle tier at all, rather than wrapping every data key directly under the master
/// key? Two reasons. Rotating one vault's key becomes a local operation instead of touching
/// every row in the installation. And the master key is needed only to unwrap a KEK, so it is
/// touched once per vault per operation rather than once per secret version.
/// </para>
/// <para>
/// Leases are never cached. An unwrapped KEK is a key to every secret in its vault, so it
/// lives inside one <c>using</c> block and is zeroed on the way out. Caching would trade that
/// for a few milliseconds and make a memory dump far more valuable.
/// </para>
/// </remarks>
public sealed class VaultKeyService : IVaultKeyService
{
    private readonly KeysteadDbContext _db;
    private readonly IAeadCipher _cipher;
    private readonly IMasterKeyProvider _masterKeys;
    private readonly IClock _clock;

    /// <summary>Creates the service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="cipher">The AEAD primitive.</param>
    /// <param name="masterKeys">Supplies the master key.</param>
    /// <param name="clock">The clock.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public VaultKeyService(
        KeysteadDbContext db,
        IAeadCipher cipher,
        IMasterKeyProvider masterKeys,
        IClock clock)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(cipher);
        ArgumentNullException.ThrowIfNull(masterKeys);
        ArgumentNullException.ThrowIfNull(clock);

        _db = db;
        _cipher = cipher;
        _masterKeys = masterKeys;
        _clock = clock;
    }

    /// <inheritdoc />
    public VaultKek CreateInitialKek(Guid workspaceId, Guid vaultId)
    {
        const int FirstVersion = 1;

        var masterKeyVersion = _masterKeys.ActiveVersion;

        using var kek = KeyMaterial.CreateRandom();
        using var masterKey = _masterKeys.GetActiveKey();

        var context = CryptoContext.ForVaultKek(
            workspaceId,
            vaultId,
            FirstVersion,
            masterKeyVersion);

        var sealedKek = _cipher.Seal(masterKey, kek.Span, context);

        return new VaultKek
        {
            Id = Guid.CreateVersion7(),
            VaultId = vaultId,
            Version = FirstVersion,

            // Nonce, tag and ciphertext concatenated into one column. A single opaque blob
            // means there is no way to persist a ciphertext while forgetting its tag.
            WrappedKek = SealedBlobPacking.Pack(sealedKek),
            MasterKeyVersion = masterKeyVersion,
            CreatedUtc = _clock.UtcNow,
        };
    }

    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">The vault has no active key.</exception>
    public async Task<VaultKeyLease> LeaseActiveAsync(
        Guid workspaceId,
        Guid vaultId,
        CancellationToken cancellationToken)
    {
        var kek = await _db.VaultKeks
            .AsNoTracking()
            .Where(k => k.VaultId == vaultId && k.RetiredUtc == null)
            .OrderByDescending(k => k.Version)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"Vault {vaultId} has no active key-encryption key. This should be impossible: a vault is created with one.");

        return Unwrap(workspaceId, vaultId, kek);
    }

    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">That key generation does not exist.</exception>
    public async Task<VaultKeyLease> LeaseAsync(
        Guid workspaceId,
        Guid vaultId,
        int version,
        CancellationToken cancellationToken)
    {
        var kek = await _db.VaultKeks
            .AsNoTracking()
            .FirstOrDefaultAsync(
                k => k.VaultId == vaultId && k.Version == version,
                cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"Vault {vaultId} has no key-encryption key at version {version}.");

        return Unwrap(workspaceId, vaultId, kek);
    }

    private VaultKeyLease Unwrap(Guid workspaceId, Guid vaultId, VaultKek kek)
    {
        var masterKey = _masterKeys.TryGetKey(kek.MasterKeyVersion)
            ?? throw new MasterKeyUnavailableException(
                $"This vault's key was sealed under master key version {kek.MasterKeyVersion}, which is not loaded. Supply that generation in configuration, or complete the rotation that was in progress.");

        byte[]? plaintextKek = null;

        try
        {
            var context = CryptoContext.ForVaultKek(
                workspaceId,
                vaultId,
                kek.Version,
                kek.MasterKeyVersion);

            plaintextKek = _cipher.Open(masterKey, SealedBlobPacking.Unpack(kek.WrappedKek), context);

            // Adopt rather than copy: the lease takes ownership and zeroes it on dispose, so
            // there is exactly one copy of this key in memory and one place that clears it.
            var material = KeyMaterial.Adopt(plaintextKek);
            plaintextKek = null;

            return new VaultKeyLease(material, kek.Version);
        }
        finally
        {
            if (plaintextKek is not null)
            {
                CryptographicOperations.ZeroMemory(plaintextKek);
            }

            masterKey.Dispose();
        }
    }
}
