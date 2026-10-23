using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Cryptography;
using Keystead.Domain.Identity;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Tokens;

/// <summary>
/// Creates and loads the ECDSA key pairs that sign machine tokens.
/// </summary>
/// <remarks>
/// The private half is sealed under the master key with AAD binding it to its own row, so a
/// signing key cannot be moved between rows and cannot be read from a stolen database. The
/// public half is stored in the clear, which means verification and a future JWKS endpoint
/// never need the master key.
/// </remarks>
public sealed class SigningKeyStore
{
    private readonly KeysteadDbContext _db;
    private readonly IAeadCipher _cipher;
    private readonly IMasterKeyProvider _masterKeys;
    private readonly IClock _clock;

    /// <summary>Creates the store.</summary>
    /// <param name="db">The database.</param>
    /// <param name="cipher">The AEAD primitive.</param>
    /// <param name="masterKeys">Supplies the master key.</param>
    /// <param name="clock">The clock.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public SigningKeyStore(
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

    /// <summary>
    /// Returns the active signing key, creating the first one if none exists.
    /// </summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The active key.</returns>
    public async Task<SigningKey> GetOrCreateActiveAsync(CancellationToken cancellationToken)
    {
        var existing = await _db.SigningKeys
            .AsNoTracking()
            .Where(k => k.RetiredUtc == null)
            .OrderByDescending(k => k.CreatedUtc)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        if (existing is not null)
        {
            return existing;
        }

        var created = Create();

        _db.SigningKeys.Add(created);

        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return created;
        }
        catch (DbUpdateException)
        {
            // Another request created the first key at the same moment. Harmless: take theirs
            // rather than insisting on ours, since either is a valid active key.
            _db.ChangeTracker.Clear();

            return await _db.SigningKeys
                .AsNoTracking()
                .Where(k => k.RetiredUtc == null)
                .OrderByDescending(k => k.CreatedUtc)
                .FirstAsync(cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>Finds a key by its id, for verifying a token that names it.</summary>
    /// <param name="kid">The key id from the token header.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The key, or null when no such key exists.</returns>
    public Task<SigningKey?> FindByKidAsync(string kid, CancellationToken cancellationToken) =>
        _db.SigningKeys
            .AsNoTracking()
            .FirstOrDefaultAsync(k => k.Kid == kid, cancellationToken);

    /// <summary>Lists every key, for a JWKS document or an operator view.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>All keys, newest first.</returns>
    public async Task<IReadOnlyList<SigningKey>> ListAsync(CancellationToken cancellationToken) =>
        await _db.SigningKeys
            .AsNoTracking()
            .OrderByDescending(k => k.CreatedUtc)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    /// <summary>
    /// Retires the active key and creates a new one.
    /// </summary>
    /// <remarks>
    /// The retired key is kept, not deleted, so tokens it already signed keep verifying until
    /// they expire. Deleting it would reject live tokens and cause an outage for no gain.
    /// </remarks>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The new active key.</returns>
    public async Task<SigningKey> RotateAsync(CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;

        var current = await _db.SigningKeys
            .Where(k => k.RetiredUtc == null)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        foreach (var key in current)
        {
            key.RetiredUtc = now;
        }

        var created = Create();
        _db.SigningKeys.Add(created);

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return created;
    }

    /// <summary>
    /// Loads a key's private half for signing.
    /// </summary>
    /// <param name="key">The key to open.</param>
    /// <returns>An ECDsa the caller disposes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="Cryptography.MasterKeyUnavailableException">
    /// The master key generation that sealed this key is not loaded.
    /// </exception>
    public ECDsa OpenPrivate(SigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        var masterKey = _masterKeys.TryGetKey(key.MasterKeyVersion)
            ?? throw new Cryptography.MasterKeyUnavailableException(
                $"The token signing key was sealed under master key version {key.MasterKeyVersion}, which is not loaded.");

        byte[]? pkcs8 = null;

        try
        {
            var context = CryptoContext.ForSigningKey(key.Id, key.MasterKeyVersion);

            pkcs8 = _cipher.Open(
                masterKey,
                new SealedBlob(key.PrivateKeyCiphertext, key.PrivateKeyNonce, key.PrivateKeyTag),
                context);

            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);

            return ecdsa;
        }
        finally
        {
            if (pkcs8 is not null)
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }

            masterKey.Dispose();
        }
    }

    /// <summary>Loads a key's public half for verification.</summary>
    /// <param name="key">The key to open.</param>
    /// <returns>An ECDsa the caller disposes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    public static ECDsa OpenPublic(SigningKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(key.PublicKey, out _);

        return ecdsa;
    }

    private SigningKey Create()
    {
        var id = Guid.CreateVersion7();
        var masterKeyVersion = _masterKeys.ActiveVersion;

        // P-256, which is what ES256 means. Chosen over Ed25519 only because it is what the
        // JOSE ecosystem and every client library support without argument.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var pkcs8 = ecdsa.ExportPkcs8PrivateKey();

        try
        {
            using var masterKey = _masterKeys.GetActiveKey();

            var context = CryptoContext.ForSigningKey(id, masterKeyVersion);
            var sealedKey = _cipher.Seal(masterKey, pkcs8, context);

            return new SigningKey
            {
                Id = id,

                // Derived from the id rather than random, so the key id is stable and
                // reproducible, and carries no information beyond identifying the key.
                Kid = id.ToString("N", CultureInfo.InvariantCulture)[..16],
                PrivateKeyCiphertext = sealedKey.Ciphertext,
                PrivateKeyNonce = sealedKey.Nonce,
                PrivateKeyTag = sealedKey.Tag,
                MasterKeyVersion = masterKeyVersion,
                PublicKey = ecdsa.ExportSubjectPublicKeyInfo(),
                CreatedUtc = _clock.UtcNow,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pkcs8);
        }
    }
}
