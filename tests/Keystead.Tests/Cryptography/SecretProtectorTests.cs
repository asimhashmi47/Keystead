using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Cryptography;
using Keystead.Application.Secrets;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Cryptography;
using Keystead.Tests.TestDoubles;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Keystead.Tests.Cryptography;

/// <summary>
/// The full three-tier envelope, end to end against a real database.
/// </summary>
/// <remarks>
/// The unit tests on <see cref="AesGcmCipher"/> prove the primitive. These prove the
/// composition: that a master key really does wrap a vault key that really does wrap a data key
/// that really does protect the value, and that moving any stored piece between rows breaks it.
/// A correct primitive assembled wrongly is still a vulnerability.
/// </remarks>
public sealed class SecretProtectorTests : IDisposable
{
    private static readonly Guid WorkspaceA = Guid.Parse("a0000000-0000-0000-0000-000000000001");
    private static readonly Guid WorkspaceB = Guid.Parse("b0000000-0000-0000-0000-000000000001");
    private static readonly Guid VaultA = Guid.Parse("a0000000-0000-0000-0000-00000000000a");
    private static readonly Guid VaultB = Guid.Parse("b0000000-0000-0000-0000-00000000000a");
    private static readonly Guid SecretOne = Guid.Parse("00000000-0000-0000-0000-000000000011");
    private static readonly Guid SecretTwo = Guid.Parse("00000000-0000-0000-0000-000000000022");

    private readonly TestDatabase _db = new();
    private readonly FixedClock _clock = new();
    private readonly InMemoryMasterKeyProvider _masterKeys = new();
    private readonly VaultKeyService _vaultKeys;
    private readonly SecretProtector _protector;

    public SecretProtectorTests()
    {
        _vaultKeys = new VaultKeyService(
            _db.Context,
            new AesGcmCipher(),
            _masterKeys,
            _clock);

        _protector = new SecretProtector(_vaultKeys, new AesGcmCipher());

        Seed();
    }

    public void Dispose()
    {
        _masterKeys.Dispose();
        _db.Dispose();
    }

    private void Seed()
    {
        foreach (var (workspaceId, vaultId, slug) in new[]
        {
            (WorkspaceA, VaultA, "a"),
            (WorkspaceB, VaultB, "b"),
        })
        {
            _db.Context.Workspaces.Add(new Workspace
            {
                Id = workspaceId,
                Name = slug,
                Slug = slug,
                CreatedUtc = _clock.UtcNow,
            });

            _db.Context.Vaults.Add(new Vault
            {
                Id = vaultId,
                WorkspaceId = workspaceId,
                Name = slug,
                Slug = slug,
                ColorToken = "indigo",
                CreatedUtc = _clock.UtcNow,
                RecoveryWindowDays = 30,
                PurgeProtection = false,
            });

            _db.Context.VaultKeks.Add(_vaultKeys.CreateInitialKek(workspaceId, vaultId));
        }

        _db.Context.SaveChanges();
    }

    private static SecretPath Path(
        Guid workspaceId,
        Guid vaultId,
        Guid secretId,
        Guid versionId) =>
        new(workspaceId, vaultId, secretId, versionId);

    private static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);

    [Fact]
    public async Task AValue_RoundTripsThroughTheFullEnvelope()
    {
        var versionId = Guid.CreateVersion7();
        var path = Path(WorkspaceA, VaultA, SecretOne, versionId);
        var plaintext = Bytes("Server=db;User=app;Password=hunter2");

        var protectedValue = await _protector.ProtectAsync(path, plaintext, CancellationToken.None);
        var recovered = await _protector.UnprotectAsync(path, protectedValue, CancellationToken.None);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public async Task TheStoredCiphertext_DoesNotContainThePlaintext()
    {
        var path = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        const string Secret = "a-very-distinctive-secret-value";

        var protectedValue = await _protector.ProtectAsync(path, Bytes(Secret), CancellationToken.None);

        var printable = Encoding.UTF8.GetString(
            protectedValue.Ciphertext.Where(b => b is >= 32 and < 127).ToArray());

        Assert.DoesNotContain(Secret, printable, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EachVersion_GetsItsOwnDataKey()
    {
        // One key per version is what makes two versions of the same secret cryptographically
        // unrelated. Identical plaintext in two versions must produce unrelated wrapped keys.
        var first = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        var second = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());

        var a = await _protector.ProtectAsync(first, Bytes("same value"), CancellationToken.None);
        var b = await _protector.ProtectAsync(second, Bytes("same value"), CancellationToken.None);

        Assert.NotEqual(a.WrappedDek, b.WrappedDek);
        Assert.NotEqual(a.Ciphertext, b.Ciphertext);
    }

    [Fact]
    public async Task AnEmptyValue_RoundTrips()
    {
        var path = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());

        var protectedValue = await _protector.ProtectAsync(path, [], CancellationToken.None);
        var recovered = await _protector.UnprotectAsync(path, protectedValue, CancellationToken.None);

        Assert.Empty(recovered);
    }

    [Fact]
    public async Task ALargeValue_RoundTrips()
    {
        // A secret may legitimately be a certificate rather than a short string.
        var path = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        var plaintext = RandomNumberGenerator.GetBytes(256 * 1024);

        var protectedValue = await _protector.ProtectAsync(path, plaintext, CancellationToken.None);
        var recovered = await _protector.UnprotectAsync(path, protectedValue, CancellationToken.None);

        Assert.Equal(plaintext, recovered);
    }

    // -----------------------------------------------------------------------
    // Relocation. Each of these is what an attacker with database write access
    // but no key would actually try.
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AValueMovedToAnotherSecret_FailsToOpen()
    {
        var versionId = Guid.CreateVersion7();
        var original = Path(WorkspaceA, VaultA, SecretOne, versionId);
        var relocated = Path(WorkspaceA, VaultA, SecretTwo, versionId);

        var protectedValue = await _protector.ProtectAsync(
            original, Bytes("privileged"), CancellationToken.None);

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => _protector.UnprotectAsync(relocated, protectedValue, CancellationToken.None));
    }

    [Fact]
    public async Task AValueMovedToAnotherVersion_FailsToOpen()
    {
        var original = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        var relocated = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());

        var protectedValue = await _protector.ProtectAsync(
            original, Bytes("privileged"), CancellationToken.None);

        // This is the rollback-forgery case: replaying an old ciphertext into a new version row
        // must not work, or history could be rewritten.
        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => _protector.UnprotectAsync(relocated, protectedValue, CancellationToken.None));
    }

    [Fact]
    public async Task AValueMovedToAnotherVault_FailsToOpen()
    {
        var versionId = Guid.CreateVersion7();
        var original = Path(WorkspaceA, VaultA, SecretOne, versionId);
        var relocated = Path(WorkspaceB, VaultB, SecretOne, versionId);

        var protectedValue = await _protector.ProtectAsync(
            original, Bytes("privileged"), CancellationToken.None);

        // Fails twice over: a different vault key cannot unwrap the data key, and the AAD does
        // not match either. Belt and braces, and both are deliberate.
        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => _protector.UnprotectAsync(relocated, protectedValue, CancellationToken.None));
    }

    [Fact]
    public async Task AValueClaimingAnotherWorkspace_FailsToOpen()
    {
        var versionId = Guid.CreateVersion7();
        var original = Path(WorkspaceA, VaultA, SecretOne, versionId);
        var lying = Path(WorkspaceB, VaultA, SecretOne, versionId);

        var protectedValue = await _protector.ProtectAsync(
            original, Bytes("privileged"), CancellationToken.None);

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => _protector.UnprotectAsync(lying, protectedValue, CancellationToken.None));
    }

    [Fact]
    public async Task ATamperedCiphertext_FailsToOpen()
    {
        var path = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        var protectedValue = await _protector.ProtectAsync(
            path, Bytes("value"), CancellationToken.None);

        protectedValue.Ciphertext[0] ^= 0x01;

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => _protector.UnprotectAsync(path, protectedValue, CancellationToken.None));
    }

    [Fact]
    public async Task ATamperedWrappedDataKey_FailsToOpen()
    {
        var path = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        var protectedValue = await _protector.ProtectAsync(
            path, Bytes("value"), CancellationToken.None);

        // Flip a byte inside the wrapped key's ciphertext, past its nonce and tag header.
        protectedValue.WrappedDek[^1] ^= 0x01;

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => _protector.UnprotectAsync(path, protectedValue, CancellationToken.None));
    }

    [Fact]
    public async Task ADataKeyFromAnotherVersion_FailsToOpen()
    {
        // Mix and match: keep one version's value but splice in another's wrapped key. The
        // data-key AAD carries the version, so the unwrap fails before the value is touched.
        var firstPath = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        var secondPath = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());

        var first = await _protector.ProtectAsync(firstPath, Bytes("one"), CancellationToken.None);
        var second = await _protector.ProtectAsync(secondPath, Bytes("two"), CancellationToken.None);

        var spliced = first with { WrappedDek = second.WrappedDek };

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => _protector.UnprotectAsync(firstPath, spliced, CancellationToken.None));
    }

    [Fact]
    public async Task AValuePresentedAsItsOwnWrappedKey_FailsToOpen()
    {
        // The purpose tag in the AAD. Both blobs are AES-GCM output under keys in this vault,
        // and they still cannot stand in for one another.
        var path = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        var protectedValue = await _protector.ProtectAsync(
            path, Bytes("value"), CancellationToken.None);

        var confused = protectedValue with
        {
            WrappedDek = SealedBlobPacking.Pack(
                new SealedBlob(
                    protectedValue.Ciphertext,
                    protectedValue.Nonce,
                    protectedValue.Tag)),
        };

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => _protector.UnprotectAsync(path, confused, CancellationToken.None));
    }

    [Fact]
    public async Task AMalformedWrappedKey_IsRejectedWithAClearError()
    {
        var path = Path(WorkspaceA, VaultA, SecretOne, Guid.CreateVersion7());
        var protectedValue = await _protector.ProtectAsync(
            path, Bytes("value"), CancellationToken.None);

        var truncated = protectedValue with { WrappedDek = new byte[8] };

        // A corrupt row should say so, not fail as though the key were wrong.
        await Assert.ThrowsAsync<ArgumentException>(
            () => _protector.UnprotectAsync(path, truncated, CancellationToken.None));
    }

    // -----------------------------------------------------------------------
    // Key hierarchy behaviour
    // -----------------------------------------------------------------------

    [Fact]
    public void TheWrappedVaultKey_IsNotThePlaintextKey()
    {
        var kek = _db.Context.VaultKeks.AsNoTracking().First(k => k.VaultId == VaultA);

        // 32-byte key plus a 12-byte nonce and a 16-byte tag.
        Assert.Equal(60, kek.WrappedKek.Length);
        Assert.Equal(1, kek.Version);
    }

    [Fact]
    public async Task AVaultKeySealedUnderAnUnloadedMasterGeneration_ReportsThatClearly()
    {
        // The honest failure for "you retired a master key too early": a named configuration
        // problem, not a tag mismatch that looks like corruption.
        var kek = await _db.Context.VaultKeks.FirstAsync(k => k.VaultId == VaultA);
        kek.MasterKeyVersion = 999;
        await _db.Context.SaveChangesAsync();

        var exception = await Assert.ThrowsAsync<MasterKeyUnavailableException>(
            () => _vaultKeys.LeaseActiveAsync(WorkspaceA, VaultA, CancellationToken.None));

        Assert.Contains("999", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EachVaultHasAnIndependentKey()
    {
        // Two vaults, same workspace-level master key, must not produce the same wrapped KEK.
        var keks = await _db.Context.VaultKeks.AsNoTracking().ToListAsync();

        Assert.Equal(2, keks.Count);
        Assert.NotEqual(keks[0].WrappedKek, keks[1].WrappedKek);
    }

    [Fact]
    public async Task ALeasedVaultKey_IsZeroedWhenTheLeaseIsDisposed()
    {
        var lease = await _vaultKeys.LeaseActiveAsync(WorkspaceA, VaultA, CancellationToken.None);

        Assert.Equal(32, lease.Key.Span.Length);

        lease.Dispose();

        // Reading a disposed key must fail loudly rather than return zeroes that would be
        // silently used as an encryption key.
        Assert.Throws<ObjectDisposedException>(() => _ = lease.Key.Span.Length);
    }
}
