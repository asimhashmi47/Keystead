using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Keystead.Application.Cryptography;
using Keystead.Infrastructure.Cryptography;
using Xunit;

namespace Keystead.Tests.Cryptography;

/// <summary>
/// The tamper and misuse suite for the AEAD primitive.
/// </summary>
/// <remarks>
/// Every test here corresponds to a way an attacker with database write access might try to
/// make the server decrypt something it should not. A round-trip test alone would pass against
/// a cipher with no authentication at all, which is why the failure cases carry the weight.
/// </remarks>
public sealed class AesGcmCipherTests
{
    private static readonly Guid Workspace = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid VaultId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid SecretId = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid VersionId = Guid.Parse("44444444-4444-4444-4444-444444444444");

    private readonly AesGcmCipher _cipher = new();

    private static CryptoContext Context() =>
        CryptoContext.ForSecretValue(Workspace, VaultId, SecretId, VersionId);

    [Fact]
    public void Seal_ThenOpen_RecoversThePlaintext()
    {
        using var key = KeyMaterial.CreateRandom();
        var plaintext = Encoding.UTF8.GetBytes("Server=db;Password=correct-horse-battery-staple");

        var blob = _cipher.Seal(key, plaintext, Context());
        var recovered = _cipher.Open(key, blob, Context());

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Seal_ProducesCiphertextThatDoesNotContainThePlaintext()
    {
        using var key = KeyMaterial.CreateRandom();
        var plaintext = Encoding.UTF8.GetBytes("super-secret-value");

        var blob = _cipher.Seal(key, plaintext, Context());

        // A sanity check against the catastrophic implementation mistake of storing the input.
        Assert.DoesNotContain(
            Encoding.UTF8.GetString(plaintext),
            Encoding.UTF8.GetString(blob.Ciphertext.Where(b => b is >= 32 and < 127).ToArray()),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Seal_UsesAFreshNonceEveryTime()
    {
        using var key = KeyMaterial.CreateRandom();
        var plaintext = Encoding.UTF8.GetBytes("same input every time");

        // A repeated nonce under one key is catastrophic for GCM: it leaks the XOR of the
        // plaintexts and allows tag forgery. 200 seals is a cheap smoke test for a counter
        // or a constant having crept in.
        var nonces = Enumerable.Range(0, 200)
            .Select(_ => Convert.ToHexStringLower(_cipher.Seal(key, plaintext, Context()).Nonce))
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(200, nonces.Count);
    }

    [Fact]
    public void Seal_ProducesDifferentCiphertextForIdenticalInput()
    {
        using var key = KeyMaterial.CreateRandom();
        var plaintext = Encoding.UTF8.GetBytes("same input every time");

        var first = _cipher.Seal(key, plaintext, Context());
        var second = _cipher.Seal(key, plaintext, Context());

        Assert.NotEqual(first.Ciphertext, second.Ciphertext);
    }

    [Fact]
    public void Open_WithTamperedCiphertext_Throws()
    {
        using var key = KeyMaterial.CreateRandom();
        var blob = _cipher.Seal(key, Encoding.UTF8.GetBytes("value"), Context());

        blob.Ciphertext[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(
            () => _cipher.Open(key, blob, Context()));
    }

    [Fact]
    public void Open_WithTamperedNonce_Throws()
    {
        using var key = KeyMaterial.CreateRandom();
        var blob = _cipher.Seal(key, Encoding.UTF8.GetBytes("value"), Context());

        blob.Nonce[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(
            () => _cipher.Open(key, blob, Context()));
    }

    [Fact]
    public void Open_WithTamperedTag_Throws()
    {
        using var key = KeyMaterial.CreateRandom();
        var blob = _cipher.Seal(key, Encoding.UTF8.GetBytes("value"), Context());

        blob.Tag[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(
            () => _cipher.Open(key, blob, Context()));
    }

    [Fact]
    public void Open_WithWrongKey_Throws()
    {
        using var key = KeyMaterial.CreateRandom();
        using var other = KeyMaterial.CreateRandom();
        var blob = _cipher.Seal(key, Encoding.UTF8.GetBytes("value"), Context());

        Assert.Throws<AuthenticationTagMismatchException>(
            () => _cipher.Open(other, blob, Context()));
    }

    /// <summary>
    /// The row-swap defence. Each case moves a ciphertext into a different position in the
    /// hierarchy, which is exactly what an attacker with database write access would attempt
    /// in order to read a privileged secret through an unprivileged row.
    /// </summary>
    /// <param name="differingPart">Which part of the context the attacker changes.</param>
    [Theory]
    [InlineData("workspace")]
    [InlineData("vault")]
    [InlineData("secret")]
    [InlineData("version")]
    public void Open_WithCiphertextMovedToAnotherRow_Throws(string differingPart)
    {
        using var key = KeyMaterial.CreateRandom();
        var blob = _cipher.Seal(key, Encoding.UTF8.GetBytes("privileged value"), Context());

        var other = Guid.Parse("99999999-9999-9999-9999-999999999999");

        var relocated = differingPart switch
        {
            "workspace" => CryptoContext.ForSecretValue(other, VaultId, SecretId, VersionId),
            "vault" => CryptoContext.ForSecretValue(Workspace, other, SecretId, VersionId),
            "secret" => CryptoContext.ForSecretValue(Workspace, VaultId, other, VersionId),
            "version" => CryptoContext.ForSecretValue(Workspace, VaultId, SecretId, other),
            _ => throw new ArgumentOutOfRangeException(nameof(differingPart)),
        };

        Assert.Throws<AuthenticationTagMismatchException>(
            () => _cipher.Open(key, blob, relocated));
    }

    [Fact]
    public void Open_WithCiphertextRepurposedAsAWrappedKey_Throws()
    {
        // The purpose is part of the AAD, so a sealed secret value cannot be presented as a
        // wrapped DEK even though both are AES-GCM output under a key in the same vault.
        using var key = KeyMaterial.CreateRandom();
        var valueContext = CryptoContext.ForSecretValue(Workspace, VaultId, SecretId, VersionId);
        var keyWrapContext = CryptoContext.ForDataKey(
            Workspace, VaultId, SecretId, VersionId, kekVersion: 0);

        var blob = _cipher.Seal(key, Encoding.UTF8.GetBytes("value"), valueContext);

        Assert.Throws<AuthenticationTagMismatchException>(
            () => _cipher.Open(key, blob, keyWrapContext));
    }

    [Fact]
    public void Seal_WithEmptyPlaintext_RoundTrips()
    {
        using var key = KeyMaterial.CreateRandom();

        var blob = _cipher.Seal(key, [], Context());
        var recovered = _cipher.Open(key, blob, Context());

        Assert.Empty(recovered);
        Assert.Equal(SealedBlob.TagLength, blob.Tag.Length);
    }

    [Fact]
    public void Seal_ProducesTheDocumentedNonceAndTagLengths()
    {
        using var key = KeyMaterial.CreateRandom();

        var blob = _cipher.Seal(key, Encoding.UTF8.GetBytes("value"), Context());

        Assert.Equal(12, blob.Nonce.Length);
        Assert.Equal(16, blob.Tag.Length);
    }
}
