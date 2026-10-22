using System;
using System.Text;
using Keystead.Application.Cryptography;
using Xunit;

namespace Keystead.Tests.Cryptography;

/// <summary>
/// The AAD encoding is a security boundary, not a formatting detail: if two different contexts
/// can produce the same bytes, the row-swap defence has a hole in it.
/// </summary>
public sealed class CryptoContextTests
{
    private static readonly Guid A = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid B = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static readonly Guid C = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
    private static readonly Guid D = Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");

    [Fact]
    public void SameInputs_ProduceIdenticalAad()
    {
        var first = CryptoContext.ForSecretValue(A, B, C, D);
        var second = CryptoContext.ForSecretValue(A, B, C, D);

        Assert.True(first.Aad.SequenceEqual(second.Aad));
        Assert.Equal(first, second);
    }

    [Fact]
    public void DifferentPurpose_ProducesDifferentAad()
    {
        var value = CryptoContext.ForSecretValue(A, B, C, D);
        var dataKey = CryptoContext.ForDataKey(A, B, C, D, kekVersion: 0);

        Assert.False(value.Aad.SequenceEqual(dataKey.Aad));
    }

    /// <summary>
    /// Shuffling the identifiers between positions must change the AAD. A delimiter-joined
    /// encoding could let a vault id and a secret id trade places and still hash the same way;
    /// length prefixing is what prevents it.
    /// </summary>
    [Fact]
    public void SwappingIdentifierPositions_ProducesDifferentAad()
    {
        var original = CryptoContext.ForSecretValue(A, B, C, D);
        var shuffled = CryptoContext.ForSecretValue(B, A, C, D);

        Assert.False(original.Aad.SequenceEqual(shuffled.Aad));
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(2, 3)]
    [InlineData(1, 100)]
    public void DifferentKekVersion_ProducesDifferentAad(int first, int second)
    {
        // Binding the key generation means a re-wrapped row cannot be rolled back to its
        // previous wrapping by restoring the old blob.
        var a = CryptoContext.ForDataKey(A, B, C, D, first);
        var b = CryptoContext.ForDataKey(A, B, C, D, second);

        Assert.False(a.Aad.SequenceEqual(b.Aad));
    }

    [Fact]
    public void VaultKekContext_DistinguishesMasterKeyGeneration()
    {
        var underV1 = CryptoContext.ForVaultKek(A, B, kekVersion: 1, masterKeyVersion: 1);
        var underV2 = CryptoContext.ForVaultKek(A, B, kekVersion: 1, masterKeyVersion: 2);

        Assert.False(underV1.Aad.SequenceEqual(underV2.Aad));
    }

    [Fact]
    public void VaultKekContext_DistinguishesKekGenerationFromMasterGeneration()
    {
        // The two version numbers are combined into one field, so this guards against a
        // collision in that packing: (master 1, kek 2) must not equal (master 2, kek 1).
        var a = CryptoContext.ForVaultKek(A, B, kekVersion: 2, masterKeyVersion: 1);
        var b = CryptoContext.ForVaultKek(A, B, kekVersion: 1, masterKeyVersion: 2);

        Assert.False(a.Aad.SequenceEqual(b.Aad));
    }

    [Fact]
    public void Aad_CarriesTheSchemeTag()
    {
        var context = CryptoContext.ForSecretValue(A, B, C, D);
        var bytes = context.Aad.ToArray();

        Assert.Contains(
            CryptoContext.Scheme,
            Encoding.UTF8.GetString(bytes),
            StringComparison.Ordinal);
    }

    [Fact]
    public void TotpSeedContext_IsPerUser()
    {
        var first = CryptoContext.ForTotpSeed(A, masterKeyVersion: 1);
        var second = CryptoContext.ForTotpSeed(B, masterKeyVersion: 1);

        Assert.False(first.Aad.SequenceEqual(second.Aad));
    }

    [Fact]
    public void TotpSeedAndSigningKey_AreDistinctEvenForTheSameId()
    {
        var totp = CryptoContext.ForTotpSeed(A, masterKeyVersion: 1);
        var signing = CryptoContext.ForSigningKey(A, masterKeyVersion: 1);

        Assert.False(totp.Aad.SequenceEqual(signing.Aad));
    }
}
