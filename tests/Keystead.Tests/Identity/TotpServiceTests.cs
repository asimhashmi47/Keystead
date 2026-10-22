using System;
using System.Linq;
using Keystead.Application.Identity;
using Keystead.Infrastructure.Cryptography;
using Keystead.Infrastructure.Identity;
using Keystead.Tests.TestDoubles;
using OtpNet;
using Xunit;

namespace Keystead.Tests.Identity;

public sealed class TotpServiceTests : IDisposable
{
    private static readonly Guid UserId = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid OtherUserId = Guid.Parse("99999999-8888-7777-6666-555555555555");

    private readonly InMemoryMasterKeyProvider _masterKeys = new();
    private readonly TotpService _service;

    public TotpServiceTests() =>
        _service = new TotpService(new AesGcmCipher(), _masterKeys);

    public void Dispose() => _masterKeys.Dispose();

    /// <summary>
    /// Produces a valid code from the enrolment's displayed secret, the way an authenticator
    /// app would.
    /// </summary>
    private static string CurrentCode(TotpEnrolment enrolment)
    {
        var seed = Base32Encoding.ToBytes(enrolment.SharedSecretBase32);
        return new Totp(seed, step: 30, mode: OtpHashMode.Sha1, totpSize: 6).ComputeTotp();
    }

    [Fact]
    public void CreateEnrolment_ProducesAUsableSecretAndUri()
    {
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");

        // 160 bits in base32 is 32 characters.
        Assert.Equal(32, enrolment.SharedSecretBase32.Length);
        Assert.StartsWith("otpauth://totp/Keystead:", enrolment.ProvisioningUri, StringComparison.Ordinal);
        Assert.Contains("issuer=Keystead", enrolment.ProvisioningUri, StringComparison.Ordinal);
        Assert.Contains("period=30", enrolment.ProvisioningUri, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateEnrolment_SealsTheSeedRatherThanStoringIt()
    {
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");
        var plaintextSeed = Base32Encoding.ToBytes(enrolment.SharedSecretBase32);

        // The stored ciphertext must not be the seed. A plaintext TOTP column would let anyone
        // with the database mint valid second factors.
        Assert.NotEqual(plaintextSeed, enrolment.Seed.Ciphertext);
        Assert.Equal(12, enrolment.Seed.Nonce.Length);
        Assert.Equal(16, enrolment.Seed.Tag.Length);
    }

    [Fact]
    public void CreateEnrolment_ProducesADifferentSeedEachTime()
    {
        var first = _service.CreateEnrolment(UserId, "ada@example.com");
        var second = _service.CreateEnrolment(UserId, "ada@example.com");

        Assert.NotEqual(first.SharedSecretBase32, second.SharedSecretBase32);
    }

    [Fact]
    public void Verify_AcceptsACurrentCode()
    {
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");

        var result = _service.Verify(UserId, enrolment.Seed, CurrentCode(enrolment), null);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_RejectsAWrongCode()
    {
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");

        Assert.False(_service.Verify(UserId, enrolment.Seed, "000000", null).IsValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("abcdef")]
    public void Verify_RejectsMalformedInputWithoutThrowing(string code)
    {
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");

        Assert.False(_service.Verify(UserId, enrolment.Seed, code, null).IsValid);
    }

    [Fact]
    public void Verify_RejectsACodeAlreadyUsed()
    {
        // The replay guard. RFC 6238 would leave this code valid for the rest of its step, so
        // a code captured by a phishing proxy would still work.
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");
        var code = CurrentCode(enrolment);

        var first = _service.Verify(UserId, enrolment.Seed, code, null);
        Assert.True(first.IsValid);

        var replay = _service.Verify(UserId, enrolment.Seed, code, first.Window);
        Assert.False(replay.IsValid);
    }

    [Fact]
    public void Verify_RejectsACodeFromAWindowAlreadyPassed()
    {
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");
        var code = CurrentCode(enrolment);

        var result = _service.Verify(UserId, enrolment.Seed, code, null);

        // Pretending a later window was already consumed must reject this earlier code too,
        // otherwise the guard could be walked backwards.
        var stale = _service.Verify(UserId, enrolment.Seed, code, result.Window + 5);

        Assert.False(stale.IsValid);
    }

    [Fact]
    public void Verify_RejectsASeedMovedToAnotherUsersRow()
    {
        // The AAD binding. Copying a seed row from one account to another must not produce a
        // working second factor on the target account.
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");

        var result = _service.Verify(OtherUserId, enrolment.Seed, CurrentCode(enrolment), null);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Verify_RejectsATamperedSeed()
    {
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");
        var tampered = enrolment.Seed.Ciphertext.ToArray();
        tampered[0] ^= 0x01;

        var seed = new StoredTotpSeed(
            tampered,
            enrolment.Seed.Nonce,
            enrolment.Seed.Tag,
            enrolment.Seed.MasterKeyVersion);

        Assert.False(_service.Verify(UserId, seed, CurrentCode(enrolment), null).IsValid);
    }

    [Fact]
    public void Verify_FailsWhenTheSealingMasterKeyGenerationIsNotLoaded()
    {
        // A configuration problem, surfaced as a failure rather than an exception so it cannot
        // be used to tell accounts apart. It means a retired master key was dropped too early.
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");

        var seed = new StoredTotpSeed(
            enrolment.Seed.Ciphertext,
            enrolment.Seed.Nonce,
            enrolment.Seed.Tag,
            MasterKeyVersion: 999);

        Assert.False(_service.Verify(UserId, seed, CurrentCode(enrolment), null).IsValid);
    }

    [Fact]
    public void Verify_StillWorksAcrossAMasterKeyRotation()
    {
        // The seed records which generation sealed it, so rotating the master key does not
        // invalidate existing enrolments while the re-wrap job works through.
        var enrolment = _service.CreateEnrolment(UserId, "ada@example.com");
        var sealedUnderV1 = enrolment.Seed;

        _masterKeys.RotateToNewVersion();

        var result = _service.Verify(UserId, sealedUnderV1, CurrentCode(enrolment), null);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void CreateEnrolment_WithNoAccountLabel_Throws()
    {
        Assert.Throws<ArgumentException>(() => _service.CreateEnrolment(UserId, "   "));
    }
}
