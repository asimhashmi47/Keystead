using System;
using Keystead.Application.Abstractions;
using Keystead.Infrastructure.Cryptography;
using Keystead.Tests.TestDoubles;
using Microsoft.Extensions.Options;
using Xunit;

namespace Keystead.Tests.Cryptography;

public sealed class Argon2idPasswordHasherTests : IDisposable
{
    private readonly InMemoryMasterKeyProvider _masterKeys = new();

    /// <summary>
    /// Test parameters sit at the OWASP floor rather than the production default, so the suite
    /// stays fast. One test below deliberately runs at the shipped parameters to prove they
    /// work and are not merely configured.
    /// </summary>
    private static Argon2idOptions FastOptions() => new()
    {
        MemoryKib = 19_456,
        Iterations = 2,
        Parallelism = 1,
        SaltLength = 16,
        HashLength = 32,
    };

    private Argon2idPasswordHasher Create(Argon2idOptions? options = null) =>
        new(Options.Create(options ?? FastOptions()), _masterKeys);

    public void Dispose() => _masterKeys.Dispose();

    [Fact]
    public void Hash_ThenVerify_Succeeds()
    {
        var hasher = Create();
        var digest = hasher.Hash("correct horse battery staple");

        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.Verify("correct horse battery staple", digest));
    }

    [Fact]
    public void Verify_WithWrongPassword_Fails()
    {
        var hasher = Create();
        var digest = hasher.Hash("correct horse battery staple");

        Assert.Equal(
            PasswordVerificationResult.Failed,
            hasher.Verify("correct horse battery stapler", digest));
    }

    [Fact]
    public void Hash_ProducesADifferentDigestForTheSamePassword()
    {
        // A fresh salt per hash is what stops a precomputed table and stops two users with the
        // same password being visibly identical in the database.
        var hasher = Create();

        Assert.NotEqual(
            hasher.Hash("same password"),
            hasher.Hash("same password"));
    }

    [Fact]
    public void Hash_EmitsThePhcFormatWithItsParameters()
    {
        var hasher = Create();
        var digest = hasher.Hash("password");

        Assert.StartsWith("$argon2id$v=19$m=19456,t=2,p=1$", digest, StringComparison.Ordinal);
        Assert.Equal(6, digest.Split('$').Length);
    }

    [Fact]
    public void Hash_NeverContainsThePassword()
    {
        var hasher = Create();
        const string Password = "a-very-distinctive-password-string";

        Assert.DoesNotContain(Password, hasher.Hash(Password), StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_AgainstADigestFromWeakerParameters_AsksForARehash()
    {
        // Raising the cost must not lock anyone out. The old digest still verifies, and the
        // caller is told to upgrade it while it holds the plaintext.
        var weak = Create(new Argon2idOptions
        {
            MemoryKib = 19_456,
            Iterations = 2,
            Parallelism = 1,
        });

        var digest = weak.Hash("password");

        var strong = Create(new Argon2idOptions
        {
            MemoryKib = 32_768,
            Iterations = 3,
            Parallelism = 1,
        });

        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            strong.Verify("password", digest));
    }

    [Fact]
    public void Verify_AgainstADigestFromStrongerParameters_DoesNotAskForARehash()
    {
        var strong = Create(new Argon2idOptions
        {
            MemoryKib = 32_768,
            Iterations = 3,
            Parallelism = 1,
        });

        var digest = strong.Hash("password");

        var weak = Create(new Argon2idOptions
        {
            MemoryKib = 19_456,
            Iterations = 2,
            Parallelism = 1,
        });

        Assert.Equal(PasswordVerificationResult.Success, weak.Verify("password", digest));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-digest")]
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1$onlyfourfields")]
    [InlineData("$argon2i$v=19$m=19456,t=2,p=1$c2FsdA==$aGFzaA==")]
    [InlineData("$argon2id$v=16$m=19456,t=2,p=1$c2FsdA==$aGFzaA==")]
    [InlineData("$argon2id$v=19$m=abc,t=2,p=1$c2FsdA==$aGFzaA==")]
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1$not!base64$aGFzaA==")]
    [InlineData("$argon2id$v=19$m=19456,t=2,p=1$$")]
    public void Verify_WithAMalformedDigest_FailsWithoutThrowing(string digest)
    {
        // A corrupt or hand-edited row must be a plain failure. If it threw, the resulting
        // error response would distinguish "this account exists but its row is broken" from
        // "no such account", which is a user-enumeration oracle.
        var hasher = Create();

        Assert.Equal(PasswordVerificationResult.Failed, hasher.Verify("password", digest));
    }

    [Fact]
    public void Verify_WithADifferentPepper_Fails()
    {
        // This is the pepper doing its job: the digest is unverifiable without the key-side
        // input, so a stolen database alone cannot be attacked offline.
        using var withPepper = new InMemoryMasterKeyProvider(pepper: [1, 2, 3, 4]);
        using var withOther = new InMemoryMasterKeyProvider(pepper: [9, 9, 9, 9]);

        var options = Options.Create(FastOptions());
        var a = new Argon2idPasswordHasher(options, withPepper);
        var b = new Argon2idPasswordHasher(options, withOther);

        var digest = a.Hash("password");

        Assert.Equal(PasswordVerificationResult.Success, a.Verify("password", digest));
        Assert.Equal(PasswordVerificationResult.Failed, b.Verify("password", digest));
    }

    [Fact]
    public void Verify_WhenAPepperIsAddedLater_FailsForExistingDigests()
    {
        // Documented consequence: introducing a pepper invalidates every existing hash, so it
        // is a setup-time decision, not a later tweak. DEPLOYMENT.md says so, and this test
        // makes sure the behaviour matches the documentation.
        using var without = new InMemoryMasterKeyProvider();
        var options = Options.Create(FastOptions());
        var digest = new Argon2idPasswordHasher(options, without).Hash("password");

        using var with = new InMemoryMasterKeyProvider(pepper: [7, 7, 7, 7]);

        Assert.Equal(
            PasswordVerificationResult.Failed,
            new Argon2idPasswordHasher(options, with).Verify("password", digest));
    }

    [Fact]
    public void Hash_AtTheShippedParameters_RoundTrips()
    {
        // Slower than the rest of the suite on purpose: the production defaults must be proven
        // to work, not just declared.
        var hasher = Create(new Argon2idOptions());
        var digest = hasher.Hash("production parameters");

        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=1$", digest, StringComparison.Ordinal);
        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.Verify("production parameters", digest));
    }

    [Fact]
    public void Hash_WithNull_Throws()
    {
        var hasher = Create();

        Assert.Throws<ArgumentNullException>(() => hasher.Hash(null!));
    }

    [Fact]
    public void Verify_HandlesUnicodePasswords()
    {
        var hasher = Create();
        const string Password = "paßwörd-日本語-🔐";

        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.Verify(Password, hasher.Hash(Password)));
    }
}
