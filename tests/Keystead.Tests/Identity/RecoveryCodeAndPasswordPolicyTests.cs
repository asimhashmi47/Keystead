using System;
using System.Linq;
using Keystead.Infrastructure.Identity;
using Microsoft.Extensions.Options;
using Xunit;

namespace Keystead.Tests.Identity;

public sealed class RecoveryCodeServiceTests
{
    private readonly RecoveryCodeService _service = new();

    [Fact]
    public void Generate_IssuesTenCodes()
    {
        Assert.Equal(10, _service.Generate().Count);
        Assert.Equal(10, _service.CodesPerUser);
    }

    [Fact]
    public void Generate_ProducesDistinctCodes()
    {
        var codes = _service.Generate();

        Assert.Equal(
            10,
            codes.Select(c => c.PlaintextCode).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Generate_ProducesCodesInReadableGroups()
    {
        var code = _service.Generate()[0].PlaintextCode;

        // Four groups of five, so it can be read off a printout without losing your place.
        Assert.Equal(23, code.Length);
        Assert.Equal(4, code.Split('-').Length);
        Assert.All(code.Split('-'), group => Assert.Equal(5, group.Length));
    }

    [Fact]
    public void Generate_AvoidsTheAmbiguousLetters()
    {
        // No I, L, O or U anywhere: a code that has to be retyped must not turn on telling
        // 0 from O or 1 from l.
        foreach (var code in _service.Generate())
        {
            Assert.DoesNotContain('I', code.PlaintextCode);
            Assert.DoesNotContain('L', code.PlaintextCode);
            Assert.DoesNotContain('O', code.PlaintextCode);
            Assert.DoesNotContain('U', code.PlaintextCode);
        }
    }

    [Fact]
    public void Generate_StoresAHashNotThePlaintext()
    {
        var code = _service.Generate()[0];

        Assert.Equal(32, code.Hash.Length);

        // The hash must not be a transparent encoding of the code.
        Assert.DoesNotContain(
            code.PlaintextCode.Replace("-", string.Empty, StringComparison.Ordinal),
            Convert.ToHexStringLower(code.Hash),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AGeneratedCode_VerifiesAgainstItsStoredHash()
    {
        var code = _service.Generate()[0];
        var candidate = _service.HashForComparison(code.PlaintextCode);

        Assert.NotNull(candidate);
        Assert.True(_service.Matches(candidate, code.Hash));
    }

    [Theory]
    [InlineData("lower case")]
    [InlineData("no separators")]
    [InlineData("spaced out")]
    public void VerificationForgivesHowAHumanRetypesIt(string scenario)
    {
        var code = _service.Generate()[0];

        var retyped = scenario switch
        {
            "lower case" => code.PlaintextCode.ToLowerInvariant(),
            "no separators" => code.PlaintextCode.Replace("-", string.Empty, StringComparison.Ordinal),
            "spaced out" => code.PlaintextCode.Replace("-", " ", StringComparison.Ordinal),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
        };

        var candidate = _service.HashForComparison(retyped);

        Assert.NotNull(candidate);
        Assert.True(_service.Matches(candidate, code.Hash));
    }

    [Fact]
    public void VerificationFoldsTheCommonlyConfusedCharacters()
    {
        // Someone reading 0 as O, or 1 as I, should still get in. Refusing them helps nobody
        // and pushes people towards storing the codes somewhere less safe.
        var code = _service.Generate()[0];
        var confused = code.PlaintextCode
            .Replace('0', 'O')
            .Replace('1', 'I');

        var candidate = _service.HashForComparison(confused);

        Assert.NotNull(candidate);
        Assert.True(_service.Matches(candidate, code.Hash));
    }

    [Theory]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("ABCDE-ABCDE-ABCDE-ABCDE-ABCDE")]
    [InlineData("ABCDE-ABCDE-ABCDE-ABC!E")]
    public void AnUnparseableCode_HashesToNull(string code)
    {
        Assert.Null(_service.HashForComparison(code));
    }

    [Fact]
    public void ADifferentCode_DoesNotMatch()
    {
        var codes = _service.Generate();
        var candidate = _service.HashForComparison(codes[0].PlaintextCode);

        Assert.NotNull(candidate);
        Assert.False(_service.Matches(candidate, codes[1].Hash));
    }
}

public sealed class PasswordPolicyTests
{
    private readonly PasswordPolicy _policy =
        new(Options.Create(new PasswordPolicyOptions()));

    [Fact]
    public void TheMinimumLengthIsTwelve()
    {
        Assert.Equal(12, _policy.MinimumLength);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("elevenchars")]
    public void ATooShortPassword_IsRejected(string password)
    {
        var result = _policy.Check(password, null);

        Assert.False(result.IsAcceptable);
        Assert.Contains("12 characters", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void AnExcessivelyLongPassword_IsRejected()
    {
        // The cap exists so a megabyte of input cannot be pushed through Argon2id as a
        // memory-exhaustion lever.
        var result = _policy.Check(new string('x', 300), null);

        Assert.False(result.IsAcceptable);
    }

    [Fact]
    public void AReasonablePassphrase_IsAccepted()
    {
        Assert.True(_policy.Check("thistle harbour velvet onion", null).IsAcceptable);
    }

    [Fact]
    public void NoCompositionRuleIsImposed()
    {
        // Deliberately no "must contain a symbol". That rule reliably produces Password1! and
        // nothing better. A long passphrase of plain lower-case words is accepted.
        Assert.True(_policy.Check("correct pony meadow lantern", null).IsAcceptable);
    }

    [Theory]
    [InlineData("aaaaaaaaaaaaaa")]
    [InlineData("zzzzzzzzzzzz")]
    public void OneCharacterRepeated_IsRejected(string password)
    {
        var result = _policy.Check(password, null);

        Assert.False(result.IsAcceptable);
        Assert.Contains("repeated", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("abcdefghijkl")]
    [InlineData("mnopqrstuvwx")]
    [InlineData("lkjihgfedcba")]
    public void AConsecutiveRun_IsRejected(string password)
    {
        Assert.False(_policy.Check(password, null).IsAcceptable);
    }

    [Theory]
    [InlineData("123456789012345")]
    [InlineData("678901234567")]
    [InlineData("321098765432")]
    public void ADigitRunThatWrapsPastNine_IsAlsoRejected(string password)
    {
        // A plain character-delta check misses these, because the run looks broken at the
        // 9-to-0 boundary. This is the shape someone produces holding the number row down.
        Assert.False(_policy.Check(password, null).IsAcceptable);
    }

    [Fact]
    public void ADigitPasswordThatIsNotARun_IsNotRejectedByTheRunCheck()
    {
        // Guards against the modulo check over-reaching and refusing any long digit string.
        Assert.True(_policy.Check("390218475630", null).IsAcceptable);
    }

    [Theory]
    [InlineData("passwordpassword")]
    [InlineData("correcthorsebatterystaple")]
    [InlineData("qwertyuiop[]")]
    [InlineData("thisismypassword")]
    [InlineData("keysteadadmin")]
    [InlineData("summer2024567")]
    public void AKnownCommonPassword_IsRejectedEvenAtLength(string password)
    {
        // The point of weighting the deny list towards long entries: all of these clear the
        // twelve-character bar and would otherwise sail through.
        var result = _policy.Check(password, null);

        Assert.False(result.IsAcceptable);
        Assert.Contains("commonly used", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDenyListIsCaseInsensitive()
    {
        Assert.False(_policy.Check("PasswordPassword", null).IsAcceptable);
    }

    [Fact]
    public void APasswordContainingTheEmail_IsRejected()
    {
        var result = _policy.Check("ada@example.com-plus-more", "ada@example.com");

        Assert.False(result.IsAcceptable);
        Assert.Contains("email address", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void APasswordContainingTheEmailLocalPart_IsRejected()
    {
        // A password built from the account it protects is worthless against anyone who has
        // seen the member list.
        Assert.False(_policy.Check("adalovelace-rules-ok", "adalovelace@example.com").IsAcceptable);
    }

    [Fact]
    public void AVeryShortLocalPart_IsNotUsedForContainment()
    {
        // Refusing a password because it happens to contain "jo" would be noise.
        Assert.True(_policy.Check("thistle harbour velvet", "jo@example.com").IsAcceptable);
    }

    [Fact]
    public void TheCheckIsUnaffectedByACaseDifferenceInTheEmail()
    {
        Assert.False(_policy.Check("adalovelace-rules-ok", "AdaLovelace@Example.COM").IsAcceptable);
    }

    [Fact]
    public void Check_WithNullPassword_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _policy.Check(null!, null));
    }

    [Fact]
    public void AShortEntryInTheDenyList_IsStillBlockedIfTheFloorIsLowered()
    {
        // The classic top-100 are kept in the list in case an installation lowers the floor.
        var lenient = new PasswordPolicy(
            Options.Create(new PasswordPolicyOptions { MinimumLength = 12 }));

        // "password1234" is twelve characters and in the list.
        Assert.False(lenient.Check("password1234", null).IsAcceptable);
    }
}
