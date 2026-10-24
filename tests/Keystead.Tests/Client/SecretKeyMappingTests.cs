using System;
using Keystead.Client;
using Xunit;

namespace Keystead.Tests.Client;

/// <summary>
/// The name-to-configuration-key translation.
/// </summary>
/// <remarks>
/// Small and pure, and worth testing carefully: this is the piece that decides whether
/// <c>GetConnectionString("Default")</c> finds anything, and a subtle mistake here produces a
/// null connection string rather than an error.
/// </remarks>
public sealed class SecretKeyMappingTests
{
    [Theory]
    [InlineData("ConnectionStrings--Default", "ConnectionStrings:Default")]
    [InlineData("ConnectionStrings__Default", "ConnectionStrings:Default")]
    [InlineData("Serilog--MinimumLevel--Default", "Serilog:MinimumLevel:Default")]
    [InlineData("Serilog__MinimumLevel__Default", "Serilog:MinimumLevel:Default")]
    [InlineData("ApiKey", "ApiKey")]
    [InlineData("Nested--Deeply--Very--Much", "Nested:Deeply:Very:Much")]
    public void ASecretNameBecomesAConfigurationKey(string name, string expected)
    {
        Assert.Equal(expected, SecretKeyMapping.ToConfigurationKey(name));
    }

    [Fact]
    public void BothSeparatorsCanAppearInOneName()
    {
        // Someone migrating from environment variables may half-rename things. Both forms map
        // to the same separator, so a mixed name still resolves.
        Assert.Equal(
            "A:B:C",
            SecretKeyMapping.ToConfigurationKey("A--B__C"));
    }

    [Fact]
    public void DoubleUnderscoreIsHandledBeforeDoubleHyphen()
    {
        // Order matters. Processing hyphens first would leave a stray separator behind in a
        // name where the two forms overlap.
        Assert.Equal("A:B", SecretKeyMapping.ToConfigurationKey("A__B"));
        Assert.DoesNotContain("_", SecretKeyMapping.ToConfigurationKey("A__B"), StringComparison.Ordinal);
    }

    [Fact]
    public void ASingleHyphenOrUnderscoreIsLeftAlone()
    {
        // A single separator is a legitimate part of a name, not a section break.
        Assert.Equal("my-api_key", SecretKeyMapping.ToConfigurationKey("my-api_key"));
    }

    [Fact]
    public void LeadingAndTrailingSeparatorsAreTrimmed()
    {
        // A key beginning or ending with a colon would create an empty configuration section,
        // which binds to nothing and is confusing to debug.
        Assert.Equal("Thing", SecretKeyMapping.ToConfigurationKey("--Thing--"));
    }

    [Fact]
    public void APrefixCanBeStripped()
    {
        Assert.Equal(
            "ConnectionStrings:Default",
            SecretKeyMapping.ToConfigurationKey("myapp--ConnectionStrings--Default", "myapp--"));
    }

    [Fact]
    public void PrefixStrippingIsCaseInsensitive()
    {
        Assert.Equal(
            "ApiKey",
            SecretKeyMapping.ToConfigurationKey("MyApp--ApiKey", "myapp--"));
    }

    [Fact]
    public void APrefixThatDoesNotMatchIsLeftAlone()
    {
        Assert.Equal(
            "Other:ApiKey",
            SecretKeyMapping.ToConfigurationKey("Other--ApiKey", "myapp--"));
    }

    [Theory]
    [InlineData("ConnectionStrings:Default", "ConnectionStrings--Default")]
    [InlineData("ApiKey", "ApiKey")]
    [InlineData("A:B:C", "A--B--C")]
    public void AConfigurationKeyBecomesASecretName(string key, string expected)
    {
        Assert.Equal(expected, SecretKeyMapping.ToSecretName(key));
    }

    [Fact]
    public void TheRoundTripIsStable()
    {
        const string Key = "Serilog:MinimumLevel:Default";

        Assert.Equal(
            Key,
            SecretKeyMapping.ToConfigurationKey(SecretKeyMapping.ToSecretName(Key)));
    }

    [Theory]
    [InlineData("ConnectionStrings--Default", "CONNECTIONSTRINGS__DEFAULT")]
    [InlineData("ApiKey", "APIKEY")]
    [InlineData("A--B--C", "A__B__C")]
    public void ASecretNameBecomesAnEnvironmentVariable(string name, string expected)
    {
        Assert.Equal(expected, SecretKeyMapping.ToEnvironmentVariable(name));
    }

    [Theory]
    [InlineData("ConnectionStrings--Default", true)]
    [InlineData("ApiKey", true)]
    [InlineData("A_B", true)]
    [InlineData("has space", false)]
    [InlineData("has-hyphen", false)]
    [InlineData("has.dot", false)]
    [InlineData("1LeadingDigit", false)]
    [InlineData("", false)]
    public void NamesThatCannotBeEnvironmentVariablesAreRecognised(string name, bool expected)
    {
        // The CLI skips these rather than mangling them: a silently renamed variable is worse
        // than an absent one, because the child process looks correctly configured.
        Assert.Equal(expected, SecretKeyMapping.CanBeEnvironmentVariable(name));
    }

    [Fact]
    public void NullsAreRejectedRatherThanTreatedAsEmpty()
    {
        Assert.Throws<ArgumentNullException>(() => SecretKeyMapping.ToConfigurationKey(null!));
        Assert.Throws<ArgumentNullException>(() => SecretKeyMapping.ToSecretName(null!));
        Assert.Throws<ArgumentNullException>(() => SecretKeyMapping.ToEnvironmentVariable(null!));
        Assert.Throws<ArgumentNullException>(() => SecretKeyMapping.CanBeEnvironmentVariable(null!));
    }
}
