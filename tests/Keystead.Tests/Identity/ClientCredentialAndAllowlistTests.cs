using System;
using System.Linq;
using Keystead.Application.Identity;
using Xunit;

namespace Keystead.Tests.Identity;

public sealed class ClientCredentialTests
{
    [Fact]
    public void ACreatedSecret_IsWellFormedAndPrefixed()
    {
        var (secret, _) = ClientCredential.Create();

        Assert.StartsWith(ClientCredential.LivePrefix, secret, StringComparison.Ordinal);
        Assert.True(ClientCredential.IsWellFormed(secret));
    }

    [Fact]
    public void ATestSecret_UsesTheTestPrefix()
    {
        var (secret, _) = ClientCredential.Create(ClientCredential.TestPrefix);

        Assert.StartsWith(ClientCredential.TestPrefix, secret, StringComparison.Ordinal);
        Assert.True(ClientCredential.IsWellFormed(secret));
    }

    [Fact]
    public void AnUnknownPrefix_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => ClientCredential.Create("ksd_staging_"));
    }

    [Fact]
    public void EverySecretIsDistinct()
    {
        var secrets = Enumerable.Range(0, 200)
            .Select(_ => ClientCredential.Create().Secret)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(200, secrets.Count);
    }

    [Fact]
    public void ASecretCarriesTheExpectedEntropy()
    {
        var (secret, _) = ClientCredential.Create();

        // 32 bytes at 5 bits per base32 character is 52 characters, after the prefix and
        // before the checksum separator.
        var body = secret[..secret.LastIndexOf('_')];
        var random = body[ClientCredential.LivePrefix.Length..];

        Assert.Equal(52, random.Length);
    }

    [Fact]
    public void TheStoredHashIsNotTheSecret()
    {
        var (secret, hash) = ClientCredential.Create();

        Assert.Equal(32, hash.Length);
        Assert.DoesNotContain(
            secret,
            Convert.ToHexStringLower(hash),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheHashVerifiesAgainstItsSecret()
    {
        var (secret, hash) = ClientCredential.Create();

        Assert.True(ClientCredential.Matches(ClientCredential.Hash(secret), hash));
    }

    [Fact]
    public void ADifferentSecretDoesNotMatch()
    {
        var (_, hash) = ClientCredential.Create();
        var (other, _) = ClientCredential.Create();

        Assert.False(ClientCredential.Matches(ClientCredential.Hash(other), hash));
    }

    [Fact]
    public void ATruncatedSecret_FailsItsChecksum()
    {
        // The reason the checksum exists: a developer who pasted all but the last character
        // is told the credential is malformed rather than that authentication failed.
        var (secret, _) = ClientCredential.Create();

        Assert.False(ClientCredential.IsWellFormed(secret[..^1]));
    }

    [Fact]
    public void ASecretWithATamperedBody_FailsItsChecksum()
    {
        var (secret, _) = ClientCredential.Create();
        var characters = secret.ToCharArray();

        // Flip a character inside the random body, leaving the checksum alone.
        var index = ClientCredential.LivePrefix.Length + 3;
        characters[index] = characters[index] == 'A' ? 'B' : 'A';

        Assert.False(ClientCredential.IsWellFormed(new string(characters)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ksd_live_")]
    [InlineData("ksd_live_ABC")]
    [InlineData("nothing_like_it")]
    [InlineData("ksd_live_ABCDEF_TOOLONGCHECKSUM")]
    public void Rubbish_IsNotWellFormed(string? candidate)
    {
        Assert.False(ClientCredential.IsWellFormed(candidate));
    }

    [Fact]
    public void AClientIdIsShapedDifferentlyFromASecret()
    {
        // So the two cannot be confused in configuration or in a support conversation.
        var clientId = ClientCredential.CreateClientId();
        var (secret, _) = ClientCredential.Create();

        Assert.StartsWith("ksid_", clientId, StringComparison.Ordinal);
        Assert.False(ClientCredential.IsWellFormed(clientId));
        Assert.False(secret.StartsWith("ksid_", StringComparison.Ordinal));
    }

    [Fact]
    public void ASecretContainsNoAmbiguousCharacters()
    {
        var (secret, _) = ClientCredential.Create();
        var body = secret[ClientCredential.LivePrefix.Length..];

        Assert.DoesNotContain('I', body);
        Assert.DoesNotContain('L', body);
        Assert.DoesNotContain('O', body);
        Assert.DoesNotContain('U', body);
    }
}

public sealed class IpAllowlistTests
{
    [Fact]
    public void AnEmptyAllowlistAllowsEverything()
    {
        // The default. Requiring an allowlist would stop most people getting started.
        Assert.True(IpAllowlist.IsAllowed([], "203.0.113.5"));
        Assert.True(IpAllowlist.IsAllowed([], "2001:db8::1"));
    }

    [Fact]
    public void AnExactAddressMatches()
    {
        Assert.True(IpAllowlist.IsAllowed(["203.0.113.5"], "203.0.113.5"));
        Assert.False(IpAllowlist.IsAllowed(["203.0.113.5"], "203.0.113.6"));
    }

    [Theory]
    [InlineData("203.0.113.0/24", "203.0.113.1", true)]
    [InlineData("203.0.113.0/24", "203.0.113.255", true)]
    [InlineData("203.0.113.0/24", "203.0.114.1", false)]
    [InlineData("203.0.113.0/25", "203.0.113.100", true)]
    [InlineData("203.0.113.0/25", "203.0.113.200", false)]
    [InlineData("203.0.113.128/25", "203.0.113.200", true)]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("0.0.0.0/0", "198.51.100.7", true)]
    [InlineData("203.0.113.5/32", "203.0.113.5", true)]
    [InlineData("203.0.113.5/32", "203.0.113.6", false)]
    public void Ipv4RangesMatchOnTheirPrefix(string range, string candidate, bool expected)
    {
        Assert.Equal(expected, IpAllowlist.IsAllowed([range], candidate));
    }

    [Theory]
    [InlineData("2001:db8::/32", "2001:db8::1", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    [InlineData("2001:db8:abcd::/48", "2001:db8:abcd::5", true)]
    [InlineData("2001:db8:abcd::/48", "2001:db8:abce::5", false)]
    public void Ipv6RangesMatchOnTheirPrefix(string range, string candidate, bool expected)
    {
        Assert.Equal(expected, IpAllowlist.IsAllowed([range], candidate));
    }

    [Fact]
    public void AnIpv4AddressMappedIntoIpv6StillMatchesAnIpv4Rule()
    {
        // Without this the control would silently stop working the day the server started
        // accepting IPv6 connections, because the same client would arrive as ::ffff:x.x.x.x.
        Assert.True(IpAllowlist.IsAllowed(["203.0.113.0/24"], "::ffff:203.0.113.5"));
        Assert.True(IpAllowlist.IsAllowed(["203.0.113.5"], "::ffff:203.0.113.5"));
    }

    [Fact]
    public void AnAddressFamilyMismatchDoesNotMatch()
    {
        Assert.False(IpAllowlist.IsAllowed(["2001:db8::/32"], "203.0.113.5"));
        Assert.False(IpAllowlist.IsAllowed(["203.0.113.0/24"], "2001:db8::1"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-address")]
    [InlineData("999.999.999.999")]
    public void AnUnreadableAddressIsRefusedWhenAnAllowlistExists(string? candidate)
    {
        // Fails closed. A network restriction that cannot determine the address and allows the
        // request anyway is not a restriction.
        Assert.False(IpAllowlist.IsAllowed(["203.0.113.0/24"], candidate));
    }

    [Theory]
    [InlineData("203.0.113.0/33")]
    [InlineData("203.0.113.0/-1")]
    [InlineData("203.0.113.0/abc")]
    [InlineData("garbage")]
    [InlineData("")]
    public void AMalformedEntryMatchesNothing(string entry)
    {
        Assert.False(IpAllowlist.IsAllowed([entry], "203.0.113.5"));
    }

    [Fact]
    public void AnyEntryMatchingIsEnough()
    {
        string[] allowlist = ["198.51.100.0/24", "203.0.113.5", "2001:db8::/32"];

        Assert.True(IpAllowlist.IsAllowed(allowlist, "203.0.113.5"));
        Assert.True(IpAllowlist.IsAllowed(allowlist, "198.51.100.77"));
        Assert.True(IpAllowlist.IsAllowed(allowlist, "2001:db8::9"));
        Assert.False(IpAllowlist.IsAllowed(allowlist, "192.0.2.1"));
    }

    [Fact]
    public void WhitespaceAroundAnEntryIsForgiven()
    {
        Assert.True(IpAllowlist.IsAllowed(["  203.0.113.0/24  "], "203.0.113.5"));
    }
}
