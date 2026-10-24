using System;
using System.Collections.Generic;
using System.Linq;
using Keystead.Web.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Keystead.SecurityTests;

/// <summary>
/// What the reverse proxy configuration is allowed to say, and whether it is heard at all.
/// </summary>
/// <remarks>
/// <para>
/// The second half of that sentence is why this file exists. The section used to bind straight
/// onto <c>ForwardedHeadersOptions</c>, and the configuration binder cannot construct an
/// <c>IPNetwork</c> from a string, so every proxy an operator named was dropped in silence.
/// The deployment kept running, trusted loopback only, and therefore saw the proxy's address as
/// every client's: the IP allowlist on a service identity checked the wrong address and the
/// per-address rate limit treated every caller as one. The setting documented as the fix did
/// nothing, and nothing about a running installation looked wrong.
/// </para>
/// <para>
/// So the first test here is not about refusing bad configuration. It is about the
/// configuration arriving.
/// </para>
/// </remarks>
public sealed class ReverseProxyConfigurationTests
{
    private static ReverseProxyOptions Bound(params (string Key, string Value)[] settings)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings.Select(s =>
                new KeyValuePair<string, string?>($"{ReverseProxyOptions.SectionName}:{s.Key}", s.Value)))
            .Build();

        var options = new ReverseProxyOptions();
        configuration.GetSection(ReverseProxyOptions.SectionName).Bind(options);

        return options;
    }

    [Fact]
    public void WhatTheOperatorConfigures_ActuallyArrives()
    {
        var options = Bound(
            ("KnownNetworks:0", "172.16.0.0/12"),
            ("KnownProxies:0", "10.0.0.5"),
            ("ForwardLimit", "2"));

        Assert.Equal(["172.16.0.0/12"], options.KnownNetworks);
        Assert.Equal(["10.0.0.5"], options.KnownProxies);
        Assert.Equal(2, options.ForwardLimit);
    }

    [Fact]
    public void ANamedProxyNetwork_ReachesTheFrameworkOptions()
    {
        // The end of the path the binder used to break: configuration in, forwarded-headers
        // options out, with the operator's network actually in the trusted list.
        var forwarded = new ForwardedHeadersOptions();

        ReverseProxyConfiguration.Apply(Bound(("KnownNetworks:0", "172.16.0.0/12")), forwarded);

        var network = Assert.Single(forwarded.KnownIPNetworks);

        Assert.Equal("172.16.0.0", network.BaseAddress.ToString());
        Assert.Equal(12, network.PrefixLength);
        Assert.True(forwarded.ForwardedHeaders.HasFlag(ForwardedHeaders.XForwardedFor));
        Assert.True(forwarded.ForwardedHeaders.HasFlag(ForwardedHeaders.XForwardedProto));
    }

    [Fact]
    public void NamingAProxy_ReplacesTheLoopbackDefaultRatherThanAddingToIt()
    {
        // Otherwise anything reaching the application directly on the host — a sibling
        // container, a process on the machine — could still choose its own address.
        var forwarded = new ForwardedHeadersOptions();

        ReverseProxyConfiguration.Apply(Bound(("KnownProxies:0", "10.0.0.5")), forwarded);

        Assert.Empty(forwarded.KnownIPNetworks);
        Assert.Equal(["10.0.0.5"], forwarded.KnownProxies.Select(p => p.ToString()));
    }

    [Fact]
    public void ConfiguringNothing_LeavesTheLoopbackDefaultInPlace()
    {
        var forwarded = new ForwardedHeadersOptions();
        var before = forwarded.KnownIPNetworks.Count;

        ReverseProxyConfiguration.Apply(new ReverseProxyOptions(), forwarded);

        Assert.Equal(before, forwarded.KnownIPNetworks.Count);
        Assert.Equal(1, forwarded.ForwardLimit);
    }

    [Fact]
    public void TheDefaults_AreAccepted()
    {
        // If this ever fails, the check is refusing the configuration the application ships
        // with, which makes it a liability rather than a control.
        Assert.Null(ReverseProxyConfiguration.Validate(new ReverseProxyOptions()));
    }

    [Theory]
    [InlineData("10.0.0.0/8")]
    [InlineData("172.16.0.0/12")]
    [InlineData("192.168.1.0/24")]
    [InlineData("2001:db8::/32")]
    public void ANamedNetwork_IsAccepted(string range)
    {
        Assert.Null(ReverseProxyConfiguration.Validate(Bound(("KnownNetworks:0", range))));
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("0.0.0.0/4")]
    [InlineData("::/0")]
    public void TrustingEveryAddress_RefusesToStart(string range)
    {
        var failure = ReverseProxyConfiguration.Validate(Bound(("KnownNetworks:0", range)));

        Assert.NotNull(failure);
        Assert.Contains(range, failure, StringComparison.Ordinal);
        Assert.Contains("rate limit", failure, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("allowlist", failure, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnOperatorWhoSaysSoExplicitly_IsAllowedToStart()
    {
        Assert.Null(ReverseProxyConfiguration.Validate(Bound(
            ("KnownNetworks:0", "0.0.0.0/0"),
            ("TrustAnyProxyAddress", "true"))));
    }

    [Theory]
    [InlineData("172.16.0.0")]
    [InlineData("not-a-network")]
    [InlineData("172.16.0.0/99")]
    public void AnUnparseableNetwork_RefusesToStartEvenWhenAcknowledged(string entry)
    {
        // A typo is never a decision. Dropping it quietly is what caused the original defect,
        // so the acknowledgement covers a wide range and nothing else.
        var failure = ReverseProxyConfiguration.Validate(Bound(
            ("KnownNetworks:0", entry),
            ("TrustAnyProxyAddress", "true")));

        Assert.NotNull(failure);
        Assert.Contains("CIDR", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnparseableProxyAddress_RefusesToStart()
    {
        var failure = ReverseProxyConfiguration.Validate(Bound(("KnownProxies:0", "10.0.0.5/32")));

        Assert.NotNull(failure);
        Assert.Contains("not an IP address", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void ApplyingAnInvalidConfiguration_Throws()
    {
        // Apply is what runs at startup, so it has to refuse rather than apply a subset.
        var forwarded = new ForwardedHeadersOptions();

        Assert.Throws<InvalidOperationException>(
            () => ReverseProxyConfiguration.Apply(Bound(("KnownNetworks:0", "0.0.0.0/0")), forwarded));
    }
}
