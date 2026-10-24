using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

// The framework's own IPNetwork is deprecated in favour of the one in System.Net, and both are
// in scope here because ForwardedHeaders lives in the former's namespace.
using IPNetwork = System.Net.IPNetwork;

namespace Keystead.Web.Security;

/// <summary>
/// Turns <see cref="ReverseProxyOptions"/> into forwarded-headers configuration, or refuses.
/// </summary>
/// <remarks>
/// Two jobs, kept apart so both can be tested without a host: deciding whether a configuration
/// is acceptable, and applying one that is.
/// </remarks>
public static class ReverseProxyConfiguration
{
    /// <summary>
    /// The narrowest IPv4 prefix still treated as naming a network rather than everything.
    /// </summary>
    /// <remarks>
    /// A <c>/8</c> is already sixteen million addresses, far wider than any proxy fleet. The
    /// threshold is not trying to judge what size is sensible — that depends on the estate —
    /// but to catch the two values people actually paste in, <c>0.0.0.0/0</c> and <c>::/0</c>,
    /// and anything close enough to them to mean the same thing.
    /// </remarks>
    public const int MinimumIPv4PrefixLength = 8;

    /// <summary>The equivalent threshold for IPv6.</summary>
    public const int MinimumIPv6PrefixLength = 32;

    /// <summary>
    /// Checks a configuration before anything is applied.
    /// </summary>
    /// <param name="options">The operator's settings.</param>
    /// <returns>The reason the process must not start, or null when it may.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    public static string? Validate(ReverseProxyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var problems = new List<string>();

        foreach (var entry in options.KnownNetworks)
        {
            if (!TryParseNetwork(entry, out var network))
            {
                problems.Add(string.Format(
                    CultureInfo.InvariantCulture,
                    "KnownNetworks entry '{0}' is not a CIDR range such as 172.16.0.0/12.",
                    entry));

                continue;
            }

            // Unparseable is always fatal. Too wide is fatal unless the operator said
            // otherwise, because there is a real deployment where it is the right answer.
            if (!options.TrustAnyProxyAddress && IsTooWide(network))
            {
                problems.Add(string.Format(
                    CultureInfo.InvariantCulture,
                    "KnownNetworks entry '{0}' is wide enough that any client could choose the "
                    + "address Keystead sees, which defeats the per-address rate limits and the "
                    + "IP allowlist on service identities. Name the proxy's own network, or set "
                    + "{1}:TrustAnyProxyAddress to true if every connection really does "
                    + "terminate at a proxy that overwrites X-Forwarded-For.",
                    entry,
                    ReverseProxyOptions.SectionName));
            }
        }

        problems.AddRange(options.KnownProxies
            .Where(entry => !IPAddress.TryParse(entry, out _))
            .Select(entry => string.Format(
                CultureInfo.InvariantCulture,
                "KnownProxies entry '{0}' is not an IP address.",
                entry)));

        return problems.Count == 0 ? null : string.Join(" ", problems);
    }

    /// <summary>
    /// Applies a validated configuration.
    /// </summary>
    /// <param name="options">The operator's settings.</param>
    /// <param name="forwarded">The framework options to populate.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="InvalidOperationException">The configuration is not valid.</exception>
    public static void Apply(ReverseProxyOptions options, ForwardedHeadersOptions forwarded)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(forwarded);

        if (Validate(options) is { } failure)
        {
            throw new InvalidOperationException(failure);
        }

        // The protocol as well as the address: without it the application believes every
        // request behind a TLS-terminating proxy arrived over plain HTTP, and the redirect and
        // the Secure cookie policy both behave accordingly.
        forwarded.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        forwarded.ForwardLimit = options.ForwardLimit;

        if (options.KnownNetworks.Count == 0 && options.KnownProxies.Count == 0)
        {
            // Nothing named, so the framework defaults stand: loopback only, which trusts
            // nothing a remote client can reach.
            return;
        }

        // Naming a proxy replaces the defaults rather than adding to them. Keeping loopback
        // trusted alongside a named proxy would mean anything that reaches the application
        // directly on the host — another container on the same bridge, a process on the
        // machine — could still set its own address.
        forwarded.KnownIPNetworks.Clear();
        forwarded.KnownProxies.Clear();

        foreach (var entry in options.KnownNetworks)
        {
            // Already validated above, which is why this cannot fail; parsing again rather
            // than carrying the parsed values through keeps Validate free of side effects.
            forwarded.KnownIPNetworks.Add(IPNetwork.Parse(entry));
        }

        foreach (var entry in options.KnownProxies)
        {
            forwarded.KnownProxies.Add(IPAddress.Parse(entry));
        }
    }

    private static bool IsTooWide(IPNetwork network)
    {
        var floor = network.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6
            ? MinimumIPv6PrefixLength
            : MinimumIPv4PrefixLength;

        return network.PrefixLength < floor;
    }

    /// <summary>
    /// Parses a CIDR range, and only a CIDR range.
    /// </summary>
    /// <remarks>
    /// A bare address here would be a <c>KnownProxies</c> entry. Silently treating it as a
    /// <c>/32</c> would hide a configuration mistake rather than report it.
    /// </remarks>
    private static bool TryParseNetwork(string entry, out IPNetwork network) =>
        IPNetwork.TryParse(entry, out network);
}
