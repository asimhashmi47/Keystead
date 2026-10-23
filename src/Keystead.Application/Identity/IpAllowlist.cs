using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Keystead.Application.Identity;

/// <summary>
/// Matches a client address against a service identity's allowlist.
/// </summary>
/// <remarks>
/// <para>
/// Accepts plain addresses and CIDR ranges, IPv4 and IPv6. An empty allowlist means no network
/// restriction, which is the default: requiring one would stop most people getting started, and
/// a half-configured allowlist that silently matched nothing would be worse than none.
/// </para>
/// <para>
/// This only means anything if the address it is given is real. Behind a reverse proxy the
/// address comes from a forwarded header, which any client can set, so the forwarded-headers
/// middleware is configured to trust only known proxies. An operator who widens that list
/// carelessly disables this control without disabling the appearance of it, which is why
/// DEPLOYMENT.md says so explicitly.
/// </para>
/// </remarks>
public static class IpAllowlist
{
    /// <summary>Whether an address is permitted by an allowlist.</summary>
    /// <param name="allowlist">The configured entries. Empty means allow everything.</param>
    /// <param name="candidate">The client address, as a string.</param>
    /// <returns><see langword="true"/> when the address is permitted.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="allowlist"/> is null.</exception>
    public static bool IsAllowed(IEnumerable<string> allowlist, string? candidate)
    {
        ArgumentNullException.ThrowIfNull(allowlist);

        var entries = allowlist as IReadOnlyCollection<string> ?? [.. allowlist];

        if (entries.Count == 0)
        {
            return true;
        }

        if (!IPAddress.TryParse(candidate, out var address))
        {
            // An allowlist is configured but the address could not be determined. Refuse:
            // a network restriction that fails open is not a restriction.
            return false;
        }

        // An IPv4 address arriving mapped into IPv6 (::ffff:198.51.100.7) must match an IPv4
        // allowlist entry. Without this the control would silently stop working the day the
        // server started accepting IPv6.
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        foreach (var entry in entries)
        {
            if (Matches(entry, address))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Matches(string entry, IPAddress address)
    {
        var trimmed = entry.Trim();

        if (trimmed.Length == 0)
        {
            return false;
        }

        var slash = trimmed.IndexOf('/', StringComparison.Ordinal);

        if (slash < 0)
        {
            return IPAddress.TryParse(trimmed, out var single)
                && Normalise(single).Equals(address);
        }

        if (!IPAddress.TryParse(trimmed[..slash], out var network)
            || !int.TryParse(
                trimmed[(slash + 1)..],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var prefixLength))
        {
            return false;
        }

        network = Normalise(network);

        if (network.AddressFamily != address.AddressFamily)
        {
            return false;
        }

        var maxPrefix = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

        if (prefixLength < 0 || prefixLength > maxPrefix)
        {
            return false;
        }

        return SharesPrefix(network, address, prefixLength);
    }

    private static IPAddress Normalise(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool SharesPrefix(IPAddress network, IPAddress candidate, int prefixLength)
    {
        var networkBytes = network.GetAddressBytes();
        var candidateBytes = candidate.GetAddressBytes();

        if (networkBytes.Length != candidateBytes.Length)
        {
            return false;
        }

        var wholeBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var i = 0; i < wholeBytes; i++)
        {
            if (networkBytes[i] != candidateBytes[i])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));

        return (networkBytes[wholeBytes] & mask) == (candidateBytes[wholeBytes] & mask);
    }
}
