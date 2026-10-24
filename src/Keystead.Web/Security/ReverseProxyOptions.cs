using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Keystead.Web.Security;

/// <summary>
/// Which proxies are allowed to tell Keystead who the client is.
/// </summary>
/// <remarks>
/// <para>
/// This section used to bind straight onto <c>ForwardedHeadersOptions</c>, which looked like
/// the tidy choice — the framework's own vocabulary, no translation layer — and did not work.
/// The configuration binder can set a scalar such as <c>ForwardLimit</c>, but it cannot turn
/// the string <c>"172.16.0.0/12"</c> into an <c>IPNetwork</c>, so every network and every proxy
/// an operator named was silently dropped and the defaults stayed in place.
/// </para>
/// <para>
/// The consequence was not a visible error. The deployment kept running and trusted loopback
/// only, so <c>X-Forwarded-For</c> was ignored and every client appeared to be the proxy: the
/// IP allowlist on a service identity compared the proxy's address instead of the caller's, and
/// the per-address rate limit treated the entire internet as one client. The setting documented
/// as the fix for exactly that did nothing.
/// </para>
/// <para>
/// So the strings are owned here and parsed deliberately. A value that cannot be parsed, or a
/// range wide enough that any client could choose its own address, stops the process at startup
/// instead.
/// </para>
/// </remarks>
public sealed class ReverseProxyOptions
{
    /// <summary>The configuration section these options bind to.</summary>
    public const string SectionName = "Keystead:ReverseProxy";

    /// <summary>
    /// How many entries to read from the right of <c>X-Forwarded-For</c>.
    /// </summary>
    /// <remarks>
    /// One, unless there is genuinely a second trusted hop. Each additional hop is one more
    /// place that can write an address Keystead will believe.
    /// </remarks>
    [Range(1, 8)]
    public int ForwardLimit { get; set; } = 1;

    /// <summary>
    /// The networks the proxy's own addresses sit in, in CIDR form, for example
    /// <c>172.16.0.0/12</c>.
    /// </summary>
    public IList<string> KnownNetworks { get; } = [];

    /// <summary>Individual proxy addresses, for example <c>10.0.0.5</c>.</summary>
    public IList<string> KnownProxies { get; } = [];

    /// <summary>
    /// Accepts a known-network range wide enough to cover any client.
    /// </summary>
    /// <remarks>
    /// There is one deployment where this is correct: every connection terminates at a proxy
    /// that overwrites <c>X-Forwarded-For</c> rather than appending to it, and nothing can
    /// reach the application except through it. It is a sentence someone has to mean, which is
    /// why it is a setting and not a threshold.
    /// </remarks>
    public bool TrustAnyProxyAddress { get; set; }
}
