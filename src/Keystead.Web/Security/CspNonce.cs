using System;
using System.Security.Cryptography;

namespace Keystead.Web.Security;

/// <summary>
/// A per-request Content Security Policy nonce.
/// </summary>
/// <remarks>
/// <para>
/// Registered as a scoped service so that the middleware writing the CSP header and the Razor
/// page rendering the script tags are guaranteed to use the same value. Generating the nonce in
/// two places is the classic way to ship a policy that blocks the application's own scripts.
/// </para>
/// <para>
/// 128 bits from the cryptographic generator, fresh per request. A predictable or reused nonce
/// is worth nothing: an attacker who can guess it can inject a script tag that the policy will
/// happily execute.
/// </para>
/// </remarks>
public sealed class CspNonce
{
    private readonly Lazy<string> _value = new(
        () => Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
        isThreadSafe: true);

    /// <summary>The base64 nonce for this request.</summary>
    public string Value => _value.Value;
}
