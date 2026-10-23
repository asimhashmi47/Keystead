using System;

namespace Keystead.Domain.Identity;

/// <summary>
/// An ECDSA P-256 key pair used to sign machine tokens, with its private half sealed under the
/// master key.
/// </summary>
/// <remarks>
/// <para>
/// Asymmetric rather than symmetric, which matters more than it first appears. With HS256 the
/// verifier needs the same key that signs, so anything that can check a token can also mint
/// one. With ES256 the private half never leaves this server and the public half can be
/// published freely, so a compromised verifier is not a token factory.
/// </para>
/// <para>
/// Several generations can exist at once. A token carries its key id in the header, so rotation
/// means issuing under a new key while still verifying tokens signed by the previous one until
/// they expire, with no window where valid tokens are rejected.
/// </para>
/// </remarks>
public sealed class SigningKey
{
    /// <summary>Surrogate key, and the AAD binding for the sealed private key.</summary>
    public required Guid Id { get; init; }

    /// <summary>
    /// The key id placed in the token header. Short and opaque; it identifies which key to
    /// verify against and reveals nothing else.
    /// </summary>
    public required string Kid { get; init; }

    /// <summary>The PKCS#8 private key, sealed under the master key.</summary>
    public required byte[] PrivateKeyCiphertext { get; set; }

    /// <summary>The AES-GCM nonce for the sealed private key.</summary>
    public required byte[] PrivateKeyNonce { get; set; }

    /// <summary>The AES-GCM tag for the sealed private key.</summary>
    public required byte[] PrivateKeyTag { get; set; }

    /// <summary>Which master key generation sealed the private key.</summary>
    public required int MasterKeyVersion { get; set; }

    /// <summary>
    /// The SubjectPublicKeyInfo-encoded public key, stored in the clear.
    /// </summary>
    /// <remarks>
    /// Deliberately unencrypted. It is not secret, and keeping it readable means token
    /// verification and a future JWKS endpoint do not need the master key at all.
    /// </remarks>
    public required byte[] PublicKey { get; init; }

    /// <summary>When this key was created.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>When this key stopped being used for new signatures, if it has been rotated.</summary>
    public DateTimeOffset? RetiredUtc { get; set; }

    /// <summary>Whether new tokens should be signed with this key.</summary>
    public bool IsActive => RetiredUtc is null;

    /// <summary>
    /// Whether this key may still be used to verify a token.
    /// </summary>
    /// <remarks>
    /// A retired key stays usable for verification until every token it signed has expired.
    /// Dropping it at rotation would invalidate live tokens and cause an outage for no
    /// security gain, since the key is no longer signing anything new.
    /// </remarks>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    /// <param name="maxTokenLifetime">The longest lifetime any issued token can have.</param>
    public bool CanVerify(DateTimeOffset now, TimeSpan maxTokenLifetime) =>
        RetiredUtc is null || now < RetiredUtc.Value + maxTokenLifetime;
}
