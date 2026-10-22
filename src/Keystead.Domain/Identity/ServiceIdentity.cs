using System;
using System.Collections.Generic;

namespace Keystead.Domain.Identity;

/// <summary>
/// A machine principal: the equivalent of an application registration. It authenticates with
/// client credentials to obtain a short-lived token, and is scoped to specific vaults.
/// </summary>
/// <remarks>
/// The client secret is never stored. What is kept is its SHA-256 digest, so a stolen database
/// does not yield usable credentials. Two hashes are supported at once to allow rotation with
/// an overlap period: the new secret is issued, deployments move across, then the old digest is
/// cleared without any window in which neither works.
/// </remarks>
public sealed class ServiceIdentity
{
    /// <summary>Stable identifier.</summary>
    public required Guid Id { get; init; }

    /// <summary>Owning workspace.</summary>
    public required Guid WorkspaceId { get; init; }

    /// <summary>Display name, for example <c>billing-api-prod</c>.</summary>
    public required string Name { get; set; }

    /// <summary>The public client identifier, safe to put in configuration.</summary>
    public required string ClientId { get; init; }

    /// <summary>SHA-256 of the active client secret.</summary>
    public required byte[] ClientSecretHash { get; set; }

    /// <summary>
    /// SHA-256 of the previous client secret during a rotation overlap, cleared once every
    /// consumer has moved to the new one.
    /// </summary>
    public byte[]? PreviousClientSecretHash { get; set; }

    /// <summary>When the overlap period for <see cref="PreviousClientSecretHash"/> ends.</summary>
    public DateTimeOffset? PreviousSecretExpiresUtc { get; set; }

    /// <summary>When the identity itself stops being able to authenticate, if it expires.</summary>
    public DateTimeOffset? ExpiresUtc { get; set; }

    /// <summary>
    /// Addresses and CIDR ranges this identity may authenticate from. Empty means no network
    /// restriction; a populated list is enforced on every token request and every API call.
    /// </summary>
    public IList<string> IpAllowlist { get; set; } = [];

    /// <summary>When the identity was created.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>When the identity last obtained a token, for the stale-credential view.</summary>
    public DateTimeOffset? LastUsedUtc { get; set; }

    /// <summary>Whether the identity is enabled. Disabling takes effect on the next token request.</summary>
    public required bool IsActive { get; set; }

    /// <summary>Whether the identity may currently authenticate.</summary>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    public bool CanAuthenticate(DateTimeOffset now) =>
        IsActive && (ExpiresUtc is null || now < ExpiresUtc);

    /// <summary>
    /// Whether the previous secret is still inside its overlap window and should therefore
    /// still be accepted.
    /// </summary>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    public bool PreviousSecretUsable(DateTimeOffset now) =>
        PreviousClientSecretHash is not null
        && PreviousSecretExpiresUtc is { } expires
        && now < expires;
}
