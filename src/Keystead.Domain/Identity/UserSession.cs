using System;

namespace Keystead.Domain.Identity;

/// <summary>
/// A tracked sign-in. Persisting sessions is what makes a session list and a
/// sign-out-everywhere action possible, and lets a stolen cookie be revoked server-side
/// rather than waiting for it to expire.
/// </summary>
public sealed class UserSession
{
    /// <summary>Stable identifier, carried in the authentication cookie as a claim.</summary>
    public required Guid Id { get; init; }

    /// <summary>The signed-in user.</summary>
    public required Guid UserId { get; init; }

    /// <summary>When the session began.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>When the session was last seen, used for the idle timeout.</summary>
    public required DateTimeOffset LastSeenUtc { get; set; }

    /// <summary>
    /// When this session must end regardless of activity. An absolute timeout bounds the damage
    /// from a cookie stolen from a machine that is in constant use.
    /// </summary>
    public required DateTimeOffset AbsoluteExpiryUtc { get; init; }

    /// <summary>The address the session was created from, for the session list and anomaly flags.</summary>
    public required string CreatedIp { get; init; }

    /// <summary>The user agent string captured at sign-in.</summary>
    public required string UserAgent { get; init; }

    /// <summary>When the session was explicitly revoked, if it was.</summary>
    public DateTimeOffset? RevokedUtc { get; set; }

    /// <summary>
    /// When the user last proved their identity again for a high-privilege action. Revealing a
    /// secret, deleting a vault, changing a role and creating a service identity all require a
    /// recent step-up, so a long-lived session is not a standing authorisation to do anything.
    /// </summary>
    public DateTimeOffset? LastStepUpUtc { get; set; }

    /// <summary>Navigation to the owning user.</summary>
    public User? User { get; init; }

    /// <summary>Whether the session is currently valid.</summary>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    /// <param name="idleTimeout">How long a session may sit unused.</param>
    public bool IsActive(DateTimeOffset now, TimeSpan idleTimeout) =>
        RevokedUtc is null
        && now < AbsoluteExpiryUtc
        && now - LastSeenUtc < idleTimeout;

    /// <summary>Whether a step-up re-authentication is still fresh enough to authorise an action.</summary>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    /// <param name="window">How long a step-up stays valid.</param>
    public bool HasFreshStepUp(DateTimeOffset now, TimeSpan window) =>
        LastStepUpUtc is { } at && now - at < window;
}
