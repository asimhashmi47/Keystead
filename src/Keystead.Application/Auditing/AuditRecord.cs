using System;
using Keystead.Domain.Auditing;

namespace Keystead.Application.Auditing;

/// <summary>
/// Everything a caller supplies when recording an audited action.
/// </summary>
/// <remarks>
/// Deliberately missing the three fields a caller must not choose: the sequence number, the
/// previous hash and the hash. Those are the chain's own business, assigned at append time, so
/// there is no call site that can accidentally write a link that does not join up.
/// </remarks>
public sealed record AuditRecord
{
    /// <summary>The workspace the action belonged to, or null for installation-wide events.</summary>
    public Guid? WorkspaceId { get; init; }

    /// <summary>Whether the actor was a user, a service identity, the system, or anonymous.</summary>
    public required ActorType ActorType { get; init; }

    /// <summary>The actor identifier, or null when anonymous.</summary>
    public Guid? ActorId { get; init; }

    /// <summary>A display label for the actor, captured now so history survives deletion.</summary>
    public required string ActorLabel { get; init; }

    /// <summary>What happened.</summary>
    public required AuditAction Action { get; init; }

    /// <summary>Whether it succeeded, was denied, or errored.</summary>
    public required AuditOutcome Outcome { get; init; }

    /// <summary>The kind of thing acted upon, for example <c>secret</c> or <c>session</c>.</summary>
    public required string ResourceType { get; init; }

    /// <summary>The identifier of the thing acted upon, when there is one.</summary>
    public Guid? ResourceId { get; init; }

    /// <summary>A human-readable name for the resource. A name, never a value.</summary>
    public string? ResourceLabel { get; init; }

    /// <summary>The address the request came from.</summary>
    public required string IpAddress { get; init; }

    /// <summary>The user agent string.</summary>
    public string? UserAgent { get; init; }

    /// <summary>The correlation id, to tie this entry to its log lines.</summary>
    public string? CorrelationId { get; init; }

    /// <summary>
    /// Extra structured detail as JSON, for example the old and new role on a role change.
    /// Never a secret value.
    /// </summary>
    public string? DataJson { get; init; }
}
