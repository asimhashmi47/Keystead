using System;

namespace Keystead.Domain.Vaults;

/// <summary>
/// An explicit grant of access to one vault, for either a user or a service identity.
/// </summary>
/// <remarks>
/// Workspace role alone does not imply vault access for Readers and Contributors: the grant
/// must exist. This is what makes "scoped by workspace" and "authorized" two separate checks,
/// as CLAUDE.md rule 8 requires.
/// </remarks>
public sealed class VaultAssignment
{
    /// <summary>Surrogate key.</summary>
    public required Guid Id { get; init; }

    /// <summary>The vault being granted.</summary>
    public required Guid VaultId { get; init; }

    /// <summary>The user or service identity receiving the grant.</summary>
    public required Guid SubjectId { get; init; }

    /// <summary>Whether the subject is a user or a service identity.</summary>
    public required SubjectType SubjectType { get; init; }

    /// <summary>Read or write.</summary>
    public required VaultPermission Permission { get; set; }

    /// <summary>When the grant was made.</summary>
    public required DateTimeOffset GrantedUtc { get; init; }

    /// <summary>Navigation to the vault.</summary>
    public Vault? Vault { get; init; }
}
