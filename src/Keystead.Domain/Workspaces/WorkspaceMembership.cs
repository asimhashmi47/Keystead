using System;
using Keystead.Domain.Identity;

namespace Keystead.Domain.Workspaces;

/// <summary>A user's role in one workspace. A user may belong to several workspaces.</summary>
public sealed class WorkspaceMembership
{
    /// <summary>Surrogate key.</summary>
    public required Guid Id { get; init; }

    /// <summary>The workspace being granted.</summary>
    public required Guid WorkspaceId { get; init; }

    /// <summary>The user receiving the grant.</summary>
    public required Guid UserId { get; init; }

    /// <summary>
    /// The role held. Never model-bound from a form: role changes go through an explicit,
    /// audited, step-up-protected use case (CLAUDE.md: separate input models).
    /// </summary>
    public required WorkspaceRole Role { get; set; }

    /// <summary>When the grant was made.</summary>
    public required DateTimeOffset GrantedUtc { get; init; }

    /// <summary>Navigation to the workspace.</summary>
    public Workspace? Workspace { get; init; }

    /// <summary>Navigation to the user.</summary>
    public User? User { get; init; }

    /// <summary>
    /// Whether this role must have TOTP multi-factor authentication enrolled.
    /// Mandatory for Owner and Admin, per section 4 of the specification.
    /// </summary>
    public bool RequiresMfa => Role >= WorkspaceRole.Admin;
}
