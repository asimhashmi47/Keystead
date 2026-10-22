namespace Keystead.Domain.Workspaces;

/// <summary>
/// A member's role within a workspace. Ordered least to most privileged so that
/// comparisons like <c>role &gt;= WorkspaceRole.Admin</c> read naturally and stay correct
/// if roles are added between the existing ones.
/// </summary>
public enum WorkspaceRole
{
    /// <summary>May read secret metadata and reveal values in vaults they are assigned to.</summary>
    Reader = 10,

    /// <summary>May create and update secrets in vaults they are assigned to.</summary>
    Contributor = 20,

    /// <summary>May manage vaults, members, and service identities. MFA is mandatory.</summary>
    Admin = 30,

    /// <summary>Full control, including workspace deletion and key rotation. MFA is mandatory.</summary>
    Owner = 40,
}
