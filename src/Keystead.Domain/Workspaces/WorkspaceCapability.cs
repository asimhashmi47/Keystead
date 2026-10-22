namespace Keystead.Domain.Workspaces;

/// <summary>
/// A workspace-level thing a principal may be allowed to do.
/// </summary>
/// <remarks>
/// Named capabilities rather than role checks scattered through the code. A call site that asks
/// "may this principal manage members" states its intent; one that asks "is this principal an
/// Admin" has baked a policy decision into a page handler, and the next role added quietly
/// gets the wrong answer.
/// </remarks>
public enum WorkspaceCapability
{
    /// <summary>Rename or delete the workspace itself.</summary>
    ManageWorkspace = 1,

    /// <summary>Invite members, remove them, and change their roles.</summary>
    ManageMembers = 2,

    /// <summary>Create, rename and delete vaults, and grant access to them.</summary>
    ManageVaults = 3,

    /// <summary>Create and revoke service identities.</summary>
    ManageServiceIdentities = 4,

    /// <summary>Rotate the master key or a vault key-encryption key.</summary>
    RotateKeys = 5,

    /// <summary>Read the audit log.</summary>
    ViewAudit = 6,

    /// <summary>Permanently purge a soft-deleted vault or secret.</summary>
    PurgeData = 7,
}
