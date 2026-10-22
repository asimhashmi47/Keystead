using System;

namespace Keystead.Domain.Workspaces;

/// <summary>
/// The single authority on what each workspace role may do.
/// </summary>
/// <remarks>
/// <para>
/// One place, pure, no database. The matrix is the security model, so it is worth being able
/// to read it in full on one screen and to test it exhaustively.
/// </para>
/// <para>
/// Note what Contributor and Reader cannot do: nothing administrative, and in particular no
/// vault access by virtue of role alone. A Reader with no vault assignment can reach no
/// secrets at all. Owner and Admin do get implicit access to every vault in their workspace,
/// because they can grant themselves one anyway and pretending otherwise would only hide who
/// could see what.
/// </para>
/// </remarks>
public static class RoleCapabilities
{
    /// <summary>Whether a role may exercise a capability.</summary>
    /// <param name="role">The role held in the workspace.</param>
    /// <param name="capability">The capability being attempted.</param>
    /// <returns><see langword="true"/> when the role allows it.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The capability is not a known value.</exception>
    public static bool Allows(WorkspaceRole role, WorkspaceCapability capability) =>
        capability switch
        {
            // Destroying or renaming the tenant is the Owner's alone.
            WorkspaceCapability.ManageWorkspace => role is WorkspaceRole.Owner,

            // Changing roles is an escalation path, so it stops at Admin and above.
            WorkspaceCapability.ManageMembers => role >= WorkspaceRole.Admin,

            WorkspaceCapability.ManageVaults => role >= WorkspaceRole.Admin,

            WorkspaceCapability.ManageServiceIdentities => role >= WorkspaceRole.Admin,

            // Key rotation can make every secret unreadable if it goes wrong. Owner only.
            WorkspaceCapability.RotateKeys => role is WorkspaceRole.Owner,

            // The audit log records who read which secret, which is itself sensitive, so it is
            // not readable by every member.
            WorkspaceCapability.ViewAudit => role >= WorkspaceRole.Admin,

            // Irreversible. Owner only, and still subject to purge protection on the vault.
            WorkspaceCapability.PurgeData => role is WorkspaceRole.Owner,

            _ => throw new ArgumentOutOfRangeException(
                nameof(capability),
                capability,
                "Unknown workspace capability. A capability with no explicit rule must not default to allowed."),
        };

    /// <summary>
    /// Whether a role has implicit access to every vault in its workspace, without an explicit
    /// assignment.
    /// </summary>
    /// <param name="role">The role held in the workspace.</param>
    /// <returns><see langword="true"/> for Admin and Owner.</returns>
    public static bool HasImplicitVaultAccess(WorkspaceRole role) => role >= WorkspaceRole.Admin;

    /// <summary>
    /// The highest vault permission a role may hold, capping whatever an assignment grants.
    /// </summary>
    /// <remarks>
    /// A Reader handed a write assignment by mistake still cannot write. The cap means a
    /// misconfigured grant degrades to read rather than silently promoting someone.
    /// </remarks>
    /// <param name="role">The role held in the workspace.</param>
    /// <returns>The ceiling for that role.</returns>
    public static Vaults.VaultPermission Ceiling(WorkspaceRole role) =>
        role is WorkspaceRole.Reader
            ? Vaults.VaultPermission.Read
            : Vaults.VaultPermission.Write;

    /// <summary>Whether TOTP multi-factor authentication is mandatory for a role.</summary>
    /// <param name="role">The role held in the workspace.</param>
    /// <returns><see langword="true"/> for Admin and Owner.</returns>
    public static bool RequiresMfa(WorkspaceRole role) => role >= WorkspaceRole.Admin;
}
