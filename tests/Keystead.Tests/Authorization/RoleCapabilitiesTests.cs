using System;
using System.Linq;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Xunit;

namespace Keystead.Tests.Authorization;

/// <summary>
/// The role/capability matrix, tested exhaustively.
/// </summary>
/// <remarks>
/// Every role is checked against every capability, so the matrix cannot be widened by
/// accident. A test that only covered the allowed combinations would pass just as happily if
/// Reader were granted everything.
/// </remarks>
public sealed class RoleCapabilitiesTests
{
    private static readonly WorkspaceRole[] AllRoles =
        Enum.GetValues<WorkspaceRole>();

    private static readonly WorkspaceCapability[] AllCapabilities =
        Enum.GetValues<WorkspaceCapability>();

    [Theory]
    [InlineData(WorkspaceRole.Owner, WorkspaceCapability.ManageWorkspace, true)]
    [InlineData(WorkspaceRole.Admin, WorkspaceCapability.ManageWorkspace, false)]
    [InlineData(WorkspaceRole.Contributor, WorkspaceCapability.ManageWorkspace, false)]
    [InlineData(WorkspaceRole.Reader, WorkspaceCapability.ManageWorkspace, false)]
    [InlineData(WorkspaceRole.Owner, WorkspaceCapability.ManageMembers, true)]
    [InlineData(WorkspaceRole.Admin, WorkspaceCapability.ManageMembers, true)]
    [InlineData(WorkspaceRole.Contributor, WorkspaceCapability.ManageMembers, false)]
    [InlineData(WorkspaceRole.Reader, WorkspaceCapability.ManageMembers, false)]
    [InlineData(WorkspaceRole.Owner, WorkspaceCapability.ManageVaults, true)]
    [InlineData(WorkspaceRole.Admin, WorkspaceCapability.ManageVaults, true)]
    [InlineData(WorkspaceRole.Contributor, WorkspaceCapability.ManageVaults, false)]
    [InlineData(WorkspaceRole.Reader, WorkspaceCapability.ManageVaults, false)]
    [InlineData(WorkspaceRole.Owner, WorkspaceCapability.ManageServiceIdentities, true)]
    [InlineData(WorkspaceRole.Admin, WorkspaceCapability.ManageServiceIdentities, true)]
    [InlineData(WorkspaceRole.Contributor, WorkspaceCapability.ManageServiceIdentities, false)]
    [InlineData(WorkspaceRole.Reader, WorkspaceCapability.ManageServiceIdentities, false)]
    [InlineData(WorkspaceRole.Owner, WorkspaceCapability.RotateKeys, true)]
    [InlineData(WorkspaceRole.Admin, WorkspaceCapability.RotateKeys, false)]
    [InlineData(WorkspaceRole.Contributor, WorkspaceCapability.RotateKeys, false)]
    [InlineData(WorkspaceRole.Reader, WorkspaceCapability.RotateKeys, false)]
    [InlineData(WorkspaceRole.Owner, WorkspaceCapability.ViewAudit, true)]
    [InlineData(WorkspaceRole.Admin, WorkspaceCapability.ViewAudit, true)]
    [InlineData(WorkspaceRole.Contributor, WorkspaceCapability.ViewAudit, false)]
    [InlineData(WorkspaceRole.Reader, WorkspaceCapability.ViewAudit, false)]
    [InlineData(WorkspaceRole.Owner, WorkspaceCapability.PurgeData, true)]
    [InlineData(WorkspaceRole.Admin, WorkspaceCapability.PurgeData, false)]
    [InlineData(WorkspaceRole.Contributor, WorkspaceCapability.PurgeData, false)]
    [InlineData(WorkspaceRole.Reader, WorkspaceCapability.PurgeData, false)]
    public void TheMatrixIsExactlyThis(
        WorkspaceRole role,
        WorkspaceCapability capability,
        bool expected)
    {
        Assert.Equal(expected, RoleCapabilities.Allows(role, capability));
    }

    [Fact]
    public void TheMatrixCoversEveryRoleAndCapabilityPair()
    {
        // Guards the table above: if a capability is added to the enum and not given a row
        // here, this test fails rather than the new capability going untested.
        var declared = typeof(RoleCapabilitiesTests)
            .GetMethod(nameof(TheMatrixIsExactlyThis))!
            .GetCustomAttributes(typeof(InlineDataAttribute), false)
            .Length;

        Assert.Equal(AllRoles.Length * AllCapabilities.Length, declared);
    }

    [Fact]
    public void AnUnknownCapability_Throws()
    {
        // Deny by default, loudly. A capability with no rule must not fall through to allowed.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => RoleCapabilities.Allows(WorkspaceRole.Owner, (WorkspaceCapability)9999));
    }

    [Fact]
    public void ReaderAndContributor_HaveNoAdministrativeCapability()
    {
        foreach (var role in new[] { WorkspaceRole.Reader, WorkspaceRole.Contributor })
        {
            Assert.All(
                AllCapabilities,
                capability => Assert.False(
                    RoleCapabilities.Allows(role, capability),
                    $"{role} must not hold {capability}."));
        }
    }

    [Fact]
    public void Owner_HoldsEveryCapability()
    {
        Assert.All(
            AllCapabilities,
            capability => Assert.True(RoleCapabilities.Allows(WorkspaceRole.Owner, capability)));
    }

    [Theory]
    [InlineData(WorkspaceRole.Owner, true)]
    [InlineData(WorkspaceRole.Admin, true)]
    [InlineData(WorkspaceRole.Contributor, false)]
    [InlineData(WorkspaceRole.Reader, false)]
    public void ImplicitVaultAccess_IsAdminAndAbove(WorkspaceRole role, bool expected)
    {
        Assert.Equal(expected, RoleCapabilities.HasImplicitVaultAccess(role));
    }

    [Theory]
    [InlineData(WorkspaceRole.Owner, VaultPermission.Write)]
    [InlineData(WorkspaceRole.Admin, VaultPermission.Write)]
    [InlineData(WorkspaceRole.Contributor, VaultPermission.Write)]
    [InlineData(WorkspaceRole.Reader, VaultPermission.Read)]
    public void TheCeiling_CapsAReadersGrant(WorkspaceRole role, VaultPermission expected)
    {
        Assert.Equal(expected, RoleCapabilities.Ceiling(role));
    }

    [Theory]
    [InlineData(WorkspaceRole.Owner, true)]
    [InlineData(WorkspaceRole.Admin, true)]
    [InlineData(WorkspaceRole.Contributor, false)]
    [InlineData(WorkspaceRole.Reader, false)]
    public void MfaIsMandatory_ForAdminAndAbove(WorkspaceRole role, bool expected)
    {
        Assert.Equal(expected, RoleCapabilities.RequiresMfa(role));
    }

    [Fact]
    public void RolesAreOrderedLeastToMostPrivileged()
    {
        // The matrix uses >= comparisons, so the numeric ordering is load-bearing. If someone
        // renumbers the enum, every "Admin and above" rule silently changes meaning.
        var ordered = AllRoles.OrderBy(r => (int)r).ToArray();

        Assert.Equal(
            new[]
            {
                WorkspaceRole.Reader,
                WorkspaceRole.Contributor,
                WorkspaceRole.Admin,
                WorkspaceRole.Owner,
            },
            ordered);
    }
}
