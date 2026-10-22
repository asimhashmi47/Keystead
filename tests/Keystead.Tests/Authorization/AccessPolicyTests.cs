using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Authorization;
using Keystead.Domain.Identity;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Authorization;
using Keystead.Infrastructure.Identity;
using Keystead.Tests.TestDoubles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace Keystead.Tests.Authorization;

/// <summary>
/// Authorization against a real database, including the cross-tenant attempts.
/// </summary>
/// <remarks>
/// Two workspaces are set up with a user in each, and the tests then try to reach across. An
/// IDOR test that only checks the happy path proves nothing: the failure has to be attempted.
/// </remarks>
public sealed class AccessPolicyTests : IDisposable
{
    private static readonly Guid WorkspaceA = Guid.Parse("a0000000-0000-0000-0000-000000000001");
    private static readonly Guid WorkspaceB = Guid.Parse("b0000000-0000-0000-0000-000000000001");
    private static readonly Guid VaultInA = Guid.Parse("a0000000-0000-0000-0000-00000000000a");
    private static readonly Guid VaultInB = Guid.Parse("b0000000-0000-0000-0000-00000000000a");

    private static readonly Guid OwnerOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a1");
    private static readonly Guid AdminOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a2");
    private static readonly Guid ContributorOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a3");
    private static readonly Guid ReaderOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a4");
    private static readonly Guid UnassignedReaderOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a5");
    private static readonly Guid DeactivatedAdminOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a6");
    private static readonly Guid OwnerOfB = Guid.Parse("00000000-0000-0000-0000-0000000000b1");
    private static readonly Guid Stranger = Guid.Parse("00000000-0000-0000-0000-0000000000ff");

    private readonly TestDatabase _db = new();
    private readonly FixedClock _clock = new();
    private readonly AccessPolicy _policy;

    public AccessPolicyTests()
    {
        Seed();

        _policy = new AccessPolicy(
            _db.Context,
            _clock,
            Options.Create(new SessionOptions()));
    }

    public void Dispose() => _db.Dispose();

    private void Seed()
    {
        var now = _clock.UtcNow;
        var context = _db.Context;

        foreach (var (id, workspace, name) in new[]
        {
            (WorkspaceA, "Workspace A", "a"),
            (WorkspaceB, "Workspace B", "b"),
        })
        {
            context.Workspaces.Add(new Workspace
            {
                Id = id,
                Name = workspace,
                Slug = name,
                CreatedUtc = now,
            });
        }

        foreach (var (id, vaultWorkspace, slug) in new[]
        {
            (VaultInA, WorkspaceA, "vault-a"),
            (VaultInB, WorkspaceB, "vault-b"),
        })
        {
            context.Vaults.Add(new Vault
            {
                Id = id,
                WorkspaceId = vaultWorkspace,
                Name = slug,
                Slug = slug,
                ColorToken = "indigo",
                CreatedUtc = now,
                RecoveryWindowDays = 30,
                PurgeProtection = false,
            });
        }

        var users = new[]
        {
            (OwnerOfA, "owner-a@example.com", WorkspaceA, WorkspaceRole.Owner, true),
            (AdminOfA, "admin-a@example.com", WorkspaceA, WorkspaceRole.Admin, true),
            (ContributorOfA, "contrib-a@example.com", WorkspaceA, WorkspaceRole.Contributor, true),
            (ReaderOfA, "reader-a@example.com", WorkspaceA, WorkspaceRole.Reader, true),
            (UnassignedReaderOfA, "lonely-a@example.com", WorkspaceA, WorkspaceRole.Reader, true),
            (DeactivatedAdminOfA, "gone-a@example.com", WorkspaceA, WorkspaceRole.Admin, false),
            (OwnerOfB, "owner-b@example.com", WorkspaceB, WorkspaceRole.Owner, true),
        };

        foreach (var (id, email, workspace, role, isActive) in users)
        {
            context.Users.Add(new User
            {
                Id = id,
                Email = email,
                DisplayName = email,
                PasswordHash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ=$aGFzaGhhc2g=",
                PasswordChangedUtc = now,
                FailedSignInCount = 0,
                CreatedUtc = now,
                IsActive = isActive,
            });

            context.WorkspaceMemberships.Add(new WorkspaceMembership
            {
                Id = Guid.CreateVersion7(),
                WorkspaceId = workspace,
                UserId = id,
                Role = role,
                GrantedUtc = now,
            });
        }

        // Explicit vault grants. Note that UnassignedReaderOfA gets none, and the Contributor
        // gets write while the Reader gets read.
        foreach (var (subject, permission) in new[]
        {
            (ContributorOfA, VaultPermission.Write),
            (ReaderOfA, VaultPermission.Read),
        })
        {
            context.VaultAssignments.Add(new VaultAssignment
            {
                Id = Guid.CreateVersion7(),
                VaultId = VaultInA,
                SubjectId = subject,
                SubjectType = SubjectType.User,
                Permission = permission,
                GrantedUtc = now,
            });
        }

        context.SaveChanges();
    }

    private static Principal User(Guid id) =>
        new(SubjectType.User, id, "test", Guid.CreateVersion7());

    private Task<AccessDecision> Vault(Guid user, Guid workspace, Guid vault, VaultPermission p) =>
        _policy.AuthorizeVaultAsync(User(user), workspace, vault, p, CancellationToken.None);

    // -----------------------------------------------------------------------
    // Cross-tenant attempts. These are the tests that matter most.
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AnOwnerOfOneWorkspace_CannotReachAVaultInAnother()
    {
        // The attacker is a legitimate Owner, just of the wrong tenant. Their role lookup
        // would succeed if the vault were not scoped first.
        var decision = await Vault(OwnerOfB, WorkspaceB, VaultInA, VaultPermission.Read);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AnOwner_CannotReachAForeignVaultByNamingTheirOwnWorkspace()
    {
        // The id-substitution attack: keep your own workspace in the request, swap in a vault
        // id you found elsewhere. Scoping is what refuses this.
        var decision = await Vault(OwnerOfA, WorkspaceA, VaultInB, VaultPermission.Read);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AnOwner_CannotReachTheirOwnVaultByNamingAForeignWorkspace()
    {
        // The mirror image: correct vault, wrong workspace. Must also fail, because otherwise
        // the workspace parameter would be decorative.
        var decision = await Vault(OwnerOfA, WorkspaceB, VaultInA, VaultPermission.Read);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AStrangerWithNoMembership_IsRefused()
    {
        var decision = await Vault(Stranger, WorkspaceA, VaultInA, VaultPermission.Read);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task ANonExistentVault_IsRefusedTheSameWayAsAForeignOne()
    {
        // Both denials must look alike to the caller: distinguishing them would confirm that a
        // vault exists in someone else's workspace.
        var missing = await Vault(OwnerOfA, WorkspaceA, Guid.NewGuid(), VaultPermission.Read);
        var foreign = await Vault(OwnerOfA, WorkspaceA, VaultInB, VaultPermission.Read);

        Assert.False(missing.IsAllowed);
        Assert.False(foreign.IsAllowed);
        Assert.Equal(missing.Reason, foreign.Reason);
    }

    [Fact]
    public async Task ACrossTenantWorkspaceCapability_IsRefused()
    {
        var decision = await _policy.AuthorizeWorkspaceAsync(
            User(OwnerOfB),
            WorkspaceA,
            WorkspaceCapability.ManageMembers,
            CancellationToken.None);

        Assert.False(decision.IsAllowed);
    }

    // -----------------------------------------------------------------------
    // Grants and ceilings within one workspace.
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AnAdmin_HasImplicitAccessWithoutAGrant()
    {
        var decision = await Vault(AdminOfA, WorkspaceA, VaultInA, VaultPermission.Write);

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task AReaderWithNoGrant_IsRefusedEvenInTheirOwnWorkspace()
    {
        // Membership is not access. This is the rule that makes a Reader's blast radius zero
        // until someone deliberately grants them a vault.
        var decision = await Vault(UnassignedReaderOfA, WorkspaceA, VaultInA, VaultPermission.Read);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AReaderWithAReadGrant_MayRead()
    {
        var decision = await Vault(ReaderOfA, WorkspaceA, VaultInA, VaultPermission.Read);

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task AReaderWithAReadGrant_MayNotWrite()
    {
        var decision = await Vault(ReaderOfA, WorkspaceA, VaultInA, VaultPermission.Write);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AReaderHandedAWriteGrantByMistake_StillCannotWrite()
    {
        // The ceiling in action. A misconfigured grant degrades to read rather than silently
        // promoting the user past their role.
        var assignment = await _db.Context.VaultAssignments
            .FirstAsync(a => a.SubjectId == ReaderOfA);

        assignment.Permission = VaultPermission.Write;
        await _db.Context.SaveChangesAsync();

        var decision = await Vault(ReaderOfA, WorkspaceA, VaultInA, VaultPermission.Write);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AContributorWithAWriteGrant_MayWrite()
    {
        var decision = await Vault(ContributorOfA, WorkspaceA, VaultInA, VaultPermission.Write);

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task ADeactivatedAdmin_LosesEveryCapability()
    {
        // Disabling an account must take effect without unpicking its grants one by one.
        var vault = await Vault(DeactivatedAdminOfA, WorkspaceA, VaultInA, VaultPermission.Read);

        var workspace = await _policy.AuthorizeWorkspaceAsync(
            User(DeactivatedAdminOfA),
            WorkspaceA,
            WorkspaceCapability.ManageMembers,
            CancellationToken.None);

        Assert.False(vault.IsAllowed);
        Assert.False(workspace.IsAllowed);
    }

    [Fact]
    public async Task ASoftDeletedVault_IsUnreachableEvenByItsOwner()
    {
        var vault = await _db.Context.Vaults.FirstAsync(v => v.Id == VaultInA);
        vault.SoftDelete(_clock.UtcNow);
        await _db.Context.SaveChangesAsync();

        var decision = await Vault(OwnerOfA, WorkspaceA, VaultInA, VaultPermission.Read);

        Assert.False(decision.IsAllowed);
    }

    // -----------------------------------------------------------------------
    // Service identities.
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AServiceIdentity_CannotPerformWorkspaceAdministration()
    {
        // A leaked client secret must not be able to escalate to owning the tenant.
        var machine = new Principal(
            SubjectType.ServiceIdentity,
            Guid.NewGuid(),
            "ci-runner",
            SessionId: null);

        var decision = await _policy.AuthorizeWorkspaceAsync(
            machine,
            WorkspaceA,
            WorkspaceCapability.ManageMembers,
            CancellationToken.None);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AServiceIdentity_GetsNoImplicitVaultAccess()
    {
        var identityId = Guid.CreateVersion7();

        _db.Context.ServiceIdentities.Add(new ServiceIdentity
        {
            Id = identityId,
            WorkspaceId = WorkspaceA,
            Name = "ci-runner",
            ClientId = "ksd_ci_runner",
            ClientSecretHash = new byte[32],
            CreatedUtc = _clock.UtcNow,
            IsActive = true,
        });

        await _db.Context.SaveChangesAsync();

        var machine = new Principal(SubjectType.ServiceIdentity, identityId, "ci-runner", null);

        var decision = await _policy.AuthorizeVaultAsync(
            machine, WorkspaceA, VaultInA, VaultPermission.Read, CancellationToken.None);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task ADisabledServiceIdentity_IsRefusedDespiteItsGrant()
    {
        // Disabling must bite on the next API call, not merely on the next token request:
        // a token already issued outlives the moment it was minted.
        var identityId = Guid.CreateVersion7();

        _db.Context.ServiceIdentities.Add(new ServiceIdentity
        {
            Id = identityId,
            WorkspaceId = WorkspaceA,
            Name = "revoked-runner",
            ClientId = "ksd_revoked",
            ClientSecretHash = new byte[32],
            CreatedUtc = _clock.UtcNow,
            IsActive = false,
        });

        _db.Context.VaultAssignments.Add(new VaultAssignment
        {
            Id = Guid.CreateVersion7(),
            VaultId = VaultInA,
            SubjectId = identityId,
            SubjectType = SubjectType.ServiceIdentity,
            Permission = VaultPermission.Read,
            GrantedUtc = _clock.UtcNow,
        });

        await _db.Context.SaveChangesAsync();

        var machine = new Principal(SubjectType.ServiceIdentity, identityId, "revoked-runner", null);

        var decision = await _policy.AuthorizeVaultAsync(
            machine, WorkspaceA, VaultInA, VaultPermission.Read, CancellationToken.None);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AnExpiredServiceIdentity_IsRefused()
    {
        var identityId = Guid.CreateVersion7();

        _db.Context.ServiceIdentities.Add(new ServiceIdentity
        {
            Id = identityId,
            WorkspaceId = WorkspaceA,
            Name = "expired-runner",
            ClientId = "ksd_expired",
            ClientSecretHash = new byte[32],
            CreatedUtc = _clock.UtcNow.AddDays(-30),
            ExpiresUtc = _clock.UtcNow.AddDays(-1),
            IsActive = true,
        });

        _db.Context.VaultAssignments.Add(new VaultAssignment
        {
            Id = Guid.CreateVersion7(),
            VaultId = VaultInA,
            SubjectId = identityId,
            SubjectType = SubjectType.ServiceIdentity,
            Permission = VaultPermission.Read,
            GrantedUtc = _clock.UtcNow,
        });

        await _db.Context.SaveChangesAsync();

        var machine = new Principal(SubjectType.ServiceIdentity, identityId, "expired-runner", null);

        var decision = await _policy.AuthorizeVaultAsync(
            machine, WorkspaceA, VaultInA, VaultPermission.Read, CancellationToken.None);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task AUserGrantDoesNotServeAServiceIdentityWithTheSameId()
    {
        // SubjectType is part of the grant key. Without it, a service identity whose id
        // happened to match a user's would inherit that user's access.
        var sharedId = ContributorOfA;

        _db.Context.ServiceIdentities.Add(new ServiceIdentity
        {
            Id = sharedId,
            WorkspaceId = WorkspaceA,
            Name = "impostor",
            ClientId = "ksd_impostor",
            ClientSecretHash = new byte[32],
            CreatedUtc = _clock.UtcNow,
            IsActive = true,
        });

        await _db.Context.SaveChangesAsync();

        var machine = new Principal(SubjectType.ServiceIdentity, sharedId, "impostor", null);

        var decision = await _policy.AuthorizeVaultAsync(
            machine, WorkspaceA, VaultInA, VaultPermission.Read, CancellationToken.None);

        Assert.False(decision.IsAllowed);
    }

    // -----------------------------------------------------------------------
    // Step-up freshness.
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AFreshStepUp_IsAccepted()
    {
        var sessionId = await CreateSessionAsync(OwnerOfA, stepUpAt: _clock.UtcNow);

        var decision = await _policy.RequireFreshStepUpAsync(
            new Principal(SubjectType.User, OwnerOfA, "owner", sessionId),
            CancellationToken.None);

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task AStaleStepUp_AsksForAnotherOne()
    {
        var sessionId = await CreateSessionAsync(OwnerOfA, stepUpAt: _clock.UtcNow);

        _clock.Advance(TimeSpan.FromMinutes(10));

        var decision = await _policy.RequireFreshStepUpAsync(
            new Principal(SubjectType.User, OwnerOfA, "owner", sessionId),
            CancellationToken.None);

        Assert.False(decision.IsAllowed);

        // Not a flat refusal: the interface can offer the modal instead of a dead end.
        Assert.True(decision.NeedsStepUp);
    }

    [Fact]
    public async Task ARevokedSession_IsRefusedOutrightRatherThanOfferedAStepUp()
    {
        var sessionId = await CreateSessionAsync(OwnerOfA, stepUpAt: _clock.UtcNow);

        var session = await _db.Context.UserSessions.FirstAsync(s => s.Id == sessionId);
        session.RevokedUtc = _clock.UtcNow;
        await _db.Context.SaveChangesAsync();

        var decision = await _policy.RequireFreshStepUpAsync(
            new Principal(SubjectType.User, OwnerOfA, "owner", sessionId),
            CancellationToken.None);

        Assert.False(decision.IsAllowed);
        Assert.False(decision.NeedsStepUp);
    }

    [Fact]
    public async Task AServiceIdentity_CannotStepUp()
    {
        var decision = await _policy.RequireFreshStepUpAsync(
            new Principal(SubjectType.ServiceIdentity, Guid.NewGuid(), "ci", null),
            CancellationToken.None);

        Assert.False(decision.IsAllowed);
        Assert.False(decision.NeedsStepUp);
    }

    [Fact]
    public async Task ASessionBelongingToAnotherUser_CannotBeUsedForStepUp()
    {
        var sessionId = await CreateSessionAsync(OwnerOfA, stepUpAt: _clock.UtcNow);

        var decision = await _policy.RequireFreshStepUpAsync(
            new Principal(SubjectType.User, AdminOfA, "admin", sessionId),
            CancellationToken.None);

        Assert.False(decision.IsAllowed);
    }

    private async Task<Guid> CreateSessionAsync(Guid userId, DateTimeOffset stepUpAt)
    {
        var id = Guid.CreateVersion7();

        _db.Context.UserSessions.Add(new UserSession
        {
            Id = id,
            UserId = userId,
            CreatedUtc = _clock.UtcNow,
            LastSeenUtc = _clock.UtcNow,
            AbsoluteExpiryUtc = _clock.UtcNow.AddHours(12),
            CreatedIp = "203.0.113.9",
            UserAgent = "test",
            LastStepUpUtc = stepUpAt,
        });

        await _db.Context.SaveChangesAsync();
        return id;
    }
}
