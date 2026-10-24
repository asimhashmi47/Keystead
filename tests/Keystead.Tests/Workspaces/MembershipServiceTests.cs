using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Domain.Common;
using Keystead.Domain.Identity;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Auditing;
using Keystead.Infrastructure.Authorization;
using Keystead.Infrastructure.Cryptography;
using Keystead.Infrastructure.Identity;
using Keystead.Infrastructure.Workspaces;
using Keystead.Tests.TestDoubles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace Keystead.Tests.Workspaces;

/// <summary>
/// Membership, roles and per-user vault grants.
/// </summary>
/// <remarks>
/// The rules worth testing here are the ones that make a workspace unrecoverable or let
/// someone escalate: removing the last owner, an admin promoting themselves, and granting
/// access across a tenant boundary.
/// </remarks>
public sealed class MembershipServiceTests : IDisposable
{
    private static readonly Guid WorkspaceA = Guid.Parse("a0000000-0000-0000-0000-000000000001");
    private static readonly Guid WorkspaceB = Guid.Parse("b0000000-0000-0000-0000-000000000001");
    private static readonly Guid VaultInA = Guid.Parse("a0000000-0000-0000-0000-00000000000a");
    private static readonly Guid VaultInB = Guid.Parse("b0000000-0000-0000-0000-00000000000a");

    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-0000000000a1");
    private static readonly Guid Admin = Guid.Parse("00000000-0000-0000-0000-0000000000a2");
    private static readonly Guid Reader = Guid.Parse("00000000-0000-0000-0000-0000000000a4");
    private static readonly Guid OwnerOfB = Guid.Parse("00000000-0000-0000-0000-0000000000b1");

    private static readonly RequestContext Request = new("203.0.113.5", "test", "req");

    private readonly TestDatabase _db = new();
    private readonly FixedClock _clock = new();
    private readonly InMemoryMasterKeyProvider _masterKeys = new();
    private readonly MembershipService _members;

    public MembershipServiceTests()
    {
        var hasher = new Argon2idPasswordHasher(
            Options.Create(new Argon2idOptions
            {
                MemoryKib = 19_456,
                Iterations = 2,
                Parallelism = 1,
            }),
            _masterKeys);

        _members = new MembershipService(
            _db.Context,
            new AccessPolicy(_db.Context, _clock, Options.Create(new SessionOptions())),
            hasher,
            new AuditChain(_db.Context, _clock),
            _clock);

        Seed();
    }

    public void Dispose()
    {
        _masterKeys.Dispose();
        _db.Dispose();
    }

    private void Seed()
    {
        var now = _clock.UtcNow;

        foreach (var (id, slug) in new[] { (WorkspaceA, "a"), (WorkspaceB, "b") })
        {
            _db.Context.Workspaces.Add(new Workspace
            {
                Id = id,
                Name = slug,
                Slug = slug,
                CreatedUtc = now,
            });
        }

        foreach (var (id, workspaceId, slug) in new[]
        {
            (VaultInA, WorkspaceA, "vault-a"),
            (VaultInB, WorkspaceB, "vault-b"),
        })
        {
            _db.Context.Vaults.Add(new Vault
            {
                Id = id,
                WorkspaceId = workspaceId,
                Name = slug,
                Slug = slug,
                ColorToken = "indigo",
                CreatedUtc = now,
                RecoveryWindowDays = 30,
                PurgeProtection = false,
            });
        }

        foreach (var (id, workspaceId, role) in new[]
        {
            (Owner, WorkspaceA, WorkspaceRole.Owner),
            (Admin, WorkspaceA, WorkspaceRole.Admin),
            (Reader, WorkspaceA, WorkspaceRole.Reader),
            (OwnerOfB, WorkspaceB, WorkspaceRole.Owner),
        })
        {
            _db.Context.Users.Add(new User
            {
                Id = id,
                Email = $"{id:N}@example.com",
                DisplayName = "test",
                PasswordHash = "digest",
                PasswordChangedUtc = now,
                FailedSignInCount = 0,
                CreatedUtc = now,
                IsActive = true,
            });

            _db.Context.WorkspaceMemberships.Add(new WorkspaceMembership
            {
                Id = Guid.CreateVersion7(),
                WorkspaceId = workspaceId,
                UserId = id,
                Role = role,
                GrantedUtc = now,
            });
        }

        _db.Context.SaveChanges();
    }

    private static Principal As(Guid userId) =>
        new(SubjectType.User, userId, $"{userId:N}@example.com", Guid.CreateVersion7());

    // -----------------------------------------------------------------------
    // The last-owner rule
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TheOnlyOwnerCannotBeDemoted()
    {
        // A workspace with no owner cannot have roles changed, keys rotated or data purged by
        // anyone. That is unrecoverable, and reachable by one careless click without this rule.
        var demoted = await _members.ChangeRoleAsync(
            As(Owner), WorkspaceA, Owner, WorkspaceRole.Admin, Request, CancellationToken.None);

        Assert.False(demoted.IsSuccess);
        Assert.Equal(DomainErrorKind.Conflict, demoted.Error.Kind);
        Assert.Contains("only owner", demoted.Error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TheOnlyOwnerCannotBeRemoved()
    {
        var removed = await _members.RemoveAsync(
            As(Owner), WorkspaceA, Owner, Request, CancellationToken.None);

        Assert.False(removed.IsSuccess);
        Assert.True(await _db.Context.WorkspaceMemberships
            .AnyAsync(m => m.UserId == Owner && m.Role == WorkspaceRole.Owner));
    }

    [Fact]
    public async Task AnOwnerCanBeDemotedOnceThereIsAnother()
    {
        await _members.ChangeRoleAsync(
            As(Owner), WorkspaceA, Admin, WorkspaceRole.Owner, Request, CancellationToken.None);

        var demoted = await _members.ChangeRoleAsync(
            As(Owner), WorkspaceA, Owner, WorkspaceRole.Admin, Request, CancellationToken.None);

        Assert.True(demoted.IsSuccess);
    }

    // -----------------------------------------------------------------------
    // Escalation
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AnAdminCannotPromoteAnyoneToOwner()
    {
        // Otherwise an admin promotes themselves in two steps and the distinction between the
        // roles means nothing.
        var promoted = await _members.ChangeRoleAsync(
            As(Admin), WorkspaceA, Reader, WorkspaceRole.Owner, Request, CancellationToken.None);

        Assert.False(promoted.IsSuccess);
        Assert.Equal(DomainErrorKind.Forbidden, promoted.Error.Kind);
    }

    [Fact]
    public async Task AnAdminCannotPromoteThemselves()
    {
        var promoted = await _members.ChangeRoleAsync(
            As(Admin), WorkspaceA, Admin, WorkspaceRole.Owner, Request, CancellationToken.None);

        Assert.False(promoted.IsSuccess);
    }

    [Fact]
    public async Task AnAdminCannotDemoteAnOwner()
    {
        var demoted = await _members.ChangeRoleAsync(
            As(Admin), WorkspaceA, Owner, WorkspaceRole.Reader, Request, CancellationToken.None);

        Assert.False(demoted.IsSuccess);
        Assert.Equal(DomainErrorKind.Forbidden, demoted.Error.Kind);
    }

    [Fact]
    public async Task AnAdminCannotAddAnOwner()
    {
        var added = await _members.AddAsync(
            As(Admin), WorkspaceA, "new@example.com", "New", WorkspaceRole.Owner,
            Request, CancellationToken.None);

        Assert.False(added.IsSuccess);
    }

    [Fact]
    public async Task AnAdminCanAddAnAdmin()
    {
        var added = await _members.AddAsync(
            As(Admin), WorkspaceA, "new@example.com", "New", WorkspaceRole.Admin,
            Request, CancellationToken.None);

        Assert.True(added.IsSuccess);
        Assert.Equal(WorkspaceRole.Admin, added.Value.Member.Role);
    }

    [Fact]
    public async Task AReaderCannotManageMembersAtAll()
    {
        var listed = await _members.ListAsync(As(Reader), WorkspaceA, CancellationToken.None);

        var added = await _members.AddAsync(
            As(Reader), WorkspaceA, "new@example.com", "New", WorkspaceRole.Reader,
            Request, CancellationToken.None);

        Assert.False(listed.IsSuccess);
        Assert.False(added.IsSuccess);
    }

    // -----------------------------------------------------------------------
    // Cross-tenant attempts
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AnOwnerOfAnotherWorkspaceCannotListMembers()
    {
        var listed = await _members.ListAsync(As(OwnerOfB), WorkspaceA, CancellationToken.None);

        Assert.False(listed.IsSuccess);
    }

    [Fact]
    public async Task AVaultFromAnotherWorkspaceCannotBeGranted()
    {
        // Checking only the member, and not the vault, would let an admin hand out access to
        // another tenant's vault. The grant would never resolve, but it would be a confusing
        // and alarming row to find in the database.
        var granted = await _members.GrantVaultAsync(
            As(Owner), WorkspaceA, Reader, VaultInB, VaultPermission.Read,
            Request, CancellationToken.None);

        Assert.False(granted.IsSuccess);
        Assert.Equal(DomainErrorKind.NotFound, granted.Error.Kind);
    }

    [Fact]
    public async Task AStrangerCannotBeGrantedAVault()
    {
        // The mirror case: a real vault, but someone who is not a member of the workspace.
        var granted = await _members.GrantVaultAsync(
            As(Owner), WorkspaceA, OwnerOfB, VaultInA, VaultPermission.Read,
            Request, CancellationToken.None);

        Assert.False(granted.IsSuccess);
    }

    // -----------------------------------------------------------------------
    // Grants
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AGrantShowsUpOnTheMemberList()
    {
        await _members.GrantVaultAsync(
            As(Owner), WorkspaceA, Reader, VaultInA, VaultPermission.Read,
            Request, CancellationToken.None);

        var listed = await _members.ListAsync(As(Owner), WorkspaceA, CancellationToken.None);
        var reader = listed.Value.First(m => m.UserId == Reader);

        Assert.Single(reader.Grants);
        Assert.Equal(VaultPermission.Read, reader.Grants[0].Permission);
        Assert.False(reader.HasImplicitVaultAccess);
    }

    [Fact]
    public async Task GrantingTwiceUpdatesRatherThanDuplicating()
    {
        await _members.GrantVaultAsync(
            As(Owner), WorkspaceA, Reader, VaultInA, VaultPermission.Read,
            Request, CancellationToken.None);

        await _members.GrantVaultAsync(
            As(Owner), WorkspaceA, Reader, VaultInA, VaultPermission.Write,
            Request, CancellationToken.None);

        var assignments = await _db.Context.VaultAssignments
            .AsNoTracking()
            .Where(a => a.SubjectId == Reader && a.VaultId == VaultInA)
            .ToListAsync();

        // A unique index enforces this too, but two rows would make the effective permission
        // ambiguous, so the service must not try.
        Assert.Single(assignments);
        Assert.Equal(VaultPermission.Write, assignments[0].Permission);
    }

    [Fact]
    public async Task RemovingAMemberRevokesTheirGrants()
    {
        // Leaving grants behind would mean re-adding the person silently restored access
        // someone had deliberately taken away.
        await _members.GrantVaultAsync(
            As(Owner), WorkspaceA, Reader, VaultInA, VaultPermission.Read,
            Request, CancellationToken.None);

        await _members.RemoveAsync(As(Owner), WorkspaceA, Reader, Request, CancellationToken.None);

        Assert.False(await _db.Context.VaultAssignments.AnyAsync(a => a.SubjectId == Reader));
        Assert.False(await _db.Context.WorkspaceMemberships.AnyAsync(m => m.UserId == Reader));
    }

    [Fact]
    public async Task AnAdminIsShownAsHavingImplicitAccess()
    {
        var listed = await _members.ListAsync(As(Owner), WorkspaceA, CancellationToken.None);
        var admin = listed.Value.First(m => m.UserId == Admin);

        Assert.True(admin.HasImplicitVaultAccess);
        Assert.True(admin.RequiresMfa);
    }

    // -----------------------------------------------------------------------
    // Adding members
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ANewMemberGetsAOneTimePasswordThatMeetsThePolicy()
    {
        var added = await _members.AddAsync(
            As(Owner), WorkspaceA, "New@Example.COM", "New Person", WorkspaceRole.Reader,
            Request, CancellationToken.None);

        Assert.True(added.IsSuccess);

        // Normalised, so sign-in by any casing finds the account.
        Assert.Equal("new@example.com", added.Value.Member.Email);

        var policy = new PasswordPolicy(Options.Create(new PasswordPolicyOptions()));
        Assert.True(policy.Check(added.Value.OneTimePassword, "new@example.com").IsAcceptable);
    }

    [Fact]
    public async Task TheOneTimePasswordVerifiesAgainstTheStoredDigest()
    {
        var added = await _members.AddAsync(
            As(Owner), WorkspaceA, "new@example.com", "New", WorkspaceRole.Reader,
            Request, CancellationToken.None);

        var stored = await _db.Context.Users
            .AsNoTracking()
            .FirstAsync(u => u.Email == "new@example.com");

        var hasher = new Argon2idPasswordHasher(
            Options.Create(new Argon2idOptions
            {
                MemoryKib = 19_456,
                Iterations = 2,
                Parallelism = 1,
            }),
            _masterKeys);

        Assert.NotEqual(
            PasswordVerificationResult.Failed,
            hasher.Verify(added.Value.OneTimePassword, stored.PasswordHash));
    }

    [Fact]
    public async Task AddingSomeoneAlreadyPresentIsRejected()
    {
        var again = await _members.AddAsync(
            As(Owner), WorkspaceA, $"{Reader:N}@example.com", "Reader", WorkspaceRole.Reader,
            Request, CancellationToken.None);

        Assert.False(again.IsSuccess);
        Assert.Equal(DomainErrorKind.Conflict, again.Error.Kind);
    }

    [Fact]
    public async Task AnExistingAccountJoinsWithoutANewPassword()
    {
        // Someone who already has an account in another workspace keeps their own password, so
        // handing back a generated one would be misleading.
        var added = await _members.AddAsync(
            As(Owner), WorkspaceA, $"{OwnerOfB:N}@example.com", "Owner B", WorkspaceRole.Reader,
            Request, CancellationToken.None);

        Assert.True(added.IsSuccess);
        Assert.Empty(added.Value.OneTimePassword);
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AnInvalidAddressIsRejected(string email)
    {
        var added = await _members.AddAsync(
            As(Owner), WorkspaceA, email, "New", WorkspaceRole.Reader,
            Request, CancellationToken.None);

        Assert.False(added.IsSuccess);
    }
}
