using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Application.Secrets;
using Keystead.Application.Vaults;
using Keystead.Domain.Common;
using Keystead.Domain.Identity;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Auditing;
using Keystead.Infrastructure.Authorization;
using Keystead.Infrastructure.Cryptography;
using Keystead.Infrastructure.Identity;
using Keystead.Infrastructure.Secrets;
using Keystead.Infrastructure.Vaults;
using Keystead.Tests.TestDoubles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Xunit;

namespace Keystead.Tests.Vaults;

public sealed class VaultServiceTests : IDisposable
{
    private static readonly Guid WorkspaceA = Guid.Parse("a0000000-0000-0000-0000-000000000001");
    private static readonly Guid WorkspaceB = Guid.Parse("b0000000-0000-0000-0000-000000000001");
    private static readonly Guid OwnerOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a1");
    private static readonly Guid AdminOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a2");
    private static readonly Guid ReaderOfA = Guid.Parse("00000000-0000-0000-0000-0000000000a4");
    private static readonly Guid OwnerOfB = Guid.Parse("00000000-0000-0000-0000-0000000000b1");

    private static readonly RequestContext Request = new("203.0.113.5", "test", "req");

    private readonly TestDatabase _db = new();
    private readonly FixedClock _clock = new();
    private readonly InMemoryMasterKeyProvider _masterKeys = new();
    private readonly VaultService _vaults;
    private readonly SecretService _secrets;

    public VaultServiceTests()
    {
        var cipher = new AesGcmCipher();
        var vaultKeys = new VaultKeyService(_db.Context, cipher, _masterKeys, _clock);
        var protector = new SecretProtector(vaultKeys, cipher);
        var audit = new AuditChain(_db.Context, _clock);
        var access = new AccessPolicy(_db.Context, _clock, Options.Create(new SessionOptions()));

        _vaults = new VaultService(_db.Context, access, vaultKeys, audit, _clock);
        _secrets = new SecretService(_db.Context, access, protector, audit, _clock);

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
                Id = id, Name = slug, Slug = slug, CreatedUtc = now,
            });
        }

        foreach (var (id, workspaceId, role) in new[]
        {
            (OwnerOfA, WorkspaceA, WorkspaceRole.Owner),
            (AdminOfA, WorkspaceA, WorkspaceRole.Admin),
            (ReaderOfA, WorkspaceA, WorkspaceRole.Reader),
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

    private static Principal Principal(Guid userId) =>
        new(SubjectType.User, userId, $"{userId:N}@example.com", Guid.CreateVersion7());

    private Task<Result<VaultSummary>> CreateAsync(
        Guid userId,
        string name = "Platform",
        bool purgeProtection = false,
        int recoveryWindowDays = 30,
        string color = "indigo") =>
        _vaults.CreateAsync(
            Principal(userId),
            WorkspaceA,
            new CreateVaultRequest(name, null, color, recoveryWindowDays, purgeProtection),
            Request,
            CancellationToken.None);

    [Fact]
    public async Task AnOwner_CanCreateAVault()
    {
        var created = await CreateAsync(OwnerOfA);

        Assert.True(created.IsSuccess);
        Assert.Equal("platform", created.Value.Slug);
        Assert.Equal(VaultPermission.Write, created.Value.Permission);
    }

    [Fact]
    public async Task ANewVault_GetsItsOwnKeyImmediately()
    {
        // A vault with no key could never hold a secret, so the two are created together.
        var created = await CreateAsync(OwnerOfA);

        var keks = await _db.Context.VaultKeks
            .AsNoTracking()
            .Where(k => k.VaultId == created.Value.Id)
            .ToListAsync();

        Assert.Single(keks);
        Assert.Equal(1, keks[0].Version);
        Assert.True(keks[0].IsActive);
    }

    [Fact]
    public async Task AReader_CannotCreateAVault()
    {
        var created = await CreateAsync(ReaderOfA);

        Assert.False(created.IsSuccess);
        Assert.Equal(DomainErrorKind.Forbidden, created.Error.Kind);
    }

    [Fact]
    public async Task AnAdmin_CanCreateAVault()
    {
        var created = await CreateAsync(AdminOfA);

        Assert.True(created.IsSuccess);
    }

    [Fact]
    public async Task ADuplicateName_IsRejected()
    {
        await CreateAsync(OwnerOfA, "Platform");
        var again = await CreateAsync(OwnerOfA, "platform");

        Assert.False(again.IsSuccess);
        Assert.Equal(DomainErrorKind.Conflict, again.Error.Kind);
    }

    [Theory]
    [InlineData("fuchsia")]
    [InlineData("#ff0000")]
    [InlineData("red; background: url(evil)")]
    [InlineData("")]
    public async Task AColourNotOnTheAllowList_IsRejected(string color)
    {
        // The token reaches a CSS custom property name in the view, so this is an allow-list
        // rather than a sanitiser.
        var created = await CreateAsync(OwnerOfA, color: color);

        Assert.False(created.IsSuccess);
        Assert.Equal(DomainErrorKind.Invalid, created.Error.Kind);
    }

    [Fact]
    public async Task AReader_SeesNoVaultsWithoutAGrant()
    {
        await CreateAsync(OwnerOfA);

        var listed = await _vaults.ListAsync(
            Principal(ReaderOfA), WorkspaceA, includeDeleted: false, CancellationToken.None);

        // Not an error: an empty list. A Reader must not be able to tell that vaults exist.
        Assert.True(listed.IsSuccess);
        Assert.Empty(listed.Value);
    }

    [Fact]
    public async Task AReaderWithAGrant_SeesTheVaultAsReadOnly()
    {
        var created = await CreateAsync(OwnerOfA);

        _db.Context.VaultAssignments.Add(new VaultAssignment
        {
            Id = Guid.CreateVersion7(),
            VaultId = created.Value.Id,
            SubjectId = ReaderOfA,
            SubjectType = SubjectType.User,
            Permission = VaultPermission.Read,
            GrantedUtc = _clock.UtcNow,
        });

        await _db.Context.SaveChangesAsync();

        var listed = await _vaults.ListAsync(
            Principal(ReaderOfA), WorkspaceA, includeDeleted: false, CancellationToken.None);

        Assert.Single(listed.Value);
        Assert.Equal(VaultPermission.Read, listed.Value[0].Permission);
    }

    [Fact]
    public async Task AnOwnerOfAnotherWorkspace_SeesNothing()
    {
        await CreateAsync(OwnerOfA);

        var listed = await _vaults.ListAsync(
            Principal(OwnerOfB), WorkspaceB, includeDeleted: false, CancellationToken.None);

        Assert.Empty(listed.Value);
    }

    [Fact]
    public async Task AVaultInAnotherWorkspace_IsNotFoundBySlug()
    {
        await CreateAsync(OwnerOfA, "Platform");

        var found = await _vaults.GetBySlugAsync(
            Principal(OwnerOfB), WorkspaceB, "platform", CancellationToken.None);

        Assert.False(found.IsSuccess);
        Assert.Equal(DomainErrorKind.NotFound, found.Error.Kind);
    }

    // -----------------------------------------------------------------------
    // Soft delete, recovery window, purge protection
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ASoftDeletedVault_IsRecoverable()
    {
        var created = await CreateAsync(OwnerOfA);
        var vaultId = created.Value.Id;

        await _vaults.SoftDeleteAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        var hidden = await _vaults.ListAsync(
            Principal(OwnerOfA), WorkspaceA, includeDeleted: false, CancellationToken.None);

        Assert.Empty(hidden.Value);

        var recovered = await _vaults.RecoverAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        Assert.True(recovered.IsSuccess);

        var visible = await _vaults.ListAsync(
            Principal(OwnerOfA), WorkspaceA, includeDeleted: false, CancellationToken.None);

        Assert.Single(visible.Value);
    }

    [Fact]
    public async Task PurgingAVaultThatIsNotDeleted_IsRefused()
    {
        var created = await CreateAsync(OwnerOfA);

        var purged = await _vaults.PurgeAsync(
            Principal(OwnerOfA), WorkspaceA, created.Value.Id, Request, CancellationToken.None);

        Assert.False(purged.IsSuccess);
        Assert.Contains("deleted first", purged.Error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PurgingBeforeTheRecoveryWindowElapses_IsRefused()
    {
        var created = await CreateAsync(OwnerOfA, recoveryWindowDays: 30);
        var vaultId = created.Value.Id;

        await _vaults.SoftDeleteAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        _clock.Advance(TimeSpan.FromDays(29));

        var purged = await _vaults.PurgeAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        Assert.False(purged.IsSuccess);
        Assert.Equal(DomainErrorKind.Conflict, purged.Error.Kind);
    }

    [Fact]
    public async Task PurgingAfterTheRecoveryWindow_Succeeds()
    {
        var created = await CreateAsync(OwnerOfA, recoveryWindowDays: 30);
        var vaultId = created.Value.Id;

        await _vaults.SoftDeleteAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        _clock.Advance(TimeSpan.FromDays(31));

        var purged = await _vaults.PurgeAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        Assert.True(purged.IsSuccess);
        Assert.False(await _db.Context.Vaults.AnyAsync(v => v.Id == vaultId));
    }

    [Fact]
    public async Task PurgeProtection_BlocksPurgeEvenAfterTheWindowElapses()
    {
        // The guard against both a malicious insider and an over-confident operator. Time
        // passing is not enough; the protection has to be turned off deliberately first.
        var created = await CreateAsync(OwnerOfA, purgeProtection: true, recoveryWindowDays: 1);
        var vaultId = created.Value.Id;

        await _vaults.SoftDeleteAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        _clock.Advance(TimeSpan.FromDays(400));

        var purged = await _vaults.PurgeAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        Assert.False(purged.IsSuccess);
        Assert.Contains("Purge protection", purged.Error.Message, StringComparison.Ordinal);
        Assert.True(await _db.Context.Vaults.AnyAsync(v => v.Id == vaultId));
    }

    [Fact]
    public async Task AnAdmin_CannotPurge()
    {
        // Purging is Owner-only, separately from managing vaults, because it is the one
        // operation that destroys key material irreversibly.
        var created = await CreateAsync(OwnerOfA, recoveryWindowDays: 1);
        var vaultId = created.Value.Id;

        await _vaults.SoftDeleteAsync(
            Principal(AdminOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        _clock.Advance(TimeSpan.FromDays(2));

        var purged = await _vaults.PurgeAsync(
            Principal(AdminOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        Assert.False(purged.IsSuccess);
        Assert.Equal(DomainErrorKind.Forbidden, purged.Error.Kind);
    }

    [Fact]
    public async Task PurgingAVault_DestroysItsSecretsAndKeys()
    {
        var created = await CreateAsync(OwnerOfA, recoveryWindowDays: 1);
        var vaultId = created.Value.Id;

        await _secrets.CreateAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId,
            new CreateSecretRequest(
                "Token", "prod", Encoding.UTF8.GetBytes("value"), null, null, null,
                new System.Collections.Generic.Dictionary<string, string>(StringComparer.Ordinal)),
            Request, CancellationToken.None);

        await _vaults.SoftDeleteAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        _clock.Advance(TimeSpan.FromDays(2));

        var purged = await _vaults.PurgeAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, Request, CancellationToken.None);

        Assert.True(purged.IsSuccess);

        // Cascades through the foreign keys, which is why the pragma enabling them is applied
        // on every connection rather than assumed.
        Assert.False(await _db.Context.Secrets.AnyAsync(s => s.VaultId == vaultId));
        Assert.False(await _db.Context.VaultKeks.AnyAsync(k => k.VaultId == vaultId));
        Assert.False(await _db.Context.SecretVersions.AnyAsync());
    }

    [Fact]
    public async Task AVaultInAnotherWorkspace_CannotBeSoftDeleted()
    {
        var created = await CreateAsync(OwnerOfA);

        var deleted = await _vaults.SoftDeleteAsync(
            Principal(OwnerOfB), WorkspaceB, created.Value.Id, Request, CancellationToken.None);

        Assert.False(deleted.IsSuccess);
        Assert.True(await _db.Context.Vaults.AnyAsync(
            v => v.Id == created.Value.Id && v.SoftDeletedUtc == null));
    }

    [Fact]
    public async Task TheSecretCount_ReflectsLiveSecretsOnly()
    {
        var created = await CreateAsync(OwnerOfA);
        var vaultId = created.Value.Id;

        var secret = await _secrets.CreateAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId,
            new CreateSecretRequest(
                "Token", "prod", Encoding.UTF8.GetBytes("value"), null, null, null,
                new System.Collections.Generic.Dictionary<string, string>(StringComparer.Ordinal)),
            Request, CancellationToken.None);

        var before = await _vaults.ListAsync(
            Principal(OwnerOfA), WorkspaceA, false, CancellationToken.None);

        Assert.Equal(1, before.Value[0].SecretCount);

        await _secrets.SoftDeleteAsync(
            Principal(OwnerOfA), WorkspaceA, vaultId, secret.Value.Id, Request, CancellationToken.None);

        var after = await _vaults.ListAsync(
            Principal(OwnerOfA), WorkspaceA, false, CancellationToken.None);

        Assert.Equal(0, after.Value[0].SecretCount);
    }
}
