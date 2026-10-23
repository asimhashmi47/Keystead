using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Keystead.Domain.Identity;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Auditing;
using Keystead.Infrastructure.Cryptography;
using Keystead.Infrastructure.Tokens;
using Keystead.Tests.TestDoubles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Keystead.Tests.Tokens;

/// <summary>
/// The machine token lifecycle, and the attacks that JWT implementations classically fall to.
/// </summary>
/// <remarks>
/// The round-trip test is the least interesting one here. What matters is that a forged
/// algorithm, a forged signature, an expired token, a retired key past its grace, and a
/// revoked identity are each refused, and that every refusal looks the same from outside.
/// </remarks>
public sealed class TokenIssuerTests : IDisposable
{
    private static readonly Guid WorkspaceA = Guid.Parse("a0000000-0000-0000-0000-000000000001");
    private static readonly Guid VaultA = Guid.Parse("a0000000-0000-0000-0000-00000000000a");

    private static readonly RequestContext FromAllowed =
        new("203.0.113.5", "smoke/1.0", "req-1");

    private readonly TestDatabase _db = new();
    private readonly FixedClock _clock = new();
    private readonly InMemoryMasterKeyProvider _masterKeys = new();
    private readonly TokenOptions _options = new();
    private readonly SigningKeyStore _keys;
    private readonly TokenIssuer _issuer;

    public TokenIssuerTests()
    {
        var cipher = new AesGcmCipher();
        _keys = new SigningKeyStore(_db.Context, cipher, _masterKeys, _clock);

        _issuer = new TokenIssuer(
            _db.Context,
            _keys,
            new AuditChain(_db.Context, _clock),
            _clock,
            Options.Create(_options));

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

        _db.Context.Workspaces.Add(new Workspace
        {
            Id = WorkspaceA, Name = "A", Slug = "a", CreatedUtc = now,
        });

        _db.Context.Vaults.Add(new Vault
        {
            Id = VaultA,
            WorkspaceId = WorkspaceA,
            Name = "Prod",
            Slug = "prod",
            ColorToken = "indigo",
            CreatedUtc = now,
            RecoveryWindowDays = 30,
            PurgeProtection = false,
        });

        _db.Context.SaveChanges();
    }

    private (Guid Id, string ClientId, string Secret) CreateIdentity(
        bool active = true,
        DateTimeOffset? expires = null,
        IEnumerable<string>? allowlist = null,
        VaultPermission? grant = VaultPermission.Read)
    {
        var (secret, hash) = ClientCredential.Create();
        var id = Guid.CreateVersion7();
        var clientId = ClientCredential.CreateClientId();

        _db.Context.ServiceIdentities.Add(new ServiceIdentity
        {
            Id = id,
            WorkspaceId = WorkspaceA,
            Name = "ci-runner",
            ClientId = clientId,
            ClientSecretHash = hash,
            ExpiresUtc = expires,
            CreatedUtc = _clock.UtcNow,
            IsActive = active,
            IpAllowlist = allowlist is null ? [] : [.. allowlist],
        });

        if (grant is { } permission)
        {
            _db.Context.VaultAssignments.Add(new VaultAssignment
            {
                Id = Guid.CreateVersion7(),
                VaultId = VaultA,
                SubjectId = id,
                SubjectType = SubjectType.ServiceIdentity,
                Permission = permission,
                GrantedUtc = _clock.UtcNow,
            });
        }

        _db.Context.SaveChanges();

        return (id, clientId, secret);
    }

    // -----------------------------------------------------------------------
    // Issuance
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ValidCredentials_GetAToken()
    {
        var identity = CreateIdentity();

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        Assert.True(issued.IsSuccess);
        Assert.Equal((int)_options.Lifetime.TotalSeconds, issued.Value.ExpiresInSeconds);
        Assert.Single(issued.Value.Scopes);
        Assert.Equal($"vault:{VaultA:D}:read", issued.Value.Scopes[0]);
    }

    [Fact]
    public async Task AnIssuedToken_ValidatesBackToItsIdentity()
    {
        var identity = CreateIdentity();

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var validated = await _issuer.ValidateAsync(
            issued.Value.AccessToken, FromAllowed, CancellationToken.None);

        Assert.True(validated.IsSuccess);
        Assert.Equal(identity.Id, validated.Value.ServiceIdentityId);
        Assert.Equal(WorkspaceA, validated.Value.WorkspaceId);
        Assert.Single(validated.Value.Scopes);
    }

    [Fact]
    public async Task TheTokenIsSignedWithEs256AndNamesItsKey()
    {
        var identity = CreateIdentity();

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var header = new JwtSecurityTokenHandler()
            .ReadJwtToken(issued.Value.AccessToken).Header;

        Assert.Equal("ES256", header.Alg);
        Assert.False(string.IsNullOrEmpty(header.Kid));
    }

    [Fact]
    public async Task AWrongSecret_IsRefused()
    {
        var identity = CreateIdentity();
        var (other, _) = ClientCredential.Create();

        var issued = await _issuer.IssueAsync(
            identity.ClientId, other, FromAllowed, CancellationToken.None);

        Assert.False(issued.IsSuccess);
    }

    [Fact]
    public async Task AnUnknownClientAndAWrongSecret_GiveTheSameError()
    {
        // An endpoint that distinguished them would let anyone enumerate which identities
        // exist by watching which error came back.
        var identity = CreateIdentity();
        var (other, _) = ClientCredential.Create();

        var unknown = await _issuer.IssueAsync(
            "ksid_DOESNOTEXIST", other, FromAllowed, CancellationToken.None);

        var wrong = await _issuer.IssueAsync(
            identity.ClientId, other, FromAllowed, CancellationToken.None);

        Assert.False(unknown.IsSuccess);
        Assert.False(wrong.IsSuccess);
        Assert.Equal(unknown.Error.Code, wrong.Error.Code);
        Assert.Equal(unknown.Error.Message, wrong.Error.Message);
    }

    [Fact]
    public async Task AMalformedSecret_IsRefused()
    {
        var identity = CreateIdentity();

        var issued = await _issuer.IssueAsync(
            identity.ClientId, "not-a-keystead-secret", FromAllowed, CancellationToken.None);

        Assert.False(issued.IsSuccess);
    }

    [Fact]
    public async Task ADisabledIdentity_CannotGetAToken()
    {
        var identity = CreateIdentity(active: false);

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        Assert.False(issued.IsSuccess);
    }

    [Fact]
    public async Task AnExpiredIdentity_CannotGetAToken()
    {
        var identity = CreateIdentity(expires: _clock.UtcNow.AddDays(-1));

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        Assert.False(issued.IsSuccess);
    }

    [Fact]
    public async Task AnIdentityWithNoGrants_GetsATokenWithNoScopes()
    {
        // Not an error. The identity is authentic; it simply cannot reach anything, and every
        // endpoint re-checks the grant anyway.
        var identity = CreateIdentity(grant: null);

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        Assert.True(issued.IsSuccess);
        Assert.Empty(issued.Value.Scopes);
    }

    // -----------------------------------------------------------------------
    // IP allowlist
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AnAddressOffTheAllowlist_IsRefusedAtIssuance()
    {
        var identity = CreateIdentity(allowlist: ["198.51.100.0/24"]);

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        Assert.False(issued.IsSuccess);
    }

    [Fact]
    public async Task AnAddressOnTheAllowlist_IsAccepted()
    {
        var identity = CreateIdentity(allowlist: ["203.0.113.0/24"]);

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        Assert.True(issued.IsSuccess);
    }

    [Fact]
    public async Task MovingTheAllowlistInvalidatesAnAlreadyIssuedToken()
    {
        // The allowlist is re-checked on every call, not just at issuance. A token outlives
        // the moment it was minted, so tightening the list has to bite immediately.
        var identity = CreateIdentity();

        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var stored = await _db.Context.ServiceIdentities.FirstAsync(i => i.Id == identity.Id);
        stored.IpAllowlist = ["198.51.100.0/24"];
        await _db.Context.SaveChangesAsync();

        var validated = await _issuer.ValidateAsync(
            issued.Value.AccessToken, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    // -----------------------------------------------------------------------
    // Secret rotation with overlap
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AfterRotation_BothSecretsWorkInsideTheOverlap()
    {
        // The whole point of the overlap: deployments move across without a window in which
        // neither secret authenticates.
        var identity = CreateIdentity();
        var (newSecret, newHash) = ClientCredential.Create();

        var stored = await _db.Context.ServiceIdentities.FirstAsync(i => i.Id == identity.Id);
        stored.PreviousClientSecretHash = stored.ClientSecretHash;
        stored.PreviousSecretExpiresUtc = _clock.UtcNow.AddHours(1);
        stored.ClientSecretHash = newHash;
        await _db.Context.SaveChangesAsync();

        var withOld = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var withNew = await _issuer.IssueAsync(
            identity.ClientId, newSecret, FromAllowed, CancellationToken.None);

        Assert.True(withOld.IsSuccess);
        Assert.True(withNew.IsSuccess);
    }

    [Fact]
    public async Task AfterTheOverlapExpires_TheOldSecretStopsWorking()
    {
        var identity = CreateIdentity();
        var (newSecret, newHash) = ClientCredential.Create();

        var stored = await _db.Context.ServiceIdentities.FirstAsync(i => i.Id == identity.Id);
        stored.PreviousClientSecretHash = stored.ClientSecretHash;
        stored.PreviousSecretExpiresUtc = _clock.UtcNow.AddHours(1);
        stored.ClientSecretHash = newHash;
        await _db.Context.SaveChangesAsync();

        _clock.Advance(TimeSpan.FromHours(2));

        var withOld = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var withNew = await _issuer.IssueAsync(
            identity.ClientId, newSecret, FromAllowed, CancellationToken.None);

        Assert.False(withOld.IsSuccess);
        Assert.True(withNew.IsSuccess);
    }

    // -----------------------------------------------------------------------
    // Validation: the classic JWT attacks
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AnUnsignedToken_IsRefused()
    {
        // The alg:none attack. Closed by pinning ValidAlgorithms to ES256 alone.
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var original = new JwtSecurityTokenHandler().ReadJwtToken(issued.Value.AccessToken);

        var header = Base64Url("""{"alg":"none","typ":"JWT","kid":"%KID%"}"""
            .Replace("%KID%", original.Header.Kid, StringComparison.Ordinal));

        var payload = issued.Value.AccessToken.Split('.')[1];
        var forged = $"{header}.{payload}.";

        var validated = await _issuer.ValidateAsync(forged, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    [Fact]
    public async Task ATokenSignedWithTheKeyAsAnHmacSecret_IsRefused()
    {
        // The HS256 confusion attack: take the public key, use it as an HMAC secret, and hope
        // the verifier honours the algorithm the token names. Closed by the same pin.
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var signingKey = await _keys.GetOrCreateActiveAsync(CancellationToken.None);
        var original = new JwtSecurityTokenHandler().ReadJwtToken(issued.Value.AccessToken);

        var handler = new JwtSecurityTokenHandler();
        var hmacKey = new SymmetricSecurityKey(signingKey.PublicKey) { KeyId = signingKey.Kid };

        var forged = handler.WriteToken(handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            NotBefore = _clock.UtcNow.UtcDateTime,
            IssuedAt = _clock.UtcNow.UtcDateTime,
            Expires = _clock.UtcNow.AddMinutes(10).UtcDateTime,
            SigningCredentials = new SigningCredentials(hmacKey, SecurityAlgorithms.HmacSha256),
            Subject = new ClaimsIdentity(original.Claims),
        }));

        var validated = await _issuer.ValidateAsync(forged, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    [Fact]
    public async Task ATokenSignedByADifferentKey_IsRefused()
    {
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var signingKey = await _keys.GetOrCreateActiveAsync(CancellationToken.None);
        var original = new JwtSecurityTokenHandler().ReadJwtToken(issued.Value.AccessToken);

        // A key the attacker generated, but claiming the server's key id.
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var handler = new JwtSecurityTokenHandler();

        var forged = handler.WriteToken(handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            NotBefore = _clock.UtcNow.UtcDateTime,
            IssuedAt = _clock.UtcNow.UtcDateTime,
            Expires = _clock.UtcNow.AddMinutes(10).UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(attackerKey) { KeyId = signingKey.Kid },
                SecurityAlgorithms.EcdsaSha256),
            Subject = new ClaimsIdentity(original.Claims),
        }));

        var validated = await _issuer.ValidateAsync(forged, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    [Fact]
    public async Task ATamperedPayload_IsRefused()
    {
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var parts = issued.Value.AccessToken.Split('.');
        var tampered = $"{parts[0]}.{parts[1]}.{Flip(parts[2])}";

        var validated = await _issuer.ValidateAsync(tampered, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    [Fact]
    public async Task ATokenWithNoKeyId_IsRefused()
    {
        // Without a kid there is nothing to verify against. Trying every key would be how a
        // validator ends up accepting a token signed by a key it should have rejected.
        var handler = new JwtSecurityTokenHandler();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var forged = handler.WriteToken(handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            NotBefore = _clock.UtcNow.UtcDateTime,
            IssuedAt = _clock.UtcNow.UtcDateTime,
            Expires = _clock.UtcNow.AddMinutes(10).UtcDateTime,
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
        }));

        var validated = await _issuer.ValidateAsync(forged, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not.a.token")]
    [InlineData("eyJhbGciOiJub25lIn0")]
    public async Task Rubbish_IsRefusedWithoutThrowing(string token)
    {
        var validated = await _issuer.ValidateAsync(token, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    [Fact]
    public async Task AnExpiredToken_IsRefused()
    {
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        // Past the lifetime and past the skew allowance.
        _clock.Advance(_options.Lifetime + _options.ClockSkew + TimeSpan.FromMinutes(1));

        var validated = await _issuer.ValidateAsync(
            issued.Value.AccessToken, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    [Fact]
    public async Task ARevokedIdentity_CannotUseATokenItAlreadyHolds()
    {
        // The property that makes revocation meaningful: it takes effect on the next call,
        // not when the token happens to expire.
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var before = await _issuer.ValidateAsync(
            issued.Value.AccessToken, FromAllowed, CancellationToken.None);

        Assert.True(before.IsSuccess);

        var stored = await _db.Context.ServiceIdentities.FirstAsync(i => i.Id == identity.Id);
        stored.IsActive = false;
        await _db.Context.SaveChangesAsync();

        var after = await _issuer.ValidateAsync(
            issued.Value.AccessToken, FromAllowed, CancellationToken.None);

        Assert.False(after.IsSuccess);
    }

    [Fact]
    public async Task ADeletedIdentity_CannotUseATokenItAlreadyHolds()
    {
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        await _db.Context.ServiceIdentities
            .Where(i => i.Id == identity.Id)
            .ExecuteDeleteAsync();

        var validated = await _issuer.ValidateAsync(
            issued.Value.AccessToken, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    // -----------------------------------------------------------------------
    // Signing key rotation
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AfterSigningKeyRotation_OldTokensStillVerify()
    {
        // Rotation must not reject tokens that are still inside their validity window, or
        // every rotation would be a brief outage.
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        await _keys.RotateAsync(CancellationToken.None);

        var validated = await _issuer.ValidateAsync(
            issued.Value.AccessToken, FromAllowed, CancellationToken.None);

        Assert.True(validated.IsSuccess);
    }

    [Fact]
    public async Task AfterRotation_NewTokensUseTheNewKey()
    {
        var identity = CreateIdentity();

        var first = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        await _keys.RotateAsync(CancellationToken.None);

        var second = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        var handler = new JwtSecurityTokenHandler();

        Assert.NotEqual(
            handler.ReadJwtToken(first.Value.AccessToken).Header.Kid,
            handler.ReadJwtToken(second.Value.AccessToken).Header.Kid);
    }

    [Fact]
    public async Task ARetiredKeyStopsVerifyingOnceItsGraceElapses()
    {
        var identity = CreateIdentity();
        var issued = await _issuer.IssueAsync(
            identity.ClientId, identity.Secret, FromAllowed, CancellationToken.None);

        await _keys.RotateAsync(CancellationToken.None);

        _clock.Advance(_options.RetiredKeyGrace + TimeSpan.FromMinutes(1));

        var validated = await _issuer.ValidateAsync(
            issued.Value.AccessToken, FromAllowed, CancellationToken.None);

        Assert.False(validated.IsSuccess);
    }

    [Fact]
    public async Task TheSigningKeyIsStoredSealed()
    {
        await _keys.GetOrCreateActiveAsync(CancellationToken.None);

        var key = await _db.Context.SigningKeys.AsNoTracking().FirstAsync();

        // The public half is readable so verification never needs the master key; the private
        // half is ciphertext so a stolen database cannot mint tokens.
        Assert.NotEmpty(key.PublicKey);
        Assert.NotEmpty(key.PrivateKeyCiphertext);
        Assert.Equal(12, key.PrivateKeyNonce.Length);
        Assert.Equal(16, key.PrivateKeyTag.Length);

        using var publicKey = SigningKeyStore.OpenPublic(key);
        Assert.Equal(256, publicKey.KeySize);
    }

    [Fact]
    public async Task ASigningKeyMovedToAnotherRow_CannotBeOpened()
    {
        // AAD binds the sealed private key to its own row, so a signing key cannot be
        // relocated any more than a secret value can.
        var key = await _keys.GetOrCreateActiveAsync(CancellationToken.None);

        var moved = new SigningKey
        {
            Id = Guid.CreateVersion7(),
            Kid = "relocated",
            PrivateKeyCiphertext = key.PrivateKeyCiphertext,
            PrivateKeyNonce = key.PrivateKeyNonce,
            PrivateKeyTag = key.PrivateKeyTag,
            MasterKeyVersion = key.MasterKeyVersion,
            PublicKey = key.PublicKey,
            CreatedUtc = key.CreatedUtc,
        };

        Assert.Throws<AuthenticationTagMismatchException>(() => _keys.OpenPrivate(moved));
    }

    private static string Base64Url(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string Flip(string signature)
    {
        var characters = signature.ToCharArray();
        characters[0] = characters[0] == 'A' ? 'B' : 'A';
        return new string(characters);
    }
}
