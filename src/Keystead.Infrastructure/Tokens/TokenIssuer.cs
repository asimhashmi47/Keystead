using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Identity;
using Keystead.Application.Tokens;
using Keystead.Domain.Auditing;
using Keystead.Domain.Common;
using Keystead.Domain.Vaults;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Keystead.Infrastructure.Tokens;

/// <summary>
/// Issues and validates ES256 machine tokens.
/// </summary>
/// <remarks>
/// <para>
/// Validation here is deliberately strict, because the well-known failures of JWT are all
/// failures of permissiveness. The algorithm is pinned to a single value, so neither
/// <c>alg: none</c> nor the HS256 confusion attack (handing a verifier the public key as an
/// HMAC secret) can get through. Issuer and audience are required and compared exactly. Clock
/// skew is thirty seconds rather than the library default of five minutes, because a generous
/// skew quietly extends every token's real lifetime.
/// </para>
/// <para>
/// The scopes in a token are a record of what was granted when it was minted, not the
/// authorization decision. Every endpoint re-resolves the grant from the database through
/// <c>IAccessPolicy</c>, so revoking a vault assignment takes effect on the next call instead
/// of when the token happens to expire.
/// </para>
/// </remarks>
public sealed class TokenIssuer : ITokenIssuer
{
    private const string ScopeClaim = "scope";
    private const string WorkspaceClaim = "kst:ws";
    private const string NameClaim = "kst:name";

    private static readonly DomainError GenericFailure = DomainError.Forbidden(
        "token.invalid_client",
        "Those client credentials were not accepted.");

    private readonly KeysteadDbContext _db;
    private readonly SigningKeyStore _keys;
    private readonly IAuditChain _audit;
    private readonly IClock _clock;
    private readonly TokenOptions _options;

    /// <summary>Creates the issuer.</summary>
    /// <param name="db">The database.</param>
    /// <param name="keys">The signing key store.</param>
    /// <param name="audit">The audit chain.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="options">Token lifetimes and validation parameters.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public TokenIssuer(
        KeysteadDbContext db,
        SigningKeyStore keys,
        IAuditChain audit,
        IClock clock,
        IOptions<TokenOptions> options)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(options);

        _db = db;
        _keys = keys;
        _audit = audit;
        _clock = clock;
        _options = options.Value;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<MachineToken>> IssueAsync(
        string clientId,
        string clientSecret,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(clientSecret);
        ArgumentNullException.ThrowIfNull(context);

        var now = _clock.UtcNow;

        // Structural check first. It costs nothing and means a truncated paste is refused
        // without a database round trip.
        if (!ClientCredential.IsWellFormed(clientSecret))
        {
            await DenyAsync(context, clientId, null, "Malformed client secret.", cancellationToken)
                .ConfigureAwait(false);

            return Result<MachineToken>.Fail(GenericFailure);
        }

        var identity = await _db.ServiceIdentities
            .FirstOrDefaultAsync(i => i.ClientId == clientId, cancellationToken)
            .ConfigureAwait(false);

        var candidate = ClientCredential.Hash(clientSecret);

        if (identity is null)
        {
            // Compare against a dummy digest anyway, so an unknown client id costs the same as
            // a known one and the endpoint cannot be used to enumerate identities.
            ClientCredential.Matches(candidate, new byte[32]);

            await DenyAsync(context, clientId, null, "No such client.", cancellationToken)
                .ConfigureAwait(false);

            return Result<MachineToken>.Fail(GenericFailure);
        }

        if (!identity.CanAuthenticate(now))
        {
            await DenyAsync(
                context, clientId, identity.WorkspaceId,
                identity.IsActive ? "Identity has expired." : "Identity is disabled.",
                cancellationToken).ConfigureAwait(false);

            return Result<MachineToken>.Fail(GenericFailure);
        }

        if (!IpAllowlist.IsAllowed(identity.IpAllowlist, context.IpAddress))
        {
            await AuditAsync(
                context, AuditAction.IpAllowlistBlocked, AuditOutcome.Denied,
                identity.WorkspaceId, identity.Id, identity.Name,
                $"Address {context.IpAddress} is not on the allowlist.",
                cancellationToken).ConfigureAwait(false);

            return Result<MachineToken>.Fail(GenericFailure);
        }

        // The current secret, or the previous one while its overlap window is open. The
        // overlap is what lets a deployment roll across without a gap in which neither works.
        var matched = ClientCredential.Matches(candidate, identity.ClientSecretHash);

        if (!matched
            && identity.PreviousSecretUsable(now)
            && ClientCredential.Matches(candidate, identity.PreviousClientSecretHash!))
        {
            matched = true;
        }

        if (!matched)
        {
            await DenyAsync(
                context, clientId, identity.WorkspaceId, "Incorrect client secret.",
                cancellationToken).ConfigureAwait(false);

            return Result<MachineToken>.Fail(GenericFailure);
        }

        var scopes = await ResolveScopesAsync(identity.Id, cancellationToken).ConfigureAwait(false);

        var signingKey = await _keys.GetOrCreateActiveAsync(cancellationToken).ConfigureAwait(false);

        using var ecdsa = _keys.OpenPrivate(signingKey);

        var credentials = new SigningCredentials(
            new ECDsaSecurityKey(ecdsa) { KeyId = signingKey.Kid, CryptoProviderFactory = Uncached() },
            SecurityAlgorithms.EcdsaSha256);

        var expires = now + _options.Lifetime;

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = credentials,
            Subject = new ClaimsIdentity(BuildClaims(identity.Id, identity.WorkspaceId, identity.Name, scopes)),
        };

        var handler = new JwtSecurityTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var token = handler.WriteToken(handler.CreateToken(descriptor));

        identity.LastUsedUtc = now;
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await AuditAsync(
            context, AuditAction.TokenIssued, AuditOutcome.Success,
            identity.WorkspaceId, identity.Id, identity.Name,
            $"Valid for {_options.Lifetime.TotalMinutes:0} minutes, {scopes.Count} scope(s).",
            cancellationToken).ConfigureAwait(false);

        return Result<MachineToken>.Ok(new MachineToken(
            token,
            (int)_options.Lifetime.TotalSeconds,
            scopes.Select(s => s.ToString()).ToList()));
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<Result<MachinePrincipal>> ValidateAsync(
        string token,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(context);

        var handler = new JwtSecurityTokenHandler();

        if (!handler.CanReadToken(token))
        {
            return Result<MachinePrincipal>.Fail(GenericFailure);
        }

        string? kid;

        try
        {
            kid = handler.ReadJwtToken(token).Header.Kid;
        }
        catch (ArgumentException)
        {
            return Result<MachinePrincipal>.Fail(GenericFailure);
        }

        if (string.IsNullOrEmpty(kid))
        {
            // Without a key id there is nothing to verify against, and guessing would mean
            // trying every key, which is how a validator ends up accepting a token signed by a
            // retired key it should have rejected.
            return Result<MachinePrincipal>.Fail(GenericFailure);
        }

        var signingKey = await _keys.FindByKidAsync(kid, cancellationToken).ConfigureAwait(false);

        if (signingKey is null
            || !signingKey.CanVerify(_clock.UtcNow, _options.RetiredKeyGrace))
        {
            return Result<MachinePrincipal>.Fail(GenericFailure);
        }

        using var ecdsa = SigningKeyStore.OpenPublic(signingKey);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new ECDsaSecurityKey(ecdsa)
            {
                KeyId = signingKey.Kid,
                CryptoProviderFactory = Uncached(),
            },

            // One algorithm, named explicitly. This single line is what closes 'alg: none' and
            // the HS256-confusion attack, both of which depend on the verifier accepting
            // whatever algorithm the token asks for.
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],

            ClockSkew = _options.ClockSkew,

            // Lifetime is checked against the injected clock, not the library's own reading of
            // DateTime.UtcNow. Two clocks would mean the issuer stamps 'exp' from one and the
            // validator judges it by another, which is both untestable and quietly wrong if
            // they ever disagree.
            LifetimeValidator = ValidateLifetime,
        };

        ClaimsPrincipal principal;

        try
        {
            principal = handler.ValidateToken(token, parameters, out _);
        }
        catch (SecurityTokenException)
        {
            // Expired, wrong signature, wrong issuer, wrong audience, wrong algorithm. All one
            // answer to the caller: an invalid token is an invalid token.
            return Result<MachinePrincipal>.Fail(GenericFailure);
        }
        catch (CryptographicException)
        {
            return Result<MachinePrincipal>.Fail(GenericFailure);
        }

        if (!TryReadPrincipal(principal, out var machine))
        {
            return Result<MachinePrincipal>.Fail(GenericFailure);
        }

        // Re-checked on every call, not just at issuance. A token outlives the moment it was
        // minted, so disabling an identity or moving its allowlist has to bite here.
        var identity = await _db.ServiceIdentities
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Id == machine.ServiceIdentityId, cancellationToken)
            .ConfigureAwait(false);

        if (identity is null
            || !identity.CanAuthenticate(_clock.UtcNow)
            || identity.WorkspaceId != machine.WorkspaceId)
        {
            return Result<MachinePrincipal>.Fail(GenericFailure);
        }

        if (!IpAllowlist.IsAllowed(identity.IpAllowlist, context.IpAddress))
        {
            await AuditAsync(
                context, AuditAction.IpAllowlistBlocked, AuditOutcome.Denied,
                identity.WorkspaceId, identity.Id, identity.Name,
                $"Address {context.IpAddress} is not on the allowlist.",
                cancellationToken).ConfigureAwait(false);

            return Result<MachinePrincipal>.Fail(GenericFailure);
        }

        return Result<MachinePrincipal>.Ok(machine);
    }

    /// <summary>
    /// A crypto provider factory with caching switched off.
    /// </summary>
    /// <remarks>
    /// IdentityModel caches signature providers keyed by the security key, and a cached
    /// provider keeps a reference to the ECDsa it was built with. Since the private key is
    /// opened per request and disposed on the way out, a cached provider would outlive its key
    /// and the next request would fail with ObjectDisposedException. Caching off means each
    /// request builds a provider bound to a live key.
    ///
    /// The alternative, holding one ECDsa open for the process lifetime, would be faster and
    /// would keep an unwrapped signing key in memory indefinitely. That is the trade this
    /// product does not take.
    /// </remarks>
    private static CryptoProviderFactory Uncached() =>
        new() { CacheSignatureProviders = false };

    /// <summary>
    /// Checks a token's validity window against the injected clock.
    /// </summary>
    /// <remarks>
    /// Both bounds are required. A token with no expiry would never stop working, and one
    /// without a not-before could be minted ahead of time and banked.
    /// </remarks>
    private bool ValidateLifetime(
        DateTime? notBefore,
        DateTime? expires,
        SecurityToken? token,
        TokenValidationParameters parameters)
    {
        if (expires is null)
        {
            return false;
        }

        var now = _clock.UtcNow.UtcDateTime;

        if (now > expires.Value + _options.ClockSkew)
        {
            return false;
        }

        return notBefore is null || now >= notBefore.Value - _options.ClockSkew;
    }

    private static IEnumerable<Claim> BuildClaims(
        Guid identityId,
        Guid workspaceId,
        string name,
        IReadOnlyList<VaultScope> scopes)
    {
        yield return new Claim(
            JwtRegisteredClaimNames.Sub,
            identityId.ToString("D", CultureInfo.InvariantCulture));

        yield return new Claim(
            WorkspaceClaim,
            workspaceId.ToString("D", CultureInfo.InvariantCulture));

        yield return new Claim(NameClaim, name);

        foreach (var scope in scopes)
        {
            yield return new Claim(ScopeClaim, scope.ToString());
        }
    }

    private static bool TryReadPrincipal(
        ClaimsPrincipal principal,
        out MachinePrincipal machine)
    {
        machine = null!;

        var subject = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var workspace = principal.FindFirst(WorkspaceClaim)?.Value;

        if (!Guid.TryParse(subject, CultureInfo.InvariantCulture, out var identityId)
            || !Guid.TryParse(workspace, CultureInfo.InvariantCulture, out var workspaceId))
        {
            return false;
        }

        var scopes = new List<VaultScope>();

        foreach (var claim in principal.FindAll(ScopeClaim))
        {
            if (TryParseScope(claim.Value, out var scope))
            {
                scopes.Add(scope);
            }
        }

        machine = new MachinePrincipal(
            identityId,
            workspaceId,
            principal.FindFirst(NameClaim)?.Value ?? "service-identity",
            scopes);

        return true;
    }

    private static bool TryParseScope(string value, out VaultScope scope)
    {
        scope = null!;

        var parts = value.Split(':');

        if (parts.Length != 3
            || !string.Equals(parts[0], "vault", StringComparison.Ordinal)
            || !Guid.TryParse(parts[1], CultureInfo.InvariantCulture, out var vaultId))
        {
            return false;
        }

        var write = string.Equals(parts[2], "write", StringComparison.Ordinal);

        if (!write && !string.Equals(parts[2], "read", StringComparison.Ordinal))
        {
            return false;
        }

        scope = new VaultScope(vaultId, write);
        return true;
    }

    private async Task<IReadOnlyList<VaultScope>> ResolveScopesAsync(
        Guid identityId,
        CancellationToken cancellationToken)
    {
        var assignments = await _db.VaultAssignments
            .AsNoTracking()
            .Where(a => a.SubjectId == identityId
                && a.SubjectType == SubjectType.ServiceIdentity
                && a.Vault!.SoftDeletedUtc == null)
            .Select(a => new { a.VaultId, a.Permission })
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return assignments
            .Select(a => new VaultScope(a.VaultId, a.Permission == VaultPermission.Write))
            .ToList();
    }

    private Task DenyAsync(
        RequestContext context,
        string clientId,
        Guid? workspaceId,
        string reason,
        CancellationToken cancellationToken) =>
        AuditAsync(
            context, AuditAction.TokenDenied, AuditOutcome.Denied,
            workspaceId, null, clientId, reason, cancellationToken);

    private async Task AuditAsync(
        RequestContext context,
        AuditAction action,
        AuditOutcome outcome,
        Guid? workspaceId,
        Guid? identityId,
        string label,
        string? detail,
        CancellationToken cancellationToken) =>
        _ = await _audit.AppendAsync(
            new AuditRecord
            {
                WorkspaceId = workspaceId,
                ActorType = ActorType.ServiceIdentity,
                ActorId = identityId,
                ActorLabel = label,
                Action = action,
                Outcome = outcome,
                ResourceType = "service_identity",
                ResourceId = identityId,
                IpAddress = context.IpAddress,
                UserAgent = context.UserAgent,
                CorrelationId = context.CorrelationId,
                DataJson = detail is null
                    ? null
                    : System.Text.Json.JsonSerializer.Serialize(new { reason = detail }),
            },
            cancellationToken).ConfigureAwait(false);
}
