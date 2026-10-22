using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Cryptography;
using Keystead.Application.Identity;
using Keystead.Domain.Auditing;
using Keystead.Domain.Identity;
using Keystead.Domain.Keys;
using Keystead.Domain.Workspaces;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Identity;

/// <summary>
/// First-run initialisation: creates the first workspace and its owner.
/// </summary>
/// <remarks>
/// The guard at the top of <see cref="InitialiseAsync"/> is the important part. The setup page
/// has to be reachable without authentication, because there is nobody to authenticate as yet.
/// If it stayed reachable after setup, it would be a permanent unauthenticated route to
/// creating an Owner account. So initialisation is refused the moment any user exists, and the
/// page itself redirects away.
/// </remarks>
public sealed class InstallationService : IInstallationService
{
    private readonly KeysteadDbContext _db;
    private readonly IPasswordHasher _passwords;
    private readonly IPasswordPolicy _policy;
    private readonly IMasterKeyProvider _masterKeys;
    private readonly IAuditChain _audit;
    private readonly IClock _clock;

    /// <summary>Creates the service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="passwords">The password hasher.</param>
    /// <param name="policy">The password policy.</param>
    /// <param name="masterKeys">The master key provider, for the recovery kit fingerprint.</param>
    /// <param name="audit">The audit chain.</param>
    /// <param name="clock">The clock.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public InstallationService(
        KeysteadDbContext db,
        IPasswordHasher passwords,
        IPasswordPolicy policy,
        IMasterKeyProvider masterKeys,
        IAuditChain audit,
        IClock clock)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(passwords);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(masterKeys);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(clock);

        _db = db;
        _passwords = passwords;
        _policy = policy;
        _masterKeys = masterKeys;
        _audit = audit;
        _clock = clock;
    }

    /// <inheritdoc />
    public Task<bool> IsInitialisedAsync(CancellationToken cancellationToken) =>
        _db.Users.AsNoTracking().AnyAsync(cancellationToken);

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public async Task<InitialisationResult> InitialiseAsync(
        InitialisationRequest request,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        if (await IsInitialisedAsync(cancellationToken).ConfigureAwait(false))
        {
            return InitialisationResult.Failed(
                "This installation has already been set up. Sign in instead.");
        }

        var email = request.Email.Trim().ToLowerInvariant();

        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@', StringComparison.Ordinal))
        {
            return InitialisationResult.Failed("Enter a valid email address.");
        }

        if (string.IsNullOrWhiteSpace(request.WorkspaceName))
        {
            return InitialisationResult.Failed("Enter a name for your workspace.");
        }

        var passwordCheck = _policy.Check(request.Password, email);

        if (!passwordCheck.IsAcceptable)
        {
            return InitialisationResult.Failed(passwordCheck.Reason!);
        }

        var now = _clock.UtcNow;
        var workspaceId = Guid.CreateVersion7();
        var userId = Guid.CreateVersion7();

        _db.Workspaces.Add(new Workspace
        {
            Id = workspaceId,
            Name = request.WorkspaceName.Trim(),
            Slug = Slugify(request.WorkspaceName),
            CreatedUtc = now,
        });

        _db.Users.Add(new User
        {
            Id = userId,
            Email = email,
            DisplayName = string.IsNullOrWhiteSpace(request.DisplayName)
                ? email
                : request.DisplayName.Trim(),
            PasswordHash = _passwords.Hash(request.Password),
            PasswordChangedUtc = now,
            FailedSignInCount = 0,
            CreatedUtc = now,
            IsActive = true,
        });

        _db.WorkspaceMemberships.Add(new WorkspaceMembership
        {
            Id = Guid.CreateVersion7(),
            WorkspaceId = workspaceId,
            UserId = userId,
            Role = WorkspaceRole.Owner,
            GrantedUtc = now,
        });

        // Record the master key generation that this installation was created under, with its
        // fingerprint. If a later start supplies a different key, the mismatch is detectable
        // before anything tries and fails to decrypt.
        _db.MasterKeyVersions.Add(new MasterKeyVersion
        {
            Version = _masterKeys.ActiveVersion,
            KeyCheckValue = _masterKeys.ActiveKeyCheckValue,
            CreatedUtc = now,
        });

        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await _audit.AppendAsync(
            new AuditRecord
            {
                WorkspaceId = workspaceId,
                ActorType = ActorType.User,
                ActorId = userId,
                ActorLabel = email,
                Action = AuditAction.InstallationInitialised,
                Outcome = AuditOutcome.Success,
                ResourceType = "workspace",
                ResourceId = workspaceId,
                ResourceLabel = request.WorkspaceName.Trim(),
                IpAddress = context.IpAddress,
                UserAgent = context.UserAgent,
                CorrelationId = context.CorrelationId,
                DataJson = System.Text.Json.JsonSerializer.Serialize(new
                {
                    masterKeyVersion = _masterKeys.ActiveVersion,
                    masterKeyCheckValue = _masterKeys.ActiveKeyCheckValue,
                }),
            },
            cancellationToken).ConfigureAwait(false);

        return InitialisationResult.Ok(workspaceId, userId, _masterKeys.ActiveKeyCheckValue);
    }

    /// <summary>
    /// Reduces a name to a URL-safe slug.
    /// </summary>
    /// <remarks>
    /// An allow-list, not a deny-list: anything that is not a lower-case letter, a digit or a
    /// hyphen is dropped. Removing known-bad characters always misses one.
    /// </remarks>
    private static string Slugify(string name)
    {
        var builder = new System.Text.StringBuilder(name.Length);
        var lastWasHyphen = false;

        foreach (var character in name.Trim().ToLowerInvariant())
        {
            if (char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character))
            {
                builder.Append(character);
                lastWasHyphen = false;
            }
            else if (!lastWasHyphen && builder.Length > 0)
            {
                builder.Append('-');
                lastWasHyphen = true;
            }
        }

        var slug = builder.ToString().Trim('-');

        // A name made entirely of characters the allow-list drops (for example a name in a
        // script this slug format cannot represent) leaves nothing behind, so fall back to a
        // generated slug rather than rejecting the workspace name.
        return slug.Length == 0
            ? "workspace-" + Guid.CreateVersion7().ToString("N")[..12]
            : slug[..Math.Min(slug.Length, 100)];
    }
}
