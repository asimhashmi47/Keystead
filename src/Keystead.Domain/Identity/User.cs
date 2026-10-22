using System;
using System.Collections.Generic;
using Keystead.Domain.Workspaces;

namespace Keystead.Domain.Identity;

/// <summary>A human principal, authenticated by password plus TOTP.</summary>
public sealed class User
{
    /// <summary>Stable identifier.</summary>
    public required Guid Id { get; init; }

    /// <summary>Sign-in address, stored normalised to lower case and unique.</summary>
    public required string Email { get; set; }

    /// <summary>Display name.</summary>
    public required string DisplayName { get; set; }

    /// <summary>
    /// The Argon2id digest of the password. Encoded with its algorithm and parameters so that
    /// stored hashes stay verifiable after the cost parameters are raised.
    /// </summary>
    public required string PasswordHash { get; set; }

    /// <summary>When the password was last changed, used to invalidate older sessions.</summary>
    public required DateTimeOffset PasswordChangedUtc { get; set; }

    /// <summary>
    /// The TOTP shared secret, sealed under the master key. Never stored in plaintext: an
    /// attacker holding the database must not be able to mint valid second factors.
    /// </summary>
    public byte[]? MfaSecretCiphertext { get; set; }

    /// <summary>The AES-GCM nonce for <see cref="MfaSecretCiphertext"/>.</summary>
    public byte[]? MfaSecretNonce { get; set; }

    /// <summary>The AES-GCM tag for <see cref="MfaSecretCiphertext"/>.</summary>
    public byte[]? MfaSecretTag { get; set; }

    /// <summary>
    /// Which master key generation sealed <see cref="MfaSecretCiphertext"/>.
    /// </summary>
    /// <remarks>
    /// Recorded per row rather than assumed to be the active generation, so a seed sealed
    /// before a master key rotation stays readable while the re-wrap job works through.
    /// </remarks>
    public int MfaSeedMasterKeyVersion { get; set; }

    /// <summary>When TOTP enrolment completed. Null means MFA is not active.</summary>
    public DateTimeOffset? MfaEnrolledUtc { get; set; }

    /// <summary>
    /// The highest TOTP time step this user has already consumed.
    /// </summary>
    /// <remarks>
    /// RFC 6238 only makes a code valid for its time step, so a code captured by a phishing
    /// proxy or read over a shoulder stays usable for the rest of that step and the skew window
    /// either side. Recording the step and refusing anything at or below it makes a correct code
    /// single-use.
    /// </remarks>
    public long? LastUsedTotpWindow { get; set; }

    /// <summary>Consecutive failed sign-in attempts since the last success.</summary>
    public required int FailedSignInCount { get; set; }

    /// <summary>When the current lockout expires, if the account is locked.</summary>
    public DateTimeOffset? LockoutEndUtc { get; set; }

    /// <summary>When the account was created.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>Whether the account may sign in at all.</summary>
    public required bool IsActive { get; set; }

    /// <summary>Single-use recovery codes, stored hashed.</summary>
    public ICollection<UserRecoveryCode> RecoveryCodes { get; } = new List<UserRecoveryCode>();

    /// <summary>Active and revoked sessions for this user.</summary>
    public ICollection<UserSession> Sessions { get; } = new List<UserSession>();

    /// <summary>Workspace memberships and the role held in each.</summary>
    public ICollection<WorkspaceMembership> Memberships { get; } = new List<WorkspaceMembership>();

    /// <summary>Whether TOTP is enrolled and usable.</summary>
    public bool MfaEnabled => MfaEnrolledUtc is not null && MfaSecretCiphertext is not null;

    /// <summary>Whether the account is locked out at the given moment.</summary>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    public bool IsLockedOut(DateTimeOffset now) => LockoutEndUtc is { } end && now < end;

    /// <summary>
    /// Records a failed sign-in and applies a progressive lockout: the delay grows with the
    /// number of consecutive failures, so an online guessing attack becomes uneconomic long
    /// before a legitimate user is seriously inconvenienced.
    /// </summary>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    public void RegisterFailedSignIn(DateTimeOffset now)
    {
        FailedSignInCount++;

        var delay = FailedSignInCount switch
        {
            < 3 => TimeSpan.Zero,
            < 5 => TimeSpan.FromSeconds(5),
            < 7 => TimeSpan.FromSeconds(30),
            < 10 => TimeSpan.FromMinutes(5),
            _ => TimeSpan.FromMinutes(30),
        };

        if (delay > TimeSpan.Zero)
        {
            LockoutEndUtc = now + delay;
        }
    }

    /// <summary>Clears the failure counter and any lockout after a successful sign-in.</summary>
    public void RegisterSuccessfulSignIn()
    {
        FailedSignInCount = 0;
        LockoutEndUtc = null;
    }
}
