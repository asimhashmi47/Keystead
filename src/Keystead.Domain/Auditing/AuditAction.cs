namespace Keystead.Domain.Auditing;

/// <summary>
/// What happened. Every value here is written to the audit chain; there is no "other" bucket,
/// because an action nobody named is an action nobody reviews.
/// </summary>
public enum AuditAction
{
    /// <summary>A user signed in successfully.</summary>
    SignInSucceeded = 100,

    /// <summary>A sign-in attempt failed.</summary>
    SignInFailed = 101,

    /// <summary>An account was locked out after repeated failures.</summary>
    AccountLockedOut = 102,

    /// <summary>A user signed out.</summary>
    SignedOut = 103,

    /// <summary>A session was revoked, individually or by signing out everywhere.</summary>
    SessionRevoked = 104,

    /// <summary>A sign-in arrived from an address not seen before for this user.</summary>
    SignInFromNewAddress = 105,

    /// <summary>TOTP enrolment completed.</summary>
    MfaEnrolled = 110,

    /// <summary>A TOTP challenge was answered correctly.</summary>
    MfaSucceeded = 111,

    /// <summary>A TOTP challenge failed.</summary>
    MfaFailed = 112,

    /// <summary>A single-use recovery code was consumed.</summary>
    RecoveryCodeUsed = 113,

    /// <summary>A step-up re-authentication succeeded.</summary>
    StepUpSucceeded = 114,

    /// <summary>A step-up re-authentication failed.</summary>
    StepUpFailed = 115,

    /// <summary>A password was changed.</summary>
    PasswordChanged = 116,

    /// <summary>A vault was created.</summary>
    VaultCreated = 200,

    /// <summary>A vault was updated.</summary>
    VaultUpdated = 201,

    /// <summary>A vault was soft deleted.</summary>
    VaultSoftDeleted = 202,

    /// <summary>A soft-deleted vault was recovered.</summary>
    VaultRecovered = 203,

    /// <summary>A vault was permanently purged.</summary>
    VaultPurged = 204,

    /// <summary>A secret was created.</summary>
    SecretCreated = 300,

    /// <summary>A new version of a secret was written.</summary>
    SecretVersionCreated = 301,

    /// <summary>A secret value was decrypted and returned.</summary>
    SecretValueRead = 302,

    /// <summary>Secret metadata was listed, without any value.</summary>
    SecretListed = 303,

    /// <summary>A secret or one of its versions was enabled or disabled.</summary>
    SecretEnabledChanged = 304,

    /// <summary>A secret was soft deleted.</summary>
    SecretSoftDeleted = 305,

    /// <summary>A soft-deleted secret was recovered.</summary>
    SecretRecovered = 306,

    /// <summary>A secret was rolled back to an earlier version.</summary>
    SecretRolledBack = 307,

    /// <summary>A secret read was refused.</summary>
    SecretReadDenied = 308,

    /// <summary>An unusual read pattern was detected, such as a burst of reads.</summary>
    AnomalousReadBurst = 309,

    /// <summary>A workspace membership role was changed.</summary>
    RoleChanged = 400,

    /// <summary>A vault assignment was granted.</summary>
    VaultAccessGranted = 401,

    /// <summary>A vault assignment was revoked.</summary>
    VaultAccessRevoked = 402,

    /// <summary>A service identity was created.</summary>
    ServiceIdentityCreated = 500,

    /// <summary>A service identity secret was rotated.</summary>
    ServiceIdentitySecretRotated = 501,

    /// <summary>A service identity was disabled or deleted.</summary>
    ServiceIdentityRevoked = 502,

    /// <summary>A machine token was issued.</summary>
    TokenIssued = 503,

    /// <summary>A machine token request was refused.</summary>
    TokenDenied = 504,

    /// <summary>A request was refused because of the identity IP allowlist.</summary>
    IpAllowlistBlocked = 505,

    /// <summary>A request was refused by a rate limit.</summary>
    RateLimited = 506,

    /// <summary>The installation was initialised by the first-run wizard.</summary>
    InstallationInitialised = 600,

    /// <summary>The master key was rotated and vault KEKs re-wrapped.</summary>
    MasterKeyRotated = 601,

    /// <summary>A vault KEK was rotated and its DEKs re-wrapped.</summary>
    VaultKekRotated = 602,

    /// <summary>The audit chain was verified.</summary>
    AuditChainVerified = 603,

    /// <summary>A Content Security Policy violation was reported by a browser.</summary>
    CspViolationReported = 604,
}
