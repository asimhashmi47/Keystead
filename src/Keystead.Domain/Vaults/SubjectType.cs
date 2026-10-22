namespace Keystead.Domain.Vaults;

/// <summary>Whether a vault grant belongs to a human user or a machine principal.</summary>
public enum SubjectType
{
    /// <summary>A human, authenticated by cookie with password and TOTP.</summary>
    User = 1,

    /// <summary>A service identity, authenticated by client credentials for a short-lived JWT.</summary>
    ServiceIdentity = 2,
}
