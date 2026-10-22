namespace Keystead.Domain.Auditing;

/// <summary>Who performed an audited action.</summary>
public enum ActorType
{
    /// <summary>No authenticated principal, for example a failed sign-in.</summary>
    Anonymous = 0,

    /// <summary>A human user.</summary>
    User = 1,

    /// <summary>A service identity.</summary>
    ServiceIdentity = 2,

    /// <summary>The system itself, for example a background rotation job.</summary>
    System = 3,
}
