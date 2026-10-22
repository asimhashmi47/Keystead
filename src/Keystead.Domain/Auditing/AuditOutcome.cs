namespace Keystead.Domain.Auditing;

/// <summary>Whether the audited attempt succeeded. Failures are recorded as deliberately as successes.</summary>
public enum AuditOutcome
{
    /// <summary>The action completed.</summary>
    Success = 1,

    /// <summary>The action was refused, for example by authorization or a rate limit.</summary>
    Denied = 2,

    /// <summary>The action failed for a technical reason.</summary>
    Error = 3,
}
