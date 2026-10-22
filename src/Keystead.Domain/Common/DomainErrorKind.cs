namespace Keystead.Domain.Common;

/// <summary>Broad category of a <see cref="DomainError"/>, mapped to an HTTP status at the edge.</summary>
public enum DomainErrorKind
{
    /// <summary>Maps to 404.</summary>
    NotFound = 1,

    /// <summary>Maps to 403.</summary>
    Forbidden = 2,

    /// <summary>Maps to 409.</summary>
    Conflict = 3,

    /// <summary>Maps to 400.</summary>
    Invalid = 4,

    /// <summary>Maps to 403 with a challenge that drives the step-up modal.</summary>
    StepUpRequired = 5,
}
