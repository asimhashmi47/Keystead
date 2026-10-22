namespace Keystead.Domain.Common;

/// <summary>
/// A domain rule violation that the caller is expected to handle: not found, forbidden,
/// a conflicting name, an exhausted recovery window.
/// </summary>
/// <remarks>
/// Deliberately carries no secret material. Messages here reach the user interface and the
/// audit log, so they describe the rule that was broken and never the value involved.
/// See CLAUDE.md rule 5.
/// </remarks>
public sealed class DomainError
{
    private DomainError(DomainErrorKind kind, string code, string message)
    {
        Kind = kind;
        Code = code;
        Message = message;
    }

    /// <summary>The broad category, which maps to an HTTP status at the edge.</summary>
    public DomainErrorKind Kind { get; }

    /// <summary>A stable machine-readable identifier, for example <c>secret.name_taken</c>.</summary>
    public string Code { get; }

    /// <summary>A human-readable explanation that is safe to display and to log.</summary>
    public string Message { get; }

    /// <summary>The requested resource does not exist, or the caller may not know that it does.</summary>
    public static DomainError NotFound(string code, string message) =>
        new(DomainErrorKind.NotFound, code, message);

    /// <summary>The caller is authenticated but not permitted to do this.</summary>
    public static DomainError Forbidden(string code, string message) =>
        new(DomainErrorKind.Forbidden, code, message);

    /// <summary>The request is well formed but breaks a domain rule.</summary>
    public static DomainError Conflict(string code, string message) =>
        new(DomainErrorKind.Conflict, code, message);

    /// <summary>The request is malformed or fails validation.</summary>
    public static DomainError Invalid(string code, string message) =>
        new(DomainErrorKind.Invalid, code, message);

    /// <summary>The caller must complete a step-up re-authentication first.</summary>
    public static DomainError StepUpRequired(string code, string message) =>
        new(DomainErrorKind.StepUpRequired, code, message);
}
