using System;

namespace Keystead.Domain.Identity;

/// <summary>
/// A single-use MFA recovery code, stored only as a hash. Ten are issued at enrolment and
/// displayed exactly once.
/// </summary>
public sealed class UserRecoveryCode
{
    /// <summary>Surrogate key.</summary>
    public required Guid Id { get; init; }

    /// <summary>The owning user.</summary>
    public required Guid UserId { get; init; }

    /// <summary>
    /// SHA-256 of the code. Compared in fixed time; the plaintext code exists only in the
    /// response that shows it to the user once.
    /// </summary>
    public required byte[] CodeHash { get; init; }

    /// <summary>When the code was consumed, if it has been. A used code is never accepted again.</summary>
    public DateTimeOffset? UsedUtc { get; set; }

    /// <summary>Navigation to the owning user.</summary>
    public User? User { get; init; }

    /// <summary>Whether this code is still usable.</summary>
    public bool IsUnused => UsedUtc is null;
}
