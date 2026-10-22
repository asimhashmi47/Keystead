using System;

namespace Keystead.Application.Abstractions;

/// <summary>
/// The current time, injected rather than read from a static.
/// </summary>
/// <remarks>
/// Expiry, lockout, rotation overlap, step-up freshness and token lifetime are all time
/// decisions that must be testable. A test that has to sleep is a test nobody runs.
/// </remarks>
public interface IClock
{
    /// <summary>The current instant, in UTC.</summary>
    DateTimeOffset UtcNow { get; }
}
