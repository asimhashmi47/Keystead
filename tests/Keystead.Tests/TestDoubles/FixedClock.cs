using System;
using Keystead.Application.Abstractions;

namespace Keystead.Tests.TestDoubles;

/// <summary>A clock the test controls, so expiry and lockout are testable without sleeping.</summary>
internal sealed class FixedClock : IClock
{
    public FixedClock(DateTimeOffset? start = null) =>
        UtcNow = start ?? new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    public DateTimeOffset UtcNow { get; set; }

    /// <summary>Moves the clock forward.</summary>
    public void Advance(TimeSpan by) => UtcNow += by;
}
