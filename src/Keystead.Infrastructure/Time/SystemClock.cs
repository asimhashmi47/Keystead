using System;
using Keystead.Application.Abstractions;

namespace Keystead.Infrastructure.Time;

/// <summary>The real clock, reading UTC from the operating system.</summary>
public sealed class SystemClock : IClock
{
    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
