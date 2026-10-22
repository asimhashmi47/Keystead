using System;
using System.ComponentModel.DataAnnotations;

namespace Keystead.Infrastructure.Identity;

/// <summary>Session and step-up lifetimes.</summary>
public sealed class SessionOptions
{
    /// <summary>The configuration section these options bind to.</summary>
    public const string SectionName = "Keystead:Sessions";

    /// <summary>
    /// How long a session may sit unused before it stops being valid.
    /// </summary>
    [Range(typeof(TimeSpan), "00:05:00", "24:00:00")]
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// How long a session lasts regardless of activity.
    /// </summary>
    /// <remarks>
    /// An idle timeout alone never expires a session on a machine that is in constant use, so a
    /// cookie stolen from a developer's always-open browser would last indefinitely. The
    /// absolute bound is what makes that finite.
    /// </remarks>
    [Range(typeof(TimeSpan), "01:00:00", "720:00:00")]
    public TimeSpan AbsoluteLifetime { get; set; } = TimeSpan.FromHours(12);

    /// <summary>
    /// How long a step-up re-authentication stays fresh.
    /// </summary>
    /// <remarks>
    /// Short on purpose. The point of a step-up is that revealing a secret or changing a role
    /// requires proof of presence now, not proof that someone was present this morning.
    /// </remarks>
    [Range(typeof(TimeSpan), "00:01:00", "01:00:00")]
    public TimeSpan StepUpWindow { get; set; } = TimeSpan.FromMinutes(5);
}
