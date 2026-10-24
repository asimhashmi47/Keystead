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

    /// <summary>
    /// How stale the recorded last-seen time is allowed to get before it is written again.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every authenticated request touches its session, and writing the timestamp on every one
    /// of them turns each page view into a database write. On SQLite, which takes a single
    /// writer at a time, that makes the write the throughput ceiling for the whole
    /// application: a load test found it pinned at roughly forty requests a second regardless
    /// of what the requests were doing, with the processor mostly idle.
    /// </para>
    /// <para>
    /// Coarsening the timestamp removes the write from the common path without changing what
    /// it is for. The idle timeout is measured in tens of minutes; the cost of this is that a
    /// session may expire up to this much earlier than it strictly should, which at a minute
    /// against thirty is not a difference anyone can perceive.
    /// </para>
    /// </remarks>
    [Range(typeof(TimeSpan), "00:00:00", "00:05:00")]
    public TimeSpan LastSeenPrecision { get; set; } = TimeSpan.FromMinutes(1);
}
