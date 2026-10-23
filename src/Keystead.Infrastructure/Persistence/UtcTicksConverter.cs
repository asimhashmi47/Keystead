using System;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Keystead.Infrastructure.Persistence;

/// <summary>
/// Stores a <see cref="DateTimeOffset"/> as UTC ticks in an integer column.
/// </summary>
/// <remarks>
/// <para>
/// SQLite has no date type. The provider's default for <see cref="DateTimeOffset"/> is a text
/// column holding an ISO-8601 string with its offset, and that has two consequences which only
/// show up at runtime: an aggregate over the column is rejected outright
/// (<c>cannot apply aggregate operator 'Max'</c>), and a comparison sorts lexicographically,
/// so two instants written with different offsets compare in the wrong order.
/// </para>
/// <para>
/// Integer ticks fix both. Comparison, ordering and aggregation become ordinary integer
/// operations, and an index on a timestamp column becomes useful rather than decorative, which
/// matters for the audit log and the expiry queries that scan on date.
/// </para>
/// <para>
/// The offset is not preserved, and that is deliberate rather than a loss: every timestamp in
/// this model is UTC by construction, which the <c>Utc</c> suffix on each property records.
/// Values are normalised with <see cref="DateTimeOffset.ToUniversalTime"/> on the way in and
/// read back with a zero offset, so a round trip returns the same instant.
/// </para>
/// </remarks>
public sealed class UtcTicksConverter : ValueConverter<DateTimeOffset, long>
{
    /// <summary>Creates the converter.</summary>
    public UtcTicksConverter()
        : base(
            value => value.ToUniversalTime().Ticks,
            ticks => new DateTimeOffset(ticks, TimeSpan.Zero))
    {
    }
}

/// <summary>
/// Stores a nullable <see cref="DateTimeOffset"/> as UTC ticks.
/// </summary>
/// <remarks>See <see cref="UtcTicksConverter"/> for why.</remarks>
public sealed class NullableUtcTicksConverter : ValueConverter<DateTimeOffset?, long?>
{
    /// <summary>Creates the converter.</summary>
    public NullableUtcTicksConverter()
        : base(
            value => value == null ? null : value.Value.ToUniversalTime().Ticks,
            ticks => ticks == null ? null : new DateTimeOffset(ticks.Value, TimeSpan.Zero))
    {
    }
}
