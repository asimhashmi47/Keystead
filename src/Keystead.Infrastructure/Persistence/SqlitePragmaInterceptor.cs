using System;
using System.Data.Common;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Keystead.Infrastructure.Persistence;

/// <summary>
/// Applies the SQLite pragmas Keystead depends on, on every connection.
/// </summary>
/// <remarks>
/// <para>
/// These are set per connection, not once at startup, because SQLite scopes most pragmas to
/// the connection. <c>foreign_keys</c> in particular defaults to <em>off</em>, which means a
/// cascade this model relies on would silently not happen and orphaned secret versions could
/// outlive the vault they belonged to.
/// </para>
/// <para>
/// WAL is persistent once set, but setting it here keeps the behaviour explicit rather than
/// depending on how the file was first created.
/// </para>
/// </remarks>
public sealed class SqlitePragmaInterceptor : DbConnectionInterceptor
{
    private readonly int _busyTimeoutMs;

    /// <summary>Creates the interceptor.</summary>
    /// <param name="busyTimeoutMs">
    /// How long a writer waits for a lock before giving up. SQLite allows one writer at a
    /// time, so without a timeout a brief overlap surfaces as an immediate "database is
    /// locked" error rather than a short wait.
    /// </param>
    public SqlitePragmaInterceptor(int busyTimeoutMs = 5_000) => _busyTimeoutMs = busyTimeoutMs;

    /// <inheritdoc />
    public override void ConnectionOpened(
        DbConnection connection,
        ConnectionEndEventData eventData)
    {
        ArgumentNullException.ThrowIfNull(connection);

        Apply(connection);
        base.ConnectionOpened(connection, eventData);
    }

    /// <inheritdoc />
    public override async Task ConnectionOpenedAsync(
        DbConnection connection,
        ConnectionEndEventData eventData,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);

        await ApplyAsync(connection, cancellationToken).ConfigureAwait(false);
        await base.ConnectionOpenedAsync(connection, eventData, cancellationToken)
            .ConfigureAwait(false);
    }

    private void Apply(DbConnection connection)
    {
        using var command = connection.CreateCommand();

        // CA2100: SQLite does not accept parameters in a PRAGMA statement, so the value has to
        // be part of the statement text. It is an int that has already passed
        // DatabaseOptions' [Range(0, 60_000)] validation and is formatted invariantly, so it
        // cannot carry SQL. Nothing user-supplied reaches this string.
#pragma warning disable CA2100
        command.CommandText = BuildPragmaScript(_busyTimeoutMs);
#pragma warning restore CA2100

        command.ExecuteNonQuery();
    }

    private async Task ApplyAsync(DbConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();

        // See the justification in Apply above.
#pragma warning disable CA2100
        command.CommandText = BuildPragmaScript(_busyTimeoutMs);
#pragma warning restore CA2100

        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string BuildPragmaScript(int busyTimeoutMs) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"""
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = {busyTimeoutMs};
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            """);
}
