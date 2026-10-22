using System;
using Keystead.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Tests.TestDoubles;

/// <summary>
/// A real SQLite database, in memory, for one test.
/// </summary>
/// <remarks>
/// <para>
/// A real database rather than the EF in-memory provider, deliberately. The in-memory provider
/// does not enforce unique indexes or foreign keys, and this suite's whole purpose is to prove
/// that tenant scoping and the audit chain's unique sequence actually hold. A fake that cannot
/// fail the way production fails is a fake that passes tests production would not.
/// </para>
/// <para>
/// The connection is held open for the fixture's lifetime because a SQLite in-memory database
/// is destroyed when its last connection closes.
/// </para>
/// </remarks>
internal sealed class TestDatabase : IDisposable
{
    private readonly SqliteConnection _connection;

    public TestDatabase()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();

        // foreign_keys is off by default in SQLite and is scoped to the connection, so the
        // cascades the model relies on would silently not happen without this.
        using (var pragma = _connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA foreign_keys = ON;";
            pragma.ExecuteNonQuery();
        }

        Context = CreateContext();
        Context.Database.EnsureCreated();
    }

    /// <summary>The context under test.</summary>
    public KeysteadDbContext Context { get; }

    /// <summary>
    /// Opens a second context over the same database, for tests that need to prove a change
    /// was persisted rather than merely tracked.
    /// </summary>
    public KeysteadDbContext CreateContext() =>
        new(new DbContextOptionsBuilder<KeysteadDbContext>()
            .UseSqlite(_connection)
            .Options);

    public void Dispose()
    {
        Context.Dispose();
        _connection.Dispose();
    }
}
