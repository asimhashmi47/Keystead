using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Keystead.Infrastructure.Persistence;

/// <summary>
/// Builds a context for <c>dotnet ef</c> at design time.
/// </summary>
/// <remarks>
/// Deliberately independent of the web host. Letting the tooling boot the real application
/// would mean a migration could not be scaffolded without a valid master key present, which
/// would make schema work depend on production key material for no reason. The connection
/// string here points at a scratch file that is never used at runtime.
/// </remarks>
internal sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<KeysteadDbContext>
{
    public KeysteadDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<KeysteadDbContext>()
            .UseSqlite("Data Source=design-time.db")
            .Options;

        return new KeysteadDbContext(options);
    }
}
