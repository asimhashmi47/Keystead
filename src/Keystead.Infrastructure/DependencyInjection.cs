using System;
using System.IO;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Authorization;
using Keystead.Application.Cryptography;
using Keystead.Application.Identity;
using Keystead.Application.Secrets;
using Keystead.Application.Vaults;
using Keystead.Application.Workspaces;
using Keystead.Infrastructure.Auditing;
using Keystead.Infrastructure.Authorization;
using Keystead.Infrastructure.Cryptography;
using Keystead.Infrastructure.Identity;
using Keystead.Infrastructure.Persistence;
using Keystead.Infrastructure.Secrets;
using Keystead.Infrastructure.Vaults;
using Keystead.Infrastructure.Workspaces;
using Keystead.Infrastructure.Time;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Keystead.Infrastructure;

/// <summary>Registers the infrastructure implementations of the application's ports.</summary>
public static class DependencyInjection
{
    /// <summary>
    /// Adds persistence, cryptography and clock services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration.</param>
    /// <returns>The same collection, for chaining.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static IServiceCollection AddKeysteadInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // ValidateOnStart means a misconfiguration is a startup failure, not a surprise on the
        // first request that happens to need the setting.
        services.AddOptions<DatabaseOptions>()
            .Bind(configuration.GetSection(DatabaseOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<MasterKeyOptions>()
            .Bind(configuration.GetSection(MasterKeyOptions.SectionName))
            .ValidateOnStart();

        services.AddOptions<Argon2idOptions>()
            .Bind(configuration.GetSection(Argon2idOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<PasswordPolicyOptions>()
            .Bind(configuration.GetSection(PasswordPolicyOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<SessionOptions>()
            .Bind(configuration.GetSection(SessionOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddSingleton<IClock, SystemClock>();
        services.AddSingleton<IAeadCipher, AesGcmCipher>();

        // The master key is loaded once and held for the process lifetime, so the provider is
        // a singleton. It owns the key bytes and zeroes them when the container is disposed.
        services.AddSingleton<ConfiguredMasterKeyProvider>();
        services.AddSingleton<IMasterKeyProvider>(
            sp => sp.GetRequiredService<ConfiguredMasterKeyProvider>());

        services.AddSingleton<IPasswordHasher, Argon2idPasswordHasher>();
        services.AddSingleton<IPasswordPolicy, PasswordPolicy>();
        services.AddSingleton<IRecoveryCodeService, RecoveryCodeService>();
        services.AddSingleton<ITotpService, TotpService>();

        // Scoped: these take the request's DbContext, so their lifetime must match it.
        services.AddScoped<IAuditChain, AuditChain>();
        services.AddScoped<IAuditQuery, AuditQuery>();
        services.AddScoped<IAccessPolicy, AccessPolicy>();
        services.AddScoped<ISignInService, SignInService>();
        services.AddScoped<IInstallationService, InstallationService>();
        services.AddScoped<IMfaEnrolmentService, MfaEnrolmentService>();
        services.AddScoped<IVaultKeyService, VaultKeyService>();
        services.AddScoped<ISecretProtector, SecretProtector>();
        services.AddScoped<IVaultService, VaultService>();
        services.AddScoped<ISecretService, SecretService>();
        services.AddScoped<ICurrentWorkspace, CurrentWorkspace>();

        services.AddDbContext<KeysteadDbContext>((sp, builder) =>
        {
            var options = sp.GetRequiredService<IOptions<DatabaseOptions>>().Value;

            builder.UseSqlite(BuildConnectionString(options));
            builder.AddInterceptors(new SqlitePragmaInterceptor(options.BusyTimeoutMs));

            // Secret ciphertext must never be echoed into a log line by the query pipeline.
            builder.EnableSensitiveDataLogging(false);
            builder.EnableDetailedErrors(false);
        });

        return services;
    }

    /// <summary>
    /// Builds the SQLite connection string, and creates the containing directory if needed.
    /// </summary>
    /// <param name="options">The database options.</param>
    /// <returns>A connection string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    public static string BuildConnectionString(DatabaseOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var fullPath = Path.GetFullPath(options.Path);
        var directory = Path.GetDirectoryName(fullPath);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var connection = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,

            // Shared cache plus WAL is the combination that lets readers continue while a
            // writer holds the write lock.
            Cache = SqliteCacheMode.Shared,
            ForeignKeys = true,
            Pooling = true,
        };

        // Optional whole-database encryption. Requires a SQLCipher-enabled native provider;
        // documented in DEPLOYMENT.md, off by default because the stock provider ignores it.
        if (!string.IsNullOrEmpty(options.SqlCipherKey))
        {
            connection.Password = options.SqlCipherKey;
        }

        return connection.ToString();
    }
}
