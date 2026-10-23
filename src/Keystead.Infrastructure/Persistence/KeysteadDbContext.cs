using System;
using Keystead.Domain.Auditing;
using Keystead.Domain.Identity;
using Keystead.Domain.Keys;
using Keystead.Domain.Secrets;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Persistence;

/// <summary>
/// The Keystead database.
/// </summary>
/// <remarks>
/// Every column that holds key or secret material holds ciphertext. There is no plaintext
/// secret column anywhere in this model, which is what makes a stolen database file
/// recoverable only by someone who also holds the master key.
/// </remarks>
public sealed class KeysteadDbContext : DbContext
{
    /// <summary>Creates the context.</summary>
    /// <param name="options">The configured options.</param>
    public KeysteadDbContext(DbContextOptions<KeysteadDbContext> options)
        : base(options)
    {
    }

    /// <summary>Tenants.</summary>
    public DbSet<Workspace> Workspaces => Set<Workspace>();

    /// <summary>Workspace role grants.</summary>
    public DbSet<WorkspaceMembership> WorkspaceMemberships => Set<WorkspaceMembership>();

    /// <summary>Vaults.</summary>
    public DbSet<Vault> Vaults => Set<Vault>();

    /// <summary>Wrapped vault key-encryption keys.</summary>
    public DbSet<VaultKek> VaultKeks => Set<VaultKek>();

    /// <summary>Per-vault access grants.</summary>
    public DbSet<VaultAssignment> VaultAssignments => Set<VaultAssignment>();

    /// <summary>Secrets.</summary>
    public DbSet<Secret> Secrets => Set<Secret>();

    /// <summary>Secret labels.</summary>
    public DbSet<SecretTag> SecretTags => Set<SecretTag>();

    /// <summary>Sealed secret versions.</summary>
    public DbSet<SecretVersion> SecretVersions => Set<SecretVersion>();

    /// <summary>Human users.</summary>
    public DbSet<User> Users => Set<User>();

    /// <summary>Hashed single-use MFA recovery codes.</summary>
    public DbSet<UserRecoveryCode> UserRecoveryCodes => Set<UserRecoveryCode>();

    /// <summary>Tracked sign-ins.</summary>
    public DbSet<UserSession> UserSessions => Set<UserSession>();

    /// <summary>Machine principals.</summary>
    public DbSet<ServiceIdentity> ServiceIdentities => Set<ServiceIdentity>();

    /// <summary>The tamper-evident audit chain.</summary>
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    /// <summary>Master key generations.</summary>
    public DbSet<MasterKeyVersion> MasterKeyVersions => Set<MasterKeyVersion>();

    /// <summary>Token signing key pairs.</summary>
    public DbSet<SigningKey> SigningKeys => Set<SigningKey>();

    /// <summary>
    /// Applies the UTC-ticks conversion to every timestamp in the model.
    /// </summary>
    /// <remarks>
    /// Set as a convention rather than per property, so a timestamp added later gets it
    /// automatically. Forgetting it on one column would produce a text date that compares
    /// lexicographically and cannot be aggregated, and the failure would only appear the first
    /// time something queried on it.
    /// </remarks>
    /// <param name="configurationBuilder">The convention builder.</param>
    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        ArgumentNullException.ThrowIfNull(configurationBuilder);

        base.ConfigureConventions(configurationBuilder);

        configurationBuilder.Properties<DateTimeOffset>()
            .HaveConversion<UtcTicksConverter>();

        configurationBuilder.Properties<DateTimeOffset?>()
            .HaveConversion<NullableUtcTicksConverter>();
    }

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(KeysteadDbContext).Assembly);
    }
}
