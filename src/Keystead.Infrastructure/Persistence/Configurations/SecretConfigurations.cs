using System;
using Keystead.Domain.Secrets;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Keystead.Infrastructure.Persistence.Configurations;

internal sealed class SecretConfiguration : IEntityTypeConfiguration<Secret>
{
    public void Configure(EntityTypeBuilder<Secret> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("secrets");
        builder.HasKey(s => s.Id);

        builder.Property(s => s.Name).HasMaxLength(256).IsRequired();
        builder.Property(s => s.Environment).HasMaxLength(64).IsRequired();
        builder.Property(s => s.ContentType).HasMaxLength(128);
        builder.Property(s => s.Enabled).IsRequired();
        builder.Property(s => s.CreatedUtc).IsRequired();
        builder.Property(s => s.SoftDeletedUtc);

        // The lookup an application performs at runtime: name plus environment inside a vault.
        builder.HasIndex(s => new { s.VaultId, s.Environment, s.Name }).IsUnique();
        builder.HasIndex(s => s.VaultId);

        // Drives the "expiring soon" dashboard card without a table scan.
        builder.HasIndex(s => s.ExpiresUtc);

        builder.Ignore(s => s.IsDeleted);
        builder.Ignore(s => s.LatestVersionNumber);

        builder.HasMany(s => s.Tags)
            .WithOne(t => t.Secret)
            .HasForeignKey(t => t.SecretId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(s => s.Versions)
            .WithOne(v => v.Secret)
            .HasForeignKey(v => v.SecretId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class SecretTagConfiguration : IEntityTypeConfiguration<SecretTag>
{
    public void Configure(EntityTypeBuilder<SecretTag> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("secret_tags");
        builder.HasKey(t => t.Id);

        builder.Property(t => t.Key).HasMaxLength(64).IsRequired();
        builder.Property(t => t.Value).HasMaxLength(256).IsRequired();

        builder.HasIndex(t => new { t.SecretId, t.Key }).IsUnique();

        // Filtering the vault table by tag reads key first.
        builder.HasIndex(t => new { t.Key, t.Value });
    }
}

internal sealed class SecretVersionConfiguration : IEntityTypeConfiguration<SecretVersion>
{
    public void Configure(EntityTypeBuilder<SecretVersion> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("secret_versions");
        builder.HasKey(v => v.Id);

        builder.Property(v => v.Version).IsRequired();

        // No length cap on the ciphertext: a secret may legitimately be a certificate.
        // Request body limits bound the input size at the edge instead.
        builder.Property(v => v.Ciphertext).IsRequired();

        builder.Property(v => v.Nonce)
            .HasMaxLength(SecretVersion.NonceLength)
            .IsFixedLength()
            .IsRequired();

        builder.Property(v => v.AuthTag)
            .HasMaxLength(SecretVersion.AuthTagLength)
            .IsFixedLength()
            .IsRequired();

        builder.Property(v => v.WrappedDek).HasMaxLength(128).IsRequired();
        builder.Property(v => v.KekVersion).IsRequired();
        builder.Property(v => v.Enabled).IsRequired();
        builder.Property(v => v.CreatedUtc).IsRequired();
        builder.Property(v => v.CreatedBySubjectId).IsRequired();
        builder.Property(v => v.CreatedByLabel).HasMaxLength(256).IsRequired();

        builder.HasIndex(v => new { v.SecretId, v.Version }).IsUnique();
    }
}
