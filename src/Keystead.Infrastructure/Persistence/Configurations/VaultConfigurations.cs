using System;
using Keystead.Domain.Vaults;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Keystead.Infrastructure.Persistence.Configurations;

internal sealed class VaultConfiguration : IEntityTypeConfiguration<Vault>
{
    public void Configure(EntityTypeBuilder<Vault> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("vaults");
        builder.HasKey(v => v.Id);

        builder.Property(v => v.Name).HasMaxLength(200).IsRequired();
        builder.Property(v => v.Slug).HasMaxLength(100).IsRequired();
        builder.Property(v => v.Description).HasMaxLength(1000);
        builder.Property(v => v.ColorToken).HasMaxLength(32).IsRequired();
        builder.Property(v => v.RecoveryWindowDays).IsRequired();
        builder.Property(v => v.PurgeProtection).IsRequired();
        builder.Property(v => v.CreatedUtc).IsRequired();

        // SoftDeletedUtc has a private setter so that deletion goes through the domain method.
        builder.Property(v => v.SoftDeletedUtc);

        builder.Property<Guid>("WorkspaceId").IsRequired();
        builder.HasIndex(v => new { v.WorkspaceId, v.Slug }).IsUnique();

        // Scoping index: every vault query starts from the workspace, so this is the access
        // path that matters, not the primary key.
        builder.HasIndex(v => v.WorkspaceId);

        builder.Ignore(v => v.IsDeleted);

        builder.HasMany(v => v.Keks)
            .WithOne(k => k.Vault)
            .HasForeignKey(k => k.VaultId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(v => v.Secrets)
            .WithOne(s => s.Vault)
            .HasForeignKey(s => s.VaultId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class VaultKekConfiguration : IEntityTypeConfiguration<VaultKek>
{
    public void Configure(EntityTypeBuilder<VaultKek> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("vault_keks");
        builder.HasKey(k => k.Id);

        // A 32-byte key sealed with AES-GCM: 32 bytes of ciphertext, plus the 12-byte nonce
        // and 16-byte tag carried in the same envelope.
        builder.Property(k => k.WrappedKek).HasMaxLength(128).IsRequired();
        builder.Property(k => k.Version).IsRequired();
        builder.Property(k => k.MasterKeyVersion).IsRequired();
        builder.Property(k => k.CreatedUtc).IsRequired();

        builder.HasIndex(k => new { k.VaultId, k.Version }).IsUnique();

        builder.Ignore(k => k.IsActive);
    }
}

internal sealed class VaultAssignmentConfiguration : IEntityTypeConfiguration<VaultAssignment>
{
    public void Configure(EntityTypeBuilder<VaultAssignment> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("vault_assignments");
        builder.HasKey(a => a.Id);

        builder.Property(a => a.SubjectType).HasConversion<int>().IsRequired();
        builder.Property(a => a.Permission).HasConversion<int>().IsRequired();
        builder.Property(a => a.GrantedUtc).IsRequired();

        // One grant per subject per vault, for the same reason as workspace membership:
        // two rows would make the effective permission ambiguous.
        builder.HasIndex(a => new { a.VaultId, a.SubjectId, a.SubjectType }).IsUnique();

        // The authorization lookup goes subject first: "what may this principal reach".
        builder.HasIndex(a => new { a.SubjectId, a.SubjectType });

        builder.HasOne(a => a.Vault)
            .WithMany()
            .HasForeignKey(a => a.VaultId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
