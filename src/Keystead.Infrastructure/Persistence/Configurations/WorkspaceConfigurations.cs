using System;
using Keystead.Domain.Keys;
using Keystead.Domain.Workspaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Keystead.Infrastructure.Persistence.Configurations;

internal sealed class WorkspaceConfiguration : IEntityTypeConfiguration<Workspace>
{
    public void Configure(EntityTypeBuilder<Workspace> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("workspaces");
        builder.HasKey(w => w.Id);

        builder.Property(w => w.Name).HasMaxLength(200).IsRequired();
        builder.Property(w => w.Slug).HasMaxLength(100).IsRequired();
        builder.Property(w => w.CreatedUtc).IsRequired();

        builder.HasIndex(w => w.Slug).IsUnique();

        builder.HasMany(w => w.Memberships)
            .WithOne(m => m.Workspace)
            .HasForeignKey(m => m.WorkspaceId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class WorkspaceMembershipConfiguration : IEntityTypeConfiguration<WorkspaceMembership>
{
    public void Configure(EntityTypeBuilder<WorkspaceMembership> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("workspace_memberships");
        builder.HasKey(m => m.Id);

        builder.Property(m => m.Role).HasConversion<int>().IsRequired();
        builder.Property(m => m.GrantedUtc).IsRequired();

        // One role per user per workspace. Two rows would make "what may this person do here"
        // ambiguous, and an ambiguous authorization answer is a vulnerability.
        builder.HasIndex(m => new { m.WorkspaceId, m.UserId }).IsUnique();

        builder.HasOne(m => m.User)
            .WithMany(u => u.Memberships)
            .HasForeignKey(m => m.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class MasterKeyVersionConfiguration : IEntityTypeConfiguration<MasterKeyVersion>
{
    public void Configure(EntityTypeBuilder<MasterKeyVersion> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("master_key_versions");
        builder.HasKey(v => v.Version);

        builder.Property(v => v.Version).ValueGeneratedNever();
        builder.Property(v => v.KeyCheckValue).HasMaxLength(32).IsRequired();
        builder.Property(v => v.CreatedUtc).IsRequired();

        builder.Ignore(v => v.IsActive);
    }
}
