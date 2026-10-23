using System;
using Keystead.Application.Cryptography;
using Keystead.Domain.Auditing;
using Keystead.Domain.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Keystead.Infrastructure.Persistence.Configurations;

internal sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("users");
        builder.HasKey(u => u.Id);

        builder.Property(u => u.Email).HasMaxLength(320).IsRequired();
        builder.Property(u => u.DisplayName).HasMaxLength(200).IsRequired();

        // PHC-encoded Argon2id digest: algorithm, parameters, salt and hash in one string.
        builder.Property(u => u.PasswordHash).HasMaxLength(512).IsRequired();
        builder.Property(u => u.PasswordChangedUtc).IsRequired();

        // The TOTP seed is sealed under the master key, so this column is ciphertext.
        builder.Property(u => u.MfaSecretCiphertext).HasMaxLength(256);
        builder.Property(u => u.MfaSecretNonce)
            .HasMaxLength(SealedBlob.NonceLength)
            .IsFixedLength();
        builder.Property(u => u.MfaSecretTag)
            .HasMaxLength(SealedBlob.TagLength)
            .IsFixedLength();

        builder.Property(u => u.MfaSeedMasterKeyVersion).IsRequired();

        // The TOTP replay guard: the highest time step this user has consumed.
        builder.Property(u => u.LastUsedTotpWindow);

        builder.Property(u => u.FailedSignInCount).IsRequired();
        builder.Property(u => u.IsActive).IsRequired();
        builder.Property(u => u.CreatedUtc).IsRequired();

        builder.HasIndex(u => u.Email).IsUnique();

        builder.Ignore(u => u.MfaEnabled);

        builder.HasMany(u => u.RecoveryCodes)
            .WithOne(c => c.User)
            .HasForeignKey(c => c.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasMany(u => u.Sessions)
            .WithOne(s => s.User)
            .HasForeignKey(s => s.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class UserRecoveryCodeConfiguration : IEntityTypeConfiguration<UserRecoveryCode>
{
    public void Configure(EntityTypeBuilder<UserRecoveryCode> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("user_recovery_codes");
        builder.HasKey(c => c.Id);

        builder.Property(c => c.CodeHash).HasMaxLength(32).IsFixedLength().IsRequired();
        builder.HasIndex(c => c.UserId);

        builder.Ignore(c => c.IsUnused);
    }
}

internal sealed class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
{
    public void Configure(EntityTypeBuilder<UserSession> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("user_sessions");
        builder.HasKey(s => s.Id);

        builder.Property(s => s.CreatedUtc).IsRequired();
        builder.Property(s => s.LastSeenUtc).IsRequired();
        builder.Property(s => s.AbsoluteExpiryUtc).IsRequired();
        builder.Property(s => s.CreatedIp).HasMaxLength(64).IsRequired();
        builder.Property(s => s.UserAgent).HasMaxLength(512).IsRequired();

        builder.HasIndex(s => s.UserId);
    }
}

internal sealed class ServiceIdentityConfiguration : IEntityTypeConfiguration<ServiceIdentity>
{
    public void Configure(EntityTypeBuilder<ServiceIdentity> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("service_identities");
        builder.HasKey(i => i.Id);

        builder.Property(i => i.Name).HasMaxLength(200).IsRequired();
        builder.Property(i => i.ClientId).HasMaxLength(64).IsRequired();

        // Only the SHA-256 of the client secret is stored; the secret itself is shown once.
        builder.Property(i => i.ClientSecretHash).HasMaxLength(32).IsFixedLength().IsRequired();
        builder.Property(i => i.PreviousClientSecretHash).HasMaxLength(32).IsFixedLength();

        builder.Property(i => i.CreatedUtc).IsRequired();
        builder.Property(i => i.IsActive).IsRequired();

        // Mapped as an EF primitive collection (a JSON column). A separate table would be more
        // normal, but the allowlist is read on every token request and is never queried by
        // element, so keeping it on the row avoids a join on the hottest authorization path.
        builder.PrimitiveCollection(i => i.IpAllowlist)
            .HasColumnName("ip_allowlist")
            .HasMaxLength(2048)
            .IsRequired();

        builder.HasIndex(i => i.ClientId).IsUnique();
        builder.HasIndex(i => i.WorkspaceId);
    }
}

internal sealed class AuditEntryConfiguration : IEntityTypeConfiguration<AuditEntry>
{
    public void Configure(EntityTypeBuilder<AuditEntry> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("audit_entries");
        builder.HasKey(e => e.Id);

        // Seq is the chain position. Unique and never reused, so a gap is itself evidence
        // that a row was removed.
        builder.Property(e => e.Seq).IsRequired();
        builder.HasIndex(e => e.Seq).IsUnique();

        builder.Property(e => e.ActorType).HasConversion<int>().IsRequired();
        builder.Property(e => e.ActorLabel).HasMaxLength(320).IsRequired();
        builder.Property(e => e.Action).HasConversion<int>().IsRequired();
        builder.Property(e => e.Outcome).HasConversion<int>().IsRequired();
        builder.Property(e => e.ResourceType).HasMaxLength(64).IsRequired();
        builder.Property(e => e.ResourceLabel).HasMaxLength(256);
        builder.Property(e => e.IpAddress).HasMaxLength(64).IsRequired();
        builder.Property(e => e.UserAgent).HasMaxLength(512);
        builder.Property(e => e.CorrelationId).HasMaxLength(64);
        builder.Property(e => e.DataJson).HasMaxLength(4000);
        builder.Property(e => e.CreatedUtc).IsRequired();

        builder.Property(e => e.PreviousHash)
            .HasMaxLength(AuditEntry.HashLength)
            .IsFixedLength()
            .IsRequired();

        builder.Property(e => e.Hash)
            .HasMaxLength(AuditEntry.HashLength)
            .IsFixedLength()
            .IsRequired();

        // The audit view is always filtered by workspace and ordered by time.
        builder.HasIndex(e => new { e.WorkspaceId, e.CreatedUtc });
        builder.HasIndex(e => new { e.WorkspaceId, e.Action });
    }
}

internal sealed class SigningKeyConfiguration : IEntityTypeConfiguration<SigningKey>
{
    public void Configure(EntityTypeBuilder<SigningKey> builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.ToTable("signing_keys");
        builder.HasKey(k => k.Id);

        builder.Property(k => k.Kid).HasMaxLength(64).IsRequired();
        builder.HasIndex(k => k.Kid).IsUnique();

        // A sealed PKCS#8 P-256 private key: roughly 140 bytes of ciphertext plus its header.
        builder.Property(k => k.PrivateKeyCiphertext).HasMaxLength(512).IsRequired();

        builder.Property(k => k.PrivateKeyNonce)
            .HasMaxLength(SealedBlob.NonceLength)
            .IsFixedLength()
            .IsRequired();

        builder.Property(k => k.PrivateKeyTag)
            .HasMaxLength(SealedBlob.TagLength)
            .IsFixedLength()
            .IsRequired();

        builder.Property(k => k.MasterKeyVersion).IsRequired();

        // Stored in the clear on purpose: it is not secret, and keeping it readable means
        // verification never needs the master key.
        builder.Property(k => k.PublicKey).HasMaxLength(256).IsRequired();

        builder.Property(k => k.CreatedUtc).IsRequired();

        builder.Ignore(k => k.IsActive);
    }
}
