using System;
using System.Collections.Generic;
using Keystead.Domain.Secrets;

namespace Keystead.Domain.Vaults;

/// <summary>
/// A named container of secrets inside a workspace, and the owner of a key-encryption key.
/// Deleting a vault is soft by default so that a mistaken click is survivable.
/// </summary>
public sealed class Vault
{
    /// <summary>Stable identifier, part of the AAD for every ciphertext below it.</summary>
    public required Guid Id { get; init; }

    /// <summary>Owning workspace. Every query against this vault is scoped by it.</summary>
    public required Guid WorkspaceId { get; init; }

    /// <summary>Display name.</summary>
    public required string Name { get; set; }

    /// <summary>URL-safe identifier, unique within the workspace.</summary>
    public required string Slug { get; set; }

    /// <summary>Optional human description.</summary>
    public string? Description { get; set; }

    /// <summary>
    /// Semantic colour token for the vault badge, for example <c>violet</c> or <c>teal</c>.
    /// A token, never a raw hex value (CLAUDE.md UI rules).
    /// </summary>
    public required string ColorToken { get; set; }

    /// <summary>When the vault was created.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>
    /// When the vault was soft deleted, if it has been. While set, the vault and its secrets
    /// are hidden from normal queries but fully recoverable.
    /// </summary>
    public DateTimeOffset? SoftDeletedUtc { get; private set; }

    /// <summary>How long a soft-deleted vault stays recoverable before it may be purged.</summary>
    public required int RecoveryWindowDays { get; set; }

    /// <summary>
    /// When set, the vault cannot be purged even after its recovery window expires. This is the
    /// guard against both a malicious insider and an over-confident operator.
    /// </summary>
    public required bool PurgeProtection { get; set; }

    /// <summary>The generations of this vault's key-encryption key.</summary>
    public ICollection<VaultKek> Keks { get; } = new List<VaultKek>();

    /// <summary>The secrets held in this vault.</summary>
    public ICollection<Secret> Secrets { get; } = new List<Secret>();

    /// <summary>Whether the vault is currently soft deleted.</summary>
    public bool IsDeleted => SoftDeletedUtc is not null;

    /// <summary>Marks the vault soft deleted. Idempotent.</summary>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    public void SoftDelete(DateTimeOffset now) => SoftDeletedUtc ??= now;

    /// <summary>Restores a soft-deleted vault.</summary>
    public void Recover() => SoftDeletedUtc = null;

    /// <summary>
    /// Whether the vault may be permanently purged: it must be soft deleted, its recovery
    /// window must have elapsed, and purge protection must be off.
    /// </summary>
    /// <param name="now">The current time, supplied by the caller's clock.</param>
    public bool CanPurge(DateTimeOffset now) =>
        !PurgeProtection
        && SoftDeletedUtc is { } deleted
        && now >= deleted.AddDays(RecoveryWindowDays);
}
