using System;
using System.Collections.Generic;
using Keystead.Domain.Vaults;

namespace Keystead.Application.Vaults;

/// <summary>What the caller supplies to create a vault.</summary>
/// <param name="Name">Display name.</param>
/// <param name="Description">Optional description.</param>
/// <param name="ColorToken">Semantic colour token for the badge, never a raw hex value.</param>
/// <param name="RecoveryWindowDays">How long a soft-deleted vault stays recoverable.</param>
/// <param name="PurgeProtection">Whether the vault may ever be purged.</param>
public sealed record CreateVaultRequest(
    string Name,
    string? Description,
    string ColorToken,
    int RecoveryWindowDays,
    bool PurgeProtection);

/// <summary>A vault as shown in a list.</summary>
/// <param name="Id">The vault identifier.</param>
/// <param name="Name">Display name.</param>
/// <param name="Slug">URL-safe identifier.</param>
/// <param name="Description">Optional description.</param>
/// <param name="ColorToken">Badge colour token.</param>
/// <param name="SecretCount">How many live secrets it holds.</param>
/// <param name="ExpiringSoonCount">How many of those expire within 30 days.</param>
/// <param name="CreatedUtc">When it was created.</param>
/// <param name="SoftDeletedUtc">When it was soft deleted, if it was.</param>
/// <param name="PurgeProtection">Whether purge protection is on.</param>
/// <param name="Permission">
/// What the asking principal may do here. Resolved per caller, so two people see different
/// values for the same vault.
/// </param>
public sealed record VaultSummary(
    Guid Id,
    string Name,
    string Slug,
    string? Description,
    string ColorToken,
    int SecretCount,
    int ExpiringSoonCount,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? SoftDeletedUtc,
    bool PurgeProtection,
    VaultPermission Permission);

/// <summary>The colour tokens a vault badge may use.</summary>
/// <remarks>
/// An allow-list, checked on write. Without it a vault could carry an arbitrary string that
/// the view would interpolate into a CSS custom property name, which is a needless way to let
/// user input reach a stylesheet.
/// </remarks>
public static class VaultColorTokens
{
    /// <summary>The permitted tokens.</summary>
    public static IReadOnlySet<string> All { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        "indigo",
        "violet",
        "teal",
        "emerald",
        "amber",
        "rose",
        "sky",
    };

    /// <summary>The token used when none is chosen.</summary>
    public const string Default = "indigo";

    /// <summary>Whether a token is permitted.</summary>
    /// <param name="token">The token to check.</param>
    /// <returns><see langword="true"/> when it is on the allow-list.</returns>
    public static bool IsValid(string? token) =>
        token is not null && All.Contains(token);
}
