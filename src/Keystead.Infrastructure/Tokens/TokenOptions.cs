using System;
using System.ComponentModel.DataAnnotations;

namespace Keystead.Infrastructure.Tokens;

/// <summary>Machine token lifetimes and validation parameters.</summary>
public sealed class TokenOptions
{
    /// <summary>The configuration section these options bind to.</summary>
    public const string SectionName = "Keystead:Tokens";

    /// <summary>
    /// How long an issued token is valid for.
    /// </summary>
    /// <remarks>
    /// Short on purpose. A machine token is a bearer credential with no second factor, so its
    /// lifetime is the window in which a leaked one is useful. The SDK refreshes
    /// automatically, which makes a short lifetime invisible to applications and expensive
    /// for anyone who steals one from a log.
    /// </remarks>
    [Range(typeof(TimeSpan), "00:01:00", "01:00:00")]
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How much clock skew is tolerated when validating a token.
    /// </summary>
    /// <remarks>
    /// Thirty seconds, not the library default of five minutes. A generous skew silently
    /// extends every token's real lifetime by that much in both directions, which undoes the
    /// point of a short lifetime.
    /// </remarks>
    [Range(typeof(TimeSpan), "00:00:00", "00:05:00")]
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>The issuer claim written into, and required on, every token.</summary>
    [Required]
    [MinLength(1)]
    public string Issuer { get; set; } = "keystead";

    /// <summary>The audience claim written into, and required on, every token.</summary>
    [Required]
    [MinLength(1)]
    public string Audience { get; set; } = "keystead.api";

    /// <summary>
    /// How long after retirement a signing key may still verify tokens.
    /// </summary>
    /// <remarks>
    /// Must be at least <see cref="Lifetime"/>, or rotation would reject tokens that are still
    /// inside their validity window. Validated on startup.
    /// </remarks>
    [Range(typeof(TimeSpan), "00:01:00", "02:00:00")]
    public TimeSpan RetiredKeyGrace { get; set; } = TimeSpan.FromMinutes(15);
}
