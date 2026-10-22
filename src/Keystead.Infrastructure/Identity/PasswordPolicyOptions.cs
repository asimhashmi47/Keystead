using System.ComponentModel.DataAnnotations;

namespace Keystead.Infrastructure.Identity;

/// <summary>The installation's password requirements.</summary>
public sealed class PasswordPolicyOptions
{
    /// <summary>The configuration section these options bind to.</summary>
    public const string SectionName = "Keystead:PasswordPolicy";

    /// <summary>
    /// The shortest password accepted. Twelve is the specified floor, and the deny list is
    /// weighted towards passwords that survive it.
    /// </summary>
    [Range(12, 128)]
    public int MinimumLength { get; set; } = 12;

    /// <summary>
    /// The longest password accepted. An upper bound exists only so that a very large input
    /// cannot be pushed through Argon2id as a memory-exhaustion lever.
    /// </summary>
    [Range(64, 1024)]
    public int MaximumLength { get; set; } = 256;
}
