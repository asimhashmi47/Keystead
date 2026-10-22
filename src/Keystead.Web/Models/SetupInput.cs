using System.ComponentModel.DataAnnotations;

namespace Keystead.Web.Pages;

/// <summary>The first-run wizard's fields.</summary>
public sealed class SetupInput
{
    /// <summary>The name of the first workspace.</summary>
    [Required]
    [StringLength(200, MinimumLength = 2)]
    public string WorkspaceName { get; set; } = string.Empty;

    /// <summary>The owner's display name.</summary>
    [Required]
    [StringLength(200, MinimumLength = 2)]
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>The owner's sign-in address.</summary>
    [Required]
    [EmailAddress]
    [StringLength(320)]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// The owner's chosen password. The real rules live in <c>IPasswordPolicy</c>; this
    /// attribute only catches the obvious case before a round trip.
    /// </summary>
    [Required]
    [StringLength(256, MinimumLength = 12)]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    /// <summary>The password, retyped.</summary>
    [Required]
    [Compare(nameof(Password), ErrorMessage = "The two passwords do not match.")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; } = string.Empty;
}
