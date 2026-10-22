using System.ComponentModel.DataAnnotations;

namespace Keystead.Web.Pages;

/// <summary>
/// The sign-in form's fields.
/// </summary>
/// <remarks>
/// No length or complexity validation on the password here beyond a sane upper bound. The
/// policy is enforced when a password is <em>set</em>; applying it at sign-in would tell an
/// attacker that an existing password fails the current rules, and would lock out users whose
/// password predates a policy change.
/// </remarks>
public sealed class SignInInput
{
    /// <summary>The submitted email address.</summary>
    [Required]
    [EmailAddress]
    [StringLength(320)]
    public string Email { get; set; } = string.Empty;

    /// <summary>The submitted password.</summary>
    [Required]
    [StringLength(1024)]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
}
