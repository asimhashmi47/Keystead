using System.ComponentModel.DataAnnotations;

namespace Keystead.Web.Pages;

/// <summary>A submitted six-digit TOTP code.</summary>
public sealed class MfaCodeInput
{
    /// <summary>The code from the authenticator app.</summary>
    [Required]
    [StringLength(8)]
    public string Code { get; set; } = string.Empty;
}
