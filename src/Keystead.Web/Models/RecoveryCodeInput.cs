using System.ComponentModel.DataAnnotations;

namespace Keystead.Web.Pages;

/// <summary>A submitted single-use recovery code.</summary>
public sealed class RecoveryCodeInput
{
    /// <summary>
    /// The code as the user typed it. Separators and casing are normalised by the service, so
    /// no format is imposed here beyond a length bound.
    /// </summary>
    [Required]
    [StringLength(64)]
    public string Code { get; set; } = string.Empty;
}
