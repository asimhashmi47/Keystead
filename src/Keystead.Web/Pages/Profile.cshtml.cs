using System;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Keystead.Web.Pages;

/// <summary>
/// The signed-in person's own account: password, second factor, sessions.
/// </summary>
/// <remarks>
/// Rate limited on the MFA policy because both forms accept the account password and would
/// otherwise be an unlimited guessing oracle against a session someone left open.
/// </remarks>
[EnableRateLimiting("mfa")]
public sealed class ProfileModel : KeysteadPageModel
{
    private readonly IProfileService _profile;

    /// <summary>Creates the page model.</summary>
    /// <param name="profile">The profile service.</param>
    /// <exception cref="ArgumentNullException"><paramref name="profile"/> is null.</exception>
    public ProfileModel(IProfileService profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        _profile = profile;
    }

    /// <summary>The account's details.</summary>
    public ProfileView? View { get; private set; }

    /// <summary>The change-password form.</summary>
    [BindProperty]
    public ChangePasswordInput Password { get; set; } = new();

    /// <summary>The reset-MFA form.</summary>
    [BindProperty]
    public ResetMfaInput Mfa { get; set; } = new();

    /// <summary>An error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>A confirmation message, or null.</summary>
    [TempData]
    public string? Notice { get; set; }

    /// <summary>Loads the profile.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken) =>
        await LoadAsync(cancellationToken).ConfigureAwait(false) ? Page() : RedirectToPage("/SignIn");

    /// <summary>Changes the password.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect on success, or the page with an error.</returns>
    public async Task<IActionResult> OnPostChangePasswordAsync(CancellationToken cancellationToken)
    {
        if (CurrentUserId is not { } userId || CurrentSessionId is not { } sessionId)
        {
            return RedirectToPage("/SignIn");
        }

        await LoadAsync(cancellationToken).ConfigureAwait(false);

        if (!ModelState.IsValid)
        {
            Error = "Check the fields below.";
            return Page();
        }

        var changed = await _profile.ChangePasswordAsync(
            userId,
            sessionId,
            Password.CurrentPassword,
            Password.NewPassword,
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (changed.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        Notice = changed.Value > 0
            ? $"Password changed. {changed.Value} other session(s) were signed out."
            : "Password changed.";

        return RedirectToPage();
    }

    /// <summary>Clears the TOTP enrolment so a new authenticator can be set up.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect to enrolment on success, or the page with an error.</returns>
    public async Task<IActionResult> OnPostResetMfaAsync(CancellationToken cancellationToken)
    {
        if (CurrentUserId is not { } userId)
        {
            return RedirectToPage("/SignIn");
        }

        await LoadAsync(cancellationToken).ConfigureAwait(false);

        if (!ModelState.IsValid)
        {
            Error = "Enter your password.";
            return Page();
        }

        var reset = await _profile.ResetMfaAsync(
            userId,
            Mfa.CurrentPassword,
            Mfa.TotpOrRecoveryCode,
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (reset.Error is { } error)
        {
            Error = error.Message;
            return Page();
        }

        Notice = "Two-factor authentication was cleared. Set up a new authenticator now.";

        return RedirectToPage("/MfaEnrol");
    }

    private async Task<bool> LoadAsync(CancellationToken cancellationToken)
    {
        if (CurrentUserId is not { } userId)
        {
            return false;
        }

        var loaded = await _profile.GetAsync(userId, cancellationToken).ConfigureAwait(false);

        if (!loaded.IsSuccess)
        {
            return false;
        }

        View = loaded.Value;
        return true;
    }
}

/// <summary>The change-password form's fields.</summary>
public sealed class ChangePasswordInput
{
    /// <summary>The existing password.</summary>
    [Required]
    [StringLength(1024)]
    [DataType(DataType.Password)]
    public string CurrentPassword { get; set; } = string.Empty;

    /// <summary>
    /// The proposed password. The real rules live in <c>IPasswordPolicy</c>; this attribute
    /// only catches the obvious case before a round trip.
    /// </summary>
    [Required]
    [StringLength(256, MinimumLength = 12)]
    [DataType(DataType.Password)]
    public string NewPassword { get; set; } = string.Empty;

    /// <summary>The proposed password, retyped.</summary>
    [Required]
    [Compare(nameof(NewPassword), ErrorMessage = "The two passwords do not match.")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; } = string.Empty;
}

/// <summary>The reset-MFA form's fields.</summary>
public sealed class ResetMfaInput
{
    /// <summary>The existing password.</summary>
    [Required]
    [StringLength(1024)]
    [DataType(DataType.Password)]
    public string CurrentPassword { get; set; } = string.Empty;

    /// <summary>A current authenticator code, or a recovery code.</summary>
    [StringLength(64)]
    public string? TotpOrRecoveryCode { get; set; }
}
