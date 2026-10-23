using System;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Keystead.Web.Pages;

/// <summary>
/// Re-confirming identity before a high-privilege action.
/// </summary>
/// <remarks>
/// <para>
/// A long-lived session is not a standing authorisation to reveal every secret in it. The
/// step-up asks for the password again, and the TOTP code too when one is enrolled, so that
/// a session left open on an unlocked laptop does not hand over the vault.
/// </para>
/// <para>
/// Requires an authenticated session through the fallback policy: this re-confirms an identity
/// rather than establishing one. Rate limited on the MFA policy, because it accepts the same
/// credentials as sign-in and would otherwise be an unlimited password oracle.
/// </para>
/// </remarks>
[EnableRateLimiting("mfa")]
public sealed class StepUpModel : KeysteadPageModel
{
    private readonly ISignInService _signIn;

    /// <summary>Creates the page model.</summary>
    /// <param name="signIn">The sign-in service.</param>
    /// <exception cref="ArgumentNullException"><paramref name="signIn"/> is null.</exception>
    public StepUpModel(ISignInService signIn)
    {
        ArgumentNullException.ThrowIfNull(signIn);
        _signIn = signIn;
    }

    /// <summary>The submitted credentials.</summary>
    [BindProperty]
    public StepUpInput Input { get; set; } = new();

    /// <summary>Where to return to afterwards.</summary>
    [BindProperty(SupportsGet = true)]
    public string? Next { get; set; }

    /// <summary>An error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>Shows the form.</summary>
    public void OnGet()
    {
        // Nothing to load: the form needs only the already-authenticated session.
    }

    /// <summary>Confirms identity and records the step-up against the session.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>A redirect back on success, or the form with an error.</returns>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (CurrentUserId is not { } userId || CurrentSessionId is not { } sessionId)
        {
            return RedirectToPage("/SignIn");
        }

        if (!ModelState.IsValid)
        {
            Error = "Enter your password.";
            return Page();
        }

        var confirmed = await _signIn.StepUpAsync(
            userId,
            sessionId,
            Input.Password,
            Input.TotpCode,
            RequestContext,
            cancellationToken).ConfigureAwait(false);

        if (!confirmed)
        {
            // One message for a wrong password and a wrong code, for the same reason sign-in
            // has one: the difference would tell an attacker which factor they already hold.
            Error = "That did not match. Check your password and, if you use one, your current code.";
            return Page();
        }

        // Local URLs only. An unchecked return parameter here is an open redirect, and this
        // one is reached immediately after someone typed their password.
        return !string.IsNullOrEmpty(Next) && Url.IsLocalUrl(Next)
            ? Redirect(Next)
            : RedirectToPage("/Index");
    }
}

/// <summary>The step-up form's fields.</summary>
public sealed class StepUpInput
{
    /// <summary>The account password.</summary>
    [Required]
    [StringLength(1024)]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// A current TOTP code. Required when the account has MFA enrolled, which the service
    /// checks; the form does not know whether this account has it.
    /// </summary>
    [StringLength(8)]
    public string? TotpCode { get; set; }
}
