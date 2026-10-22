using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Identity;
using Keystead.Web.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using QRCoder;

namespace Keystead.Web.Pages;

/// <summary>
/// TOTP enrolment.
/// </summary>
/// <remarks>
/// <para>
/// Reachable two ways: by a signed-in user choosing to enrol, and by a half-authenticated user
/// whose role mandates MFA and who has not enrolled yet. The second case is why this page
/// accepts the pending scheme as well as the main one.
/// </para>
/// <para>
/// The QR code is computed on this server. A hosted QR generator would mean posting the TOTP
/// seed to a third party, which would be an absurd way to undo the point of a second factor.
/// </para>
/// <para>
/// The module grid is exposed as data and drawn by the view as ordinary SVG elements, rather
/// than as a pre-rendered SVG string handed to a raw-HTML helper. That keeps every byte of
/// markup inside Razor's encoder (CLAUDE.md rule 9): there is no "but this markup is ours"
/// exception to argue about later, and the source grep in the security suite can stay an
/// absolute check for zero occurrences rather than a list of blessed exemptions.
/// </para>
/// </remarks>
[AllowAnonymous]
[EnableRateLimiting("mfa")]
public sealed class MfaEnrolModel : KeysteadPageModel
{
    private readonly IMfaEnrolmentService _enrolment;

    /// <summary>Creates the page model.</summary>
    /// <param name="enrolment">The enrolment service.</param>
    /// <exception cref="ArgumentNullException"><paramref name="enrolment"/> is null.</exception>
    public MfaEnrolModel(IMfaEnrolmentService enrolment)
    {
        ArgumentNullException.ThrowIfNull(enrolment);
        _enrolment = enrolment;
    }

    /// <summary>The submitted code.</summary>
    [BindProperty]
    public MfaCodeInput Input { get; set; } = new();

    /// <summary>The error to show, or null.</summary>
    public string? Error { get; private set; }

    /// <summary>The shared secret, shown once so it can be entered manually.</summary>
    public string? SharedSecret { get; private set; }

    /// <summary>
    /// The dark modules of the QR code, as (x, y) coordinates in module units.
    /// </summary>
    public IReadOnlyList<QrModule> QrModules { get; private set; } = [];

    /// <summary>The width and height of the QR grid, in module units.</summary>
    public int QrSize { get; private set; }

    /// <summary>The recovery codes, shown exactly once after enrolment completes.</summary>
    public IReadOnlyList<string>? RecoveryCodes { get; private set; }

    /// <summary>One dark module of a QR code.</summary>
    /// <param name="X">Column, in module units.</param>
    /// <param name="Y">Row, in module units.</param>
    public readonly record struct QrModule(int X, int Y);

    /// <summary>Starts enrolment.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The page, or a redirect when there is no account to enrol.</returns>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var userId = await ResolveUserIdAsync().ConfigureAwait(false);

        if (userId is null)
        {
            return RedirectToPage("/SignIn");
        }

        var enrolment = await _enrolment
            .BeginAsync(userId.Value, cancellationToken)
            .ConfigureAwait(false);

        if (enrolment is null)
        {
            // Already enrolled, or the account is not usable. Replacing an existing
            // authenticator is a separate step-up-protected operation, not a silent
            // re-enrolment here.
            return RedirectToPage("/Security");
        }

        SharedSecret = enrolment.SharedSecretBase32;
        BuildQr(enrolment.ProvisioningUri);

        return Page();
    }

    /// <summary>Completes enrolment by proving a code.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The recovery codes on success, or the form with an error.</returns>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var userId = await ResolveUserIdAsync().ConfigureAwait(false);

        if (userId is null)
        {
            return RedirectToPage("/SignIn");
        }

        if (!ModelState.IsValid)
        {
            Error = "Enter the six-digit code shown in your authenticator app.";
            return Page();
        }

        var codes = await _enrolment
            .CompleteAsync(userId.Value, Input.Code, RequestContext, cancellationToken)
            .ConfigureAwait(false);

        if (codes is null)
        {
            Error = "That code was not accepted. Check that your authenticator shows Keystead, and try the current code.";
            return Page();
        }

        // Shown on this response only. Not held in TempData, so a refresh cannot reproduce
        // them; the response is no-store, so the back button cannot either.
        RecoveryCodes = codes;

        return Page();
    }

    /// <summary>
    /// Finds the account being enrolled: the signed-in user, or the half-authenticated one
    /// from the password step.
    /// </summary>
    private async Task<Guid?> ResolveUserIdAsync()
    {
        if (CurrentUserId is { } signedIn)
        {
            return signedIn;
        }

        var pending = await HttpContext
            .AuthenticateAsync(KeysteadSchemes.MfaPending)
            .ConfigureAwait(false);

        return pending.Succeeded ? KeysteadClaims.GetUserId(pending.Principal) : null;
    }

    private void BuildQr(string provisioningUri)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(provisioningUri, QRCodeGenerator.ECCLevel.Q);

        var matrix = data.ModuleMatrix;
        var modules = new List<QrModule>();

        for (var y = 0; y < matrix.Count; y++)
        {
            var row = matrix[y];

            for (var x = 0; x < row.Length; x++)
            {
                if (row[x])
                {
                    modules.Add(new QrModule(x, y));
                }
            }
        }

        QrSize = matrix.Count;
        QrModules = modules;
    }
}
