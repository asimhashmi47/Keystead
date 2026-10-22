namespace Keystead.Application.Identity;

/// <summary>
/// The result of starting TOTP enrolment.
/// </summary>
/// <param name="SharedSecretBase32">
/// The secret in the form an authenticator app expects. Shown to the user exactly once, during
/// enrolment, and never persisted in this form.
/// </param>
/// <param name="ProvisioningUri">
/// The <c>otpauth://</c> URI the QR code encodes.
/// </param>
/// <param name="Seed">The sealed seed to store against the user.</param>
public sealed record TotpEnrolment(
    string SharedSecretBase32,
    string ProvisioningUri,
    StoredTotpSeed Seed);
