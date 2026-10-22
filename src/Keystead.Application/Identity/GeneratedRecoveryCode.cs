namespace Keystead.Application.Identity;

/// <summary>
/// A newly issued recovery code.
/// </summary>
/// <param name="PlaintextCode">
/// The code to display. This is the only moment it exists in this form; only the hash is kept.
/// </param>
/// <param name="Hash">The SHA-256 digest to store.</param>
public sealed record GeneratedRecoveryCode(string PlaintextCode, byte[] Hash);
