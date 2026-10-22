namespace Keystead.Application.Identity;

/// <summary>What the first-run wizard collects.</summary>
/// <param name="WorkspaceName">The name of the first workspace.</param>
/// <param name="Email">The owner's sign-in address.</param>
/// <param name="DisplayName">The owner's display name.</param>
/// <param name="Password">The owner's chosen password.</param>
public sealed record InitialisationRequest(
    string WorkspaceName,
    string Email,
    string DisplayName,
    string Password);
