using System;

namespace Keystead.Application.Identity;

/// <summary>The outcome of first-run initialisation.</summary>
/// <param name="Succeeded">Whether the installation was initialised.</param>
/// <param name="Error">A message for the form when it failed.</param>
/// <param name="WorkspaceId">The new workspace.</param>
/// <param name="OwnerUserId">The new owner account.</param>
/// <param name="MasterKeyCheckValue">
/// The non-secret fingerprint of the active master key, for the recovery kit. An operator can
/// compare it later to confirm they are holding the right key, without the fingerprint being
/// any use for recovering the key itself.
/// </param>
public sealed record InitialisationResult(
    bool Succeeded,
    string? Error,
    Guid? WorkspaceId,
    Guid? OwnerUserId,
    string? MasterKeyCheckValue)
{
    /// <summary>A failed attempt.</summary>
    /// <param name="error">Why it failed.</param>
    public static InitialisationResult Failed(string error) =>
        new(false, error, null, null, null);

    /// <summary>A successful initialisation.</summary>
    /// <param name="workspaceId">The new workspace.</param>
    /// <param name="ownerUserId">The new owner.</param>
    /// <param name="keyCheckValue">The master key fingerprint for the recovery kit.</param>
    public static InitialisationResult Ok(Guid workspaceId, Guid ownerUserId, string keyCheckValue) =>
        new(true, null, workspaceId, ownerUserId, keyCheckValue);
}
