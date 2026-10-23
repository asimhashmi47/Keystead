using System;
using System.Collections.Generic;

namespace Keystead.Application.Tokens;

/// <summary>An issued machine access token.</summary>
/// <param name="AccessToken">The signed JWT.</param>
/// <param name="ExpiresInSeconds">How long it is valid for.</param>
/// <param name="Scopes">The scopes it carries.</param>
public sealed record MachineToken(
    string AccessToken,
    int ExpiresInSeconds,
    IReadOnlyList<string> Scopes);

/// <summary>
/// One vault scope a machine token carries.
/// </summary>
/// <remarks>
/// Rendered as <c>vault:&lt;id&gt;:read</c> or <c>vault:&lt;id&gt;:write</c>. The scope is a
/// statement of what the identity was granted when the token was minted; it is not the
/// authorization decision. Every endpoint still resolves the grant from the database, so
/// revoking access takes effect on the next call rather than when the token expires.
/// </remarks>
/// <param name="VaultId">The vault.</param>
/// <param name="CanWrite">Whether write was granted.</param>
public sealed record VaultScope(Guid VaultId, bool CanWrite)
{
    /// <summary>Renders the scope string.</summary>
    public override string ToString() =>
        $"vault:{VaultId:D}:{(CanWrite ? "write" : "read")}";
}

/// <summary>The identity a validated token resolves to.</summary>
/// <param name="ServiceIdentityId">The machine principal.</param>
/// <param name="WorkspaceId">The workspace it belongs to.</param>
/// <param name="Name">Its display name, for audit entries.</param>
/// <param name="Scopes">The scopes the token carried.</param>
public sealed record MachinePrincipal(
    Guid ServiceIdentityId,
    Guid WorkspaceId,
    string Name,
    IReadOnlyList<VaultScope> Scopes);
