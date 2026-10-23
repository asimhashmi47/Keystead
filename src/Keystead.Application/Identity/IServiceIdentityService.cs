using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Authorization;
using Keystead.Domain.Common;
using Keystead.Domain.Vaults;

namespace Keystead.Application.Identity;

/// <summary>Manages machine principals.</summary>
public interface IServiceIdentityService
{
    /// <summary>Lists the workspace's service identities.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The identities, without any secret material.</returns>
    Task<Result<IReadOnlyList<ServiceIdentitySummary>>> ListAsync(
        Principal principal,
        Guid workspaceId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Creates an identity, grants it the requested vault scopes, and issues its first secret.
    /// </summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="request">The identity details and the scopes to grant.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The identity and its plaintext secret, which is shown exactly once.</returns>
    Task<Result<CreatedServiceIdentity>> CreateAsync(
        Principal principal,
        Guid workspaceId,
        CreateServiceIdentityRequest request,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Issues a new secret, keeping the current one working for an overlap period.
    /// </summary>
    /// <remarks>
    /// The overlap is the point. Replacing the secret outright would break every deployment
    /// using it until each one was updated; with an overlap the new secret is distributed
    /// first and the old one expires on its own.
    /// </remarks>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="identityId">The identity to rotate.</param>
    /// <param name="overlap">How long the previous secret keeps working.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The new plaintext secret, shown exactly once.</returns>
    Task<Result<string>> RotateSecretAsync(
        Principal principal,
        Guid workspaceId,
        Guid identityId,
        TimeSpan overlap,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Disables an identity, taking effect on its next call.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="identityId">The identity to revoke.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> RevokeAsync(
        Principal principal,
        Guid workspaceId,
        Guid identityId,
        RequestContext context,
        CancellationToken cancellationToken);
}

/// <summary>What the caller supplies to create a service identity.</summary>
/// <param name="Name">Display name, for example <c>billing-api-prod</c>.</param>
/// <param name="ExpiresUtc">When the identity stops working, if it expires.</param>
/// <param name="IpAllowlist">Addresses and CIDR ranges it may call from. Empty means any.</param>
/// <param name="Scopes">The vaults to grant, and at what permission.</param>
public sealed record CreateServiceIdentityRequest(
    string Name,
    DateTimeOffset? ExpiresUtc,
    IReadOnlyList<string> IpAllowlist,
    IReadOnlyList<RequestedScope> Scopes);

/// <summary>One requested vault grant.</summary>
/// <param name="VaultId">The vault.</param>
/// <param name="Permission">Read or write.</param>
public sealed record RequestedScope(Guid VaultId, VaultPermission Permission);

/// <summary>A newly created identity and its one-time secret.</summary>
/// <param name="Identity">The identity.</param>
/// <param name="ClientSecret">
/// The plaintext secret. This is the only moment it exists; only its digest is stored.
/// </param>
public sealed record CreatedServiceIdentity(
    ServiceIdentitySummary Identity,
    string ClientSecret);

/// <summary>A service identity as shown in a list. Carries no secret material.</summary>
/// <param name="Id">The identity.</param>
/// <param name="Name">Display name.</param>
/// <param name="ClientId">The public client identifier.</param>
/// <param name="IsActive">Whether it may authenticate.</param>
/// <param name="ExpiresUtc">When it expires, if it does.</param>
/// <param name="CreatedUtc">When it was created.</param>
/// <param name="LastUsedUtc">When it last obtained a token.</param>
/// <param name="IpAllowlist">Its network restriction, if any.</param>
/// <param name="HasPendingRotation">Whether a previous secret is still inside its overlap.</param>
/// <param name="PreviousSecretExpiresUtc">When that overlap ends.</param>
/// <param name="Scopes">The vaults it can reach, and at what permission.</param>
public sealed record ServiceIdentitySummary(
    Guid Id,
    string Name,
    string ClientId,
    bool IsActive,
    DateTimeOffset? ExpiresUtc,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? LastUsedUtc,
    IReadOnlyList<string> IpAllowlist,
    bool HasPendingRotation,
    DateTimeOffset? PreviousSecretExpiresUtc,
    IReadOnlyList<GrantedScope> Scopes);

/// <summary>One vault a service identity can reach.</summary>
/// <param name="VaultId">The vault.</param>
/// <param name="VaultName">Its name.</param>
/// <param name="VaultSlug">Its slug.</param>
/// <param name="Permission">Read or write.</param>
public sealed record GrantedScope(
    Guid VaultId,
    string VaultName,
    string VaultSlug,
    VaultPermission Permission);
