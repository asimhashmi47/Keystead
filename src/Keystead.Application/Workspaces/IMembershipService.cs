using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Authorization;
using Keystead.Application.Identity;
using Keystead.Domain.Common;
using Keystead.Domain.Vaults;
using Keystead.Domain.Workspaces;

namespace Keystead.Application.Workspaces;

/// <summary>Manages who belongs to a workspace, at what role, and which vaults they can reach.</summary>
public interface IMembershipService
{
    /// <summary>Lists the workspace's members with their roles and vault grants.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The members.</returns>
    Task<Result<IReadOnlyList<MemberSummary>>> ListAsync(
        Principal principal,
        Guid workspaceId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Adds a member, creating their account with a one-time password.
    /// </summary>
    /// <remarks>
    /// Keystead sends no email, so the password is handed to the administrator to pass on out
    /// of band. That is a deliberate scope decision rather than an oversight: an installation
    /// that had to be given SMTP credentials before anyone could be invited would be a worse
    /// starting experience, and a mail server is one more place a credential can leak.
    /// </remarks>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="email">The new member's address.</param>
    /// <param name="displayName">Their display name.</param>
    /// <param name="role">The role to grant.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The member and their one-time password, shown exactly once.</returns>
    Task<Result<AddedMember>> AddAsync(
        Principal principal,
        Guid workspaceId,
        string email,
        string displayName,
        WorkspaceRole role,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>
    /// Changes a member's role.
    /// </summary>
    /// <remarks>
    /// Refuses to remove the last Owner. A workspace with no Owner cannot have its roles
    /// changed, its keys rotated, or its data purged by anyone, which is an unrecoverable state
    /// reachable by one careless click.
    /// </remarks>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="userId">The member to change.</param>
    /// <param name="role">The new role.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> ChangeRoleAsync(
        Principal principal,
        Guid workspaceId,
        Guid userId,
        WorkspaceRole role,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Removes a member from the workspace and revokes their vault grants.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="userId">The member to remove.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> RemoveAsync(
        Principal principal,
        Guid workspaceId,
        Guid userId,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Grants or changes a member's access to one vault.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="userId">The member.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="permission">Read or write.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> GrantVaultAsync(
        Principal principal,
        Guid workspaceId,
        Guid userId,
        Guid vaultId,
        VaultPermission permission,
        RequestContext context,
        CancellationToken cancellationToken);

    /// <summary>Revokes a member's access to one vault.</summary>
    /// <param name="principal">Who is asking.</param>
    /// <param name="workspaceId">The workspace.</param>
    /// <param name="userId">The member.</param>
    /// <param name="vaultId">The vault.</param>
    /// <param name="context">Where the request came from.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Success, or the reason it was refused.</returns>
    Task<Result<bool>> RevokeVaultAsync(
        Principal principal,
        Guid workspaceId,
        Guid userId,
        Guid vaultId,
        RequestContext context,
        CancellationToken cancellationToken);
}

/// <summary>A workspace member as shown on the members page.</summary>
/// <param name="UserId">The account.</param>
/// <param name="Email">Their sign-in address.</param>
/// <param name="DisplayName">Their display name.</param>
/// <param name="Role">The role they hold here.</param>
/// <param name="IsActive">Whether the account may sign in.</param>
/// <param name="MfaEnabled">Whether they have a second factor enrolled.</param>
/// <param name="RequiresMfa">Whether their role makes MFA mandatory.</param>
/// <param name="CreatedUtc">When the account was created.</param>
/// <param name="Grants">The vaults they have been granted, beyond any implicit access.</param>
/// <param name="HasImplicitVaultAccess">Whether their role reaches every vault anyway.</param>
public sealed record MemberSummary(
    Guid UserId,
    string Email,
    string DisplayName,
    WorkspaceRole Role,
    bool IsActive,
    bool MfaEnabled,
    bool RequiresMfa,
    DateTimeOffset CreatedUtc,
    IReadOnlyList<GrantedScope> Grants,
    bool HasImplicitVaultAccess);

/// <summary>A newly added member and their one-time password.</summary>
/// <param name="Member">The member.</param>
/// <param name="OneTimePassword">
/// The generated password, shown exactly once. Only its Argon2id digest is stored.
/// </param>
public sealed record AddedMember(MemberSummary Member, string OneTimePassword);
