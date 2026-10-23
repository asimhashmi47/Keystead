using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Domain.Workspaces;

namespace Keystead.Application.Workspaces;

/// <summary>Resolves which workspace a signed-in user is acting in.</summary>
public interface ICurrentWorkspace
{
    /// <summary>Lists the workspaces a user belongs to, for the switcher.</summary>
    /// <param name="userId">The signed-in user.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Their memberships, with the role held in each.</returns>
    Task<IReadOnlyList<WorkspaceMembershipView>> ListForUserAsync(
        Guid userId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Resolves the workspace a request is acting in.
    /// </summary>
    /// <remarks>
    /// Takes the requested id only as a hint and verifies the membership before returning it,
    /// so a workspace id in a URL cannot select a tenant the user does not belong to. With no
    /// hint, their first workspace is used.
    /// </remarks>
    /// <param name="userId">The signed-in user.</param>
    /// <param name="requested">A workspace id from the request, or null.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The resolved workspace, or null when the user belongs to none.</returns>
    Task<WorkspaceMembershipView?> ResolveAsync(
        Guid userId,
        Guid? requested,
        CancellationToken cancellationToken);
}

/// <summary>A workspace a user belongs to.</summary>
/// <param name="WorkspaceId">The workspace.</param>
/// <param name="Name">Display name.</param>
/// <param name="Slug">URL-safe identifier.</param>
/// <param name="Role">The role the user holds here.</param>
public sealed record WorkspaceMembershipView(
    Guid WorkspaceId,
    string Name,
    string Slug,
    WorkspaceRole Role);
