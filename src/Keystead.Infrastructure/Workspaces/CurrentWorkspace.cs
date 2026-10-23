using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Workspaces;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Workspaces;

/// <summary>Resolves the acting workspace from the user's memberships.</summary>
public sealed class CurrentWorkspace : ICurrentWorkspace
{
    private readonly KeysteadDbContext _db;

    /// <summary>Creates the resolver.</summary>
    /// <param name="db">The database.</param>
    /// <exception cref="ArgumentNullException"><paramref name="db"/> is null.</exception>
    public CurrentWorkspace(KeysteadDbContext db)
    {
        ArgumentNullException.ThrowIfNull(db);
        _db = db;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<WorkspaceMembershipView>> ListForUserAsync(
        Guid userId,
        CancellationToken cancellationToken) =>
        await _db.WorkspaceMemberships
            .AsNoTracking()
            .Where(m => m.UserId == userId)
            .OrderBy(m => m.Workspace!.Name)
            .Select(m => new WorkspaceMembershipView(
                m.WorkspaceId,
                m.Workspace!.Name,
                m.Workspace.Slug,
                m.Role))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

    /// <inheritdoc />
    public async Task<WorkspaceMembershipView?> ResolveAsync(
        Guid userId,
        Guid? requested,
        CancellationToken cancellationToken)
    {
        var memberships = await ListForUserAsync(userId, cancellationToken).ConfigureAwait(false);

        // The requested id is a hint, not an instruction. Looking it up inside the user's own
        // memberships means a workspace id pasted into a URL cannot select someone else's
        // tenant; it simply does not match, and the default is used instead.
        if (requested is { } id)
        {
            var match = memberships.FirstOrDefault(m => m.WorkspaceId == id);

            if (match is not null)
            {
                return match;
            }
        }

        return memberships.Count > 0 ? memberships[0] : null;
    }
}
