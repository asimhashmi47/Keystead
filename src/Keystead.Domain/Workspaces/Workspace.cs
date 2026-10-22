using System;
using System.Collections.Generic;

namespace Keystead.Domain.Workspaces;

/// <summary>
/// A tenant. The workspace is the hard isolation boundary in Keystead: every query is scoped
/// by it and every ciphertext is cryptographically bound to it through AAD, so a row cannot be
/// read from, or moved into, another workspace.
/// </summary>
public sealed class Workspace
{
    /// <summary>Stable identifier, also part of the AAD for every ciphertext below it.</summary>
    public required Guid Id { get; init; }

    /// <summary>Display name.</summary>
    public required string Name { get; set; }

    /// <summary>URL-safe identifier, unique across the installation.</summary>
    public required string Slug { get; set; }

    /// <summary>When the workspace was created.</summary>
    public required DateTimeOffset CreatedUtc { get; init; }

    /// <summary>Members of this workspace and their roles.</summary>
    public ICollection<WorkspaceMembership> Memberships { get; } = new List<WorkspaceMembership>();
}
