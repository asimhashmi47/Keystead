using System;
using Keystead.Domain.Vaults;

namespace Keystead.Application.Authorization;

/// <summary>
/// Who is asking. Covers both humans and machines, so authorization has one code path rather
/// than two that can drift apart.
/// </summary>
/// <param name="Type">Whether this is a user or a service identity.</param>
/// <param name="Id">The subject identifier.</param>
/// <param name="Label">A display label for audit entries.</param>
/// <param name="SessionId">
/// The session, for a user. Used to check step-up freshness; null for a service identity,
/// which has no interactive session and therefore cannot step up.
/// </param>
public sealed record Principal(SubjectType Type, Guid Id, string Label, Guid? SessionId);
