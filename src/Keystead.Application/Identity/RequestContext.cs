namespace Keystead.Application.Identity;

/// <summary>
/// Where a request came from, carried into audit entries and session records.
/// </summary>
/// <param name="IpAddress">The client address, after forwarded headers have been resolved.</param>
/// <param name="UserAgent">The user agent string, or null when absent.</param>
/// <param name="CorrelationId">The request correlation id, to tie the audit entry to the log.</param>
public sealed record RequestContext(string IpAddress, string? UserAgent, string? CorrelationId);
