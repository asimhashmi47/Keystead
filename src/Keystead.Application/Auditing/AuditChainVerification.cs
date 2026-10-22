namespace Keystead.Application.Auditing;

/// <summary>The outcome of verifying the audit chain.</summary>
/// <param name="IsIntact">Whether every link verified and the sequence is unbroken.</param>
/// <param name="EntriesChecked">How many entries were walked.</param>
/// <param name="FirstBrokenSeq">
/// The sequence number of the first entry that failed, or null when the chain is intact.
/// Reporting where it broke is the point: it tells an investigator which period to distrust,
/// rather than invalidating the whole log.
/// </param>
/// <param name="Failure">A short description of what was wrong, or null when intact.</param>
public sealed record AuditChainVerification(
    bool IsIntact,
    long EntriesChecked,
    long? FirstBrokenSeq,
    string? Failure)
{
    /// <summary>An intact chain of the given length.</summary>
    /// <param name="entriesChecked">How many entries were walked.</param>
    public static AuditChainVerification Intact(long entriesChecked) =>
        new(true, entriesChecked, null, null);

    /// <summary>A chain that failed at a specific entry.</summary>
    /// <param name="entriesChecked">How many entries were walked before the failure.</param>
    /// <param name="brokenSeq">Where it broke.</param>
    /// <param name="failure">What was wrong.</param>
    public static AuditChainVerification Broken(
        long entriesChecked,
        long brokenSeq,
        string failure) =>
        new(false, entriesChecked, brokenSeq, failure);
}
