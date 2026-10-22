using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Domain.Auditing;
using Keystead.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Keystead.Infrastructure.Auditing;

/// <summary>
/// Appends to and verifies the audit hash chain.
/// </summary>
/// <remarks>
/// <para>
/// Appending is a read-then-write: find the tail, hash against it, insert at the next sequence
/// number. That is a race, and the race matters, because two entries at the same position would
/// leave the chain with a fork that verification could never resolve.
/// </para>
/// <para>
/// Three things guard it, in order of how much they are relied on. The unique index on
/// <c>Seq</c> is the one that actually guarantees correctness: a loser in the race gets a
/// constraint violation rather than writing a duplicate. The retry loop turns that violation
/// back into a successful append at the next free position. The in-process semaphore merely
/// keeps the common case from reaching the database at all, and is not load-bearing, because
/// a second process would not share it.
/// </para>
/// </remarks>
public sealed class AuditChain : IAuditChain
{
    private const int MaxAppendAttempts = 5;

    // Not load-bearing: see the remarks above. It reduces contention within one process; the
    // unique index is what makes concurrent appends safe.
    private static readonly SemaphoreSlim AppendGate = new(1, 1);

    private readonly KeysteadDbContext _db;
    private readonly IClock _clock;

    /// <summary>Creates the chain service.</summary>
    /// <param name="db">The database.</param>
    /// <param name="clock">The clock.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public AuditChain(KeysteadDbContext db, IClock clock)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(clock);

        _db = db;
        _clock = clock;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="record"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The entry could not be appended after several attempts, which means sustained write
    /// contention rather than a lost race. Audit failure is never swallowed: a caller that
    /// cannot record what it did must not proceed as though it had.
    /// </exception>
    public async Task<long> AppendAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        await AppendGate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            for (var attempt = 1; attempt <= MaxAppendAttempts; attempt++)
            {
                try
                {
                    return await TryAppendAsync(record, cancellationToken).ConfigureAwait(false);
                }
                catch (DbUpdateException) when (attempt < MaxAppendAttempts)
                {
                    // Another writer took this sequence number. Clear the failed insert from
                    // the tracker, then re-read the tail and try the next position.
                    _db.ChangeTracker.Clear();
                }
            }

            throw new InvalidOperationException(
                "Could not append an audit entry after repeated attempts. The action was not completed, because an unrecorded action is worse than a failed one.");
        }
        finally
        {
            AppendGate.Release();
        }
    }

    private async Task<long> TryAppendAsync(
        AuditRecord record,
        CancellationToken cancellationToken)
    {
        var tail = await _db.AuditEntries
            .AsNoTracking()
            .OrderByDescending(e => e.Seq)
            .Select(e => new { e.Seq, e.Hash })
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        var seq = (tail?.Seq ?? 0) + 1;
        var previousHash = tail?.Hash ?? AuditEntry.GenesisHash.ToArray();

        var entry = new AuditEntry
        {
            Id = Guid.CreateVersion7(),
            Seq = seq,
            WorkspaceId = record.WorkspaceId,
            ActorType = record.ActorType,
            ActorId = record.ActorId,
            ActorLabel = Truncate(record.ActorLabel, 320)!,
            Action = record.Action,
            Outcome = record.Outcome,
            ResourceType = Truncate(record.ResourceType, 64)!,
            ResourceId = record.ResourceId,
            ResourceLabel = Truncate(record.ResourceLabel, 256),
            IpAddress = Truncate(record.IpAddress, 64)!,
            UserAgent = Truncate(record.UserAgent, 512),
            CorrelationId = Truncate(record.CorrelationId, 64),
            DataJson = Truncate(record.DataJson, 4000),
            CreatedUtc = _clock.UtcNow,
            PreviousHash = previousHash,

            // Placeholder only so the object is constructible; replaced immediately below.
            // The hash must be computed from the finished entry, including its timestamp.
            Hash = [],
        };

        var linked = Relink(entry, previousHash);

        _db.AuditEntries.Add(linked);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return seq;
    }

    /// <inheritdoc />
    public async Task<AuditChainVerification> VerifyAsync(CancellationToken cancellationToken)
    {
        var previousHash = AuditEntry.GenesisHash.ToArray();
        var expectedSeq = 1L;
        var checked_ = 0L;

        // Streamed rather than materialised: the audit log is the one table that only grows,
        // and loading all of it to verify it would make verification fail first on memory.
        var entries = _db.AuditEntries
            .AsNoTracking()
            .OrderBy(e => e.Seq)
            .AsAsyncEnumerable();

        await foreach (var entry in entries.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            if (entry.Seq != expectedSeq)
            {
                // A gap means a row was deleted. Hashes alone cannot show this, because what
                // remains either side of the gap is internally consistent; the sequence can.
                return AuditChainVerification.Broken(
                    checked_,
                    entry.Seq,
                    $"Sequence gap: expected entry {expectedSeq} but found {entry.Seq}. One or more entries have been removed.");
            }

            if (!entry.VerifyAgainst(previousHash))
            {
                return AuditChainVerification.Broken(
                    checked_,
                    entry.Seq,
                    $"Entry {entry.Seq} does not match its recorded hash. It has been altered, or the entry before it has.");
            }

            previousHash = entry.Hash;
            expectedSeq++;
            checked_++;
        }

        return AuditChainVerification.Intact(checked_);
    }

    /// <summary>
    /// Returns a copy of the entry with its chain hash computed.
    /// </summary>
    /// <remarks>
    /// A copy rather than a mutation because <see cref="AuditEntry.Hash"/> is <c>init</c>-only:
    /// an entry whose hash can be reassigned after construction is an entry whose hash can be
    /// reassigned by anything that holds it.
    /// </remarks>
    private static AuditEntry Relink(AuditEntry entry, byte[] previousHash) =>
        new()
        {
            Id = entry.Id,
            Seq = entry.Seq,
            WorkspaceId = entry.WorkspaceId,
            ActorType = entry.ActorType,
            ActorId = entry.ActorId,
            ActorLabel = entry.ActorLabel,
            Action = entry.Action,
            Outcome = entry.Outcome,
            ResourceType = entry.ResourceType,
            ResourceId = entry.ResourceId,
            ResourceLabel = entry.ResourceLabel,
            IpAddress = entry.IpAddress,
            UserAgent = entry.UserAgent,
            CorrelationId = entry.CorrelationId,
            DataJson = entry.DataJson,
            CreatedUtc = entry.CreatedUtc,
            PreviousHash = previousHash,
            Hash = entry.ComputeHash(previousHash),
        };

    /// <summary>
    /// Caps a field at its column width.
    /// </summary>
    /// <remarks>
    /// Truncating here rather than letting the insert fail matters: a 2 KB user-agent string
    /// must not be able to stop a failed sign-in being recorded. The attacker controls that
    /// header, and an audit write that throws is an audit write that did not happen.
    /// </remarks>
    private static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];
}
