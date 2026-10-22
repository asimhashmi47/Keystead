using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Auditing;
using Keystead.Domain.Auditing;
using Keystead.Tests.TestDoubles;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Keystead.Tests.Auditing;

/// <summary>
/// The audit chain writer against a real database, including what happens when someone edits
/// the table afterwards.
/// </summary>
public sealed class AuditChainWriterTests : IDisposable
{
    private readonly TestDatabase _db = new();
    private readonly FixedClock _clock = new();
    private readonly Infrastructure.Auditing.AuditChain _chain;

    public AuditChainWriterTests() =>
        _chain = new Infrastructure.Auditing.AuditChain(_db.Context, _clock);

    public void Dispose() => _db.Dispose();

    private static AuditRecord Record(
        AuditAction action = AuditAction.SignInSucceeded,
        AuditOutcome outcome = AuditOutcome.Success,
        string label = "ada@example.com") => new()
        {
            ActorType = ActorType.User,
            ActorId = Guid.CreateVersion7(),
            ActorLabel = label,
            Action = action,
            Outcome = outcome,
            ResourceType = "user",
            IpAddress = "203.0.113.1",
            UserAgent = "test-agent",
            CorrelationId = "req-1",
        };

    [Fact]
    public async Task TheFirstEntry_IsAtSequenceOneAndLinksToGenesis()
    {
        var seq = await _chain.AppendAsync(Record(), CancellationToken.None);

        Assert.Equal(1, seq);

        var entry = await _db.Context.AuditEntries.AsNoTracking().SingleAsync();

        Assert.Equal(AuditEntry.GenesisHash.ToArray(), entry.PreviousHash);
        Assert.True(entry.VerifyAgainst(AuditEntry.GenesisHash));
    }

    [Fact]
    public async Task SequentialAppends_FormAVerifiableChain()
    {
        for (var i = 0; i < 20; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(1));
            await _chain.AppendAsync(Record(), CancellationToken.None);
        }

        var result = await _chain.VerifyAsync(CancellationToken.None);

        Assert.True(result.IsIntact);
        Assert.Equal(20, result.EntriesChecked);
        Assert.Null(result.FirstBrokenSeq);
    }

    [Fact]
    public async Task EachEntry_CommitsToItsPredecessorsHash()
    {
        await _chain.AppendAsync(Record(), CancellationToken.None);
        _clock.Advance(TimeSpan.FromSeconds(1));
        await _chain.AppendAsync(Record(), CancellationToken.None);

        var entries = await _db.Context.AuditEntries
            .AsNoTracking()
            .OrderBy(e => e.Seq)
            .ToListAsync();

        Assert.Equal(entries[0].Hash, entries[1].PreviousHash);
    }

    [Fact]
    public async Task AnEmptyChain_VerifiesAsIntact()
    {
        var result = await _chain.VerifyAsync(CancellationToken.None);

        Assert.True(result.IsIntact);
        Assert.Equal(0, result.EntriesChecked);
    }

    [Fact]
    public async Task EditingAStoredEntry_IsDetectedAndLocated()
    {
        for (var i = 0; i < 10; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(1));
            await _chain.AppendAsync(Record(), CancellationToken.None);
        }

        // The cover-up: rewrite a denied outcome to look successful, using a second context so
        // this is a genuine out-of-band database edit rather than a tracked change.
        await using (var tamperer = _db.CreateContext())
        {
            await tamperer.AuditEntries
                .Where(e => e.Seq == 4)
                .ExecuteUpdateAsync(s => s.SetProperty(e => e.ActorLabel, "someone.else@example.com"));
        }

        var result = await _chain.VerifyAsync(CancellationToken.None);

        Assert.False(result.IsIntact);
        Assert.Equal(4, result.FirstBrokenSeq);
        Assert.Contains("altered", result.Failure, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DeletingAnEntry_IsDetectedAsASequenceGap()
    {
        for (var i = 0; i < 10; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(1));
            await _chain.AppendAsync(Record(), CancellationToken.None);
        }

        await using (var tamperer = _db.CreateContext())
        {
            await tamperer.AuditEntries.Where(e => e.Seq == 5).ExecuteDeleteAsync();
        }

        var result = await _chain.VerifyAsync(CancellationToken.None);

        Assert.False(result.IsIntact);

        // Reported at 6, because that is where the sequence first disagrees with expectation.
        Assert.Equal(6, result.FirstBrokenSeq);
        Assert.Contains("removed", result.Failure, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VerificationReportsHowFarItGotBeforeBreaking()
    {
        // Locating the break matters: it tells an investigator which period to distrust rather
        // than invalidating the whole log.
        for (var i = 0; i < 10; i++)
        {
            _clock.Advance(TimeSpan.FromSeconds(1));
            await _chain.AppendAsync(Record(), CancellationToken.None);
        }

        await using (var tamperer = _db.CreateContext())
        {
            await tamperer.AuditEntries
                .Where(e => e.Seq == 8)
                .ExecuteUpdateAsync(s => s.SetProperty(e => e.IpAddress, "198.51.100.200"));
        }

        var result = await _chain.VerifyAsync(CancellationToken.None);

        Assert.False(result.IsIntact);
        Assert.Equal(8, result.FirstBrokenSeq);
        Assert.Equal(7, result.EntriesChecked);
    }

    [Fact]
    public async Task ConcurrentAppends_AllSucceedWithDistinctSequenceNumbers()
    {
        // The append is a read-then-write race. Each writer needs its own context, because a
        // DbContext is not thread safe; what is being tested is that the unique index plus the
        // retry loop produce a chain with no duplicate or missing positions.
        const int Writers = 12;

        var tasks = Enumerable.Range(0, Writers).Select(async _ =>
        {
            await using var context = _db.CreateContext();
            var chain = new Infrastructure.Auditing.AuditChain(context, _clock);
            return await chain.AppendAsync(Record(), CancellationToken.None);
        });

        var sequences = await Task.WhenAll(tasks);

        Assert.Equal(Writers, sequences.Distinct().Count());
        Assert.Equal(Enumerable.Range(1, Writers).Select(i => (long)i).OrderBy(i => i), sequences.OrderBy(s => s));
    }

    [Fact]
    public async Task AChainBuiltConcurrently_StillVerifies()
    {
        const int Writers = 12;

        await Task.WhenAll(Enumerable.Range(0, Writers).Select(async _ =>
        {
            await using var context = _db.CreateContext();
            var chain = new Infrastructure.Auditing.AuditChain(context, _clock);
            await chain.AppendAsync(Record(), CancellationToken.None);
        }));

        var result = await _chain.VerifyAsync(CancellationToken.None);

        Assert.True(result.IsIntact);
        Assert.Equal(Writers, result.EntriesChecked);
    }

    [Fact]
    public async Task AnOverlongUserAgent_IsTruncatedRatherThanFailingTheWrite()
    {
        // The attacker controls this header. An audit write that throws on a 2 KB user agent
        // would be a way to stop a failed sign-in being recorded at all.
        var record = Record() with { UserAgent = new string('x', 5_000) };

        var seq = await _chain.AppendAsync(record, CancellationToken.None);

        var entry = await _db.Context.AuditEntries.AsNoTracking().SingleAsync(e => e.Seq == seq);

        Assert.Equal(512, entry.UserAgent!.Length);

        var result = await _chain.VerifyAsync(CancellationToken.None);
        Assert.True(result.IsIntact);
    }

    [Fact]
    public async Task DeniedOutcomes_AreRecordedAsDeliberatelyAsSuccesses()
    {
        await _chain.AppendAsync(
            Record(AuditAction.SignInFailed, AuditOutcome.Denied),
            CancellationToken.None);

        var entry = await _db.Context.AuditEntries.AsNoTracking().SingleAsync();

        Assert.Equal(AuditOutcome.Denied, entry.Outcome);
        Assert.Equal(AuditAction.SignInFailed, entry.Action);
    }

    [Fact]
    public async Task TheRecordedTimestampComesFromTheInjectedClock()
    {
        _clock.UtcNow = new DateTimeOffset(2026, 7, 4, 9, 30, 0, TimeSpan.Zero);

        await _chain.AppendAsync(Record(), CancellationToken.None);

        var entry = await _db.Context.AuditEntries.AsNoTracking().SingleAsync();

        Assert.Equal(_clock.UtcNow, entry.CreatedUtc);
    }
}
