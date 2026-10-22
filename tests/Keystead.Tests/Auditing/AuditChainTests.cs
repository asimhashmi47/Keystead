using System;
using System.Collections.Generic;
using Keystead.Domain.Auditing;
using Xunit;

namespace Keystead.Tests.Auditing;

/// <summary>
/// The audit log's claim is that history cannot be edited without detection. These tests make
/// that claim falsifiable: each one performs the edit an insider would attempt and asserts
/// that verification fails.
/// </summary>
public sealed class AuditChainTests
{
    private static readonly DateTimeOffset Start =
        new(2026, 3, 1, 9, 0, 0, TimeSpan.Zero);

    private static AuditEntry Build(
        long seq,
        byte[] previousHash,
        AuditAction action = AuditAction.SecretValueRead,
        AuditOutcome outcome = AuditOutcome.Success,
        string? label = null)
    {
        var entry = new AuditEntry
        {
            Id = Guid.Parse($"00000000-0000-0000-0000-{seq:D12}"),
            Seq = seq,
            WorkspaceId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
            ActorType = ActorType.User,
            ActorId = Guid.Parse("22222222-2222-2222-2222-222222222222"),
            ActorLabel = label ?? "ada@example.com",
            Action = action,
            Outcome = outcome,
            ResourceType = "secret",
            ResourceId = Guid.Parse("33333333-3333-3333-3333-333333333333"),
            ResourceLabel = "ConnectionStrings--Default",
            IpAddress = "203.0.113.7",
            UserAgent = "Mozilla/5.0",
            CorrelationId = $"req-{seq}",
            DataJson = null,
            CreatedUtc = Start.AddSeconds(seq),
            PreviousHash = previousHash,
            Hash = [],
        };

        return Rehash(entry, previousHash);
    }

    private static AuditEntry Rehash(AuditEntry entry, byte[] previousHash) =>
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

    private static List<AuditEntry> BuildChain(int length)
    {
        var chain = new List<AuditEntry>(length);
        var previous = AuditEntry.GenesisHash.ToArray();

        for (var i = 1; i <= length; i++)
        {
            var entry = Build(i, previous);
            chain.Add(entry);
            previous = entry.Hash;
        }

        return chain;
    }

    private static bool Verify(IReadOnlyList<AuditEntry> chain)
    {
        var previous = AuditEntry.GenesisHash.ToArray();

        foreach (var entry in chain)
        {
            if (!entry.VerifyAgainst(previous))
            {
                return false;
            }

            previous = entry.Hash;
        }

        return true;
    }

    [Fact]
    public void AnUntouchedChain_Verifies()
    {
        Assert.True(Verify(BuildChain(25)));
    }

    [Fact]
    public void TheFirstEntry_CommitsToTheGenesisHash()
    {
        var chain = BuildChain(1);

        Assert.Equal(AuditEntry.GenesisHash.ToArray(), chain[0].PreviousHash);
        Assert.True(chain[0].VerifyAgainst(AuditEntry.GenesisHash));
    }

    [Fact]
    public void HashesAre32Bytes()
    {
        var chain = BuildChain(3);

        Assert.All(chain, e => Assert.Equal(AuditEntry.HashLength, e.Hash.Length));
    }

    [Fact]
    public void EveryEntry_HasADistinctHash()
    {
        var chain = BuildChain(50);
        var distinct = new HashSet<string>(StringComparer.Ordinal);

        foreach (var entry in chain)
        {
            Assert.True(distinct.Add(Convert.ToHexStringLower(entry.Hash)));
        }
    }

    [Fact]
    public void EditingAnEntryInPlace_BreaksVerification()
    {
        // The simplest cover-up: change the outcome of a denied read to look successful,
        // or in this case rewrite who did it, leaving the stored hash alone.
        var chain = BuildChain(10);

        chain[4] = new AuditEntry
        {
            Id = chain[4].Id,
            Seq = chain[4].Seq,
            WorkspaceId = chain[4].WorkspaceId,
            ActorType = chain[4].ActorType,
            ActorId = chain[4].ActorId,
            ActorLabel = "someone-else@example.com",
            Action = chain[4].Action,
            Outcome = chain[4].Outcome,
            ResourceType = chain[4].ResourceType,
            ResourceId = chain[4].ResourceId,
            ResourceLabel = chain[4].ResourceLabel,
            IpAddress = chain[4].IpAddress,
            UserAgent = chain[4].UserAgent,
            CorrelationId = chain[4].CorrelationId,
            DataJson = chain[4].DataJson,
            CreatedUtc = chain[4].CreatedUtc,
            PreviousHash = chain[4].PreviousHash,
            Hash = chain[4].Hash,
        };

        Assert.False(Verify(chain));
    }

    [Fact]
    public void RehashingAnEditedEntry_StillBreaksTheFollowingLink()
    {
        // The sophisticated cover-up: edit the entry and recompute its own hash so that it is
        // internally consistent. The next entry still commits to the old hash, so the chain
        // breaks one link later. Repairing the whole tail is the only way, which is precisely
        // the cost the chain is meant to impose.
        var chain = BuildChain(10);
        var tampered = Rehash(
            Build(5, chain[4].PreviousHash, label: "someone-else@example.com"),
            chain[4].PreviousHash);

        chain[4] = tampered;

        Assert.True(tampered.VerifyAgainst(chain[3].Hash));
        Assert.False(Verify(chain));
        Assert.False(chain[5].VerifyAgainst(tampered.Hash));
    }

    [Fact]
    public void DeletingAnEntry_BreaksVerification()
    {
        var chain = BuildChain(10);
        chain.RemoveAt(5);

        Assert.False(Verify(chain));
    }

    [Fact]
    public void ReorderingEntries_BreaksVerification()
    {
        var chain = BuildChain(10);
        (chain[3], chain[6]) = (chain[6], chain[3]);

        Assert.False(Verify(chain));
    }

    [Fact]
    public void TruncatingTheTail_LeavesTheRemainderVerifiableButTheSequenceGapped()
    {
        // Honest limitation: lopping entries off the end cannot be detected by hashes alone,
        // because what remains is a valid prefix. The Seq column is what exposes it, so the
        // verifier checks sequence continuity as well as hashes.
        var chain = BuildChain(10);
        chain.RemoveRange(7, 3);

        Assert.True(Verify(chain));
        Assert.Equal(7, chain.Count);
        Assert.Equal(7, chain[^1].Seq);
    }

    [Fact]
    public void AnEntryWithAForgedPreviousHash_FailsVerification()
    {
        var chain = BuildChain(5);
        var forged = new byte[AuditEntry.HashLength];
        Array.Fill(forged, (byte)0xFF);

        Assert.False(chain[2].VerifyAgainst(forged));
    }

    [Fact]
    public void ChangingTheTimestamp_BreaksVerification()
    {
        var previous = AuditEntry.GenesisHash.ToArray();
        var entry = Build(1, previous);

        var moved = new AuditEntry
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
            CreatedUtc = entry.CreatedUtc.AddSeconds(1),
            PreviousHash = entry.PreviousHash,
            Hash = entry.Hash,
        };

        Assert.False(moved.VerifyAgainst(previous));
    }

    [Fact]
    public void TheSameInstantInADifferentOffset_HashesIdentically()
    {
        // The timestamp is normalised to UTC before hashing, so a server whose offset changes
        // does not invalidate its own history.
        var previous = AuditEntry.GenesisHash.ToArray();
        var utc = Build(1, previous);

        var shifted = new AuditEntry
        {
            Id = utc.Id,
            Seq = utc.Seq,
            WorkspaceId = utc.WorkspaceId,
            ActorType = utc.ActorType,
            ActorId = utc.ActorId,
            ActorLabel = utc.ActorLabel,
            Action = utc.Action,
            Outcome = utc.Outcome,
            ResourceType = utc.ResourceType,
            ResourceId = utc.ResourceId,
            ResourceLabel = utc.ResourceLabel,
            IpAddress = utc.IpAddress,
            UserAgent = utc.UserAgent,
            CorrelationId = utc.CorrelationId,
            DataJson = utc.DataJson,
            CreatedUtc = utc.CreatedUtc.ToOffset(TimeSpan.FromHours(5)),
            PreviousHash = utc.PreviousHash,
            Hash = utc.Hash,
        };

        Assert.True(shifted.VerifyAgainst(previous));
    }

    [Fact]
    public void ANullFieldAndAnEmptyField_HashDifferently()
    {
        // Length prefixing distinguishes null from empty. Without it, an entry with no detail
        // and an entry with empty detail would be indistinguishable to the chain, which is a
        // small but real ambiguity in what the log committed to.
        var previous = AuditEntry.GenesisHash.ToArray();
        var withNull = Build(1, previous);

        var withEmpty = new AuditEntry
        {
            Id = withNull.Id,
            Seq = withNull.Seq,
            WorkspaceId = withNull.WorkspaceId,
            ActorType = withNull.ActorType,
            ActorId = withNull.ActorId,
            ActorLabel = withNull.ActorLabel,
            Action = withNull.Action,
            Outcome = withNull.Outcome,
            ResourceType = withNull.ResourceType,
            ResourceId = withNull.ResourceId,
            ResourceLabel = withNull.ResourceLabel,
            IpAddress = withNull.IpAddress,
            UserAgent = withNull.UserAgent,
            CorrelationId = withNull.CorrelationId,
            DataJson = string.Empty,
            CreatedUtc = withNull.CreatedUtc,
            PreviousHash = previous,
            Hash = [],
        };

        Assert.NotEqual(
            Convert.ToHexStringLower(withNull.Hash),
            Convert.ToHexStringLower(withEmpty.ComputeHash(previous)));
    }

    [Fact]
    public void ComputeHash_WithWrongLengthPreviousHash_Throws()
    {
        var entry = Build(1, AuditEntry.GenesisHash.ToArray());

        Assert.Throws<ArgumentException>(() => entry.ComputeHash(new byte[16]));
    }

    [Fact]
    public void DeniedAndSuccessfulOutcomes_HashDifferently()
    {
        // Flipping a denial to a success is the most valuable single edit an attacker could
        // make, so it gets its own test.
        var previous = AuditEntry.GenesisHash.ToArray();
        var denied = Build(1, previous, outcome: AuditOutcome.Denied);
        var succeeded = Build(1, previous, outcome: AuditOutcome.Success);

        Assert.NotEqual(
            Convert.ToHexStringLower(denied.Hash),
            Convert.ToHexStringLower(succeeded.Hash));
    }
}
