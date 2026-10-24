using System;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Infrastructure.Cryptography;
using Keystead.Infrastructure.Identity;
using Keystead.Tests.TestDoubles;
using Microsoft.Extensions.Options;
using Xunit;

namespace Keystead.Tests.Identity;

/// <summary>
/// What the sign-in service is allowed to cost before anyone has tried to sign in.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of a real defect. The decoy digest that makes an unknown address cost
/// the same as a known one was computed in the constructor, and the service is registered
/// scoped, so every request that injected it ran a full Argon2id hash: 64 MiB and about a
/// third of a second. That included an anonymous <c>GET</c> of the sign-in page, which does no
/// work at all. It made the whole application roughly twenty times slower than it needed to
/// be, and it handed an unauthenticated caller a cheap way to spend the server's memory and
/// processor.
/// </para>
/// <para>
/// The property worth holding is narrow and easy to state: constructing the service hashes
/// nothing. Where the decoy is computed is an implementation detail; that it is not computed
/// on the way in is not.
/// </para>
/// </remarks>
public sealed class SignInServiceCostTests
{
    [Fact]
    public void ConstructingTheService_HashesNothing()
    {
        using var database = new TestDatabase();
        using var masterKeys = new InMemoryMasterKeyProvider();
        var hasher = new CountingPasswordHasher();

        _ = new SignInService(
            database.Context,
            hasher,
            new TotpService(new AesGcmCipher(), masterKeys),
            new RecoveryCodeService(),
            new NullAuditChain(),
            new FixedClock(new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero)),
            Options.Create(new SessionOptions()));

        Assert.Equal(0, hasher.HashCalls);
    }

    /// <summary>Counts how many times a hash was asked for.</summary>
    private sealed class CountingPasswordHasher : IPasswordHasher
    {
        public int HashCalls { get; private set; }

        public string Hash(string password)
        {
            HashCalls++;
            return "counted";
        }

        public PasswordVerificationResult Verify(string password, string encodedHash) =>
            PasswordVerificationResult.Failed;
    }

    /// <summary>An audit chain the test never reaches, because nothing is signed in.</summary>
    private sealed class NullAuditChain : IAuditChain
    {
        public Task<long> AppendAsync(AuditRecord record, CancellationToken cancellationToken) =>
            Task.FromResult(0L);

        public Task<AuditChainVerification> VerifyAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
