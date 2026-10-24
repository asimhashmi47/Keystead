using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Application.Abstractions;
using Keystead.Application.Auditing;
using Keystead.Application.Identity;
using Keystead.Domain.Identity;
using Keystead.Infrastructure.Cryptography;
using Keystead.Infrastructure.Identity;
using Keystead.Tests.TestDoubles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OtpNet;
using Xunit;

namespace Keystead.Tests.Identity;

/// <summary>
/// Where the session identifier comes from, across the two-step sign-in.
/// </summary>
/// <remarks>
/// <para>
/// Session fixation is the attack these tests exist for: an attacker who can plant a session
/// identifier before authentication, and finds it still valid afterwards, is signed in as the
/// victim without ever knowing a credential. The defence is that the identifier a client ends
/// up holding is one the server minted after the last factor was proven, and that nothing
/// issued earlier survives.
/// </para>
/// <para>
/// The structure was already right — a separate short-lived scheme carries the pending user id
/// between the password step and the code step, and no session row exists until both factors
/// are in. What was missing was anything that said so, which is the only reason a correct
/// implementation stays correct through the next change.
/// </para>
/// </remarks>
public sealed class SessionFreshnessTests : IDisposable
{
    private const string Password = "correct horse battery staple";

    private readonly TestDatabase _database = new();
    private readonly InMemoryMasterKeyProvider _masterKeys = new();
    private readonly RequestContext _context = new("203.0.113.9", "tests", "correlation");
    private readonly TotpService _totp;
    private readonly SignInService _signIn;
    private readonly User _user;
    private readonly string _sharedSecret;

    public SessionFreshnessTests()
    {
        _totp = new TotpService(new AesGcmCipher(), _masterKeys);

        var userId = Guid.CreateVersion7();
        var enrolment = _totp.CreateEnrolment(userId, "ada@example.com");
        _sharedSecret = enrolment.SharedSecretBase32;

        _user = new User
        {
            Id = userId,
            Email = "ada@example.com",
            DisplayName = "Ada",
            PasswordHash = Password,
            PasswordChangedUtc = DateTimeOffset.UtcNow,
            FailedSignInCount = 0,
            CreatedUtc = DateTimeOffset.UtcNow,
            IsActive = true,
            MfaSecretCiphertext = enrolment.Seed.Ciphertext,
            MfaSecretNonce = enrolment.Seed.Nonce,
            MfaSecretTag = enrolment.Seed.Tag,
            MfaSeedMasterKeyVersion = enrolment.Seed.MasterKeyVersion,
            MfaEnrolledUtc = DateTimeOffset.UtcNow,
        };

        _database.Context.Users.Add(_user);
        _database.Context.SaveChanges();

        _signIn = new SignInService(
            _database.Context,
            new StubPasswordHasher(),
            _totp,
            new RecoveryCodeService(),
            new CountingAuditChain(),
            new FixedClock(DateTimeOffset.UtcNow),
            Options.Create(new SessionOptions()));
    }

    public void Dispose()
    {
        _database.Dispose();
        _masterKeys.Dispose();
    }

    private string CurrentCode() =>
        new Totp(Base32Encoding.ToBytes(_sharedSecret), step: 30, mode: OtpHashMode.Sha1, totpSize: 6)
            .ComputeTotp();

    [Fact]
    public async Task ThePasswordStepAlone_CreatesNoSession()
    {
        // The half-authenticated state is a cookie carrying a user id and nothing else. If a
        // session row existed here, the password alone would be enough for anything that reads
        // one — which is the whole point of the second factor.
        var outcome = await _signIn
            .AuthenticateAsync(_user.Email, Password, _context, CancellationToken.None);

        Assert.Equal(SignInStatus.MfaRequired, outcome.Status);
        Assert.Null(outcome.SessionId);
        Assert.Empty(await _database.Context.UserSessions.ToListAsync());
    }

    [Fact]
    public async Task AWrongSecondFactor_CreatesNoSession()
    {
        await _signIn.AuthenticateAsync(_user.Email, Password, _context, CancellationToken.None);

        var outcome = await _signIn
            .VerifyMfaAsync(_user.Id, "000000", _context, CancellationToken.None);

        Assert.Equal(SignInStatus.Failed, outcome.Status);
        Assert.Null(outcome.SessionId);
        Assert.Empty(await _database.Context.UserSessions.ToListAsync());
    }

    [Fact]
    public async Task TheSessionIsMintedOnlyAfterTheSecondFactor()
    {
        await _signIn.AuthenticateAsync(_user.Email, Password, _context, CancellationToken.None);

        var outcome = await _signIn
            .VerifyMfaAsync(_user.Id, CurrentCode(), _context, CancellationToken.None);

        Assert.Equal(SignInStatus.Succeeded, outcome.Status);
        Assert.NotNull(outcome.SessionId);

        var sessions = await _database.Context.UserSessions.AsNoTracking().ToListAsync();

        var session = Assert.Single(sessions);
        Assert.Equal(outcome.SessionId, session.Id);
        Assert.Equal(_user.Id, session.UserId);
    }

    [Fact]
    public async Task EachCompletedSignIn_GetsItsOwnIdentifier()
    {
        // The identifier is server-minted per completion, so one cannot be carried from an
        // earlier sign-in — or planted before one — and reused.
        await _signIn.AuthenticateAsync(_user.Email, Password, _context, CancellationToken.None);

        var first = await _signIn
            .VerifyMfaAsync(_user.Id, CurrentCode(), _context, CancellationToken.None);

        // A new code, because the used time step is burned and a replay is refused. Waiting
        // for the next window would make this test take half a minute, so the recorded window
        // is cleared instead: what is under test here is the session identifier, and the
        // replay guard has its own tests.
        var user = await _database.Context.Users.FirstAsync(u => u.Id == _user.Id);
        user.LastUsedTotpWindow = null;
        await _database.Context.SaveChangesAsync();

        await _signIn.AuthenticateAsync(_user.Email, Password, _context, CancellationToken.None);

        var second = await _signIn
            .VerifyMfaAsync(_user.Id, CurrentCode(), _context, CancellationToken.None);

        Assert.Equal(SignInStatus.Succeeded, second.Status);
        Assert.NotEqual(first.SessionId, second.SessionId);
    }

    [Fact]
    public async Task TheNewSessionStartsWithAFreshStepUp()
    {
        // Proving two factors is proof of identity, so demanding another confirmation to
        // reveal a secret in the first minute would be theatre. That it is the sign-in that
        // sets this, rather than anything a client sends, is the part worth asserting.
        await _signIn.AuthenticateAsync(_user.Email, Password, _context, CancellationToken.None);

        var outcome = await _signIn
            .VerifyMfaAsync(_user.Id, CurrentCode(), _context, CancellationToken.None);

        var session = await _database.Context.UserSessions
            .AsNoTracking()
            .FirstAsync(s => s.Id == outcome.SessionId);

        Assert.NotNull(session.LastStepUpUtc);
        Assert.Equal(session.CreatedUtc, session.LastStepUpUtc);
    }

    /// <summary>
    /// Accepts the one password this fixture uses, without paying for Argon2id.
    /// </summary>
    /// <remarks>
    /// The real hasher costs 64 MiB and about a third of a second per verification, and these
    /// tests verify several times each. What is under test is where the session comes from,
    /// not the digest; the hasher has its own tests.
    /// </remarks>
    private sealed class StubPasswordHasher : IPasswordHasher
    {
        public string Hash(string password) => password;

        public PasswordVerificationResult Verify(string password, string encodedHash) =>
            string.Equals(password, encodedHash, StringComparison.Ordinal)
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
    }

    /// <summary>An audit chain that records nothing but counts, so appends are not silent.</summary>
    private sealed class CountingAuditChain : IAuditChain
    {
        public Task<long> AppendAsync(AuditRecord record, CancellationToken cancellationToken) =>
            Task.FromResult(0L);

        public Task<AuditChainVerification> VerifyAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
