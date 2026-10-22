using System;
using Keystead.Domain.Identity;
using Xunit;

namespace Keystead.Tests.Identity;

/// <summary>
/// The progressive lockout and session lifetime rules, tested as pure domain logic against a
/// clock the test controls. A test that had to sleep for thirty minutes would never be run.
/// </summary>
public sealed class LockoutAndSessionTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static User NewUser() => new()
    {
        Id = Guid.CreateVersion7(),
        Email = "ada@example.com",
        DisplayName = "Ada",
        PasswordHash = "digest",
        PasswordChangedUtc = Now,
        FailedSignInCount = 0,
        CreatedUtc = Now,
        IsActive = true,
    };

    [Fact]
    public void TheFirstTwoFailures_DoNotLockTheAccount()
    {
        // A locked account after one typo would be a self-inflicted denial of service, and
        // would also hand an attacker a trivial way to lock any account they can name.
        var user = NewUser();

        user.RegisterFailedSignIn(Now);
        user.RegisterFailedSignIn(Now);

        Assert.False(user.IsLockedOut(Now));
        Assert.Equal(2, user.FailedSignInCount);
    }

    [Theory]
    [InlineData(3, 5)]
    [InlineData(4, 5)]
    [InlineData(5, 30)]
    [InlineData(6, 30)]
    public void FailuresThreeToSix_LockForSecondsNotMinutes(int failures, int expectedSeconds)
    {
        var user = NewUser();

        for (var i = 0; i < failures; i++)
        {
            user.RegisterFailedSignIn(Now);
        }

        Assert.True(user.IsLockedOut(Now));
        Assert.Equal(Now.AddSeconds(expectedSeconds), user.LockoutEndUtc);
    }

    [Theory]
    [InlineData(7, 5)]
    [InlineData(9, 5)]
    [InlineData(10, 30)]
    [InlineData(25, 30)]
    public void SustainedFailures_EscalateToMinutes(int failures, int expectedMinutes)
    {
        // The escalation is what makes an online guessing attack uneconomic: by the tenth
        // attempt the attacker is limited to two guesses an hour.
        var user = NewUser();

        for (var i = 0; i < failures; i++)
        {
            user.RegisterFailedSignIn(Now);
        }

        Assert.Equal(Now.AddMinutes(expectedMinutes), user.LockoutEndUtc);
    }

    [Fact]
    public void TheLockoutExpires_OnItsOwn()
    {
        var user = NewUser();

        for (var i = 0; i < 5; i++)
        {
            user.RegisterFailedSignIn(Now);
        }

        Assert.True(user.IsLockedOut(Now));
        Assert.False(user.IsLockedOut(Now.AddSeconds(31)));
    }

    [Fact]
    public void ASuccessfulSignIn_ClearsTheCounterAndTheLockout()
    {
        var user = NewUser();

        for (var i = 0; i < 12; i++)
        {
            user.RegisterFailedSignIn(Now);
        }

        user.RegisterSuccessfulSignIn();

        Assert.Equal(0, user.FailedSignInCount);
        Assert.Null(user.LockoutEndUtc);
        Assert.False(user.IsLockedOut(Now));
    }

    [Fact]
    public void MfaIsNotEnabled_WithoutBothTheSeedAndTheEnrolmentTimestamp()
    {
        // Half-enrolled must count as not enrolled. If a seed were written but enrolment never
        // completed, treating MFA as active would lock the user out of their own account.
        var user = NewUser();

        Assert.False(user.MfaEnabled);

        user.MfaSecretCiphertext = new byte[32];
        Assert.False(user.MfaEnabled);

        user.MfaEnrolledUtc = Now;
        Assert.True(user.MfaEnabled);
    }

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------

    private static UserSession NewSession(
        DateTimeOffset created,
        DateTimeOffset? absoluteExpiry = null) => new()
    {
        Id = Guid.CreateVersion7(),
        UserId = Guid.CreateVersion7(),
        CreatedUtc = created,
        LastSeenUtc = created,
        AbsoluteExpiryUtc = absoluteExpiry ?? created.AddHours(12),
        CreatedIp = "203.0.113.4",
        UserAgent = "test",
    };

    [Fact]
    public void AFreshSession_IsActive()
    {
        var session = NewSession(Now);

        Assert.True(session.IsActive(Now, TimeSpan.FromMinutes(30)));
    }

    [Fact]
    public void AnIdleSession_StopsBeingActive()
    {
        var session = NewSession(Now);

        Assert.True(session.IsActive(Now.AddMinutes(29), TimeSpan.FromMinutes(30)));
        Assert.False(session.IsActive(Now.AddMinutes(31), TimeSpan.FromMinutes(30)));
    }

    [Fact]
    public void ASessionInConstantUse_StillEndsAtItsAbsoluteExpiry()
    {
        // This is the point of the absolute bound. The session below is touched continuously,
        // so the idle timeout never fires; without the absolute expiry a cookie stolen from an
        // always-open browser would last forever.
        var session = NewSession(Now, absoluteExpiry: Now.AddHours(12));

        session.LastSeenUtc = Now.AddHours(13);

        Assert.False(session.IsActive(Now.AddHours(13), TimeSpan.FromMinutes(30)));
    }

    [Fact]
    public void ARevokedSession_IsImmediatelyInactive()
    {
        var session = NewSession(Now);
        session.RevokedUtc = Now;

        Assert.False(session.IsActive(Now, TimeSpan.FromMinutes(30)));
    }

    [Fact]
    public void StepUpFreshness_ExpiresWithItsWindow()
    {
        var session = NewSession(Now);
        session.LastStepUpUtc = Now;

        Assert.True(session.HasFreshStepUp(Now.AddMinutes(4), TimeSpan.FromMinutes(5)));
        Assert.False(session.HasFreshStepUp(Now.AddMinutes(6), TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void ASessionThatNeverSteppedUp_HasNoFreshStepUp()
    {
        var session = NewSession(Now);

        Assert.False(session.HasFreshStepUp(Now, TimeSpan.FromMinutes(5)));
    }
}
