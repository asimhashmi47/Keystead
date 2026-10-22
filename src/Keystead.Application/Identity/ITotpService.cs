using System;

namespace Keystead.Application.Identity;

/// <summary>Generates and verifies time-based one-time passwords.</summary>
public interface ITotpService
{
    /// <summary>Creates a new enrolment: a fresh seed, its sealed form, and the display data.</summary>
    /// <param name="userId">The user enrolling, bound into the seal as AAD.</param>
    /// <param name="accountLabel">The label shown in the authenticator app, normally the email.</param>
    /// <returns>The enrolment, whose plaintext secret is shown exactly once.</returns>
    TotpEnrolment CreateEnrolment(Guid userId, string accountLabel);

    /// <summary>Verifies a submitted code against a stored seed.</summary>
    /// <param name="userId">The user the seed belongs to, checked as AAD.</param>
    /// <param name="seed">The stored sealed seed.</param>
    /// <param name="code">The submitted six-digit code.</param>
    /// <param name="lastUsedWindow">
    /// The highest time step this user has already consumed, or null if none. A code at or
    /// below it is rejected as a replay.
    /// </param>
    /// <returns>The outcome, including the window to record on success.</returns>
    TotpVerification Verify(Guid userId, StoredTotpSeed seed, string code, long? lastUsedWindow);
}
