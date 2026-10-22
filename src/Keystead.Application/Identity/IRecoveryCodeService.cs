using System.Collections.Generic;

namespace Keystead.Application.Identity;

/// <summary>Issues and verifies single-use MFA recovery codes.</summary>
public interface IRecoveryCodeService
{
    /// <summary>How many codes are issued at enrolment.</summary>
    int CodesPerUser { get; }

    /// <summary>Generates a fresh set of codes.</summary>
    /// <returns>
    /// The plaintext codes, to show the user exactly once, each paired with the hash to store.
    /// </returns>
    IReadOnlyList<GeneratedRecoveryCode> Generate();

    /// <summary>Hashes a submitted code so it can be compared against stored hashes.</summary>
    /// <param name="code">The submitted code, in any casing or with separators.</param>
    /// <returns>The hash to compare, or null when the input cannot be a valid code.</returns>
    byte[]? HashForComparison(string code);

    /// <summary>Compares two code hashes in fixed time.</summary>
    /// <param name="candidate">The hash of the submitted code.</param>
    /// <param name="stored">A stored hash.</param>
    /// <returns><see langword="true"/> when they match.</returns>
    bool Matches(byte[] candidate, byte[] stored);
}
