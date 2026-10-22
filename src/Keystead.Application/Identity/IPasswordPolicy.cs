namespace Keystead.Application.Identity;

/// <summary>Checks that a password meets the installation's requirements.</summary>
public interface IPasswordPolicy
{
    /// <summary>The shortest password accepted.</summary>
    int MinimumLength { get; }

    /// <summary>Evaluates a candidate password.</summary>
    /// <param name="password">The proposed password.</param>
    /// <param name="email">The account email, so a password containing it can be refused.</param>
    /// <returns>The outcome, with a reason when it fails.</returns>
    PasswordPolicyResult Check(string password, string? email);
}
