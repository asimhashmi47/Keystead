using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using Keystead.Application.Identity;
using Microsoft.Extensions.Options;

namespace Keystead.Infrastructure.Identity;

/// <summary>
/// Enforces the installation's password requirements.
/// </summary>
/// <remarks>
/// <para>
/// Length and uniqueness, not composition rules. There is no "must contain a symbol"
/// requirement, because that reliably produces <c>Password1!</c> and nothing better: the user
/// satisfies the rule in the most predictable way available. A long passphrase checked against
/// a deny list is both stronger and easier to remember.
/// </para>
/// <para>
/// Four checks, in increasing cost: length, then variety, then containment of the account's own
/// identifiers, then the deny list.
/// </para>
/// </remarks>
public sealed class PasswordPolicy : IPasswordPolicy
{
    private const string ResourceName = "Keystead.Infrastructure.Identity.CommonPasswords.txt";

    private static readonly Lazy<HashSet<string>> DenyList = new(Load, isThreadSafe: true);

    private readonly PasswordPolicyOptions _options;

    /// <summary>Creates the policy.</summary>
    /// <param name="options">The configured requirements.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    public PasswordPolicy(IOptions<PasswordPolicyOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
    }

    /// <inheritdoc />
    public int MinimumLength => _options.MinimumLength;

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
    public PasswordPolicyResult Check(string password, string? email)
    {
        ArgumentNullException.ThrowIfNull(password);

        if (password.Length < _options.MinimumLength)
        {
            return PasswordPolicyResult.Rejected(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Use at least {_options.MinimumLength} characters. A long passphrase is stronger than a short complicated one."));
        }

        if (password.Length > _options.MaximumLength)
        {
            // An upper bound exists only to stop a megabyte of input being fed through
            // Argon2id, which would be a cheap way to exhaust server memory.
            return PasswordPolicyResult.Rejected(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"Use at most {_options.MaximumLength} characters."));
        }

        var lowered = password.ToLowerInvariant();

        if (IsSingleRepeatedCharacter(password))
        {
            return PasswordPolicyResult.Rejected(
                "That is one character repeated. Use a passphrase of several unrelated words.");
        }

        if (IsSequentialRun(lowered))
        {
            return PasswordPolicyResult.Rejected(
                "That is a sequence of consecutive characters. Use a passphrase of several unrelated words.");
        }

        if (ContainsAccountIdentifier(lowered, email))
        {
            return PasswordPolicyResult.Rejected(
                "Do not include your email address or name in your password.");
        }

        if (DenyList.Value.Contains(lowered))
        {
            return PasswordPolicyResult.Rejected(
                "That password appears in lists of commonly used passwords. Choose something unrelated to it.");
        }

        return PasswordPolicyResult.Acceptable;
    }

    private static bool IsSingleRepeatedCharacter(string password)
    {
        for (var i = 1; i < password.Length; i++)
        {
            if (password[i] != password[0])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Whether the whole password is one ascending or descending run, such as
    /// <c>abcdefghijkl</c>, <c>987654321098</c> or <c>123456789012345</c>.
    /// </summary>
    /// <remarks>
    /// Digit-only input is additionally checked modulo 10. A plain character-delta check misses
    /// <c>123456789012345</c>, because the run appears to break at the 9-to-0 wrap, and that is
    /// exactly the shape someone produces when they hold a number row down past the end.
    /// </remarks>
    private static bool IsSequentialRun(string lowered)
    {
        if (lowered.Length < 4)
        {
            return false;
        }

        if (IsRunWithDelta(lowered, modulus: null))
        {
            return true;
        }

        // Only meaningful for digits: wrapping 'z' to 'a' is not a pattern anyone types.
        return lowered.All(char.IsAsciiDigit) && IsRunWithDelta(lowered, modulus: 10);
    }

    private static bool IsRunWithDelta(string value, int? modulus)
    {
        var ascending = true;
        var descending = true;

        for (var i = 1; i < value.Length; i++)
        {
            var delta = value[i] - value[i - 1];

            if (modulus is { } m)
            {
                // Normalise into [0, m) so that 9 to 0 reads as +1 rather than -9.
                delta = ((delta % m) + m) % m;
            }

            var step = modulus is { } mod ? mod : 0;

            if (delta != 1)
            {
                ascending = false;
            }

            if (delta != (modulus is null ? -1 : step - 1))
            {
                descending = false;
            }

            if (!ascending && !descending)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Whether the password contains the email, its local part, or a domain-free fragment of it.
    /// </summary>
    /// <remarks>
    /// A password built from the account it protects is worthless against anyone who knows the
    /// account, which is everyone who has seen a member list.
    /// </remarks>
    private static bool ContainsAccountIdentifier(string lowered, string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }

        var normalisedEmail = email.Trim().ToLowerInvariant();

        if (lowered.Contains(normalisedEmail, StringComparison.Ordinal))
        {
            return true;
        }

        var at = normalisedEmail.IndexOf('@', StringComparison.Ordinal);

        if (at <= 0)
        {
            return false;
        }

        var localPart = normalisedEmail[..at];

        // Only worth checking if the local part is long enough to carry meaning. Refusing a
        // password because it happens to contain "jo" would be noise.
        return localPart.Length >= 4
            && lowered.Contains(localPart, StringComparison.Ordinal);
    }

    private static HashSet<string> Load()
    {
        var set = new HashSet<string>(StringComparer.Ordinal);

        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName);

        if (stream is null)
        {
            // Fail loudly rather than silently accepting every password. A deny list that
            // quietly became empty is worse than no deny list, because the security centre
            // would still report the check as active.
            throw new InvalidOperationException(
                $"The embedded password deny list '{ResourceName}' is missing from the assembly.");
        }

        using var reader = new StreamReader(stream);
        string? line;

        while ((line = reader.ReadLine()) is not null)
        {
            var trimmed = line.Trim();

            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
            {
                continue;
            }

            set.Add(trimmed.ToLowerInvariant());
        }

        return set;
    }
}
