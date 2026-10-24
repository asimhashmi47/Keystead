using System;

namespace Keystead.Client;

/// <summary>
/// Translates a Keystead secret name into a .NET configuration key.
/// </summary>
/// <remarks>
/// <para>
/// A configuration key uses <c>:</c> as its section separator, which is not a character anyone
/// wants in a URL path or a shell variable. The convention, shared with the other
/// configuration providers people already use, is that <c>--</c> and <c>__</c> both stand in
/// for it. So the secret <c>ConnectionStrings--Default</c> binds to
/// <c>ConnectionStrings:Default</c>, and an application reads it with
/// <c>configuration.GetConnectionString("Default")</c> without knowing Keystead exists.
/// </para>
/// <para>
/// The double-underscore form is the one the .NET environment-variable provider uses, so a
/// secret can be moved from an environment variable into Keystead without renaming it.
/// </para>
/// </remarks>
public static class SecretKeyMapping
{
    /// <summary>
    /// Converts a secret name to a configuration key.
    /// </summary>
    /// <param name="secretName">The secret's name.</param>
    /// <param name="keyPrefix">An optional prefix to strip first.</param>
    /// <returns>The configuration key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secretName"/> is null.</exception>
    public static string ToConfigurationKey(string secretName, string? keyPrefix = null)
    {
        ArgumentNullException.ThrowIfNull(secretName);

        var name = secretName;

        if (!string.IsNullOrEmpty(keyPrefix)
            && name.StartsWith(keyPrefix, StringComparison.OrdinalIgnoreCase))
        {
            name = name[keyPrefix.Length..];
        }

        // Double underscore first. Otherwise a name containing "__" would be partly consumed
        // by the "--" pass and leave a stray separator behind.
        return name
            .Replace("__", ":", StringComparison.Ordinal)
            .Replace("--", ":", StringComparison.Ordinal)
            .Trim(':');
    }

    /// <summary>
    /// Converts a configuration key back to the secret name convention.
    /// </summary>
    /// <remarks>
    /// Used by the CLI so that <c>keystead secret get ConnectionStrings:Default</c> finds a
    /// secret stored as <c>ConnectionStrings--Default</c>. Always emits the <c>--</c> form,
    /// because a round trip cannot know which of the two the name originally used.
    /// </remarks>
    /// <param name="configurationKey">The configuration key.</param>
    /// <returns>The secret name.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="configurationKey"/> is null.</exception>
    public static string ToSecretName(string configurationKey)
    {
        ArgumentNullException.ThrowIfNull(configurationKey);

        return configurationKey.Replace(":", "--", StringComparison.Ordinal);
    }

    /// <summary>
    /// Converts a secret name into an environment variable name, for <c>keystead run</c>.
    /// </summary>
    /// <remarks>
    /// Upper-cased with the separator as a double underscore, which is what the .NET
    /// environment-variable provider reads and what most other runtimes tolerate. A name with
    /// characters a shell cannot carry is skipped by the caller rather than mangled.
    /// </remarks>
    /// <param name="secretName">The secret's name.</param>
    /// <returns>The environment variable name.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secretName"/> is null.</exception>
    public static string ToEnvironmentVariable(string secretName)
    {
        ArgumentNullException.ThrowIfNull(secretName);

        return ToConfigurationKey(secretName)
            .Replace(":", "__", StringComparison.Ordinal)
            .ToUpperInvariant();
    }

    /// <summary>
    /// Whether a name can be carried safely as an environment variable.
    /// </summary>
    /// <param name="secretName">The secret's name.</param>
    /// <returns><see langword="true"/> when the mapped name is a usable variable name.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secretName"/> is null.</exception>
    public static bool CanBeEnvironmentVariable(string secretName)
    {
        ArgumentNullException.ThrowIfNull(secretName);

        var mapped = ToEnvironmentVariable(secretName);

        if (mapped.Length == 0 || char.IsAsciiDigit(mapped[0]))
        {
            return false;
        }

        foreach (var character in mapped)
        {
            if (!char.IsAsciiLetterUpper(character)
                && !char.IsAsciiDigit(character)
                && character != '_')
            {
                return false;
            }
        }

        return true;
    }
}
