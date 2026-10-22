using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;

namespace Keystead.Web.Security;

/// <summary>
/// Scrubs sensitive values out of log events before they reach a sink.
/// </summary>
/// <remarks>
/// <para>
/// This is a backstop, not the primary control. The primary control is that secret plaintext
/// is never passed to a logger in the first place (CLAUDE.md rule 5). An enricher cannot
/// recognise an arbitrary secret value by looking at it: a password really can be the string
/// "hello". So this catches the two cases that <em>are</em> recognisable, and nothing else:
/// </para>
/// <list type="number">
/// <item>a property whose <em>name</em> says it holds a credential, and</item>
/// <item>a value matching Keystead's own token format, which is self-identifying by design.</item>
/// </list>
/// <para>
/// Treating this as a safety net rather than a solution is the honest reading. The test that
/// matters is the one asserting a known secret value never reaches the sink at all.
/// </para>
/// </remarks>
public sealed partial class SecretRedactionEnricher : ILogEventEnricher
{
    /// <summary>The text substituted for a redacted value.</summary>
    public const string Placeholder = "[redacted]";

    private static readonly HashSet<string> SensitiveNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "secretvalue",
        "clientsecret",
        "client_secret",
        "token",
        "accesstoken",
        "access_token",
        "refreshtoken",
        "bearer",
        "authorization",
        "apikey",
        "api_key",
        "masterkey",
        "master_key",
        "kek",
        "dek",
        "plaintext",
        "value",
        "connectionstring",
        "totpsecret",
        "recoverycode",
        "pepper",
    };

    // Keystead's own credential format, which announces itself: ksd_live_<base32>_<checksum>.
    // A one-second timeout guards against a pathological input causing a ReDoS stall, as
    // required by section 5 of the specification.
    [GeneratedRegex(
        @"ksd_(live|test)_[A-Za-z0-9]{8,}",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex TokenPattern();

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(propertyFactory);

        foreach (var (name, value) in logEvent.Properties)
        {
            if (SensitiveNames.Contains(name))
            {
                logEvent.AddOrUpdateProperty(
                    new LogEventProperty(name, new ScalarValue(Placeholder)));
                continue;
            }

            if (value is ScalarValue { Value: string text } && ContainsToken(text))
            {
                logEvent.AddOrUpdateProperty(
                    new LogEventProperty(name, new ScalarValue(Scrub(text))));
            }
        }
    }

    /// <summary>Whether the text contains something shaped like a Keystead token.</summary>
    /// <param name="text">The text to inspect.</param>
    /// <returns><see langword="true"/> when a token-shaped substring is present.</returns>
    public static bool ContainsToken(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        try
        {
            return TokenPattern().IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            // Fail closed: if the pattern could not finish, assume the worst and redact.
            return true;
        }
    }

    /// <summary>Replaces token-shaped substrings with the placeholder.</summary>
    /// <param name="text">The text to scrub.</param>
    /// <returns>The text with any token-shaped substring replaced.</returns>
    public static string Scrub(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        try
        {
            return TokenPattern().Replace(text, Placeholder);
        }
        catch (RegexMatchTimeoutException)
        {
            return Placeholder;
        }
    }
}
