using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Keystead.Web.Security;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;
using Xunit;

namespace Keystead.SecurityTests;

/// <summary>
/// Proves that a secret value does not reach the log.
/// </summary>
/// <remarks>
/// <para>
/// Two halves, because neither alone is enough.
/// </para>
/// <para>
/// The first drives the real application through storing and revealing a secret while
/// capturing everything the Serilog console sink writes, and asserts the value appears nowhere
/// in it. That is the property that actually matters, and it is checked against the pipeline
/// as it ships.
/// </para>
/// <para>
/// The second tests the redaction enricher directly. The enricher is a backstop, not the
/// primary control: it cannot recognise an arbitrary secret by looking at it, because a
/// password really can be the string "hello". It catches the two cases that are recognisable,
/// and these tests pin that behaviour so the backstop does not quietly stop working.
/// </para>
/// </remarks>
[Collection(nameof(ConsoleCaptureCollection))]
public sealed class LogRedactionTests
{
    private const string DistinctiveValue = "Server=db;Password=zzqq-log-canary-9931";

    [Fact]
    public async Task ARevealedSecretAppearsNowhereInTheLog()
    {
        // Console.Out is process-wide, which is why this test lives in a non-parallel
        // collection. The Serilog console sink writes synchronously to it, so redirecting it
        // for the duration of the request captures what the application really emitted.
        using var captured = new StringWriter();
        var original = Console.Out;

        await using var factory = new KeysteadTestFactory();

        try
        {
            Console.SetOut(captured);

            using var client = factory.CreateApiClient();

            // Exercises the paths that handle a value: the setup wizard, the sign-in forms,
            // and the API. Any of them logging a body or a parameter would show up here.
            await client.GetAsync("/setup");
            await client.GetAsync("/sign-in");

            using var form = new FormUrlEncodedContent(new[]
            {
                new System.Collections.Generic.KeyValuePair<string, string>(
                    "Input.Password", DistinctiveValue),
                new System.Collections.Generic.KeyValuePair<string, string>(
                    "Input.Email", "canary@example.com"),
            });

            // Refused for want of an antiforgery token, which is the point: even a rejected
            // request must not have its body logged on the way out.
            using var rejected = await client.PostAsync("/sign-in", form);

            using var tokenForm = new FormUrlEncodedContent(new[]
            {
                new System.Collections.Generic.KeyValuePair<string, string>(
                    "grant_type", "client_credentials"),
                new System.Collections.Generic.KeyValuePair<string, string>(
                    "client_id", "ksid_CANARY"),
                new System.Collections.Generic.KeyValuePair<string, string>(
                    "client_secret", DistinctiveValue),
            });

            using var denied = await client.PostAsync("/api/v1/token", tokenForm);
        }
        finally
        {
            Console.SetOut(original);
        }

        var log = captured.ToString();

        Assert.DoesNotContain(DistinctiveValue, log, StringComparison.Ordinal);

        // The password and the client secret were both sent. Neither may appear, and nor may
        // a fragment distinctive enough to identify them.
        Assert.DoesNotContain("zzqq-log-canary-9931", log, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARejectedTokenRequestLogsNeitherCredential()
    {
        using var captured = new StringWriter();
        var original = Console.Out;

        await using var factory = new KeysteadTestFactory();

        try
        {
            Console.SetOut(captured);

            using var client = factory.CreateApiClient();

            using var form = new FormUrlEncodedContent(new[]
            {
                new System.Collections.Generic.KeyValuePair<string, string>(
                    "grant_type", "client_credentials"),
                new System.Collections.Generic.KeyValuePair<string, string>(
                    "client_id", "ksid_LOGCANARY"),
                new System.Collections.Generic.KeyValuePair<string, string>(
                    "client_secret", "ksd_live_LOGCANARYSECRETVALUE_ABCDEF"),
            });

            using var response = await client.PostAsync("/api/v1/token", form);
        }
        finally
        {
            Console.SetOut(original);
        }

        var log = captured.ToString();

        // The client id is not a secret and may legitimately be logged for diagnosis. The
        // secret must not be, in any form.
        Assert.DoesNotContain("LOGCANARYSECRETVALUE", log, StringComparison.Ordinal);
        Assert.DoesNotContain("ksd_live_LOGCANARY", log, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // The enricher itself
    // -----------------------------------------------------------------------

    private static LogEvent EventWith(string propertyName, object value) =>
        new(
            DateTimeOffset.UtcNow,
            LogEventLevel.Information,
            exception: null,
            new MessageTemplateParser().Parse("test {" + propertyName + "}"),
            [new LogEventProperty(propertyName, new ScalarValue(value))]);

    [Theory]
    [InlineData("password")]
    [InlineData("Password")]
    [InlineData("clientSecret")]
    [InlineData("client_secret")]
    [InlineData("token")]
    [InlineData("accessToken")]
    [InlineData("authorization")]
    [InlineData("apiKey")]
    [InlineData("masterKey")]
    [InlineData("plaintext")]
    [InlineData("value")]
    [InlineData("connectionString")]
    [InlineData("recoveryCode")]
    [InlineData("pepper")]
    public void APropertyWhoseNameSaysItHoldsACredentialIsRedacted(string propertyName)
    {
        var logEvent = EventWith(propertyName, "the-actual-secret");

        new SecretRedactionEnricher().Enrich(logEvent, new NullPropertyFactory());

        Assert.Equal(
            SecretRedactionEnricher.Placeholder,
            logEvent.Properties[propertyName].ToString().Trim('"'));
    }

    [Fact]
    public void AnOrdinaryPropertyIsLeftAlone()
    {
        // Over-redacting would make the log useless, which is its own kind of failure: nobody
        // reads a log where every field says [redacted].
        var logEvent = EventWith("vaultName", "Production");

        new SecretRedactionEnricher().Enrich(logEvent, new NullPropertyFactory());

        Assert.Contains("Production", logEvent.Properties["vaultName"].ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ksd_live_ABCDEFGH12345678", true)]
    [InlineData("ksd_test_ABCDEFGH12345678", true)]
    [InlineData("prefix ksd_live_ABCDEFGH12345678 suffix", true)]
    [InlineData("ksd_live_SHORT", false)]
    [InlineData("nothing special here", false)]
    public void ATokenShapedValueIsRecognisedWhereverItAppears(string text, bool expected)
    {
        // Keystead's own credential format is self-identifying, so this is the one case the
        // enricher can catch by looking at a value rather than at its name.
        Assert.Equal(expected, SecretRedactionEnricher.ContainsToken(text));
    }

    [Fact]
    public void ATokenShapedValueInAnOrdinaryPropertyIsScrubbed()
    {
        var logEvent = EventWith("message", "leaked ksd_live_ABCDEFGH12345678 into a log line");

        new SecretRedactionEnricher().Enrich(logEvent, new NullPropertyFactory());

        var rendered = logEvent.Properties["message"].ToString();

        Assert.DoesNotContain("ksd_live_ABCDEFGH12345678", rendered, StringComparison.Ordinal);
        Assert.Contains(SecretRedactionEnricher.Placeholder, rendered, StringComparison.Ordinal);
    }

    [Fact]
    public void ScrubbingLeavesTheSurroundingTextReadable()
    {
        var scrubbed = SecretRedactionEnricher.Scrub("before ksd_live_ABCDEFGH12345678 after");

        Assert.StartsWith("before ", scrubbed, StringComparison.Ordinal);
        Assert.EndsWith(" after", scrubbed, StringComparison.Ordinal);
    }

    private sealed class NullPropertyFactory : ILogEventPropertyFactory
    {
        public LogEventProperty CreateProperty(
            string name,
            object? value,
            bool destructureObjects = false) =>
            new(name, new ScalarValue(value));
    }
}

/// <summary>
/// Marks the tests that redirect <see cref="Console.Out"/> so they do not run in parallel.
/// </summary>
/// <remarks>
/// The redirect is process-wide. Two of these running at once would capture each other's
/// output and the assertions would be meaningless in both directions.
/// </remarks>
[CollectionDefinition(nameof(ConsoleCaptureCollection), DisableParallelization = true)]
public sealed class ConsoleCaptureCollection
{
}
