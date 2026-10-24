using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keystead.Web;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;
using OtpNet;

namespace Keystead.IntegrationTests;

/// <summary>
/// The real application, hosted in memory, with helpers for driving it as a browser would.
/// </summary>
/// <remarks>
/// Deliberately a thin wrapper rather than a fixture that pre-seeds the database directly.
/// These tests are about the flows: an installation that was set up through the wizard, a user
/// who signed in through the forms, and a token obtained from the real endpoint. Seeding rows
/// behind the pipeline would skip exactly the code under test.
/// </remarks>
public sealed class KeysteadApp : WebApplicationFactory<Program>
{
    private readonly string _root;

    /// <summary>Creates the application with an isolated database and master key.</summary>
    public KeysteadApp()
    {
        _root = Path.Combine(
            Path.GetTempPath(),
            "keystead-integration",
            Guid.CreateVersion7().ToString("N"));

        Directory.CreateDirectory(_root);
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }

    /// <summary>The base64 master key this instance was started with.</summary>
    public string MasterKey { get; }

    /// <summary>The password the setup wizard was driven with.</summary>
    public const string OwnerPassword = "thistle harbour velvet onion";

    /// <summary>The owner's email address.</summary>
    public const string OwnerEmail = "owner@example.com";

    /// <summary>The TOTP shared secret, once the owner has enrolled.</summary>
    public string? SharedSecret { get; private set; }

    /// <summary>The recovery codes issued at enrolment, each usable once.</summary>
    public IReadOnlyList<string> RecoveryCodes { get; private set; } = [];

    /// <summary>Creates a client that keeps cookies and does not follow redirects.</summary>
    /// <returns>The client.</returns>
    public HttpClient CreateBrowser() =>
        CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true,
        });

    /// <summary>Creates a client with no cookies, as an application would use.</summary>
    /// <returns>The client.</returns>
    public HttpClient CreateMachine() =>
        CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false,
        });

    /// <inheritdoc />
    protected override IHost CreateHost(IHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        Environment.SetEnvironmentVariable("KEYSTEAD_MASTER_KEY", MasterKey);
        Environment.SetEnvironmentVariable("Keystead__MasterKey__Source", "Environment");
        Environment.SetEnvironmentVariable(
            "Keystead__Database__Path",
            Path.Combine(_root, "keystead.db"));
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");

        return base.CreateHost(builder);
    }

    /// <summary>Reads the antiforgery token out of a rendered page.</summary>
    /// <param name="html">The page body.</param>
    /// <returns>The token, or null when the page carried none.</returns>
    public static string? AntiforgeryToken(string html)
    {
        ArgumentNullException.ThrowIfNull(html);

        var match = Regex.Match(
            html,
            @"name=""__keystead-csrf""[^>]*value=""([^""]+)""",
            RegexOptions.None,
            TimeSpan.FromSeconds(1));

        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>Posts a form with the antiforgery token taken from a page first fetched.</summary>
    /// <param name="client">The client to use.</param>
    /// <param name="path">Where to post.</param>
    /// <param name="fields">The form fields.</param>
    /// <param name="tokenFrom">The page to read the token from, or null to use <paramref name="path"/>.</param>
    /// <returns>The response.</returns>
    public static async Task<HttpResponseMessage> PostFormAsync(
        HttpClient client,
        string path,
        IDictionary<string, string> fields,
        string? tokenFrom = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(fields);

        using var page = await client.GetAsync(tokenFrom ?? path);
        var token = AntiforgeryToken(await page.Content.ReadAsStringAsync());

        var body = new Dictionary<string, string>(fields, StringComparer.Ordinal);

        if (token is not null)
        {
            body["__keystead-csrf"] = token;
        }

        using var content = new FormUrlEncodedContent(body);

        return await client.PostAsync(path, content);
    }

    /// <summary>Runs the first-run wizard.</summary>
    /// <param name="client">The browser client.</param>
    /// <returns>A task that completes when the installation exists.</returns>
    public static async Task SetUpAsync(HttpClient client)
    {
        using var response = await PostFormAsync(client, "/setup", new Dictionary<string, string>
        {
            ["Input.WorkspaceName"] = "Integration",
            ["Input.DisplayName"] = "Owner",
            ["Input.Email"] = OwnerEmail,
            ["Input.Password"] = OwnerPassword,
            ["Input.ConfirmPassword"] = OwnerPassword,
        });

        _ = response.EnsureSuccessStatusCode();
    }

    /// <summary>Enrols the owner in TOTP, which their role makes mandatory.</summary>
    /// <param name="client">The browser client, already past the password step.</param>
    /// <returns>The shared secret.</returns>
    public async Task<string> EnrolMfaAsync(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);

        using var page = await client.GetAsync("/mfa/enrol");
        var html = await page.Content.ReadAsStringAsync();

        var secret = Regex.Match(
            html,
            @"<code>([A-Z2-7]{32})</code>",
            RegexOptions.None,
            TimeSpan.FromSeconds(1)).Groups[1].Value;

        var totp = new Totp(Base32Encoding.ToBytes(secret));

        using var completed = await PostFormAsync(
            client,
            "/mfa/enrol",
            new Dictionary<string, string> { ["Input.Code"] = totp.ComputeTotp() },
            tokenFrom: "/mfa/enrol");

        var completedHtml = await completed.Content.ReadAsStringAsync();

        RecoveryCodes = Regex
            .Matches(
                completedHtml,
                @"<li>([0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5})</li>",
                RegexOptions.None,
                TimeSpan.FromSeconds(1))
            .Select(m => m.Groups[1].Value)
            .ToList();

        SharedSecret = secret;
        return secret;
    }

    /// <summary>
    /// Signs the owner in completely, setting up and enrolling first if needed.
    /// </summary>
    /// <remarks>
    /// Finishes with a recovery code rather than a TOTP code. The enrolment immediately above
    /// consumes its own time step, and the replay guard then refuses anything in that step, so
    /// a TOTP sign-in here would have to wait up to thirty seconds for the window to roll.
    /// Multiplied across the suite that was over four minutes of sleeping. A recovery code has
    /// no window, is issued ten at a time, and exercises a path worth covering anyway;
    /// <c>ATotpCodeCompletesSignIn</c> covers the TOTP route explicitly.
    /// </remarks>
    /// <param name="client">The browser client.</param>
    /// <returns>A task that completes when the client holds a session.</returns>
    public async Task SignInAsync(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);

        await SetUpAsync(client).ConfigureAwait(false);

        using (await PostFormAsync(client, "/sign-in", new Dictionary<string, string>
        {
            ["Input.Email"] = OwnerEmail,
            ["Input.Password"] = OwnerPassword,
        }).ConfigureAwait(false))
        {
            // The owner's role mandates MFA, so this redirects to enrolment the first time.
        }

        if (SharedSecret is null)
        {
            await EnrolMfaAsync(client).ConfigureAwait(false);
        }

        using (await PostFormAsync(client, "/sign-in", new Dictionary<string, string>
        {
            ["Input.Email"] = OwnerEmail,
            ["Input.Password"] = OwnerPassword,
        }).ConfigureAwait(false))
        {
        }

        var code = _nextRecoveryCode < RecoveryCodes.Count
            ? RecoveryCodes[_nextRecoveryCode++]
            : throw new InvalidOperationException(
                "The enrolment issued no unused recovery codes, so this client cannot sign in.");

        using var finished = await PostFormAsync(
            client,
            "/sign-in/recovery",
            new Dictionary<string, string> { ["Input.Code"] = code },
            tokenFrom: "/sign-in/recovery").ConfigureAwait(false);
    }

    private int _nextRecoveryCode;

    /// <summary>Waits for a TOTP code that differs from the one just consumed.</summary>
    /// <param name="totp">The generator.</param>
    /// <returns>A code from a step that has not been used.</returns>
    public static async Task<string> NextUnusedCodeAsync(Totp totp)
    {
        ArgumentNullException.ThrowIfNull(totp);

        var first = totp.ComputeTotp();
        var deadline = DateTimeOffset.UtcNow.AddSeconds(35);

        while (DateTimeOffset.UtcNow < deadline)
        {
            var candidate = totp.ComputeTotp();

            if (!string.Equals(candidate, first, StringComparison.Ordinal))
            {
                return candidate;
            }

            await Task.Delay(500).ConfigureAwait(false);
        }

        return totp.ComputeTotp();
    }

    /// <summary>Creates a vault and returns its id and slug.</summary>
    /// <param name="client">A signed-in browser client.</param>
    /// <param name="name">The vault name.</param>
    /// <returns>The vault's id and slug.</returns>
    public static async Task<(Guid Id, string Slug)> CreateVaultAsync(
        HttpClient client,
        string name = "Production")
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(name);

        using var created = await PostFormAsync(
            client,
            "/vaults?handler=Create",
            new Dictionary<string, string>
            {
                ["Input.Name"] = name,
                ["Input.ColorToken"] = "teal",
                ["Input.RecoveryWindowDays"] = "30",
            },
            tokenFrom: "/vaults");

        var slug = name.ToLowerInvariant();

        using var page = await client.GetAsync($"/vaults/{slug}");
        var html = await page.Content.ReadAsStringAsync();

        // The identities page carries the vault id in its grant checkboxes, which is the
        // simplest place to read it from without querying the database behind the pipeline.
        using var identities = await client.GetAsync("/identities");
        var identitiesHtml = await identities.Content.ReadAsStringAsync();

        var id = Regex.Match(
            identitiesHtml,
            @"name=""Input\.ScopedVaultIds"" value=""([0-9a-f-]{36})""",
            RegexOptions.None,
            TimeSpan.FromSeconds(1)).Groups[1].Value;

        return (Guid.Parse(id, CultureInfo.InvariantCulture), slug);
    }

    /// <summary>Stores a secret in a vault.</summary>
    /// <param name="client">A signed-in browser client.</param>
    /// <param name="slug">The vault slug.</param>
    /// <param name="name">The secret name.</param>
    /// <param name="value">The secret value.</param>
    /// <returns>A task that completes when the secret exists.</returns>
    public static async Task CreateSecretAsync(
        HttpClient client,
        string slug,
        string name,
        string value)
    {
        using var created = await PostFormAsync(
            client,
            $"/vaults/{slug}?handler=Create",
            new Dictionary<string, string>
            {
                ["Input.Name"] = name,
                ["Input.Environment"] = "prod",
                ["Input.Value"] = value,
            },
            tokenFrom: $"/vaults/{slug}");
    }

    /// <summary>Creates a service identity scoped to a vault and returns its credentials.</summary>
    /// <param name="client">A signed-in browser client.</param>
    /// <param name="vaultId">The vault to grant.</param>
    /// <param name="write">Whether to grant write.</param>
    /// <returns>The client id and secret.</returns>
    public static async Task<(string ClientId, string ClientSecret)> CreateIdentityAsync(
        HttpClient client,
        Guid vaultId,
        bool write = false)
    {
        ArgumentNullException.ThrowIfNull(client);

        using var created = await PostFormAsync(
            client,
            "/identities?handler=Create",
            new Dictionary<string, string>
            {
                ["Input.Name"] = "integration-runner",
                ["Input.ScopedVaultIds"] = vaultId.ToString("D", CultureInfo.InvariantCulture),
                ["Input.GrantWrite"] = write ? "true" : "false",
            },
            tokenFrom: "/identities");

        var html = await created.Content.ReadAsStringAsync();

        var clientId = Regex.Match(
            html,
            @"id=""issued-client-id"">(ksid_[A-Z0-9]+)<",
            RegexOptions.None,
            TimeSpan.FromSeconds(1)).Groups[1].Value;

        var secret = Regex.Match(
            html,
            @"id=""issued-secret"">(ksd_live_[A-Z0-9]+_[A-Z0-9]{6})<",
            RegexOptions.None,
            TimeSpan.FromSeconds(1)).Groups[1].Value;

        return (clientId, secret);
    }

    /// <summary>Exchanges client credentials for a bearer token.</summary>
    /// <param name="client">A machine client.</param>
    /// <param name="clientId">The client id.</param>
    /// <param name="clientSecret">The client secret.</param>
    /// <returns>The access token, or null when the exchange was refused.</returns>
    public static async Task<string?> GetTokenAsync(
        HttpClient client,
        string clientId,
        string clientSecret)
    {
        ArgumentNullException.ThrowIfNull(client);

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
        });

        using var response = await client.PostAsync("/api/v1/token", form);

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var json = System.Text.Json.JsonDocument.Parse(
            await response.Content.ReadAsStringAsync());

        return json.RootElement.TryGetProperty("access_token", out var token)
            ? token.GetString()
            : null;
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // SQLite may hold the file briefly. A leftover temp directory is not worth
            // failing a run over.
        }
    }
}
