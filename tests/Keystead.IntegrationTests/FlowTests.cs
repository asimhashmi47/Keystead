using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Xunit;

namespace Keystead.IntegrationTests;

/// <summary>
/// The flows, driven through the real HTTP pipeline.
/// </summary>
/// <remarks>
/// These cover what a unit test cannot reach: antiforgery, the authorization fallback policy,
/// the half-authenticated MFA step, rate limiting, and the machine API as an application would
/// actually call it. The service-level rules (the RBAC matrix, cross-tenant refusals, rollback
/// semantics) are covered exhaustively in <c>Keystead.Tests</c>; repeating them over HTTP
/// would be slower and prove less.
/// </remarks>
public sealed class FlowTests
{
    private const string SecretValue = "Server=db;Password=integration-canary";

    // -----------------------------------------------------------------------
    // Setup and the sign-in flow
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AFreshInstallationSendsYouToSetup()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        using var response = await browser.GetAsync("/sign-in");

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains("/setup", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task SetupClosesItselfOnceAnAccountExists()
    {
        // The setup page is necessarily anonymous. If it stayed open it would be a permanent
        // unauthenticated route to creating an owner, which would undo the whole model.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await KeysteadApp.SetUpAsync(browser);

        using var response = await browser.GetAsync("/setup");

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains("/sign-in", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnOwnerIsForcedIntoMfaEnrolmentRatherThanLetIn()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await KeysteadApp.SetUpAsync(browser);

        using var response = await KeysteadApp.PostFormAsync(
            browser,
            "/sign-in",
            new Dictionary<string, string>
            {
                ["Input.Email"] = KeysteadApp.OwnerEmail,
                ["Input.Password"] = KeysteadApp.OwnerPassword,
            });

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains("/mfa/enrol", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AWrongPasswordAndAnUnknownAccountAreIndistinguishable()
    {
        // Over HTTP, not just at the service boundary. The only difference permitted is the
        // email echoed back into the form, which the caller supplied themselves.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await KeysteadApp.SetUpAsync(browser);

        using var wrongPassword = await KeysteadApp.PostFormAsync(
            browser, "/sign-in", new Dictionary<string, string>
            {
                ["Input.Email"] = KeysteadApp.OwnerEmail,
                ["Input.Password"] = "definitely not the password",
            });

        using var unknownAccount = await KeysteadApp.PostFormAsync(
            browser, "/sign-in", new Dictionary<string, string>
            {
                ["Input.Email"] = "nobody@example.com",
                ["Input.Password"] = "definitely not the password",
            });

        Assert.Equal(wrongPassword.StatusCode, unknownAccount.StatusCode);

        var first = await wrongPassword.Content.ReadAsStringAsync();
        var second = await unknownAccount.Content.ReadAsStringAsync();

        Assert.Contains("was not accepted", first, StringComparison.Ordinal);
        Assert.Contains("was not accepted", second, StringComparison.Ordinal);

        // Neither page names which of the two things went wrong.
        foreach (var body in new[] { first, second })
        {
            Assert.DoesNotContain("no account", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("incorrect password", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("locked", body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task TheMfaPageIsUnreachableWithoutPassingThePasswordStep()
    {
        // The half-authenticated cookie is what carries the pending account. Without it a
        // client cannot arrive at the code step naming an account it has not authenticated.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await KeysteadApp.SetUpAsync(browser);

        using var response = await browser.GetAsync("/sign-in/mfa");

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains("/sign-in", response.Headers.Location!.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFullSignInReachesTheDashboard()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        using var response = await browser.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            "Integration",
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ATotpCodeCompletesSignIn()
    {
        // The primary second-factor route. The shared SignInAsync helper finishes with a
        // recovery code to keep the suite fast, so this test covers the TOTP path explicitly
        // and accepts the wait for a window the enrolment has not consumed.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await KeysteadApp.SetUpAsync(browser);

        using (await KeysteadApp.PostFormAsync(browser, "/sign-in", new Dictionary<string, string>
        {
            ["Input.Email"] = KeysteadApp.OwnerEmail,
            ["Input.Password"] = KeysteadApp.OwnerPassword,
        }))
        {
        }

        var secret = await app.EnrolMfaAsync(browser);

        using (await KeysteadApp.PostFormAsync(browser, "/sign-in", new Dictionary<string, string>
        {
            ["Input.Email"] = KeysteadApp.OwnerEmail,
            ["Input.Password"] = KeysteadApp.OwnerPassword,
        }))
        {
        }

        var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(secret));
        var code = await KeysteadApp.NextUnusedCodeAsync(totp);

        using var finished = await KeysteadApp.PostFormAsync(
            browser,
            "/sign-in/mfa",
            new Dictionary<string, string> { ["Input.Code"] = code },
            tokenFrom: "/sign-in/mfa");

        Assert.Equal(HttpStatusCode.Found, finished.StatusCode);

        using var dashboard = await browser.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, dashboard.StatusCode);
    }

    [Fact]
    public async Task TheEnrolmentQrCodeIsStableAcrossPageLoads()
    {
        // Issuing a fresh seed on every visit means someone who scans the code and then
        // reloads the page is told their correct code is wrong. Found by these tests doing
        // exactly that.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await KeysteadApp.SetUpAsync(browser);

        using (await KeysteadApp.PostFormAsync(browser, "/sign-in", new Dictionary<string, string>
        {
            ["Input.Email"] = KeysteadApp.OwnerEmail,
            ["Input.Password"] = KeysteadApp.OwnerPassword,
        }))
        {
        }

        static async Task<string> SecretOnPageAsync(HttpClient client)
        {
            using var page = await client.GetAsync("/mfa/enrol");
            var html = await page.Content.ReadAsStringAsync();

            return System.Text.RegularExpressions.Regex.Match(
                html,
                @"<code>([A-Z2-7]{32})</code>",
                System.Text.RegularExpressions.RegexOptions.None,
                TimeSpan.FromSeconds(1)).Groups[1].Value;
        }

        var first = await SecretOnPageAsync(browser);
        var second = await SecretOnPageAsync(browser);
        var third = await SecretOnPageAsync(browser);

        Assert.False(string.IsNullOrEmpty(first));
        Assert.Equal(first, second);
        Assert.Equal(first, third);
    }

    [Fact]
    public async Task AnAlreadyUsedCodeIsRefusedAsAReplay()
    {
        // RFC 6238 would leave the code valid for the rest of its step. Refusing a consumed
        // step is what makes a correct code single-use.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        var secret = app.SharedSecret!;
        var totp = new OtpNet.Totp(OtpNet.Base32Encoding.ToBytes(secret));
        var code = totp.ComputeTotp();

        // Sign out, then try to finish a new sign-in with a code from the step just consumed.
        using (await KeysteadApp.PostFormAsync(browser, "/sign-out", new Dictionary<string, string>()))
        {
        }

        using (await KeysteadApp.PostFormAsync(browser, "/sign-in", new Dictionary<string, string>
        {
            ["Input.Email"] = KeysteadApp.OwnerEmail,
            ["Input.Password"] = KeysteadApp.OwnerPassword,
        }))
        {
        }

        using var replay = await KeysteadApp.PostFormAsync(
            browser,
            "/sign-in/mfa",
            new Dictionary<string, string> { ["Input.Code"] = code },
            tokenFrom: "/sign-in/mfa");

        // Re-rendered with an error rather than redirected onward.
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Contains(
            "not accepted",
            await replay.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // Antiforgery
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData("/sign-in")]
    [InlineData("/setup")]
    [InlineData("/sign-out")]
    public async Task AStateChangingPostWithoutATokenIsRefused(string path)
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Input.Email"] = KeysteadApp.OwnerEmail,
            ["Input.Password"] = KeysteadApp.OwnerPassword,
        });

        using var response = await browser.PostAsync(path, content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task APostWithAForgedTokenIsRefused()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        // Fetch the page so the cookie half of the token pair is set, then send a different
        // form token. Both halves must match, which is what makes the pair work.
        using var page = await browser.GetAsync("/setup");

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__keystead-csrf"] = "CfDJ8-not-a-real-token",
            ["Input.WorkspaceName"] = "Forged",
            ["Input.Email"] = "attacker@example.com",
        });

        using var response = await browser.PostAsync("/setup", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------

    [Fact]
    public async Task SigningOutRevokesTheSessionServerSide()
    {
        // Clearing the cookie alone would leave a session row that still validates if the
        // cookie were replayed from elsewhere.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        using (var before = await browser.GetAsync("/"))
        {
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        }

        using (await KeysteadApp.PostFormAsync(browser, "/sign-out", new Dictionary<string, string>()))
        {
        }

        using var after = await browser.GetAsync("/");

        Assert.Equal(HttpStatusCode.Found, after.StatusCode);
    }

    // -----------------------------------------------------------------------
    // The vault and secret flow
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ASecretValueNeverAppearsInAnyPage()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        var (_, slug) = await KeysteadApp.CreateVaultAsync(browser);
        await KeysteadApp.CreateSecretAsync(browser, slug, "ConnectionStrings--Default", SecretValue);

        foreach (var path in new[] { "/", "/vaults", $"/vaults/{slug}", "/audit", "/search?q=Connection" })
        {
            using var response = await browser.GetAsync(path);
            var body = await response.Content.ReadAsStringAsync();

            Assert.DoesNotContain(SecretValue, body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task TheAuditLogVerifiesAfterRealTraffic()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        var (_, slug) = await KeysteadApp.CreateVaultAsync(browser);
        await KeysteadApp.CreateSecretAsync(browser, slug, "Token", SecretValue);

        using var response = await browser.GetAsync("/audit");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("Chain verified", body, StringComparison.Ordinal);
        Assert.Contains("VaultCreated", body, StringComparison.Ordinal);
        Assert.Contains("SecretCreated", body, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // The machine API
    // -----------------------------------------------------------------------

    [Fact]
    public async Task AnApplicationCanReadASecretWithAToken()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        var (vaultId, slug) = await KeysteadApp.CreateVaultAsync(browser);
        await KeysteadApp.CreateSecretAsync(browser, slug, "ConnectionStrings--Default", SecretValue);

        var (clientId, clientSecret) = await KeysteadApp.CreateIdentityAsync(browser, vaultId);

        using var machine = app.CreateMachine();
        var token = await KeysteadApp.GetTokenAsync(machine, clientId, clientSecret);

        Assert.NotNull(token);

        machine.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await machine.GetAsync(
            $"/api/v1/vaults/{vaultId:D}/secrets/ConnectionStrings--Default?environment=prod");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            SecretValue,
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AReadOnlyIdentityCannotWrite()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        var (vaultId, slug) = await KeysteadApp.CreateVaultAsync(browser);
        await KeysteadApp.CreateSecretAsync(browser, slug, "Token", SecretValue);

        var (clientId, clientSecret) = await KeysteadApp.CreateIdentityAsync(
            browser, vaultId, write: false);

        using var machine = app.CreateMachine();
        var token = await KeysteadApp.GetTokenAsync(machine, clientId, clientSecret);

        machine.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var body = JsonContent("second-value");

        using var response = await machine.PutAsync(
            $"/api/v1/vaults/{vaultId:D}/secrets/Token?environment=prod",
            body);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AVaultOutsideTheGrantIsNotFound()
    {
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        var (vaultId, _) = await KeysteadApp.CreateVaultAsync(browser);
        var (clientId, clientSecret) = await KeysteadApp.CreateIdentityAsync(browser, vaultId);

        using var machine = app.CreateMachine();
        var token = await KeysteadApp.GetTokenAsync(machine, clientId, clientSecret);

        machine.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await machine.GetAsync(
            $"/api/v1/vaults/{Guid.NewGuid():D}/secrets");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ARevokedIdentityCannotUseATokenItAlreadyHolds()
    {
        // The property that makes revocation meaningful over HTTP: it takes effect on the next
        // call, not when the token expires.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await app.SignInAsync(browser);

        var (vaultId, slug) = await KeysteadApp.CreateVaultAsync(browser);
        await KeysteadApp.CreateSecretAsync(browser, slug, "Token", SecretValue);

        var (clientId, clientSecret) = await KeysteadApp.CreateIdentityAsync(browser, vaultId);

        using var machine = app.CreateMachine();
        var token = await KeysteadApp.GetTokenAsync(machine, clientId, clientSecret);

        machine.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using (var before = await machine.GetAsync($"/api/v1/vaults/{vaultId:D}/secrets"))
        {
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        }

        using var identities = await browser.GetAsync("/identities");
        var html = await identities.Content.ReadAsStringAsync();

        var identityId = System.Text.RegularExpressions.Regex.Match(
            html,
            @"name=""identityId"" value=""([0-9a-f-]{36})""",
            System.Text.RegularExpressions.RegexOptions.None,
            TimeSpan.FromSeconds(1)).Groups[1].Value;

        using (await KeysteadApp.PostFormAsync(
            browser,
            "/identities?handler=Revoke",
            new Dictionary<string, string> { ["identityId"] = identityId },
            tokenFrom: "/identities"))
        {
        }

        using var after = await machine.GetAsync($"/api/v1/vaults/{vaultId:D}/secrets");

        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Theory]
    [InlineData("not-a-token")]
    [InlineData("eyJhbGciOiJub25lIn0.e30.")]
    [InlineData("")]
    public async Task AnInvalidTokenIsRefused(string token)
    {
        ArgumentNullException.ThrowIfNull(token);

        await using var app = new KeysteadApp();
        using var machine = app.CreateMachine();

        if (token.Length > 0)
        {
            machine.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
        }

        using var response = await machine.GetAsync(
            $"/api/v1/vaults/{Guid.NewGuid():D}/secrets");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TheTokenEndpointRefusesAnUnsupportedGrant()
    {
        await using var app = new KeysteadApp();
        using var machine = app.CreateMachine();

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "ksid_ANYTHING",
            ["client_secret"] = "ksd_live_ANYTHING_ABCDEF",
        });

        using var response = await machine.PostAsync("/api/v1/token", form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    [Fact]
    public async Task TheSignInEndpointIsRateLimited()
    {
        // The per-account progressive lockout bounds "many guesses at one account". This
        // bounds "one guess at many accounts", which the lockout alone would miss.
        await using var app = new KeysteadApp();
        using var browser = app.CreateBrowser();

        await KeysteadApp.SetUpAsync(browser);

        var sawRateLimit = false;

        for (var attempt = 0; attempt < 30 && !sawRateLimit; attempt++)
        {
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Input.Email"] = $"attempt{attempt}@example.com",
                ["Input.Password"] = "wrong",
            });

            using var response = await browser.PostAsync("/sign-in", content);

            if (response.StatusCode is HttpStatusCode.TooManyRequests)
            {
                sawRateLimit = true;
            }
        }

        Assert.True(sawRateLimit, "The sign-in endpoint accepted 30 attempts without limiting.");
    }

    private static StringContent JsonContent(string value)
    {
        var content = new StringContent(
            System.Text.Json.JsonSerializer.Serialize(new { value }),
            System.Text.Encoding.UTF8,
            "application/json");

        return content;
    }
}
