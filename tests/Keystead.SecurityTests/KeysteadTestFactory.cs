using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using Keystead.Web;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;

namespace Keystead.SecurityTests;

/// <summary>
/// Hosts the real application in memory for the security suite.
/// </summary>
/// <remarks>
/// <para>
/// The real pipeline, not an approximation of it. These tests exist to assert that the
/// headers, cookie flags and policies the README promises are actually produced by the
/// middleware as it is ordered in <c>Program</c>. A factory that rebuilt a simplified
/// pipeline would pass while production was misconfigured, which is the failure mode this
/// suite is meant to catch.
/// </para>
/// <para>
/// Requests are issued against an <c>https://</c> base address. That is not cosmetic: the
/// application redirects plain HTTP, and the antiforgery system refuses to issue a
/// <c>Secure</c> cookie over an insecure request. Testing over HTTP would either exercise the
/// redirect or force the cookie policy to be weakened for tests, and both would mean testing
/// something other than what ships.
/// </para>
/// </remarks>
public sealed class KeysteadTestFactory : WebApplicationFactory<Program>
{
    private readonly string _root;

    /// <summary>Creates the factory with an isolated database and master key.</summary>
    public KeysteadTestFactory()
    {
        _root = Path.Combine(Path.GetTempPath(), "keystead-tests", Guid.CreateVersion7().ToString("N"));
        Directory.CreateDirectory(_root);

        // A real random master key per factory, supplied the way an operator would supply one.
        // Generating it here rather than hardcoding a constant means a test cannot come to
        // depend on a particular key, and nothing resembling a key is committed.
        MasterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    }

    /// <summary>The base64 master key this instance was started with.</summary>
    public string MasterKey { get; }

    /// <summary>Creates a client whose requests appear as HTTPS.</summary>
    /// <returns>An HTTP client that does not follow redirects.</returns>
    public HttpClient CreateApiClient() =>
        CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),

            // Redirects stay visible, so a test can assert where the application sends an
            // unauthenticated caller rather than silently following along.
            AllowAutoRedirect = false,
        });

    /// <inheritdoc />
    protected override IHost CreateHost(IHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Set before the host is built, because the master key provider reads them during
        // service construction and the application refuses to start without a valid key.
        Environment.SetEnvironmentVariable("KEYSTEAD_MASTER_KEY", MasterKey);
        Environment.SetEnvironmentVariable("Keystead__MasterKey__Source", "Environment");
        Environment.SetEnvironmentVariable(
            "Keystead__Database__Path",
            Path.Combine(_root, "keystead.db"));

        // Development, so the schema is migrated on startup. The dev master key bootstrap is
        // skipped because the source is Environment and a key is already present.
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");

        return base.CreateHost(builder);
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
        catch (IOException)
        {
            // SQLite may still hold the file briefly. A leftover temp directory is not worth
            // failing a test run over.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>
/// The collection that owns the hosted application.
/// </summary>
/// <remarks>
/// Every suite that needs a running pipeline joins this collection, so there is one host and
/// one factory for all of them. Two <c>WebApplicationFactory</c> instances building the same
/// entry point at the same time race over it, and the loser fails with "the entry point exited
/// without ever building an IHost" — a confusing message for a plain concurrency problem.
/// Sharing the host also stops the suites from paying for a second startup.
/// </remarks>
[Xunit.CollectionDefinition(nameof(HostedAppCollection), DisableParallelization = true)]
public sealed class HostedAppCollection : Xunit.ICollectionFixture<KeysteadTestFactory>
{
}
