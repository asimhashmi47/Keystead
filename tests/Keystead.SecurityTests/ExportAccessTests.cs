using System;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace Keystead.SecurityTests;

/// <summary>
/// Who may download a table.
/// </summary>
/// <remarks>
/// <para>
/// A download is a read, and an export handler is a new way to ask for one. The risk is not
/// subtle and it is easy to create: a handler that renders a page correctly behind
/// authentication, and serves a file from the same data without it, because the file is
/// returned before the page's own checks would have run.
/// </para>
/// <para>
/// Every export here loads through the same method the page does, so the authorization is the
/// page's. These tests are what says so.
/// </para>
/// </remarks>
[Collection(nameof(HostedAppCollection))]
public sealed class ExportAccessTests
{
    private readonly KeysteadTestFactory _factory;

    /// <summary>Creates the fixture.</summary>
    /// <param name="factory">The hosted application.</param>
    /// <exception cref="ArgumentNullException"><paramref name="factory"/> is null.</exception>
    public ExportAccessTests(KeysteadTestFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        _factory = factory;
    }

    [Theory]
    [InlineData("/members?handler=Export&format=xlsx")]
    [InlineData("/members?handler=Export&format=csv")]
    [InlineData("/vaults?handler=Export&format=xlsx")]
    [InlineData("/identities?handler=Export&format=xlsx")]
    [InlineData("/security?handler=Export&format=xlsx")]
    [InlineData("/audit?handler=Export&format=csv")]
    [InlineData("/vaults/production?handler=Export&format=xlsx")]
    public async Task AnExport_IsRefusedToAnAnonymousCaller(string path)
    {
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(path);

        // Redirected to sign in, or refused outright. What must not happen is a file.
        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect
                or HttpStatusCode.Found
                or HttpStatusCode.Forbidden
                or HttpStatusCode.NotFound,
            $"{path} answered {(int)response.StatusCode}");

        Assert.NotEqual(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            response.Content.Headers.ContentType?.MediaType);

        Assert.NotEqual("text/csv", response.Content.Headers.ContentType?.MediaType);
    }

    [Theory]
    [InlineData("/members?handler=Export")]
    [InlineData("/audit?handler=Export")]
    public async Task AnExport_IsNotCacheable(string path)
    {
        // Whatever the answer is, it is not something a shared proxy should keep. The asset
        // exemption in the security headers covers a closed list of static paths, and a page
        // handler is not one of them; this is the test that says the exemption stayed closed.
        using var client = _factory.CreateApiClient();
        using var response = await client.GetAsync(path);

        var cacheControl = response.Headers.CacheControl?.ToString() ?? string.Empty;

        Assert.Contains("no-store", cacheControl, StringComparison.OrdinalIgnoreCase);
    }
}
