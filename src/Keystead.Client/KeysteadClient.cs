using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Keystead.Client;

/// <summary>
/// A client for the Keystead machine API.
/// </summary>
/// <remarks>
/// <para>
/// Holds one access token and renews it shortly before it expires. The renewal margin matters:
/// renewing exactly at expiry guarantees a race with clock skew and request latency, and the
/// failure surfaces as an intermittent 401 under load rather than as anything obvious.
/// </para>
/// <para>
/// Retries are for transport faults and 5xx only. A 401 or 403 is not retried, because the
/// answer will not change and hammering the token endpoint with bad credentials is how an
/// identity gets itself rate limited and an operator gets paged.
/// </para>
/// </remarks>
public sealed class KeysteadClient : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly KeysteadOptions _options;
    private readonly SemaphoreSlim _tokenGate = new(1, 1);

    private string? _token;
    private DateTimeOffset _tokenExpiresUtc = DateTimeOffset.MinValue;

    /// <summary>Creates a client with its own <see cref="HttpClient"/>.</summary>
    /// <param name="options">How to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    public KeysteadClient(KeysteadOptions options)
        : this(options, httpClient: null)
    {
    }

    /// <summary>Creates a client, optionally reusing a caller-supplied <see cref="HttpClient"/>.</summary>
    /// <param name="options">How to reach the server.</param>
    /// <param name="httpClient">
    /// An existing client to use, or null to create one. Supplying one is the right choice in
    /// an application with a factory; the client does not dispose what it did not create.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    public KeysteadClient(KeysteadOptions options, HttpClient? httpClient)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        _options = options;
        _ownsHttpClient = httpClient is null;

        _http = httpClient ?? new HttpClient();
        _http.BaseAddress ??= options.Endpoint;
        _http.Timeout = options.Timeout;
    }

    /// <summary>Reads one secret's value.</summary>
    /// <param name="name">
    /// The secret name, or a configuration key. A key containing <c>:</c> is translated to the
    /// stored name convention, so both forms work.
    /// </param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The value, or null when no such secret is reachable.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="name"/> is null.</exception>
    /// <exception cref="KeysteadException">The server refused the request.</exception>
    public async Task<string?> GetSecretAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        var secretName = name.Contains(':', StringComparison.Ordinal)
            ? SecretKeyMapping.ToSecretName(name)
            : name;

        var path = string.Create(
            CultureInfo.InvariantCulture,
            $"/api/v1/vaults/{_options.VaultId:D}/secrets/{Uri.EscapeDataString(secretName)}?environment={Uri.EscapeDataString(_options.Environment)}");

        using var response = await SendAsync(HttpMethod.Get, path, content: null, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode is HttpStatusCode.NotFound)
        {
            return null;
        }

        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);

        var payload = await response.Content
            .ReadFromJsonAsync<SecretResponse>(Json, cancellationToken)
            .ConfigureAwait(false);

        return payload?.Value;
    }

    /// <summary>Lists the secret names in the configured vault and environment.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The names. Never values: the list endpoint does not return them.</returns>
    /// <exception cref="KeysteadException">The server refused the request.</exception>
    public async Task<IReadOnlyList<string>> ListSecretNamesAsync(
        CancellationToken cancellationToken)
    {
        var path = string.Create(
            CultureInfo.InvariantCulture,
            $"/api/v1/vaults/{_options.VaultId:D}/secrets?environment={Uri.EscapeDataString(_options.Environment)}");

        using var response = await SendAsync(HttpMethod.Get, path, content: null, cancellationToken)
            .ConfigureAwait(false);

        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);

        var payload = await response.Content
            .ReadFromJsonAsync<List<SecretListItem>>(Json, cancellationToken)
            .ConfigureAwait(false)
            ?? [];

        var names = new List<string>(payload.Count);

        foreach (var item in payload)
        {
            if (item.Name is { Length: > 0 })
            {
                names.Add(item.Name);
            }
        }

        return names;
    }

    /// <summary>
    /// Loads every reachable secret as a configuration dictionary.
    /// </summary>
    /// <remarks>
    /// One request per secret, because the list endpoint deliberately does not return values.
    /// That is slower than a bulk read would be and it is the right trade: a bulk endpoint
    /// would mean one request that decrypts everything, and one audit entry covering a read of
    /// the whole vault rather than a record of which secrets were actually used.
    /// </remarks>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>Configuration keys mapped to values.</returns>
    /// <exception cref="KeysteadException">The server refused the request.</exception>
    public async Task<IDictionary<string, string?>> LoadConfigurationAsync(
        CancellationToken cancellationToken)
    {
        var names = await ListSecretNamesAsync(cancellationToken).ConfigureAwait(false);

        var loaded = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in names)
        {
            var value = await GetSecretAsync(name, cancellationToken).ConfigureAwait(false);

            if (value is not null)
            {
                loaded[SecretKeyMapping.ToConfigurationKey(name, _options.KeyPrefix)] = value;
            }
        }

        return loaded;
    }

    /// <summary>Writes a new value, creating the secret if it does not exist.</summary>
    /// <param name="name">The secret name or configuration key.</param>
    /// <param name="value">The value to store.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The version number written.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="KeysteadException">The server refused the request.</exception>
    public async Task<int> SetSecretAsync(
        string name,
        string value,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);

        var secretName = name.Contains(':', StringComparison.Ordinal)
            ? SecretKeyMapping.ToSecretName(name)
            : name;

        var path = string.Create(
            CultureInfo.InvariantCulture,
            $"/api/v1/vaults/{_options.VaultId:D}/secrets/{Uri.EscapeDataString(secretName)}?environment={Uri.EscapeDataString(_options.Environment)}");

        using var body = JsonContent.Create(new { value }, options: Json);

        using var response = await SendAsync(HttpMethod.Put, path, body, cancellationToken)
            .ConfigureAwait(false);

        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);

        var payload = await response.Content
            .ReadFromJsonAsync<SetSecretResponse>(Json, cancellationToken)
            .ConfigureAwait(false);

        return payload?.Version ?? 0;
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        string path,
        HttpContent? content,
        CancellationToken cancellationToken)
    {
        Exception? last = null;

        for (var attempt = 0; attempt <= _options.MaxRetries; attempt++)
        {
            if (attempt > 0)
            {
                // Exponential backoff. Not jittered, which would matter more if many
                // instances started at once; noted rather than pretended away.
                var delay = TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt - 1));
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }

            try
            {
                var token = await GetTokenAsync(cancellationToken).ConfigureAwait(false);

                using var request = new HttpRequestMessage(method, path);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                request.Content = content;

                var response = await _http
                    .SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
                    .ConfigureAwait(false);

                if (response.StatusCode is HttpStatusCode.Unauthorized && attempt < _options.MaxRetries)
                {
                    // The token may simply have aged out between the margin check and the
                    // request. Drop it and let the next attempt mint a fresh one. Tried once,
                    // not repeatedly: if a new token is also refused, the credentials or the
                    // grant are wrong and retrying will not fix either.
                    response.Dispose();
                    InvalidateToken();
                    continue;
                }

                if ((int)response.StatusCode >= 500 && attempt < _options.MaxRetries)
                {
                    response.Dispose();
                    continue;
                }

                return response;
            }
            catch (HttpRequestException ex) when (attempt < _options.MaxRetries)
            {
                last = ex;
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested
                && attempt < _options.MaxRetries)
            {
                // A timeout, not a caller cancellation. Worth another attempt.
                last = ex;
            }
        }

        throw new KeysteadException(
            $"Keystead did not respond after {_options.MaxRetries + 1} attempt(s).",
            last);
    }

    private async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (_token is { } cached && DateTimeOffset.UtcNow < _tokenExpiresUtc)
        {
            return cached;
        }

        await _tokenGate.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            // Re-checked inside the gate: several callers can arrive at an expired token at
            // once, and without this they would each mint a separate one.
            if (_token is { } current && DateTimeOffset.UtcNow < _tokenExpiresUtc)
            {
                return current;
            }

            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _options.ClientId!,
                ["client_secret"] = _options.ClientSecret!,
            });

            using var response = await _http
                .PostAsync("/api/v1/token", form, cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                // Deliberately does not echo the response body. It is a problem document, not
                // a secret, but a client that logs the token endpoint's reply verbatim is one
                // configuration mistake away from logging what it sent.
                throw new KeysteadException(
                    $"Keystead refused the client credentials ({(int)response.StatusCode}). Check the client id, the secret, and whether the identity is still enabled.");
            }

            var payload = await response.Content
                .ReadFromJsonAsync<TokenResponse>(Json, cancellationToken)
                .ConfigureAwait(false);

            if (payload?.AccessToken is not { Length: > 0 } token)
            {
                throw new KeysteadException("Keystead returned no access token.");
            }

            var lifetime = TimeSpan.FromSeconds(Math.Max(payload.ExpiresIn, 1));
            var margin = _options.TokenRenewalMargin;

            // Never let the margin consume the whole lifetime: with a one-minute token and a
            // one-minute margin the token would be considered expired the moment it arrived.
            if (margin >= lifetime)
            {
                margin = lifetime / 2;
            }

            _token = token;
            _tokenExpiresUtc = DateTimeOffset.UtcNow + lifetime - margin;

            return token;
        }
        finally
        {
            _tokenGate.Release();
        }
    }

    private void InvalidateToken()
    {
        _token = null;
        _tokenExpiresUtc = DateTimeOffset.MinValue;
    }

    private static async Task EnsureSuccessAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var detail = await ReadProblemDetailAsync(response, cancellationToken).ConfigureAwait(false);

        throw new KeysteadException(
            $"Keystead returned {(int)response.StatusCode}{(detail is null ? "." : $": {detail}")}");
    }

    private static async Task<string?> ReadProblemDetailAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        try
        {
            var problem = await response.Content
                .ReadFromJsonAsync<ProblemDocument>(Json, cancellationToken)
                .ConfigureAwait(false);

            return problem?.Detail;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or HttpRequestException)
        {
            // A non-JSON error body, perhaps from a proxy. The status code is the useful part.
            return null;
        }
    }

    /// <summary>Disposes the HTTP client if this instance created it.</summary>
    public void Dispose()
    {
        _tokenGate.Dispose();

        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);

    private sealed record SecretResponse(string? Name, int Version, string? Value);

    private sealed record SecretListItem(string? Name, string? Environment);

    private sealed record SetSecretResponse(int Version);

    private sealed record ProblemDocument(string? Title, string? Detail, int Status);
}
