using System;
using System.Threading;
using Microsoft.Extensions.Configuration;

namespace Keystead.Client;

/// <summary>
/// Adds Keystead as a configuration source, so secrets arrive through
/// <see cref="IConfiguration"/> like any other setting.
/// </summary>
/// <remarks>
/// The point of this shape is that application code never mentions Keystead. A service reads
/// <c>GetConnectionString("Default")</c> and does not know whether the value came from a file,
/// an environment variable or an encrypted vault, which means adopting Keystead is a change to
/// the host builder and nothing else.
/// </remarks>
public static class KeysteadConfigurationExtensions
{
    /// <summary>Adds Keystead as a configuration source.</summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="configure">Configures the connection.</param>
    /// <returns>The same builder, for chaining.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static IConfigurationBuilder AddKeystead(
        this IConfigurationBuilder builder,
        Action<KeysteadOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new KeysteadOptions();
        configure(options);

        return builder.Add(new KeysteadConfigurationSource(options));
    }

    /// <summary>
    /// Adds Keystead using the conventional environment variables.
    /// </summary>
    /// <remarks>
    /// Reads <c>KEYSTEAD_ENDPOINT</c>, <c>KEYSTEAD_CLIENT_ID</c>,
    /// <c>KEYSTEAD_CLIENT_SECRET</c>, <c>KEYSTEAD_VAULT_ID</c> and
    /// <c>KEYSTEAD_ENVIRONMENT</c>. This is the form a container deployment wants, because the
    /// orchestrator already knows how to inject those and the application needs no
    /// Keystead-specific configuration of its own.
    /// </remarks>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="optional">Whether a failure to load is tolerated.</param>
    /// <returns>The same builder, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    public static IConfigurationBuilder AddKeysteadFromEnvironment(
        this IConfigurationBuilder builder,
        bool optional = false)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.AddKeystead(options =>
        {
            var endpoint = Environment.GetEnvironmentVariable("KEYSTEAD_ENDPOINT");

            if (Uri.TryCreate(endpoint, UriKind.Absolute, out var parsed))
            {
                options.Endpoint = parsed;
            }

            options.ClientId = Environment.GetEnvironmentVariable("KEYSTEAD_CLIENT_ID");
            options.ClientSecret = Environment.GetEnvironmentVariable("KEYSTEAD_CLIENT_SECRET");

            if (Guid.TryParse(
                Environment.GetEnvironmentVariable("KEYSTEAD_VAULT_ID"),
                out var vaultId))
            {
                options.VaultId = vaultId;
            }

            options.Environment =
                Environment.GetEnvironmentVariable("KEYSTEAD_ENVIRONMENT") ?? "prod";

            options.Optional = optional;
        });
    }
}

/// <summary>The configuration source for Keystead.</summary>
internal sealed class KeysteadConfigurationSource : IConfigurationSource
{
    private readonly KeysteadOptions _options;

    public KeysteadConfigurationSource(KeysteadOptions options) => _options = options;

    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new KeysteadConfigurationProvider(_options);
}

/// <summary>
/// Loads secrets from Keystead into configuration, and optionally re-reads them on a timer.
/// </summary>
internal sealed class KeysteadConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly KeysteadOptions _options;
    private KeysteadClient? _client;
    private Timer? _reloadTimer;
    private bool _disposed;

    public KeysteadConfigurationProvider(KeysteadOptions options) => _options = options;

    /// <summary>
    /// Loads the secrets.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Synchronous because <see cref="ConfigurationProvider.Load"/> is, and the host calls it
    /// during startup. Blocking on the async path here is the lesser evil: the alternatives
    /// are an async-over-sync deadlock risk or a provider that reports no values until some
    /// later moment, which would make configuration binding silently incomplete.
    /// </para>
    /// <para>
    /// A failure throws unless the source is optional, so an application that cannot reach its
    /// secrets fails at startup rather than on a customer's request.
    /// </para>
    /// </remarks>
    public override void Load()
    {
        try
        {
            _options.Validate();

            _client ??= new KeysteadClient(_options);

            // GetAwaiter().GetResult() rather than .Result, so an exception surfaces as itself
            // instead of wrapped in an AggregateException an operator then has to unwrap.
            Data = _client
                .LoadConfigurationAsync(CancellationToken.None)
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();

            StartReloadTimerIfConfigured();
        }
        catch (Exception ex) when (ex is KeysteadException or InvalidOperationException)
        {
            if (!_options.Optional)
            {
                throw;
            }

            // Optional, so an empty set rather than a failure. Anything binding these values
            // will fall back to whatever other source provided them.
            Data = new System.Collections.Generic.Dictionary<string, string?>(
                StringComparer.OrdinalIgnoreCase);
        }
    }

    private void StartReloadTimerIfConfigured()
    {
        if (_options.ReloadInterval is not { } interval || _reloadTimer is not null)
        {
            return;
        }

        _reloadTimer = new Timer(
            _ => Reload(),
            state: null,
            dueTime: interval,
            period: interval);
    }

    private void Reload()
    {
        if (_disposed || _client is null)
        {
            return;
        }

        try
        {
            var loaded = _client
                .LoadConfigurationAsync(CancellationToken.None)
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();

            Data = loaded;

            // Tells anything using IOptionsMonitor or IConfiguration change tokens that the
            // values moved, which is what makes a rotated secret reach a running application.
            OnReload();
        }
        catch (KeysteadException)
        {
            // A failed refresh keeps the values already loaded. Clearing them would take an
            // application down because of one transient failure, which is worse than serving
            // a secret that is a few minutes stale.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _reloadTimer?.Dispose();
        _client?.Dispose();
    }
}
