using System;

namespace Keystead.Client;

/// <summary>How the SDK reaches a Keystead server and which secrets it loads.</summary>
public sealed class KeysteadOptions
{
    /// <summary>The server's base address.</summary>
    public Uri? Endpoint { get; set; }

    /// <summary>The public client identifier of the service identity to authenticate as.</summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// The client secret.
    /// </summary>
    /// <remarks>
    /// Read this from an environment variable or a mounted file, never from
    /// <c>appsettings.json</c>. Putting it in a configuration file that Keystead is then asked
    /// to supply secrets to is a loop with the weakest link on the outside.
    /// </remarks>
    public string? ClientSecret { get; set; }

    /// <summary>The vault to load secrets from.</summary>
    public Guid VaultId { get; set; }

    /// <summary>The environment label to load, for example <c>prod</c>.</summary>
    public string Environment { get; set; } = "prod";

    /// <summary>
    /// How often to re-read secrets, or null to load once at startup.
    /// </summary>
    /// <remarks>
    /// Polling means a rotated secret reaches a running application without a restart. It also
    /// means a request to the server on a timer, so the default is deliberately not aggressive.
    /// </remarks>
    public TimeSpan? ReloadInterval { get; set; }

    /// <summary>How long to wait for a single HTTP request.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How early to renew a token before it expires.
    /// </summary>
    /// <remarks>
    /// Renewing exactly at expiry guarantees a race with clock skew and request latency, and
    /// the failure shows up as an intermittent 401 under load.
    /// </remarks>
    public TimeSpan TokenRenewalMargin { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>How many times to retry a failed request before giving up.</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>
    /// Whether a failure to load secrets is tolerated.
    /// </summary>
    /// <remarks>
    /// False by default, and that is the right default: an application that starts without its
    /// secrets will fail later, further from the cause, probably on a customer's request. A
    /// loud failure at startup is cheaper than a confusing one at runtime.
    /// </remarks>
    public bool Optional { get; set; }

    /// <summary>
    /// An optional prefix to strip from secret names before they become configuration keys.
    /// </summary>
    public string? KeyPrefix { get; set; }

    /// <summary>Validates the options, throwing if the SDK cannot possibly work.</summary>
    /// <exception cref="InvalidOperationException">A required option is missing.</exception>
    public void Validate()
    {
        if (Endpoint is null)
        {
            throw new InvalidOperationException("Keystead: Endpoint is required.");
        }

        if (string.IsNullOrWhiteSpace(ClientId))
        {
            throw new InvalidOperationException("Keystead: ClientId is required.");
        }

        if (string.IsNullOrWhiteSpace(ClientSecret))
        {
            throw new InvalidOperationException(
                "Keystead: ClientSecret is required. Read it from an environment variable or a mounted file, not from appsettings.json.");
        }

        if (VaultId == Guid.Empty)
        {
            throw new InvalidOperationException("Keystead: VaultId is required.");
        }

        if (ReloadInterval is { } interval && interval < TimeSpan.FromSeconds(5))
        {
            throw new InvalidOperationException(
                "Keystead: ReloadInterval must be at least 5 seconds. A tighter loop would spend more time authenticating than working.");
        }
    }
}
