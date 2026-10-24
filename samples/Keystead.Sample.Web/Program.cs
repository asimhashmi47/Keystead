using System;
using System.Linq;
using Keystead.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Keystead.Sample.Web;

/// <summary>
/// A minimal application that reads its connection string from Keystead.
/// </summary>
/// <remarks>
/// <para>
/// The point of this sample is how little of it mentions Keystead. One call in the host
/// builder, and from then on the application reads <c>GetConnectionString("Default")</c> like
/// any other .NET application. Nothing downstream knows or cares where the value came from.
/// </para>
/// <para>
/// Run it with the environment variables a service identity was issued:
/// </para>
/// <code>
/// KEYSTEAD_ENDPOINT=https://localhost:5001
/// KEYSTEAD_CLIENT_ID=ksid_...
/// KEYSTEAD_CLIENT_SECRET=ksd_live_..._XXXXXX
/// KEYSTEAD_VAULT_ID=&lt;the vault's id&gt;
/// KEYSTEAD_ENVIRONMENT=prod
/// </code>
/// </remarks>
public static class Program
{
    /// <summary>Runs the sample.</summary>
    /// <param name="args">Command line arguments.</param>
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // This is the whole integration.
        //
        // Optional is true here only because this is a sample someone may run without a
        // server to point it at. A real application should leave it false, so that failing to
        // reach its secrets is a startup failure rather than a null connection string
        // discovered later on a customer's request.
        builder.Configuration.AddKeysteadFromEnvironment(optional: true);

        // Reloading every thirty seconds, so a rotated secret reaches this process without a
        // restart. Shown explicitly rather than left at the default of load-once.
        builder.Configuration.AddKeystead(options =>
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

            options.ReloadInterval = TimeSpan.FromSeconds(30);
            options.Optional = true;
        });

        var app = builder.Build();

        app.MapGet("/", (IConfiguration configuration) =>
        {
            var connectionString = configuration.GetConnectionString("Default");

            // Reports only whether the value arrived and how long it is. Printing the value
            // would make this sample a demonstration of how to leak a secret, which is the
            // opposite of the point.
            return Results.Ok(new
            {
                message = "This value came from Keystead through IConfiguration.",
                connectionStringFound = connectionString is { Length: > 0 },
                connectionStringLength = connectionString?.Length ?? 0,

                // Keys only. Values are never listed.
                keysLoaded = configuration.AsEnumerable()
                    .Where(entry => entry.Value is not null)
                    .Select(entry => entry.Key)
                    .Where(key => key.StartsWith("ConnectionStrings", StringComparison.Ordinal)
                        || key.Contains("ApiKey", StringComparison.OrdinalIgnoreCase))
                    .OrderBy(key => key, StringComparer.Ordinal)
                    .ToList(),
            });
        });

        app.MapGet("/healthz", () => Results.Ok("ok"));

        app.Run();
    }
}
