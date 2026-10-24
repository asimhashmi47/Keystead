using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Keystead.Client;

namespace Keystead.Cli;

/// <summary>
/// The <c>keystead</c> command line tool.
/// </summary>
/// <remarks>
/// <para>
/// Configured entirely by environment variables, the same ones the SDK reads. There is no
/// credential file on disk and no <c>login</c> that caches a token: a tool that wrote a
/// long-lived credential into the home directory would be the weakest part of this product,
/// and the token it would cache lives ten minutes anyway.
/// </para>
/// <para>
/// Hand-rolled argument parsing rather than a library. The surface is five commands, and the
/// one thing that genuinely needs care is the <c>--</c> separator in
/// <c>keystead run -- &lt;command&gt;</c>, where everything after it must reach the child
/// untouched.
/// </para>
/// </remarks>
public static class Program
{
    private const int ExitOk = 0;
    private const int ExitUsage = 64;
    private const int ExitConfig = 78;
    private const int ExitFailure = 70;

    /// <summary>Runs the tool.</summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>A process exit code.</returns>
    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            WriteUsage();
            return args.Length == 0 ? ExitUsage : ExitOk;
        }

        if (args[0] is "--version" or "-v")
        {
            Console.WriteLine(Version);
            return ExitOk;
        }

        using var cancellation = new CancellationTokenSource();

        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        try
        {
            return args[0] switch
            {
                "whoami" => await WhoAmIAsync(cancellation.Token).ConfigureAwait(false),
                "secret" => await SecretAsync(args, cancellation.Token).ConfigureAwait(false),
                "run" => await RunAsync(args, cancellation.Token).ConfigureAwait(false),
                "env" => await EnvAsync(cancellation.Token).ConfigureAwait(false),
                _ => Unknown(args[0]),
            };
        }
        catch (InvalidOperationException ex)
        {
            // Configuration problems: a missing endpoint, no client id, no vault.
            Error(ex.Message);
            return ExitConfig;
        }
        catch (KeysteadException ex)
        {
            Error(ex.Message);
            return ExitFailure;
        }
        catch (OperationCanceledException)
        {
            Error("Cancelled.");
            return ExitFailure;
        }
    }

    private static KeysteadClient CreateClient()
    {
        var options = new KeysteadOptions();

        var endpoint = Environment.GetEnvironmentVariable("KEYSTEAD_ENDPOINT");

        if (Uri.TryCreate(endpoint, UriKind.Absolute, out var parsed))
        {
            options.Endpoint = parsed;
        }

        options.ClientId = Environment.GetEnvironmentVariable("KEYSTEAD_CLIENT_ID");
        options.ClientSecret = Environment.GetEnvironmentVariable("KEYSTEAD_CLIENT_SECRET");

        if (Guid.TryParse(Environment.GetEnvironmentVariable("KEYSTEAD_VAULT_ID"), out var vaultId))
        {
            options.VaultId = vaultId;
        }

        options.Environment = Environment.GetEnvironmentVariable("KEYSTEAD_ENVIRONMENT") ?? "prod";

        return new KeysteadClient(options);
    }

    private static async Task<int> WhoAmIAsync(CancellationToken cancellationToken)
    {
        using var client = CreateClient();

        // Listing names is the cheapest call that proves the credentials and the grant work.
        var names = await client.ListSecretNamesAsync(cancellationToken).ConfigureAwait(false);

        Console.WriteLine($"Endpoint:    {Environment.GetEnvironmentVariable("KEYSTEAD_ENDPOINT")}");
        Console.WriteLine($"Client:      {Environment.GetEnvironmentVariable("KEYSTEAD_CLIENT_ID")}");
        Console.WriteLine($"Vault:       {Environment.GetEnvironmentVariable("KEYSTEAD_VAULT_ID")}");
        Console.WriteLine($"Environment: {Environment.GetEnvironmentVariable("KEYSTEAD_ENVIRONMENT") ?? "prod"}");
        Console.WriteLine($"Reachable:   {names.Count} secret(s)");

        return ExitOk;
    }

    private static async Task<int> SecretAsync(string[] args, CancellationToken cancellationToken)
    {
        if (args.Length < 2)
        {
            Error("Usage: keystead secret <list|get|set> ...");
            return ExitUsage;
        }

        using var client = CreateClient();

        switch (args[1])
        {
            case "list":
                {
                    var names = await client.ListSecretNamesAsync(cancellationToken)
                        .ConfigureAwait(false);

                    foreach (var name in names.OrderBy(n => n, StringComparer.Ordinal))
                    {
                        Console.WriteLine(name);
                    }

                    return ExitOk;
                }

            case "get":
                {
                    if (args.Length < 3)
                    {
                        Error("Usage: keystead secret get <name>");
                        return ExitUsage;
                    }

                    var value = await client.GetSecretAsync(args[2], cancellationToken)
                        .ConfigureAwait(false);

                    if (value is null)
                    {
                        Error($"No secret named '{args[2]}' is reachable.");
                        return ExitFailure;
                    }

                    // Written to stdout with no trailing newline, so it can be captured into a
                    // shell variable without a trailing byte that breaks a comparison. The
                    // diagnostics above went to stderr for the same reason.
                    Console.Out.Write(value);

                    return ExitOk;
                }

            case "set":
                {
                    if (args.Length < 4)
                    {
                        Error("Usage: keystead secret set <name> <value>");
                        return ExitUsage;
                    }

                    var version = await client.SetSecretAsync(args[2], args[3], cancellationToken)
                        .ConfigureAwait(false);

                    Error($"Wrote version {version.ToString(CultureInfo.InvariantCulture)} of {args[2]}.");

                    return ExitOk;
                }

            default:
                Error($"Unknown secret command '{args[1]}'.");
                return ExitUsage;
        }
    }

    private static async Task<int> EnvAsync(CancellationToken cancellationToken)
    {
        using var client = CreateClient();

        var loaded = await client.LoadConfigurationAsync(cancellationToken).ConfigureAwait(false);

        foreach (var (key, value) in loaded.OrderBy(e => e.Key, StringComparer.Ordinal))
        {
            var variable = SecretKeyMapping.ToEnvironmentVariable(
                SecretKeyMapping.ToSecretName(key));

            // Single-quoted with embedded quotes escaped, so a value containing a space, a
            // dollar sign or a backtick cannot be re-interpreted by the shell that evaluates
            // this. Printing it unquoted would make `eval $(keystead env)` an injection route
            // from whoever can write a secret.
            var escaped = (value ?? string.Empty).Replace("'", "'\\''", StringComparison.Ordinal);

            Console.WriteLine($"export {variable}='{escaped}'");
        }

        return ExitOk;
    }

    private static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        var separator = Array.IndexOf(args, "--");

        if (separator < 0 || separator == args.Length - 1)
        {
            Error("Usage: keystead run -- <command> [args...]");
            return ExitUsage;
        }

        var command = args[separator + 1];
        var commandArgs = args[(separator + 2)..];

        using var client = CreateClient();

        var loaded = await client.LoadConfigurationAsync(cancellationToken).ConfigureAwait(false);

        var startInfo = new ProcessStartInfo(command)
        {
            UseShellExecute = false,
        };

        foreach (var argument in commandArgs)
        {
            // ArgumentList, not a joined string. Joining would make a value containing a
            // space or a quote change how the child parses its own arguments.
            startInfo.ArgumentList.Add(argument);
        }

        var injected = 0;
        var skipped = new List<string>();

        foreach (var (key, value) in loaded)
        {
            var secretName = SecretKeyMapping.ToSecretName(key);

            if (!SecretKeyMapping.CanBeEnvironmentVariable(secretName))
            {
                // Skipped rather than mangled. A name that cannot be a variable name would
                // otherwise be silently renamed into something the child does not expect.
                skipped.Add(secretName);
                continue;
            }

            startInfo.Environment[SecretKeyMapping.ToEnvironmentVariable(secretName)] = value;
            injected++;
        }

        Error($"Injecting {injected.ToString(CultureInfo.InvariantCulture)} secret(s) into {command}.");

        if (skipped.Count > 0)
        {
            Error($"Skipped {skipped.Count.ToString(CultureInfo.InvariantCulture)} name(s) that cannot be environment variables: {string.Join(", ", skipped)}");
        }

        using var process = Process.Start(startInfo);

        if (process is null)
        {
            Error($"Could not start '{command}'.");
            return ExitFailure;
        }

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        // The child's exit code is this process's exit code, so `keystead run -- dotnet test`
        // can be used in a pipeline without swallowing a failure.
        return process.ExitCode;
    }

    private static int Unknown(string command)
    {
        Error($"Unknown command '{command}'.");
        WriteUsage();
        return ExitUsage;
    }

    private static void Error(string message) => Console.Error.WriteLine(message);

    private static string Version =>
        Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? "0.1.0-dev";

    private static void WriteUsage()
    {
        var output = Console.Error;

        output.WriteLine($"keystead {Version}");
        output.WriteLine();
        output.WriteLine("  Reads secrets from a Keystead server.");
        output.WriteLine();
        output.WriteLine("Commands:");
        output.WriteLine("  whoami                     Show the configured connection and what it can reach");
        output.WriteLine("  secret list                List the secret names you can read");
        output.WriteLine("  secret get <name>          Write one secret value to stdout");
        output.WriteLine("  secret set <name> <value>  Store a new version of a secret");
        output.WriteLine("  env                        Print the secrets as shell export lines");
        output.WriteLine("  run -- <command>           Run a command with the secrets in its environment");
        output.WriteLine();
        output.WriteLine("Configuration (environment variables):");
        output.WriteLine("  KEYSTEAD_ENDPOINT          The server base address");
        output.WriteLine("  KEYSTEAD_CLIENT_ID         A service identity client id");
        output.WriteLine("  KEYSTEAD_CLIENT_SECRET     Its client secret");
        output.WriteLine("  KEYSTEAD_VAULT_ID          The vault to read");
        output.WriteLine("  KEYSTEAD_ENVIRONMENT       The environment label (default: prod)");
        output.WriteLine();
        output.WriteLine("There is deliberately no 'login' that caches a credential on disk.");
        output.WriteLine("A name is accepted in either form: ConnectionStrings--Default or");
        output.WriteLine("ConnectionStrings:Default.");
    }
}
