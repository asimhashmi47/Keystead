using System;
using System.Reflection;

namespace Keystead.Cli;

/// <summary>
/// The <c>keystead</c> command line tool.
/// </summary>
/// <remarks>
/// The full command surface (<c>login</c>, <c>vault list</c>, <c>secret get</c>,
/// <c>secret set</c>, <c>audit verify</c> and <c>run -- &lt;command&gt;</c>) is milestone M7,
/// and depends on the machine API from M5. What is here now is the real entry point and
/// version reporting, so the tool packages and runs rather than existing as an empty project.
/// </remarks>
public static class Program
{
    /// <summary>Runs the tool.</summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>A process exit code.</returns>
    public static int Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Length == 1 && (args[0] is "--version" or "-v"))
        {
            Console.WriteLine(Version);
            return 0;
        }

        WriteUsage();

        // Exit 64 (EX_USAGE) when invoked with no recognised command, so a script can tell
        // "you asked for something I do not have" from "I tried and failed".
        return args.Length == 0 ? 64 : 64;
    }

    private static string Version =>
        Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? "0.1.0-dev";

    private static void WriteUsage()
    {
        Console.WriteLine($"keystead {Version}");
        Console.WriteLine();
        Console.WriteLine("  A command line client for a Keystead secrets server.");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  keystead --version");
        Console.WriteLine();
        Console.WriteLine("The following commands are implemented in milestone M7, once the");
        Console.WriteLine("machine API they depend on is in place:");
        Console.WriteLine();
        Console.WriteLine("  login                      Authenticate against a Keystead server");
        Console.WriteLine("  vault list                 List vaults you can reach");
        Console.WriteLine("  secret get <name>          Read one secret value");
        Console.WriteLine("  secret set <name> <value>  Write a new version of a secret");
        Console.WriteLine("  audit verify               Verify the audit hash chain");
        Console.WriteLine("  run -- <command>           Run a command with secrets in its environment");
    }
}
