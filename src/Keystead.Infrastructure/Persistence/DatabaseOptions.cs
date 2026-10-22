using System.ComponentModel.DataAnnotations;

namespace Keystead.Infrastructure.Persistence;

/// <summary>Where the database lives and how it is opened.</summary>
public sealed class DatabaseOptions
{
    /// <summary>The configuration section these options bind to.</summary>
    public const string SectionName = "Keystead:Database";

    /// <summary>
    /// Path to the SQLite file. The default sits in a <c>data</c> directory beside the
    /// application rather than under the web root: a database inside the served directory can
    /// be downloaded whole by anyone who guesses its name.
    /// </summary>
    [Required]
    [MinLength(1)]
    public string Path { get; set; } = "data/keystead.db";

    /// <summary>How long a writer waits for the write lock, in milliseconds.</summary>
    [Range(0, 60_000)]
    public int BusyTimeoutMs { get; set; } = 5_000;

    /// <summary>
    /// Optional SQLCipher key for whole-database encryption. Off by default: the stock
    /// <c>Microsoft.Data.Sqlite</c> native library ignores it, so enabling it without a
    /// SQLCipher build would give a false sense of protection.
    /// </summary>
    /// <remarks>
    /// This is defence in depth over the top of envelope encryption, not a substitute for it.
    /// Secret values are already individually sealed; SQLCipher additionally hides metadata
    /// such as secret names and the audit trail from someone who copies the file.
    /// </remarks>
    public string? SqlCipherKey { get; set; }

    /// <summary>Whether to run an integrity check on startup.</summary>
    public bool IntegrityCheckOnStartup { get; set; } = true;
}
