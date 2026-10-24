using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace Keystead.SecurityTests;

/// <summary>
/// Enforces the source-level rules in CLAUDE.md that no runtime test can check.
/// </summary>
/// <remarks>
/// A grep over the source is a blunt instrument, and it is the right one here. The rules these
/// tests enforce are absolute, so the check can be an absolute count of zero rather than a
/// list of blessed exemptions that grows until it means nothing. If one of these ever needs an
/// exception, that is a design conversation, and failing this test is how the conversation
/// starts.
/// </remarks>
public sealed class SourceRuleTests
{
    private static string RepositoryRoot
    {
        get
        {
            // Walks up from the test assembly until the solution file appears, so the tests do
            // not depend on where the runner was started from.
            var directory = new DirectoryInfo(AppContext.BaseDirectory);

            while (directory is not null
                && !File.Exists(Path.Combine(directory.FullName, "Keystead.slnx")))
            {
                directory = directory.Parent;
            }

            Assert.NotNull(directory);
            return directory!.FullName;
        }
    }

    private static IEnumerable<string> SourceFiles(params string[] extensions)
    {
        var root = Path.Combine(RepositoryRoot, "src");

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            if (extensions.Any(e => file.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
            {
                yield return file;
            }
        }
    }

    private static List<string> Matches(Regex pattern, params string[] extensions)
    {
        var hits = new List<string>();

        foreach (var file in SourceFiles(extensions))
        {
            var text = File.ReadAllText(file);

            if (pattern.IsMatch(text))
            {
                var relative = Path.GetRelativePath(RepositoryRoot, file);

                foreach (var match in pattern.Matches(text).Cast<Match>())
                {
                    var line = text[..match.Index].Count(c => c == '\n') + 1;
                    hits.Add($"{relative}:{line}  {match.Value.Trim()}");
                }
            }
        }

        return hits;
    }

    [Fact]
    public void NothingBypassesRazorEncoding()
    {
        // CLAUDE.md rule 9. Html.Raw is how a cross-site scripting hole gets into a Razor
        // application, and this product renders names that users control.
        var hits = Matches(new Regex(@"Html\.Raw", RegexOptions.None), ".cshtml", ".cs");

        Assert.True(hits.Count == 0, $"Found Html.Raw:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void ThereIsNoInlineScript()
    {
        // A strict nonce policy is only as good as the markup. An inline script would be
        // blocked by the policy anyway, so this catches it at review time rather than as a
        // mysteriously broken page.
        var hits = Matches(
            new Regex(@"<script(?![^>]*\ssrc=)[^>]*>\s*\S", RegexOptions.IgnoreCase),
            ".cshtml");

        Assert.True(hits.Count == 0, $"Found inline script:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void ThereAreNoInlineEventHandlers()
    {
        var hits = Matches(
            new Regex(@"\son(click|change|submit|load|error|input|focus|blur|mouseover)\s*=", RegexOptions.IgnoreCase),
            ".cshtml");

        Assert.True(hits.Count == 0, $"Found inline handlers:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void ThereAreNoInlineStyleAttributes()
    {
        // The policy is style-src 'self' 'nonce-...' with no 'unsafe-inline', and a style
        // attribute cannot carry a nonce, so the browser discards every one of these. The
        // failure is silent: the page still renders, just with the margin or the alignment
        // quietly missing, which is exactly the kind of thing that survives review. The fix is
        // a class in the stylesheet, never 'unsafe-inline' in the policy.
        var hits = Matches(
            new Regex(@"\sstyle\s*=\s*""[^""]+""", RegexOptions.IgnoreCase),
            ".cshtml");

        Assert.True(hits.Count == 0, $"Found inline style attributes:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void TheSelfHostedFontsArePresent()
    {
        // The stylesheet names these files and the policy forbids fetching a font from anyone
        // else, so a missing file is not a fallback: it is the product rendering in whatever
        // the platform happens to offer. That failure is silent too, and this is what catches
        // it before a release does.
        var stylesheet = Path.Combine(
            RepositoryRoot, "src", "Keystead.Web", "wwwroot", "css", "keystead.css");

        var css = File.ReadAllText(stylesheet);
        var referenced = Regex.Matches(css, @"url\(""(/fonts/[^""]+)""\)")
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(referenced);

        foreach (var reference in referenced)
        {
            var path = Path.Combine(
                RepositoryRoot,
                "src",
                "Keystead.Web",
                "wwwroot",
                reference.TrimStart('/').Replace('/', Path.DirectorySeparatorChar));

            Assert.True(File.Exists(path), $"The stylesheet asks for {reference}, which is not in wwwroot.");
        }

        // An open font licence has to travel with the files it covers.
        Assert.True(
            File.Exists(Path.Combine(RepositoryRoot, "src", "Keystead.Web", "wwwroot", "fonts", "OFL.txt")),
            "The font licence is missing from wwwroot/fonts.");
    }

    [Fact]
    public void NothingIsLoadedFromAThirdParty()
    {
        // Self-hosting every asset is a policy requirement, not a preference: the CSP names
        // only 'self', so a CDN reference would be blocked. It is also a supply chain
        // decision, since a script from someone else's host runs with this origin's rights.
        var hits = Matches(
            new Regex(@"https?://(?!localhost|127\.0\.0\.1|keystead\.example\.com|keystead\.dev|www\.w3\.org|learn\.microsoft\.com|motion\.dev)[a-z0-9.-]+/[^\s""')]*\.(js|css|woff2?|ttf)", RegexOptions.IgnoreCase),
            ".cshtml", ".css", ".js");

        Assert.True(hits.Count == 0, $"Found third-party assets:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void ThereIsNoEval()
    {
        var hits = Matches(
            new Regex(@"\b(eval|new\s+Function)\s*\(", RegexOptions.None),
            ".js");

        Assert.True(hits.Count == 0, $"Found eval:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void ScriptsUseTextContentRatherThanInnerHtml()
    {
        // The palette builds result rows from names that come out of the database. Building
        // that markup with innerHTML would be an injection route from anyone who can name a
        // secret.
        var hits = Matches(new Regex(@"\.innerHTML\s*=", RegexOptions.None), ".js");

        Assert.True(hits.Count == 0, $"Found innerHTML assignment:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void NoSqlIsBuiltByConcatenation()
    {
        // CLAUDE.md rule 10. The analyzer rules CA2100 and CA3001 are errors too; this catches
        // the shape before the analyzer has to.
        var hits = Matches(
            new Regex(@"(FromSqlRaw|ExecuteSqlRaw)\s*\(\s*(\$""|[a-zA-Z_][a-zA-Z0-9_]*\s*\+)", RegexOptions.None),
            ".cs");

        Assert.True(hits.Count == 0, $"Found concatenated SQL:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void NoWeakCryptographicPrimitiveIsUsed()
    {
        // MD5 and SHA-1 appear nowhere. SHA-1 is reachable only inside the TOTP library, which
        // is what RFC 6238 specifies and is not a collision-sensitive use.
        var hits = Matches(
            new Regex(@"\b(MD5|SHA1|TripleDES|RC2|DES)\.(Create|HashData)", RegexOptions.None),
            ".cs");

        Assert.True(hits.Count == 0, $"Found weak primitives:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void NoCipherModeOtherThanGcmIsUsed()
    {
        // CLAUDE.md rule 3. CBC or ECB would be unauthenticated encryption, which is the
        // mistake this product cannot afford.
        var hits = Matches(
            new Regex(@"CipherMode\.(CBC|ECB|CFB|OFB)|new\s+AesCcm\s*\(", RegexOptions.None),
            ".cs");

        Assert.True(hits.Count == 0, $"Found non-GCM cipher usage:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void NoSecretComparisonUsesEquality()
    {
        // CLAUDE.md rule 6. Comparing a hash or tag with == leaks where it first differs.
        var hits = Matches(
            new Regex(@"(Hash|Tag|Digest|Token|Secret)\s*(==|!=)\s*[a-zA-Z_]", RegexOptions.None),
            ".cs");

        Assert.True(hits.Count == 0, $"Found equality on secret-derived bytes:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void ThereAreNoUnfinishedSecurityCriticalPlaceholders()
    {
        // CLAUDE.md rule 1. A TODO in a file that touches a key is the thing that gets
        // shipped and forgotten.
        var hits = new List<string>();

        foreach (var file in SourceFiles(".cs"))
        {
            var relative = Path.GetRelativePath(RepositoryRoot, file);

            var isSecurityCritical =
                relative.Contains("Cryptography", StringComparison.OrdinalIgnoreCase)
                || relative.Contains("Identity", StringComparison.OrdinalIgnoreCase)
                || relative.Contains("Tokens", StringComparison.OrdinalIgnoreCase)
                || relative.Contains("Auditing", StringComparison.OrdinalIgnoreCase)
                || relative.Contains("Authorization", StringComparison.OrdinalIgnoreCase);

            if (!isSecurityCritical)
            {
                continue;
            }

            var text = File.ReadAllText(file);

            foreach (var marker in new[] { "TODO", "FIXME", "HACK", "XXX" })
            {
                if (text.Contains(marker, StringComparison.Ordinal))
                {
                    hits.Add($"{relative}  contains {marker}");
                }
            }
        }

        Assert.True(hits.Count == 0, $"Found placeholders in security-critical code:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void NoSecretIsCommittedInConfiguration()
    {
        // CLAUDE.md rule 11. A master key in appsettings.json is a committed master key, which
        // is the single worst outcome for this product.
        var hits = new List<string>();

        foreach (var file in SourceFiles(".json"))
        {
            var text = File.ReadAllText(file);
            var relative = Path.GetRelativePath(RepositoryRoot, file);

            // A base64 run long enough to be a 256-bit key, or anything shaped like a client
            // secret. The configuration files should name where a key lives, never hold one.
            if (Regex.IsMatch(text, @"[A-Za-z0-9+/]{43}=") || text.Contains("ksd_live_", StringComparison.Ordinal))
            {
                hits.Add(relative);
            }
        }

        Assert.True(hits.Count == 0, $"Found key-shaped values in configuration:{Environment.NewLine}{string.Join(Environment.NewLine, hits)}");
    }

    [Fact]
    public void TheGitignoreExcludesKeyAndDatabaseFiles()
    {
        // Belt and braces for the rule above: the patterns that stop a generated key or a
        // database file being committed by accident.
        var gitignore = File.ReadAllText(Path.Combine(RepositoryRoot, ".gitignore"));

        foreach (var pattern in new[] { "*.key", "*.db", "master.key", ".keystead/", "*.pem" })
        {
            Assert.Contains(pattern, gitignore, StringComparison.Ordinal);
        }
    }
}
