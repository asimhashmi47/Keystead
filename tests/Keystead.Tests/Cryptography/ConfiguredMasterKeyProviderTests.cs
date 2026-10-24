using System;
using System.IO;
using System.Security.Cryptography;
using Keystead.Application.Cryptography;
using Keystead.Infrastructure.Cryptography;
using Microsoft.Extensions.Options;
using Xunit;

namespace Keystead.Tests.Cryptography;

/// <summary>
/// The master key loader.
/// </summary>
/// <remarks>
/// Every other test in this suite uses an in-memory double, which left the real loader almost
/// untested. It is the component that decides whether the application starts at all and
/// whether a malformed or over-exposed key is accepted, so its failure paths matter more than
/// its happy path.
/// </remarks>
public sealed class ConfiguredMasterKeyProviderTests : IDisposable
{
    private readonly string _root;
    private readonly string _variable;

    public ConfiguredMasterKeyProviderTests()
    {
        _root = Path.Combine(
            Path.GetTempPath(),
            "keystead-masterkey-tests",
            Guid.CreateVersion7().ToString("N"));

        Directory.CreateDirectory(_root);

        // A unique variable name per instance, so xunit's parallel runs do not fight over the
        // process environment.
        _variable = "KEYSTEAD_TEST_KEY_" + Guid.CreateVersion7().ToString("N")[..12];
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(_variable, null);

        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static string NewKey() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeyMaterial.KeyLength));

    private ConfiguredMasterKeyProvider FromEnvironment(string? value)
    {
        Environment.SetEnvironmentVariable(_variable, value);

        return new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
        {
            Source = MasterKeySource.Environment,
            EnvironmentVariable = _variable,
            PepperEnvironmentVariable = _variable + "_PEPPER",
        }));
    }

    private ConfiguredMasterKeyProvider FromFile(string contents, string name = "master.key")
    {
        var path = Path.Combine(_root, name);
        File.WriteAllText(path, contents);

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
        {
            Source = MasterKeySource.File,
            FilePath = path,
            PepperEnvironmentVariable = _variable + "_PEPPER",
        }));
    }

    // -----------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------

    [Fact]
    public void AKeyFromTheEnvironmentIsLoaded()
    {
        var key = NewKey();

        using var provider = FromEnvironment(key);

        using var loaded = provider.GetActiveKey();

        Assert.Equal(Convert.FromBase64String(key), loaded.Span.ToArray());
        Assert.Equal(1, provider.ActiveVersion);
    }

    [Fact]
    public void AKeyFromAFileIsLoaded()
    {
        var key = NewKey();

        using var provider = FromFile(key);
        using var loaded = provider.GetActiveKey();

        Assert.Equal(Convert.FromBase64String(key), loaded.Span.ToArray());
    }

    [Fact]
    public void SurroundingWhitespaceInAKeyFileIsForgiven()
    {
        // A file written with a trailing newline is the normal case, not an error.
        var key = NewKey();

        using var provider = FromFile($"  {key}\n");
        using var loaded = provider.GetActiveKey();

        Assert.Equal(Convert.FromBase64String(key), loaded.Span.ToArray());
    }

    [Fact]
    public void EachCallGetsItsOwnCopyOfTheKey()
    {
        // The caller owns the handle and disposing it zeroes the buffer. Handing out the
        // stored array would destroy the key for everyone on the first dispose.
        using var provider = FromEnvironment(NewKey());

        using var first = provider.GetActiveKey();
        var expected = first.Span.ToArray();

        using (var second = provider.GetActiveKey())
        {
            Assert.Equal(expected, second.Span.ToArray());
        }

        // The first handle still works after the second was disposed.
        Assert.Equal(expected, first.Span.ToArray());
    }

    // -----------------------------------------------------------------------
    // Refusals. These are the point of the type.
    // -----------------------------------------------------------------------

    [Fact]
    public void AMissingEnvironmentKeyRefusesToStart()
    {
        // Starting without a key would give an application that looks healthy, accepts
        // writes, and cannot decrypt anything it stored.
        var exception = Assert.Throws<MasterKeyUnavailableException>(() => FromEnvironment(null));

        Assert.Contains(_variable, exception.Message, StringComparison.Ordinal);

        // The message tells an operator what to do, which is the whole value of failing here.
        Assert.Contains("base64", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnEmptyEnvironmentKeyRefusesToStart()
    {
        Assert.Throws<MasterKeyUnavailableException>(() => FromEnvironment("   "));
    }

    [Fact]
    public void AKeyThatIsNotBase64RefusesToStart()
    {
        var exception = Assert.Throws<MasterKeyUnavailableException>(
            () => FromEnvironment("this is not base64 at all !!!"));

        Assert.Contains("base64", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void AKeyOfTheWrongLengthRefusesToStart(int bytes)
    {
        // A 128-bit key silently accepted where 256 bits is promised would be an invisible
        // downgrade of every secret in the installation.
        var exception = Assert.Throws<MasterKeyUnavailableException>(
            () => FromEnvironment(Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes))));

        Assert.Contains(bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            exception.Message, StringComparison.Ordinal);
        Assert.Contains("256 bits", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingKeyFileRefusesToStart()
    {
        var missing = Path.Combine(_root, "nope.key");

        var exception = Assert.Throws<MasterKeyUnavailableException>(() =>
            new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
            {
                Source = MasterKeySource.File,
                FilePath = missing,
            })));

        Assert.Contains(missing, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AFileSourceWithNoPathConfiguredRefusesToStart()
    {
        var exception = Assert.Throws<MasterKeyUnavailableException>(() =>
            new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
            {
                Source = MasterKeySource.File,
                FilePath = null,
            })));

        Assert.Contains("FilePath", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnUnknownSourceRefusesToStart()
    {
        Assert.Throws<MasterKeyUnavailableException>(() =>
            new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
            {
                Source = (MasterKeySource)9999,
            })));
    }

    [Fact]
    public void AWorldReadableKeyFileRefusesToStart()
    {
        // The whole value of a file over an environment variable is that it can have an owner
        // and a mode. A file anyone can read gives up that advantage silently.
        if (OperatingSystem.IsWindows())
        {
            // File modes are a Unix concept; Windows relies on ACLs, which this check does not
            // attempt to interpret.
            return;
        }

        var path = Path.Combine(_root, "exposed.key");
        File.WriteAllText(path, NewKey());
        File.SetUnixFileMode(
            path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead);

        var exception = Assert.Throws<MasterKeyUnavailableException>(() =>
            new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
            {
                Source = MasterKeySource.File,
                FilePath = path,
            })));

        Assert.Contains("0600", exception.Message, StringComparison.Ordinal);
    }

    // -----------------------------------------------------------------------
    // Key check value
    // -----------------------------------------------------------------------

    [Fact]
    public void TheKeyCheckValueIsStableForTheSameKey()
    {
        var key = NewKey();

        using var first = FromEnvironment(key);
        var expected = first.ActiveKeyCheckValue;

        using var second = FromEnvironment(key);

        Assert.Equal(expected, second.ActiveKeyCheckValue);
    }

    [Fact]
    public void TheKeyCheckValueDiffersForADifferentKey()
    {
        using var first = FromEnvironment(NewKey());
        using var second = FromEnvironment(NewKey());

        Assert.NotEqual(first.ActiveKeyCheckValue, second.ActiveKeyCheckValue);
    }

    [Fact]
    public void TheKeyCheckValueIsTruncatedAndRevealsNothingUseful()
    {
        // Sixty-four bits: enough to detect a swapped key, far too short to help anyone
        // confirming a guess at the key itself.
        var key = NewKey();

        using var provider = FromEnvironment(key);

        Assert.Equal(16, provider.ActiveKeyCheckValue.Length);
        Assert.Matches("^[0-9a-f]{16}$", provider.ActiveKeyCheckValue);

        // It must not be a prefix of the key, or of a plain hash of it.
        Assert.DoesNotContain(
            provider.ActiveKeyCheckValue,
            Convert.ToHexStringLower(Convert.FromBase64String(key)),
            StringComparison.Ordinal);
    }

    [Fact]
    public void TheKeyCheckValueCanBeComputedWithoutAProvider()
    {
        // Used by the setup wizard, which records the fingerprint of the key the installation
        // was created under so a later mismatch is detectable.
        var key = RandomNumberGenerator.GetBytes(KeyMaterial.KeyLength);

        using var provider = FromEnvironment(Convert.ToBase64String(key));

        Assert.Equal(
            ConfiguredMasterKeyProvider.ComputeKeyCheckValue(key),
            provider.ActiveKeyCheckValue);
    }

    // -----------------------------------------------------------------------
    // Previous generations, for rotation
    // -----------------------------------------------------------------------

    [Fact]
    public void AnUnknownGenerationIsNotAvailable()
    {
        using var provider = FromEnvironment(NewKey());

        Assert.Null(provider.TryGetKey(99));
    }

    [Fact]
    public void TheActiveGenerationIsAvailableByNumber()
    {
        using var provider = FromEnvironment(NewKey());

        using var byNumber = provider.TryGetKey(provider.ActiveVersion);

        Assert.NotNull(byNumber);
    }

    [Fact]
    public void APreviousGenerationIsLoadedFromItsOwnVariable()
    {
        // Needed only while a rotation is in flight, so rows wrapped under the old key stay
        // readable until the re-wrap finishes.
        var current = NewKey();
        var previous = NewKey();
        var previousVariable = _variable + "_V1";

        Environment.SetEnvironmentVariable(_variable, current);
        Environment.SetEnvironmentVariable(previousVariable, previous);

        try
        {
            var options = new MasterKeyOptions
            {
                Source = MasterKeySource.Environment,
                EnvironmentVariable = _variable,
                ActiveVersion = 2,
            };

            options.PreviousVersions[1] = previousVariable;

            using var provider = new ConfiguredMasterKeyProvider(Options.Create(options));

            using var active = provider.GetActiveKey();
            using var old = provider.TryGetKey(1);

            Assert.Equal(2, provider.ActiveVersion);
            Assert.Equal(Convert.FromBase64String(current), active.Span.ToArray());
            Assert.NotNull(old);
            Assert.Equal(Convert.FromBase64String(previous), old!.Span.ToArray());
        }
        finally
        {
            Environment.SetEnvironmentVariable(previousVariable, null);
        }
    }

    [Fact]
    public void AMalformedPreviousGenerationRefusesToStart()
    {
        // A rotation configured with a broken old key must fail loudly, not leave rows
        // silently unreadable.
        var previousVariable = _variable + "_V1";

        Environment.SetEnvironmentVariable(_variable, NewKey());
        Environment.SetEnvironmentVariable(previousVariable, "not base64");

        try
        {
            var options = new MasterKeyOptions
            {
                Source = MasterKeySource.Environment,
                EnvironmentVariable = _variable,
                ActiveVersion = 2,
            };

            options.PreviousVersions[1] = previousVariable;

            Assert.Throws<MasterKeyUnavailableException>(
                () => new ConfiguredMasterKeyProvider(Options.Create(options)));
        }
        finally
        {
            Environment.SetEnvironmentVariable(previousVariable, null);
        }
    }

    // -----------------------------------------------------------------------
    // Pepper
    // -----------------------------------------------------------------------

    [Fact]
    public void NoPepperIsConfiguredByDefault()
    {
        // Absent is valid: password hashing then relies on the per-user salt alone, which is
        // still correct, just without the extra offline-attack barrier.
        using var provider = FromEnvironment(NewKey());

        Assert.True(provider.GetPasswordPepper().IsEmpty);
    }

    [Fact]
    public void APepperFromTheEnvironmentIsLoaded()
    {
        var pepper = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var pepperVariable = _variable + "_PEPPER";

        Environment.SetEnvironmentVariable(_variable, NewKey());
        Environment.SetEnvironmentVariable(pepperVariable, pepper);

        try
        {
            using var provider = new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
            {
                Source = MasterKeySource.Environment,
                EnvironmentVariable = _variable,
                PepperEnvironmentVariable = pepperVariable,
            }));

            Assert.Equal(Convert.FromBase64String(pepper), provider.GetPasswordPepper().ToArray());
        }
        finally
        {
            Environment.SetEnvironmentVariable(pepperVariable, null);
        }
    }

    [Fact]
    public void AMalformedPepperRefusesToStart()
    {
        var pepperVariable = _variable + "_PEPPER";

        Environment.SetEnvironmentVariable(_variable, NewKey());
        Environment.SetEnvironmentVariable(pepperVariable, "not base64 !!");

        try
        {
            var exception = Assert.Throws<MasterKeyUnavailableException>(() =>
                new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
                {
                    Source = MasterKeySource.Environment,
                    EnvironmentVariable = _variable,
                    PepperEnvironmentVariable = pepperVariable,
                })));

            Assert.Contains("pepper", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable(pepperVariable, null);
        }
    }

    // -----------------------------------------------------------------------
    // Disposal
    // -----------------------------------------------------------------------

    [Fact]
    public void DisposingZeroesTheHeldKeysAndRefusesFurtherUse()
    {
        var provider = FromEnvironment(NewKey());

        provider.Dispose();

        Assert.Throws<ObjectDisposedException>(() => provider.GetActiveKey());
        Assert.Throws<ObjectDisposedException>(() => provider.TryGetKey(1));
    }

    [Fact]
    public void DisposeIsIdempotent()
    {
        var provider = FromEnvironment(NewKey());

        provider.Dispose();
        provider.Dispose();
    }

    // -----------------------------------------------------------------------
    // The bootstrapper
    // -----------------------------------------------------------------------

    [Fact]
    public void TheBootstrapperGeneratesAUsableDevelopmentKey()
    {
        var path = Path.Combine(_root, "generated", "master.key");

        Assert.True(MasterKeyBootstrapper.EnsureKeyFile(path));
        Assert.True(File.Exists(path));

        using var provider = new ConfiguredMasterKeyProvider(Options.Create(new MasterKeyOptions
        {
            Source = MasterKeySource.ProtectedFile,
            FilePath = path,
            PepperEnvironmentVariable = _variable + "_PEPPER",
        }));

        using var key = provider.GetActiveKey();

        Assert.Equal(KeyMaterial.KeyLength, key.Span.Length);
    }

    [Fact]
    public void TheBootstrapperDoesNotReplaceAnExistingKey()
    {
        // Replacing one would make every stored secret undecryptable, silently.
        var path = Path.Combine(_root, "existing.key");

        Assert.True(MasterKeyBootstrapper.EnsureKeyFile(path));
        var original = File.ReadAllBytes(path);

        Assert.False(MasterKeyBootstrapper.EnsureKeyFile(path));
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Fact]
    public void TheBootstrapperRejectsAnEmptyPath()
    {
        Assert.Throws<ArgumentException>(() => MasterKeyBootstrapper.EnsureKeyFile("  "));
    }
}
