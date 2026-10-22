using System;
using Keystead.Application.Cryptography;
using Xunit;

namespace Keystead.Tests.Cryptography;

public sealed class KeyMaterialTests
{
    [Fact]
    public void CreateRandom_ProducesA256BitKey()
    {
        using var key = KeyMaterial.CreateRandom();

        Assert.Equal(32, key.Span.Length);
    }

    [Fact]
    public void CreateRandom_ProducesADifferentKeyEachTime()
    {
        using var first = KeyMaterial.CreateRandom();
        using var second = KeyMaterial.CreateRandom();

        Assert.False(first.Span.SequenceEqual(second.Span));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public void CopyFrom_WithWrongLength_Throws(int length)
    {
        // A 128-bit key silently accepted where 256 bits is promised would be an invisible
        // downgrade, so the length is enforced rather than padded or truncated.
        Assert.Throws<ArgumentException>(() => KeyMaterial.CopyFrom(new byte[length]));
    }

    [Fact]
    public void Adopt_WithWrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() => KeyMaterial.Adopt(new byte[16]));
    }

    [Fact]
    public void Adopt_ZeroesTheCallerArrayOnDispose()
    {
        var raw = new byte[32];
        Array.Fill(raw, (byte)0xAB);

        var key = KeyMaterial.Adopt(raw);
        key.Dispose();

        Assert.All(raw, b => Assert.Equal(0, b));
    }

    [Fact]
    public void CopyFrom_DoesNotZeroTheCallerArrayOnDispose()
    {
        // CopyFrom takes a copy, so the caller keeps ownership of its own buffer. This is the
        // distinction between the two factories, and getting it backwards would either destroy
        // a caller's data or leave a key lying around.
        var raw = new byte[32];
        Array.Fill(raw, (byte)0xAB);

        var key = KeyMaterial.CopyFrom(raw);
        key.Dispose();

        Assert.All(raw, b => Assert.Equal(0xAB, b));
    }

    [Fact]
    public void Span_AfterDispose_Throws()
    {
        var key = KeyMaterial.CreateRandom();
        key.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
        {
            _ = key.Span.Length;
        });
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var key = KeyMaterial.CreateRandom();

        key.Dispose();
        key.Dispose();
    }
}
