using Keystead.Web.Tables;
using Xunit;

namespace Keystead.Tests.Tables;

/// <summary>
/// Turning a user agent into something a person can act on.
/// </summary>
/// <remarks>
/// The security centre asks one question: do you recognise these sessions? The order of the
/// checks is the whole implementation, because every browser lies about being the others, and
/// these tests exist to pin that order down.
/// </remarks>
public sealed class DeviceSummaryTests
{
    [Theory]
    [InlineData(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Chrome on Windows")]
    [InlineData(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Safari on macOS")]
    [InlineData(
        "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Firefox on Linux")]
    [InlineData(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Safari on iPhone")]
    [InlineData(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        "Chrome on Android")]
    public void ARealAgent_BecomesAFewWords(string agent, string expected) =>
        Assert.Equal(expected, DeviceSummary.Describe(agent));

    [Fact]
    public void Edge_IsNotReportedAsChrome()
    {
        // Edge's agent carries "Chrome/" as well as "Edg/". Checking for Chrome first would
        // mean nobody using Edge ever sees their own browser named.
        const string Agent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";

        Assert.Equal("Edge on Windows", DeviceSummary.Describe(Agent));
    }

    [Fact]
    public void Chrome_IsNotReportedAsSafari()
    {
        const string Agent =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/131.0.0.0 Safari/537.36";

        Assert.Equal("Chrome on macOS", DeviceSummary.Describe(Agent));
    }

    [Fact]
    public void AnIPhone_IsNotReportedAsAMac()
    {
        // An iOS agent also says "like Mac OS X".
        Assert.Equal(
            "Safari on iPhone",
            DeviceSummary.Describe("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Safari/604.1"));
    }

    [Fact]
    public void AnAndroidPhone_IsNotReportedAsLinux()
    {
        Assert.Equal(
            "Chrome on Android",
            DeviceSummary.Describe("Mozilla/5.0 (Linux; Android 14) Chrome/131.0.0.0 Mobile Safari/537.36"));
    }

    [Theory]
    [InlineData("curl/8.4.0", "curl")]
    [InlineData("python-httpx/0.27.0", "A script")]
    [InlineData("python-requests/2.32.3", "A script")]
    public void SomethingThatIsNotABrowser_SaysSo(string agent, string expected)
    {
        // A session created by a script is exactly what someone scanning this page should
        // notice, so it is named rather than left as an unreadable string.
        Assert.Equal(expected, DeviceSummary.Describe(agent));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("unknown")]
    [InlineData("\u0001\u0002")]
    public void NothingUsable_IsSaidPlainly(string? agent) =>
        Assert.Equal(DeviceSummary.Unknown, DeviceSummary.Describe(agent));

    [Fact]
    public void APlatformWithoutARecognisedBrowser_StillNamesThePlatform()
    {
        Assert.Equal("Windows", DeviceSummary.Describe("Something/1.0 (Windows NT 10.0)"));
    }

    [Fact]
    public void TheResult_IsNeverEmpty()
    {
        // It is rendered straight into a table cell. An empty string there is a blank row that
        // looks like a rendering fault.
        Assert.False(string.IsNullOrWhiteSpace(DeviceSummary.Describe("x")));
    }
}
