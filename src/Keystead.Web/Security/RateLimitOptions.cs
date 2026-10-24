using System.ComponentModel.DataAnnotations;

namespace Keystead.Web.Security;

/// <summary>
/// The ceilings the rate limiter enforces.
/// </summary>
/// <remarks>
/// <para>
/// These were constants until it became clear that the right numbers depend entirely on where
/// the deployment sits. A limiter partitions unauthenticated traffic by remote address, so an
/// installation behind a load balancer or inside a corporate network sees every caller as one
/// address and shares one bucket between all of them. The defaults here suit a small team
/// reaching the application directly; an operator in either of those positions has to be able
/// to raise them, and had no way to.
/// </para>
/// <para>
/// Raising them is not free and the ranges say so. The floor on every value is low enough to
/// be restrictive and high enough to stay usable, and the ceiling is the point past which the
/// limiter stops meaningfully bounding anything.
/// </para>
/// </remarks>
public sealed class RateLimitOptions
{
    /// <summary>The configuration section these options bind to.</summary>
    public const string SectionName = "Keystead:RateLimits";

    /// <summary>
    /// Sign-in attempts allowed per client in five minutes.
    /// </summary>
    /// <remarks>
    /// Counts submissions, never page views. Together with the per-account progressive lockout
    /// this bounds both "many guesses at one account" and "one guess at many accounts".
    /// </remarks>
    [Range(3, 200)]
    public int SignInAttemptsPerFiveMinutes { get; set; } = 10;

    /// <summary>Second-factor and step-up attempts allowed per client in five minutes.</summary>
    [Range(3, 200)]
    public int MfaAttemptsPerFiveMinutes { get; set; } = 10;

    /// <summary>
    /// Token issuances allowed per client each minute.
    /// </summary>
    /// <remarks>
    /// Issuing a token verifies a client secret with Argon2id, so this is a deliberate cost
    /// and the ceiling is set well below what a healthy deployment needs. A fleet that trips
    /// it is asking for a token per request instead of holding one until it expires.
    /// </remarks>
    [Range(5, 2000)]
    public int TokenIssuancesPerMinute { get; set; } = 30;

    /// <summary>The burst a single client may read before replenishment governs.</summary>
    [Range(10, 20000)]
    public int SecretReadBurst { get; set; } = 120;

    /// <summary>Secret reads replenished per client each minute.</summary>
    [Range(10, 20000)]
    public int SecretReadsPerMinute { get; set; } = 60;

    /// <summary>
    /// Requests of any kind allowed per client each minute.
    /// </summary>
    /// <remarks>
    /// The backstop under every other policy. It is the one most likely to need raising,
    /// because it is the one a shared source address saturates first.
    /// </remarks>
    [Range(60, 100000)]
    public int GlobalRequestsPerMinute { get; set; } = 600;
}
