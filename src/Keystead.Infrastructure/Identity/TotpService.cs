using System;
using System.Globalization;
using System.Security.Cryptography;
using Keystead.Application.Cryptography;
using Keystead.Application.Identity;
using OtpNet;

namespace Keystead.Infrastructure.Identity;

/// <summary>
/// RFC 6238 time-based one-time passwords, with the shared secret sealed under the master key.
/// </summary>
/// <remarks>
/// <para>
/// The seed is never stored in plaintext. An attacker holding the database must not be able to
/// mint valid second factors, which is exactly what a plaintext TOTP seed column would hand
/// them. The seed is sealed with AAD binding it to its user, so a seed row cannot be moved to
/// another account.
/// </para>
/// <para>
/// A correct code is single-use. RFC 6238 only says a code is valid for its time step, which
/// means a code shoulder-surfed or captured from a phishing proxy stays usable for the rest of
/// that step and the skew window either side. Recording the highest consumed step per user and
/// refusing anything at or below it closes that, at the cost of one column.
/// </para>
/// </remarks>
public sealed class TotpService : ITotpService
{
    private const int SeedLengthBytes = 20;
    private const int StepSeconds = 30;
    private const string Issuer = "Keystead";

    private readonly IAeadCipher _cipher;
    private readonly IMasterKeyProvider _masterKeys;

    /// <summary>Creates the service.</summary>
    /// <param name="cipher">The AEAD primitive.</param>
    /// <param name="masterKeys">Supplies the master key the seed is sealed under.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public TotpService(IAeadCipher cipher, IMasterKeyProvider masterKeys)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        ArgumentNullException.ThrowIfNull(masterKeys);

        _cipher = cipher;
        _masterKeys = masterKeys;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentException"><paramref name="accountLabel"/> is null or empty.</exception>
    public TotpEnrolment CreateEnrolment(Guid userId, string accountLabel)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountLabel);

        // 160 bits, the RFC 4226 recommended seed length.
        var seed = RandomNumberGenerator.GetBytes(SeedLengthBytes);

        try
        {
            var version = _masterKeys.ActiveVersion;
            var context = CryptoContext.ForTotpSeed(userId, version);

            using var masterKey = _masterKeys.GetActiveKey();
            var blob = _cipher.Seal(masterKey, seed, context);

            var base32 = Base32Encoding.ToString(seed);

            var uri = string.Format(
                CultureInfo.InvariantCulture,
                "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&algorithm=SHA1&digits=6&period={3}",
                Uri.EscapeDataString(Issuer),
                Uri.EscapeDataString(accountLabel),
                base32,
                StepSeconds);

            return new TotpEnrolment(
                base32,
                uri,
                new StoredTotpSeed(blob.Ciphertext, blob.Nonce, blob.Tag, version));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="seed"/> is null.</exception>
    public TotpVerification Verify(
        Guid userId,
        StoredTotpSeed seed,
        string code,
        long? lastUsedWindow)
    {
        ArgumentNullException.ThrowIfNull(seed);

        if (string.IsNullOrWhiteSpace(code))
        {
            return TotpVerification.Failed;
        }

        var masterKey = _masterKeys.TryGetKey(seed.MasterKeyVersion);

        if (masterKey is null)
        {
            // The generation that sealed this seed is not loaded. Treated as a failure rather
            // than an exception so it cannot be used to distinguish accounts, but it is a
            // configuration problem: a retired master key version was dropped too early.
            return TotpVerification.Failed;
        }

        byte[]? recovered = null;

        try
        {
            var context = CryptoContext.ForTotpSeed(userId, seed.MasterKeyVersion);
            var blob = new SealedBlob(seed.Ciphertext, seed.Nonce, seed.Tag);

            recovered = _cipher.Open(masterKey, blob, context);

            var totp = new Totp(recovered, step: StepSeconds, mode: OtpHashMode.Sha1, totpSize: 6);

            // One step either side, which is the usual allowance for clock drift between a
            // phone and a server. Wider would make the replay window larger for no real gain.
            var window = new VerificationWindow(previous: 1, future: 1);

            if (!totp.VerifyTotp(code, out var matchedStep, window))
            {
                return TotpVerification.Failed;
            }

            // Replay check: a step already consumed is refused even though the code is correct.
            if (lastUsedWindow is { } used && matchedStep <= used)
            {
                return TotpVerification.Failed;
            }

            return new TotpVerification(true, matchedStep);
        }
        catch (CryptographicException)
        {
            // The seed did not authenticate: tampered, or moved from another user's row.
            return TotpVerification.Failed;
        }
        finally
        {
            if (recovered is not null)
            {
                CryptographicOperations.ZeroMemory(recovered);
            }

            masterKey.Dispose();
        }
    }
}
