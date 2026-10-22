namespace Keystead.Web.Security;

/// <summary>The authentication scheme names this application defines.</summary>
public static class KeysteadSchemes
{
    /// <summary>
    /// The half-authenticated scheme used between the password step and the second factor.
    /// </summary>
    /// <remarks>
    /// A principal on this scheme has proved a password and nothing else. It must never be
    /// accepted by an authorization policy: the only thing it is good for is telling the MFA
    /// page which account is finishing sign-in.
    /// </remarks>
    public const string MfaPending = "KeysteadMfaPending";
}
