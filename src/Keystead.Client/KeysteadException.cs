using System;

namespace Keystead.Client;

/// <summary>
/// A failure talking to a Keystead server.
/// </summary>
/// <remarks>
/// Carries a status and a problem detail, never a secret value and never the client secret
/// that was sent. An exception message ends up in a log, and a log is the place a credential
/// most often escapes from.
/// </remarks>
public sealed class KeysteadException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">What went wrong.</param>
    public KeysteadException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner cause.</summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The underlying failure.</param>
    public KeysteadException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with no message.</summary>
    public KeysteadException()
        : base("The Keystead request failed.")
    {
    }
}
