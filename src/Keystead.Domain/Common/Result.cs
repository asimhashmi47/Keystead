using System;
using System.Diagnostics.CodeAnalysis;

namespace Keystead.Domain.Common;

/// <summary>
/// The outcome of an operation that is expected to fail in ordinary use.
/// </summary>
/// <remarks>
/// Expected failures (not found, forbidden, name taken) are values, not exceptions: an
/// exception carrying a secret value is exactly the leak CLAUDE.md rule 5 forbids, and a
/// Result makes the failure path impossible to forget at the call site.
/// </remarks>
/// <typeparam name="T">The value produced on success.</typeparam>
public readonly struct Result<T> : IEquatable<Result<T>>
{
    private readonly T? _value;

    private Result(T value)
    {
        _value = value;
        Error = null;
    }

    private Result(DomainError error)
    {
        _value = default;
        Error = error;
    }

    /// <summary>The failure, or <see langword="null"/> when the operation succeeded.</summary>
    public DomainError? Error { get; }

    /// <summary>Whether the operation succeeded.</summary>
    [MemberNotNullWhen(false, nameof(Error))]
    public bool IsSuccess => Error is null;

    /// <summary>The produced value. Throws when the result is a failure.</summary>
    /// <exception cref="InvalidOperationException">The result is a failure.</exception>
    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException(
            $"Result is a failure ({Error!.Code}); check IsSuccess before reading Value.");

    /// <summary>Creates a successful result.</summary>
    public static Result<T> Ok(T value) => new(value);

    /// <summary>Creates a failed result.</summary>
    public static Result<T> Fail(DomainError error) => new(error);

    /// <summary>Implicitly wraps a value as a successful result.</summary>
    public static implicit operator Result<T>(T value) => Ok(value);

    /// <summary>Implicitly wraps an error as a failed result.</summary>
    public static implicit operator Result<T>(DomainError error) => Fail(error);

    /// <inheritdoc />
    public bool Equals(Result<T> other) =>
        Equals(Error, other.Error) && Equals(_value, other._value);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Result<T> other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Error, _value);

    /// <summary>Equality operator.</summary>
    public static bool operator ==(Result<T> left, Result<T> right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(Result<T> left, Result<T> right) => !left.Equals(right);
}
