// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;

namespace NostrNet.Events;

/// <summary>
/// A 64-byte BIP-340 Schnorr signature (concatenation of <c>r</c> and <c>s</c>).
/// </summary>
public sealed class Signature : IEquatable<Signature>
{
    /// <summary>Length of a BIP-340 signature in bytes.</summary>
    public const int Size = 64;

    private readonly byte[] _bytes;

    /// <summary>Creates a signature from a 64-byte buffer.</summary>
    public Signature(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Size)
        {
            throw new ArgumentException($"Signature must be {Size} bytes.", nameof(bytes));
        }

        _bytes = bytes.ToArray();
    }

    /// <summary>Parses a 128-character lowercase hex string.</summary>
    public static Signature FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if (hex.Length != Size * 2)
        {
            throw new FormatException($"Signature hex must be {Size * 2} characters.");
        }

        return new Signature(Convert.FromHexString(hex));
    }

    /// <summary>Attempts to parse a hex signature. Returns <c>false</c> on any failure.</summary>
    public static bool TryFromHex(string? hex, [NotNullWhen(true)] out Signature? signature)
    {
        signature = null;
        if (hex is null || hex.Length != Size * 2)
        {
            return false;
        }

        try
        {
            signature = new Signature(Convert.FromHexString(hex));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>Returns the lowercase 128-character hex encoding.</summary>
    public string ToHex() => Convert.ToHexStringLower(_bytes);

    /// <summary>Returns a read-only view over the 64 raw bytes.</summary>
    public ReadOnlySpan<byte> AsSpan() => _bytes;

    /// <inheritdoc/>
    public bool Equals(Signature? other)
        => other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Signature other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => BitConverter.ToInt32(_bytes, 0);

    /// <inheritdoc/>
    public override string ToString() => ToHex();
}
