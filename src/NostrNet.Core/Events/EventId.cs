// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;
using NostrNet.Encoding;

namespace NostrNet.Events;

/// <summary>
/// A 32-byte Nostr event identifier (SHA-256 of the canonical event serialization).
/// </summary>
public sealed class EventId : IEquatable<EventId>
{
    /// <summary>Length of an event id in bytes.</summary>
    public const int Size = 32;

    /// <summary>Human-readable prefix for NIP-19 bare-id bech32 encoding.</summary>
    public const string NoteHrp = "note";

    private readonly byte[] _bytes;

    /// <summary>Creates an event id from a 32-byte buffer.</summary>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is not 32 bytes long.</exception>
    public EventId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Size)
        {
            throw new ArgumentException($"Event id must be {Size} bytes.", nameof(bytes));
        }

        _bytes = bytes.ToArray();
    }

    /// <summary>Parses a 64-character lowercase hex string.</summary>
    public static EventId FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if (hex.Length != Size * 2)
        {
            throw new FormatException($"Event id hex must be {Size * 2} characters.");
        }

        return new EventId(Convert.FromHexString(hex));
    }

    /// <summary>Attempts to parse a hex event id. Returns <c>false</c> on any failure.</summary>
    public static bool TryFromHex(string? hex, [NotNullWhen(true)] out EventId? id)
    {
        id = null;
        if (hex is null || hex.Length != Size * 2)
        {
            return false;
        }

        try
        {
            id = new EventId(Convert.FromHexString(hex));
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

    /// <summary>Parses a NIP-19 <c>note1...</c> bech32 string.</summary>
    public static EventId FromNote(string note)
    {
        ArgumentNullException.ThrowIfNull(note);
        var decoded = Bech32.Decode(note);
        if (!string.Equals(decoded.Hrp, NoteHrp, StringComparison.Ordinal))
        {
            throw new FormatException($"Expected '{NoteHrp}' bech32 prefix.");
        }

        if (decoded.Data.Length != Size)
        {
            throw new FormatException($"note payload must be {Size} bytes; got {decoded.Data.Length}.");
        }

        return new EventId(decoded.Data);
    }

    /// <summary>Attempts to parse a <c>note</c> bech32 string. Returns <c>false</c> on any failure.</summary>
    public static bool TryFromNote(string? note, [NotNullWhen(true)] out EventId? id)
    {
        id = null;
        if (note is null)
        {
            return false;
        }

        try
        {
            id = FromNote(note);
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

    /// <summary>Returns the lowercase 64-character hex encoding.</summary>
    public string ToHex() => Convert.ToHexStringLower(_bytes);

    /// <summary>Returns the NIP-19 <c>note1...</c> bech32 encoding.</summary>
    public string ToNote() => Bech32.Encode(NoteHrp, _bytes);

    /// <summary>Returns a read-only view over the 32 raw bytes.</summary>
    public ReadOnlySpan<byte> AsSpan() => _bytes;

    /// <inheritdoc/>
    public bool Equals(EventId? other)
        => other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is EventId other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => BitConverter.ToInt32(_bytes, 0);

    /// <inheritdoc/>
    public override string ToString() => ToHex();

    /// <summary>Compares two event ids for value equality.</summary>
    public static bool operator ==(EventId? left, EventId? right)
        => left is null ? right is null : left.Equals(right);

    /// <summary>Compares two event ids for inequality.</summary>
    public static bool operator !=(EventId? left, EventId? right) => !(left == right);
}
