// SPDX-License-Identifier: MIT
//
// TLS presentation-language encoder/decoder with QUIC variable-length
// integer prefixes for opaque vectors, as used by MLS (RFC 9420) and
// required by the Marmot Group Data extension (MIP-01).
//
// References:
//   - TLS presentation language: RFC 8446 §3
//   - QUIC varint: RFC 9000 §16
//
// Wire format for varints:
//   Bits 6-7 of the first byte select length:
//     0b00xxxxxx           1 byte   value 0..63
//     0b01xxxxxx xxxxxxxx  2 bytes  value 0..16,383
//     0b10xxxxxx + 3 more  4 bytes  value 0..1,073,741,823
//     0b11xxxxxx + 7 more  8 bytes  value 0..4,611,686,018,427,387,903

using System.Buffers.Binary;

namespace NostrNet.Marmot.Encoding;

/// <summary>
/// Forward-only writer for TLS presentation-language wire format with
/// QUIC variable-length integer length prefixes.
/// </summary>
public ref struct TlsWriter
{
    private readonly Span<byte> _destination;
    private int _written;

    /// <summary>Wraps <paramref name="destination"/> as a writable byte buffer.</summary>
    public TlsWriter(Span<byte> destination)
    {
        _destination = destination;
        _written = 0;
    }

    /// <summary>Number of bytes written so far.</summary>
    public readonly int BytesWritten => _written;

    /// <summary>Writes a single byte (a <c>uint8</c> in TLS terms).</summary>
    public void WriteUInt8(byte value)
    {
        EnsureSpace(1);
        _destination[_written++] = value;
    }

    /// <summary>Writes a 16-bit unsigned big-endian integer (<c>uint16</c>).</summary>
    public void WriteUInt16BigEndian(ushort value)
    {
        EnsureSpace(2);
        BinaryPrimitives.WriteUInt16BigEndian(_destination[_written..], value);
        _written += 2;
    }

    /// <summary>Writes a 32-bit unsigned big-endian integer (<c>uint32</c>).</summary>
    public void WriteUInt32BigEndian(uint value)
    {
        EnsureSpace(4);
        BinaryPrimitives.WriteUInt32BigEndian(_destination[_written..], value);
        _written += 4;
    }

    /// <summary>Writes a 64-bit unsigned big-endian integer (<c>uint64</c>).</summary>
    public void WriteUInt64BigEndian(ulong value)
    {
        EnsureSpace(8);
        BinaryPrimitives.WriteUInt64BigEndian(_destination[_written..], value);
        _written += 8;
    }

    /// <summary>Writes raw bytes verbatim, with no length prefix.</summary>
    public void WriteRaw(scoped ReadOnlySpan<byte> bytes)
    {
        EnsureSpace(bytes.Length);
        bytes.CopyTo(_destination[_written..]);
        _written += bytes.Length;
    }

    /// <summary>
    /// Writes a variable-length integer using QUIC varint encoding (RFC 9000 §16).
    /// Used as the length prefix on opaque/variable-length TLS vectors per the
    /// <c>tls_codec</c> Rust crate convention adopted by MLS.
    /// </summary>
    public void WriteVarInt(ulong value)
    {
        if (value < (1UL << 6))
        {
            EnsureSpace(1);
            _destination[_written++] = (byte)value;
        }
        else if (value < (1UL << 14))
        {
            EnsureSpace(2);
            _destination[_written++] = (byte)(0x40 | (value >> 8));
            _destination[_written++] = (byte)value;
        }
        else if (value < (1UL << 30))
        {
            EnsureSpace(4);
            _destination[_written] = (byte)(0x80 | (value >> 24));
            _destination[_written + 1] = (byte)(value >> 16);
            _destination[_written + 2] = (byte)(value >> 8);
            _destination[_written + 3] = (byte)value;
            _written += 4;
        }
        else if (value < (1UL << 62))
        {
            EnsureSpace(8);
            _destination[_written] = (byte)(0xC0 | (value >> 56));
            _destination[_written + 1] = (byte)(value >> 48);
            _destination[_written + 2] = (byte)(value >> 40);
            _destination[_written + 3] = (byte)(value >> 32);
            _destination[_written + 4] = (byte)(value >> 24);
            _destination[_written + 5] = (byte)(value >> 16);
            _destination[_written + 6] = (byte)(value >> 8);
            _destination[_written + 7] = (byte)value;
            _written += 8;
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(value), "QUIC varints encode at most 2^62 − 1.");
        }
    }

    /// <summary>
    /// Writes a variable-length opaque byte vector: QUIC varint length
    /// followed by the bytes verbatim.
    /// </summary>
    public void WriteOpaqueVarInt(scoped ReadOnlySpan<byte> bytes)
    {
        WriteVarInt((ulong)bytes.Length);
        WriteRaw(bytes);
    }

    /// <summary>
    /// Returns the number of bytes a varint occupies for <paramref name="value"/>.
    /// </summary>
    public static int VarIntLength(ulong value)
    {
        if (value < (1UL << 6)) return 1;
        if (value < (1UL << 14)) return 2;
        if (value < (1UL << 30)) return 4;
        if (value < (1UL << 62)) return 8;
        throw new ArgumentOutOfRangeException(nameof(value), "QUIC varints encode at most 2^62 − 1.");
    }

    private void EnsureSpace(int needed)
    {
        if (_destination.Length - _written < needed)
        {
            throw new InvalidOperationException(
                $"TlsWriter destination is too small: need {needed} more bytes, have {_destination.Length - _written}.");
        }
    }
}

/// <summary>
/// Forward-only reader for TLS presentation-language wire format with
/// QUIC variable-length integer length prefixes.
/// </summary>
public ref struct TlsReader
{
    private readonly ReadOnlySpan<byte> _source;
    private int _position;

    /// <summary>Creates a reader over <paramref name="source"/>.</summary>
    public TlsReader(ReadOnlySpan<byte> source)
    {
        _source = source;
        _position = 0;
    }

    /// <summary>Number of bytes consumed so far.</summary>
    public readonly int BytesRead => _position;

    /// <summary>True if more bytes remain unread.</summary>
    public readonly bool HasMore => _position < _source.Length;

    /// <summary>Number of unread bytes.</summary>
    public readonly int Remaining => _source.Length - _position;

    /// <summary>Reads a single byte (<c>uint8</c>).</summary>
    public byte ReadUInt8()
    {
        EnsureAvailable(1);
        return _source[_position++];
    }

    /// <summary>Reads a 16-bit unsigned big-endian integer.</summary>
    public ushort ReadUInt16BigEndian()
    {
        EnsureAvailable(2);
        ushort v = BinaryPrimitives.ReadUInt16BigEndian(_source[_position..]);
        _position += 2;
        return v;
    }

    /// <summary>Reads a 32-bit unsigned big-endian integer.</summary>
    public uint ReadUInt32BigEndian()
    {
        EnsureAvailable(4);
        uint v = BinaryPrimitives.ReadUInt32BigEndian(_source[_position..]);
        _position += 4;
        return v;
    }

    /// <summary>Reads a 64-bit unsigned big-endian integer.</summary>
    public ulong ReadUInt64BigEndian()
    {
        EnsureAvailable(8);
        ulong v = BinaryPrimitives.ReadUInt64BigEndian(_source[_position..]);
        _position += 8;
        return v;
    }

    /// <summary>
    /// Reads <paramref name="count"/> raw bytes (no length prefix), returning
    /// a slice that references the underlying buffer.
    /// </summary>
    public ReadOnlySpan<byte> ReadRaw(int count)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        EnsureAvailable(count);
        var slice = _source.Slice(_position, count);
        _position += count;
        return slice;
    }

    /// <summary>Reads a QUIC variable-length integer.</summary>
    public ulong ReadVarInt()
    {
        EnsureAvailable(1);
        byte first = _source[_position];
        int prefix = first >> 6;
        int length = 1 << prefix;     // 0→1, 1→2, 2→4, 3→8

        EnsureAvailable(length);
        ulong value = (ulong)(first & 0x3F);
        for (int i = 1; i < length; i++)
        {
            value = (value << 8) | _source[_position + i];
        }

        _position += length;
        return value;
    }

    /// <summary>
    /// Reads a variable-length opaque byte vector: a QUIC varint length
    /// followed by that many bytes. The returned span references the
    /// underlying buffer.
    /// </summary>
    public ReadOnlySpan<byte> ReadOpaqueVarInt()
    {
        ulong length = ReadVarInt();
        if (length > (ulong)int.MaxValue)
        {
            throw new InvalidDataException($"Opaque vector length {length} exceeds Int32.MaxValue.");
        }

        return ReadRaw((int)length);
    }

    private readonly void EnsureAvailable(int count)
    {
        if (_source.Length - _position < count)
        {
            throw new InvalidDataException(
                $"TlsReader ran out of bytes: needed {count}, have {_source.Length - _position}.");
        }
    }
}
