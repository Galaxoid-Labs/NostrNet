// SPDX-License-Identifier: MIT
//
// TLV (Type-Length-Value) record reader/writer used by NIP-19 entities
// (nprofile, nevent, naddr).
//
// Per-record wire format:
//   1 byte:  type tag
//   1 byte:  value length (0..255)
//   N bytes: value
//
// Records are concatenated. The same type may appear multiple times (e.g.,
// multiple "relay" records in an nprofile).
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/19.md

using System.Buffers;
using System.Buffers.Binary;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Encoding;

/// <summary>
/// Forward-only writer that appends NIP-19 TLV records to a destination buffer.
/// </summary>
/// <remarks>
/// All <c>TryWrite</c> methods return <c>false</c> without advancing the cursor
/// if the destination has insufficient space or the value exceeds the 255-byte
/// per-record length limit. The caller is responsible for sizing the buffer.
/// </remarks>
internal ref struct TlvWriter
{
    private readonly Span<byte> _destination;
    private int _written;

    /// <summary>
    /// Creates a writer that appends records into <paramref name="destination"/>.
    /// </summary>
    public TlvWriter(Span<byte> destination)
    {
        _destination = destination;
        _written = 0;
    }

    /// <summary>Number of bytes written so far.</summary>
    public readonly int BytesWritten => _written;

    /// <summary>Maximum value length encodable in a single TLV record.</summary>
    public const int MaxValueLength = 255;

    /// <summary>
    /// Appends a record with the given type tag and raw byte payload.
    /// </summary>
    /// <param name="type">The 1-byte type tag.</param>
    /// <param name="value">The payload (must be at most 255 bytes).</param>
    /// <returns><c>true</c> if the record fit; <c>false</c> otherwise.</returns>
    public bool TryWrite(byte type, scoped ReadOnlySpan<byte> value)
    {
        if (value.Length > MaxValueLength)
        {
            return false;
        }

        int needed = 2 + value.Length;
        if (_destination.Length - _written < needed)
        {
            return false;
        }

        _destination[_written] = type;
        _destination[_written + 1] = (byte)value.Length;
        value.CopyTo(_destination[(_written + 2)..]);
        _written += needed;
        return true;
    }

    /// <summary>
    /// Appends a record whose 4-byte value is a big-endian unsigned 32-bit integer.
    /// </summary>
    public bool TryWriteUInt32BigEndian(byte type, uint value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, value);
        return TryWrite(type, buf);
    }

    /// <summary>
    /// Appends a record whose value is the UTF-8 encoding of <paramref name="value"/>.
    /// </summary>
    /// <returns>
    /// <c>false</c> if the UTF-8 encoding exceeds 255 bytes or the destination
    /// has insufficient space.
    /// </returns>
    public bool TryWriteUtf8(byte type, scoped ReadOnlySpan<char> value)
    {
        int maxByteCount = SysEncoding.UTF8.GetMaxByteCount(value.Length);
        byte[]? rented = null;
        Span<byte> buf = maxByteCount <= 512
            ? stackalloc byte[512]
            : (rented = ArrayPool<byte>.Shared.Rent(maxByteCount));

        try
        {
            buf = buf[..maxByteCount];
            int actual = SysEncoding.UTF8.GetBytes(value, buf);
            return TryWrite(type, buf[..actual]);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }
}

/// <summary>
/// Forward-only reader over a buffer of concatenated NIP-19 TLV records.
/// </summary>
internal ref struct TlvReader
{
    private readonly ReadOnlySpan<byte> _source;
    private int _position;

    /// <summary>
    /// Creates a reader over <paramref name="source"/>.
    /// </summary>
    public TlvReader(ReadOnlySpan<byte> source)
    {
        _source = source;
        _position = 0;
    }

    /// <summary><c>true</c> while there is at least one unread byte.</summary>
    public readonly bool HasMore => _position < _source.Length;

    /// <summary>Number of bytes consumed so far.</summary>
    public readonly int BytesRead => _position;

    /// <summary>
    /// Attempts to read the next TLV record.
    /// </summary>
    /// <param name="type">Receives the record's type tag.</param>
    /// <param name="value">Receives a slice of the source buffer covering the value.</param>
    /// <returns>
    /// <c>true</c> if a complete record was read; <c>false</c> on end-of-input
    /// or a truncated trailing record.
    /// </returns>
    public bool TryReadNext(out byte type, out ReadOnlySpan<byte> value)
    {
        type = 0;
        value = default;

        if (_position + 2 > _source.Length)
        {
            return false;
        }

        byte t = _source[_position];
        byte len = _source[_position + 1];

        if (_position + 2 + len > _source.Length)
        {
            return false;
        }

        type = t;
        value = _source.Slice(_position + 2, len);
        _position += 2 + len;
        return true;
    }
}
