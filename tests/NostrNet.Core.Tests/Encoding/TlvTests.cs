// SPDX-License-Identifier: MIT
//
// Unit tests for the NIP-19 TLV reader/writer.
//
// Higher-level integration (against the published NIP-19 nprofile/nevent/naddr
// vectors) lives with the Nip19 tests once that layer is implemented.

using NostrNet.Encoding;

namespace NostrNet.Tests.Encoding;

public class TlvTests
{
    [Fact]
    public void RoundTrip_MultipleRecords()
    {
        Span<byte> buffer = stackalloc byte[512];
        var writer = new TlvWriter(buffer);

        ReadOnlySpan<byte> pubkey = stackalloc byte[]
        {
            0x3b, 0xf0, 0xc6, 0x3f, 0xcb, 0x93, 0x46, 0x34,
            0x07, 0xaf, 0x97, 0xa5, 0xe5, 0xee, 0x64, 0xfa,
            0x88, 0x3d, 0x10, 0x7e, 0xf9, 0xe5, 0x58, 0x47,
            0x2c, 0x4e, 0xb9, 0xaa, 0xae, 0xfa, 0x45, 0x9d,
        };

        Assert.True(writer.TryWrite(0, pubkey));
        Assert.True(writer.TryWriteUtf8(1, "wss://relay.example.com"));
        Assert.True(writer.TryWriteUtf8(1, "wss://other.example.com"));
        Assert.True(writer.TryWriteUInt32BigEndian(3, 30023u));

        var reader = new TlvReader(buffer[..writer.BytesWritten]);

        Assert.True(reader.TryReadNext(out byte t0, out var v0));
        Assert.Equal(0, t0);
        Assert.True(pubkey.SequenceEqual(v0));

        Assert.True(reader.TryReadNext(out byte t1, out var v1));
        Assert.Equal(1, t1);
        Assert.Equal("wss://relay.example.com", System.Text.Encoding.UTF8.GetString(v1));

        Assert.True(reader.TryReadNext(out byte t2, out var v2));
        Assert.Equal(1, t2);
        Assert.Equal("wss://other.example.com", System.Text.Encoding.UTF8.GetString(v2));

        Assert.True(reader.TryReadNext(out byte t3, out var v3));
        Assert.Equal(3, t3);
        Assert.Equal(4, v3.Length);
        Assert.Equal(30023u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(v3));

        Assert.False(reader.HasMore);
        Assert.False(reader.TryReadNext(out _, out _));
    }

    [Fact]
    public void Write_RejectsValueLongerThan255Bytes()
    {
        Span<byte> buffer = stackalloc byte[1024];
        var writer = new TlvWriter(buffer);
        ReadOnlySpan<byte> oversized = new byte[256];

        Assert.False(writer.TryWrite(0, oversized));
        Assert.Equal(0, writer.BytesWritten);
    }

    [Fact]
    public void Write_ReturnsFalseWhenDestinationTooSmall()
    {
        Span<byte> buffer = stackalloc byte[3]; // not enough for type+len+1-byte-value
        var writer = new TlvWriter(buffer);

        Assert.True(writer.TryWrite(0, stackalloc byte[1]));        // exactly 3 bytes
        Assert.False(writer.TryWrite(1, stackalloc byte[1]));       // out of room
        Assert.Equal(3, writer.BytesWritten);
    }

    [Fact]
    public void Write_AcceptsMaxLengthValue()
    {
        Span<byte> buffer = stackalloc byte[512];
        var writer = new TlvWriter(buffer);
        Span<byte> maxLen = stackalloc byte[TlvWriter.MaxValueLength];
        maxLen.Fill(0xAB);

        Assert.True(writer.TryWrite(7, maxLen));
        Assert.Equal(2 + 255, writer.BytesWritten);

        var reader = new TlvReader(buffer[..writer.BytesWritten]);
        Assert.True(reader.TryReadNext(out byte t, out var v));
        Assert.Equal(7, t);
        Assert.True(maxLen.SequenceEqual(v));
    }

    [Fact]
    public void Write_AcceptsZeroLengthValue()
    {
        Span<byte> buffer = stackalloc byte[8];
        var writer = new TlvWriter(buffer);

        Assert.True(writer.TryWrite(42, ReadOnlySpan<byte>.Empty));
        Assert.Equal(2, writer.BytesWritten);

        var reader = new TlvReader(buffer[..writer.BytesWritten]);
        Assert.True(reader.TryReadNext(out byte t, out var v));
        Assert.Equal(42, t);
        Assert.Equal(0, v.Length);
    }

    [Fact]
    public void Read_RejectsTruncatedRecord()
    {
        // Type byte + length byte claims 10 bytes of value, but only 5 follow.
        ReadOnlySpan<byte> source = new byte[] { 0, 10, 1, 2, 3, 4, 5 };
        var reader = new TlvReader(source);
        Assert.False(reader.TryReadNext(out _, out _));
    }

    [Fact]
    public void Read_RejectsLoneTypeByte()
    {
        ReadOnlySpan<byte> source = new byte[] { 0 };
        var reader = new TlvReader(source);
        Assert.False(reader.TryReadNext(out _, out _));
    }

    [Fact]
    public void Read_EmptyBuffer_HasNoRecords()
    {
        var reader = new TlvReader(ReadOnlySpan<byte>.Empty);
        Assert.False(reader.HasMore);
        Assert.False(reader.TryReadNext(out _, out _));
    }

    [Fact]
    public void WriteUtf8_HandlesMultiByteCharacters()
    {
        Span<byte> buffer = stackalloc byte[64];
        var writer = new TlvWriter(buffer);

        Assert.True(writer.TryWriteUtf8(5, "naïve 日本"));

        var reader = new TlvReader(buffer[..writer.BytesWritten]);
        Assert.True(reader.TryReadNext(out byte t, out var v));
        Assert.Equal(5, t);
        Assert.Equal("naïve 日本", System.Text.Encoding.UTF8.GetString(v));
    }
}
