// SPDX-License-Identifier: MIT
//
// QUIC varint encoding test vectors are taken from RFC 9000 §16 Appendix A.

using NostrNet.Marmot.Encoding;

namespace NostrNet.Marmot.Tests.Encoding;

public class TlsCodecTests
{
    [Theory]
    // RFC 9000 §A.1 examples — value, encoded bytes (hex).
    [InlineData(0UL,                     "00")]
    [InlineData(0x25UL,                  "25")]                // 1-byte: 37
    [InlineData(0x3FUL,                  "3f")]                // 1-byte boundary: 63
    [InlineData(0x40UL,                  "4040")]              // 2-byte start: 64
    [InlineData(0xBFUL,                  "40bf")]              // 191
    [InlineData(0x3FFFUL,                "7fff")]              // 2-byte boundary: 16383
    [InlineData(0x4000UL,                "80004000")]          // 4-byte start: 16384
    [InlineData(0x3FFFFFFFUL,            "bfffffff")]          // 4-byte boundary: 1,073,741,823
    [InlineData(0x40000000UL,            "c000000040000000")]  // 8-byte start
    public void VarInt_RoundTrips_ForRfc9000Vectors(ulong value, string expectedHex)
    {
        byte[] expected = Convert.FromHexString(expectedHex);

        Span<byte> buffer = stackalloc byte[16];
        var writer = new TlsWriter(buffer);
        writer.WriteVarInt(value);

        Assert.Equal(expected.Length, writer.BytesWritten);
        Assert.Equal(expected, buffer[..writer.BytesWritten].ToArray());

        var reader = new TlsReader(expected);
        Assert.Equal(value, reader.ReadVarInt());
        Assert.False(reader.HasMore);
    }

    [Fact]
    public void VarIntLength_MatchesEncodedLength()
    {
        Assert.Equal(1, TlsWriter.VarIntLength(0));
        Assert.Equal(1, TlsWriter.VarIntLength(63));
        Assert.Equal(2, TlsWriter.VarIntLength(64));
        Assert.Equal(2, TlsWriter.VarIntLength(16383));
        Assert.Equal(4, TlsWriter.VarIntLength(16384));
        Assert.Equal(4, TlsWriter.VarIntLength((1UL << 30) - 1));
        Assert.Equal(8, TlsWriter.VarIntLength(1UL << 30));
        Assert.Equal(8, TlsWriter.VarIntLength((1UL << 62) - 1));
    }

    [Fact]
    public void OpaqueVarInt_RoundTrip()
    {
        byte[] payload = { 0xDE, 0xAD, 0xBE, 0xEF };

        Span<byte> buffer = stackalloc byte[16];
        var writer = new TlsWriter(buffer);
        writer.WriteOpaqueVarInt(payload);

        Assert.Equal(5, writer.BytesWritten); // 1-byte length + 4 payload

        var reader = new TlsReader(buffer[..writer.BytesWritten]);
        var read = reader.ReadOpaqueVarInt();
        Assert.True(read.SequenceEqual(payload));
        Assert.False(reader.HasMore);
    }

    [Fact]
    public void OpaqueVarInt_LongPayload_Uses2ByteLengthPrefix()
    {
        // 100-byte payload → length prefix bumps to 2 bytes (0x40 .. 0x3FFF range).
        byte[] payload = new byte[100];
        new Random(42).NextBytes(payload);

        byte[] buf = new byte[256];
        var writer = new TlsWriter(buf);
        writer.WriteOpaqueVarInt(payload);

        Assert.Equal(102, writer.BytesWritten); // 2-byte length + 100 payload

        var reader = new TlsReader(buf.AsSpan(0, writer.BytesWritten));
        Assert.True(reader.ReadOpaqueVarInt().SequenceEqual(payload));
    }

    [Fact]
    public void Integers_RoundTrip()
    {
        Span<byte> buffer = stackalloc byte[32];
        var writer = new TlsWriter(buffer);
        writer.WriteUInt8(0xAB);
        writer.WriteUInt16BigEndian(0xCAFE);
        writer.WriteUInt32BigEndian(0xDEADBEEF);
        writer.WriteUInt64BigEndian(0x0123456789ABCDEFUL);

        Assert.Equal(1 + 2 + 4 + 8, writer.BytesWritten);

        var reader = new TlsReader(buffer[..writer.BytesWritten]);
        Assert.Equal(0xAB, reader.ReadUInt8());
        Assert.Equal(0xCAFE, reader.ReadUInt16BigEndian());
        Assert.Equal(0xDEADBEEFu, reader.ReadUInt32BigEndian());
        Assert.Equal(0x0123456789ABCDEFUL, reader.ReadUInt64BigEndian());
        Assert.False(reader.HasMore);
    }

    [Fact]
    public void Writer_ThrowsWhenDestinationTooSmall()
    {
        Assert.Throws<InvalidOperationException>(WriteThreeBytesIntoTwo);

        static void WriteThreeBytesIntoTwo()
        {
            Span<byte> tiny = stackalloc byte[2];
            var writer = new TlsWriter(tiny);
            writer.WriteUInt8(0x01);
            writer.WriteUInt8(0x02);
            writer.WriteUInt8(0x03);   // overflows
        }
    }

    [Fact]
    public void Reader_ThrowsWhenSourceTooShort()
    {
        Assert.Throws<InvalidDataException>(ReadPastEnd);

        static void ReadPastEnd()
        {
            var reader = new TlsReader(new byte[] { 0xAB });
            reader.ReadUInt8();
            reader.ReadUInt8();   // out of bytes
        }
    }

    [Fact]
    public void ReadVarInt_LargestValue_RoundTrips()
    {
        ulong max = (1UL << 62) - 1;
        Span<byte> buffer = stackalloc byte[16];
        var writer = new TlsWriter(buffer);
        writer.WriteVarInt(max);

        Assert.Equal(8, writer.BytesWritten);

        var reader = new TlsReader(buffer[..writer.BytesWritten]);
        Assert.Equal(max, reader.ReadVarInt());
    }

    [Fact]
    public void WriteVarInt_RejectsValuesPast2Pow62()
    {
        Assert.Throws<ArgumentOutOfRangeException>(WriteOverflow);

        static void WriteOverflow()
        {
            Span<byte> buffer = stackalloc byte[16];
            var writer = new TlsWriter(buffer);
            writer.WriteVarInt(1UL << 62);
        }
    }
}
