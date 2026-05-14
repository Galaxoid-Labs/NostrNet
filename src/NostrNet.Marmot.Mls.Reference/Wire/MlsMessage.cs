// SPDX-License-Identifier: MIT
//
// MLSMessage envelope per RFC 9420 §6.1.
//
//   struct {
//       ProtocolVersion version;
//       WireFormat wire_format;
//       select (MLSMessage.wire_format) {
//           case mls_public_message:  PublicMessage public_message;
//           case mls_private_message: PrivateMessage private_message;
//           case mls_welcome:         Welcome welcome;
//           case mls_group_info:      GroupInfo group_info;
//           case mls_key_package:     KeyPackage key_package;
//       }
//   } MLSMessage;
//
// The reference provider only emits / parses the mls_welcome and
// mls_key_package variants. PublicMessage / PrivateMessage / GroupInfo
// envelopes are not currently exposed (group-info travels inside the
// Welcome's encrypted_group_info; we use a private-use envelope for
// application messages — see Wire/ApplicationMessage.cs).

using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>Recognized MLSMessage wire-format discriminators (RFC 9420 §17.2).</summary>
internal enum WireFormat : ushort
{
    /// <summary>Reserved / invalid.</summary>
    Reserved = 0x0000,

    /// <summary>An <c>MLSMessage</c> carrying a <c>PublicMessage</c>.</summary>
    PublicMessage = 0x0001,

    /// <summary>An <c>MLSMessage</c> carrying a <c>PrivateMessage</c>.</summary>
    PrivateMessage = 0x0002,

    /// <summary>An <c>MLSMessage</c> carrying a <c>Welcome</c>.</summary>
    Welcome = 0x0003,

    /// <summary>An <c>MLSMessage</c> carrying a <c>GroupInfo</c>.</summary>
    GroupInfo = 0x0004,

    /// <summary>An <c>MLSMessage</c> carrying a <c>KeyPackage</c>.</summary>
    KeyPackage = 0x0005,
}

/// <summary>MLSMessage envelope helpers (RFC 9420 §6.1).</summary>
internal static class MlsMessage
{
    /// <summary>Serialize a KeyPackage inside an MLSMessage envelope.</summary>
    public static byte[] EncodeKeyPackage(KeyPackage kp)
    {
        ArgumentNullException.ThrowIfNull(kp);
        byte[] body = kp.Encode();
        return EncodeWithBody(WireFormat.KeyPackage, body);
    }

    /// <summary>Parse an MLSMessage(mls_key_package) envelope and return the inner KeyPackage.</summary>
    public static KeyPackage DecodeKeyPackage(ReadOnlySpan<byte> mlsMessageBytes)
    {
        ReadOnlySpan<byte> body = ReadHeaderAndExtractBody(mlsMessageBytes, WireFormat.KeyPackage);
        return KeyPackage.Decode(body);
    }

    /// <summary>Serialize a Welcome inside an MLSMessage envelope.</summary>
    public static byte[] EncodeWelcome(Welcome welcome)
    {
        ArgumentNullException.ThrowIfNull(welcome);
        byte[] body = welcome.Encode();
        return EncodeWithBody(WireFormat.Welcome, body);
    }

    /// <summary>Parse an MLSMessage(mls_welcome) envelope and return the inner Welcome.</summary>
    public static Welcome DecodeWelcome(ReadOnlySpan<byte> mlsMessageBytes)
    {
        ReadOnlySpan<byte> body = ReadHeaderAndExtractBody(mlsMessageBytes, WireFormat.Welcome);
        return Welcome.Decode(body);
    }

    /// <summary>
    /// Peek at the wire_format discriminator without parsing the body —
    /// useful for routing inbound bytes (e.g., handling welcome vs. key
    /// package in the same inbox).
    /// </summary>
    public static WireFormat PeekWireFormat(ReadOnlySpan<byte> mlsMessageBytes)
    {
        var r = new TlsReader(mlsMessageBytes);
        var version = (ProtocolVersion)r.ReadUInt16BigEndian();
        if (version != ProtocolVersion.Mls10)
        {
            throw new System.IO.InvalidDataException(
                $"Unsupported MLS protocol version 0x{(ushort)version:X4} (only MLS 1.0 is supported).");
        }

        return (WireFormat)r.ReadUInt16BigEndian();
    }

    private static byte[] EncodeWithBody(WireFormat wireFormat, byte[] body)
    {
        byte[] buf = new byte[4 + body.Length];
        var w = new TlsWriter(buf);
        w.WriteUInt16BigEndian((ushort)ProtocolVersion.Mls10);
        w.WriteUInt16BigEndian((ushort)wireFormat);
        w.WriteRaw(body);
        return buf[..w.BytesWritten];
    }

    private static ReadOnlySpan<byte> ReadHeaderAndExtractBody(
        ReadOnlySpan<byte> mlsMessageBytes, WireFormat expected)
    {
        var r = new TlsReader(mlsMessageBytes);
        var version = (ProtocolVersion)r.ReadUInt16BigEndian();
        if (version != ProtocolVersion.Mls10)
        {
            throw new System.IO.InvalidDataException(
                $"Unsupported MLS protocol version 0x{(ushort)version:X4} (only MLS 1.0 is supported).");
        }

        var wireFormat = (WireFormat)r.ReadUInt16BigEndian();
        if (wireFormat != expected)
        {
            throw new System.IO.InvalidDataException(
                $"Expected MLSMessage wire_format 0x{(ushort)expected:X4} ({expected}); got 0x{(ushort)wireFormat:X4}.");
        }

        return mlsMessageBytes[r.BytesRead..];
    }
}
