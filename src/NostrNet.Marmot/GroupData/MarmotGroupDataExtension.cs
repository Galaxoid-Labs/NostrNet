// SPDX-License-Identifier: MIT
//
// The Marmot Group Data extension (MIP-01, extension type 0xF2EE).
//
// Carried inside an MLS group's `GroupContext.extensions` and a member's
// `LeafNode.capabilities.extensions`. Serializes with TLS presentation
// language plus QUIC-style variable-length-integer length prefixes (the
// `tls_codec` Rust crate convention adopted by MLS).
//
// Wire format (version 3):
//
//   uint16    version
//   opaque    nostr_group_id[32]            // fixed 32 bytes, no prefix
//   opaque    name<varint>                  // UTF-8
//   opaque    description<varint>           // UTF-8
//   opaque    admin_pubkeys<varint>         // concatenated 32-byte pubkeys
//   RelayUrl  relays<varint>                // see "relays vector" below
//   opaque    image_hash<varint>            // 0 or 32 bytes
//   opaque    image_key<varint>             // 0 or 32 bytes
//   opaque    image_nonce<varint>           // 0 or 12 bytes
//   opaque    image_upload_key<varint>      // 0 or 32 bytes
//   opaque    disappearing_message_secs<varint>  // 0 or 8 bytes big-endian uint64
//
// "relays vector" is itself a variable-length container: an outer varint
// gives the total byte length, and the body is a sequence of per-URL
// entries, each of which is `varint(url_byte_length) || utf-8 bytes`.

using System.Diagnostics.CodeAnalysis;
using NostrNet.Keys;
using NostrNet.Marmot.Encoding;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.GroupData;

/// <summary>
/// A typed view of the Marmot Group Data MLS extension.
/// </summary>
/// <remarks>
/// This is the payload of an MLS extension of type
/// <see cref="MarmotMlsExtensions.MarmotGroupData"/> (0xF2EE), not a Nostr
/// event. Use <see cref="Encode"/> when constructing or updating the
/// extension on an MLS group, and <see cref="Parse"/> when reading the
/// extension out of a Welcome or group state.
/// </remarks>
public sealed record MarmotGroupDataExtension
{
    /// <summary>The current Marmot Group Data extension wire-format version.</summary>
    public const ushort CurrentVersion = 3;

    /// <summary>Wire-format version (currently 3).</summary>
    public ushort Version { get; init; } = CurrentVersion;

    /// <summary>
    /// 32-byte Nostr group identifier, distinct from the MLS group id. Used
    /// as the <c>h</c>-tag value on kind-445 group events for relay routing.
    /// </summary>
    public required byte[] NostrGroupId { get; init; }

    /// <summary>Display name. Empty string permitted for unnamed groups.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Description. Empty string permitted.</summary>
    public string Description { get; init; } = string.Empty;

    /// <summary>
    /// Authoritative admin pubkeys (raw 32-byte x-only secp256k1 keys).
    /// Most group operations require at least one entry. Must not contain
    /// duplicates.
    /// </summary>
    public required IReadOnlyList<PublicKey> AdminPubkeys { get; init; }

    /// <summary>WebSocket relay URLs where the group's events are published.</summary>
    public required IReadOnlyList<string> Relays { get; init; }

    /// <summary>SHA-256 of the encrypted group image (32 bytes), or <c>null</c> if no image.</summary>
    public byte[]? ImageHash { get; init; }

    /// <summary>HKDF seed for the image encryption key (32 bytes), or <c>null</c>.</summary>
    public byte[]? ImageKey { get; init; }

    /// <summary>ChaCha20-Poly1305 nonce for image encryption (12 bytes), or <c>null</c>.</summary>
    public byte[]? ImageNonce { get; init; }

    /// <summary>Seed for the Blossom upload identity (32 bytes), or <c>null</c>.</summary>
    public byte[]? ImageUploadKey { get; init; }

    /// <summary>
    /// Disappearing-message duration. <c>null</c> means messages persist;
    /// non-null sets per-group expiration. A value of zero is invalid per spec.
    /// </summary>
    public TimeSpan? DisappearingMessageDuration { get; init; }

    /// <summary>True when all four image fields are populated and well-sized.</summary>
    public bool HasImage =>
        ImageHash is { Length: 32 }
        && ImageKey is { Length: 32 }
        && ImageNonce is { Length: 12 }
        && ImageUploadKey is { Length: 32 };

    /// <summary>
    /// Serializes the extension to its on-the-wire bytes for embedding in
    /// an MLS extension.
    /// </summary>
    /// <exception cref="InvalidOperationException">A field is the wrong length per the spec.</exception>
    public byte[] Encode()
    {
        ValidateForSerialization();

        // Two-pass: size the relays-vector body first so we can write its
        // outer varint length, then write the whole record.
        byte[][] relayBytes = new byte[Relays.Count][];
        int relaysInnerLen = 0;
        for (int i = 0; i < Relays.Count; i++)
        {
            relayBytes[i] = SysEncoding.UTF8.GetBytes(Relays[i]);
            relaysInnerLen += TlsWriter.VarIntLength((ulong)relayBytes[i].Length) + relayBytes[i].Length;
        }

        int adminBytesLen = AdminPubkeys.Count * PublicKey.Size;
        int nameLen = SysEncoding.UTF8.GetByteCount(Name);
        int descLen = SysEncoding.UTF8.GetByteCount(Description);

        int estimated =
            2                                                  // version
            + 32                                               // nostr_group_id
            + TlsWriter.VarIntLength((ulong)nameLen) + nameLen
            + TlsWriter.VarIntLength((ulong)descLen) + descLen
            + TlsWriter.VarIntLength((ulong)adminBytesLen) + adminBytesLen
            + TlsWriter.VarIntLength((ulong)relaysInnerLen) + relaysInnerLen
            + 5 * 1                                            // varint(0) for each absent optional bytes field, conservatively
            + (HasImage ? 1 + 32 + 1 + 32 + 1 + 12 + 1 + 32 : 0)
            + (DisappearingMessageDuration.HasValue ? 1 + 8 : 1);

        byte[] buffer = new byte[Math.Max(estimated + 16, 256)];
        var writer = new TlsWriter(buffer);

        writer.WriteUInt16BigEndian(Version);
        writer.WriteRaw(NostrGroupId);

        if (nameLen <= 256)
        {
            Span<byte> tmp = stackalloc byte[256];
            int n = SysEncoding.UTF8.GetBytes(Name, tmp);
            writer.WriteOpaqueVarInt(tmp[..n]);
        }
        else
        {
            writer.WriteOpaqueVarInt(SysEncoding.UTF8.GetBytes(Name));
        }

        if (descLen <= 1024)
        {
            Span<byte> tmp = stackalloc byte[1024];
            int n = SysEncoding.UTF8.GetBytes(Description, tmp);
            writer.WriteOpaqueVarInt(tmp[..n]);
        }
        else
        {
            writer.WriteOpaqueVarInt(SysEncoding.UTF8.GetBytes(Description));
        }

        // admin_pubkeys: outer varint length, then concatenated 32-byte keys.
        writer.WriteVarInt((ulong)adminBytesLen);
        Span<byte> pubBuf = stackalloc byte[PublicKey.Size];
        foreach (var pub in AdminPubkeys)
        {
            pub.CopyTo(pubBuf);
            writer.WriteRaw(pubBuf);
        }

        // relays: outer varint(total inner bytes), then each entry length-prefixed.
        writer.WriteVarInt((ulong)relaysInnerLen);
        for (int i = 0; i < relayBytes.Length; i++)
        {
            writer.WriteOpaqueVarInt(relayBytes[i]);
        }

        // Optional image fields — varint(0) when absent.
        WriteOptionalOpaque(ref writer, HasImage ? ImageHash : null);
        WriteOptionalOpaque(ref writer, HasImage ? ImageKey : null);
        WriteOptionalOpaque(ref writer, HasImage ? ImageNonce : null);
        WriteOptionalOpaque(ref writer, HasImage ? ImageUploadKey : null);

        // disappearing_message_secs: 0 bytes (absent) OR 8 bytes (big-endian uint64).
        if (DisappearingMessageDuration is TimeSpan span)
        {
            Span<byte> sec = stackalloc byte[8];
            ulong seconds = (ulong)Math.Max(0, (long)span.TotalSeconds);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(sec, seconds);
            writer.WriteOpaqueVarInt(sec);
        }
        else
        {
            writer.WriteVarInt(0);
        }

        var result = new byte[writer.BytesWritten];
        buffer.AsSpan(0, writer.BytesWritten).CopyTo(result);
        return result;
    }

    /// <summary>Parses extension wire bytes into a typed record.</summary>
    /// <exception cref="InvalidDataException">The bytes are malformed or violate spec constraints.</exception>
    public static MarmotGroupDataExtension Parse(ReadOnlySpan<byte> wire)
    {
        var reader = new TlsReader(wire);

        ushort version = reader.ReadUInt16BigEndian();
        if (version != CurrentVersion)
        {
            throw new InvalidDataException(
                $"Unsupported Marmot Group Data extension version: {version} (this build supports {CurrentVersion}).");
        }

        var nostrGroupId = reader.ReadRaw(32).ToArray();
        string name = SysEncoding.UTF8.GetString(reader.ReadOpaqueVarInt());
        string description = SysEncoding.UTF8.GetString(reader.ReadOpaqueVarInt());

        var adminBytes = reader.ReadOpaqueVarInt();
        if (adminBytes.Length % PublicKey.Size != 0)
        {
            throw new InvalidDataException(
                $"admin_pubkeys vector length ({adminBytes.Length}) is not a multiple of {PublicKey.Size}.");
        }

        int adminCount = adminBytes.Length / PublicKey.Size;
        var admins = new PublicKey[adminCount];
        var seenAdmins = new HashSet<string>(adminCount);
        for (int i = 0; i < adminCount; i++)
        {
            admins[i] = new PublicKey(adminBytes.Slice(i * PublicKey.Size, PublicKey.Size));
            if (!seenAdmins.Add(admins[i].ToHex()))
            {
                throw new InvalidDataException("admin_pubkeys contains duplicates.");
            }
        }

        // relays: outer varint is total inner byte length; iterate inner reader.
        var relayInner = reader.ReadOpaqueVarInt();
        var innerReader = new TlsReader(relayInner);
        var relays = new List<string>();
        while (innerReader.HasMore)
        {
            relays.Add(SysEncoding.UTF8.GetString(innerReader.ReadOpaqueVarInt()));
        }

        byte[]? imageHash = ReadOptionalOpaque(ref reader, expectedLength: 32, fieldName: "image_hash");
        byte[]? imageKey = ReadOptionalOpaque(ref reader, expectedLength: 32, fieldName: "image_key");
        byte[]? imageNonce = ReadOptionalOpaque(ref reader, expectedLength: 12, fieldName: "image_nonce");
        byte[]? imageUploadKey = ReadOptionalOpaque(ref reader, expectedLength: 32, fieldName: "image_upload_key");

        TimeSpan? disappearing = null;
        var disappearingBytes = reader.ReadOpaqueVarInt();
        if (disappearingBytes.Length == 8)
        {
            ulong secs = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(disappearingBytes);
            if (secs == 0)
            {
                throw new InvalidDataException("disappearing_message_secs = 0 is invalid per MIP-01.");
            }

            disappearing = TimeSpan.FromSeconds(secs);
        }
        else if (disappearingBytes.Length != 0)
        {
            throw new InvalidDataException(
                $"disappearing_message_secs has unexpected length {disappearingBytes.Length} (allowed: 0 or 8).");
        }

        return new MarmotGroupDataExtension
        {
            Version = version,
            NostrGroupId = nostrGroupId,
            Name = name,
            Description = description,
            AdminPubkeys = admins,
            Relays = relays,
            ImageHash = imageHash,
            ImageKey = imageKey,
            ImageNonce = imageNonce,
            ImageUploadKey = imageUploadKey,
            DisappearingMessageDuration = disappearing,
        };
    }

    /// <summary>Try-parse variant; returns <c>false</c> on any malformed input.</summary>
    public static bool TryParse(ReadOnlySpan<byte> wire, [NotNullWhen(true)] out MarmotGroupDataExtension? extension)
    {
        try
        {
            extension = Parse(wire);
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException)
        {
            extension = null;
            return false;
        }
    }

    private void ValidateForSerialization()
    {
        if (NostrGroupId is null || NostrGroupId.Length != 32)
        {
            throw new InvalidOperationException("NostrGroupId must be exactly 32 bytes.");
        }

        if (AdminPubkeys is null)
        {
            throw new InvalidOperationException("AdminPubkeys must not be null (use an empty list if you really want zero admins).");
        }

        if (Relays is null)
        {
            throw new InvalidOperationException("Relays must not be null.");
        }

        if (HasImage)
        {
            // HasImage already checks all four length constraints.
        }
        else if (ImageHash is not null || ImageKey is not null || ImageNonce is not null || ImageUploadKey is not null)
        {
            throw new InvalidOperationException(
                "Image fields are all-or-nothing: either set all four (hash 32, key 32, nonce 12, upload_key 32) or leave all null.");
        }

        if (DisappearingMessageDuration is TimeSpan span && span.TotalSeconds < 1)
        {
            throw new InvalidOperationException(
                "DisappearingMessageDuration must be at least 1 second (per MIP-01, 0 is rejected).");
        }
    }

    private static void WriteOptionalOpaque(ref TlsWriter writer, byte[]? value)
    {
        if (value is null)
        {
            writer.WriteVarInt(0);
        }
        else
        {
            writer.WriteOpaqueVarInt(value);
        }
    }

    private static byte[]? ReadOptionalOpaque(ref TlsReader reader, int expectedLength, string fieldName)
    {
        var bytes = reader.ReadOpaqueVarInt();
        if (bytes.Length == 0)
        {
            return null;
        }

        if (bytes.Length != expectedLength)
        {
            throw new InvalidDataException(
                $"{fieldName} has length {bytes.Length} (allowed: 0 or {expectedLength}).");
        }

        return bytes.ToArray();
    }
}
