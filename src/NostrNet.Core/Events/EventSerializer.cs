// SPDX-License-Identifier: MIT
//
// NIP-01 canonical event serialization for id computation.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/01.md
//
// The id of an event is sha256(canonical JSON serialization) where the
// canonical form is:
//
//   [
//     0,
//     <pubkey, lowercase hex>,
//     <created_at, integer>,
//     <kind, integer>,
//     <tags, array of arrays of strings>,
//     <content, string>
//   ]
//
// Whitespace must not appear. The following content-string characters MUST be
// escaped: 0x08 \b, 0x09 \t, 0x0A \n, 0x0C \f, 0x0D \r, 0x22 \", 0x5C \\.
// All other printable and non-ASCII characters appear verbatim (no escaping of
// '<', '>', '&', '/', or non-ASCII Unicode). Other control characters
// (0x00–0x1F outside the listed seven) are emitted as \u00XX since they are
// not legal verbatim in JSON either way.

using System.Buffers;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using NostrNet.Keys;

namespace NostrNet.Events;

internal static class EventSerializer
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        SkipValidation = true,
        Indented = false,
    };

    /// <summary>
    /// Computes the NIP-01 event id (SHA-256 of the canonical serialization).
    /// </summary>
    /// <remarks>
    /// Writes the canonical JSON directly into a pooled buffer and hashes the
    /// resulting span — no intermediate <c>byte[]</c> copy.
    /// </remarks>
    public static EventId ComputeId(
        PublicKey pubKey,
        long createdAt,
        int kind,
        IReadOnlyList<IReadOnlyList<string>> tags,
        string content)
    {
        ArgumentNullException.ThrowIfNull(pubKey);
        ArgumentNullException.ThrowIfNull(tags);
        ArgumentNullException.ThrowIfNull(content);

        // Start with a buffer that fits most events (~512B). Grows in place
        // for large ones — no second-stage ToArray copy.
        var buffer = new ArrayBufferWriter<byte>(initialCapacity: 512);

        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            WriteCanonical(writer, pubKey, createdAt, kind, tags, content);
        }

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(buffer.WrittenSpan, hash);
        return new EventId(hash);
    }

    private static void WriteCanonical(
        Utf8JsonWriter writer,
        PublicKey pubKey,
        long createdAt,
        int kind,
        IReadOnlyList<IReadOnlyList<string>> tags,
        string content)
    {
        writer.WriteStartArray();
        writer.WriteNumberValue(0);

        // Write the 32-byte pubkey as 64 lowercase hex chars without
        // allocating a string. WriteStringValue(ReadOnlySpan<byte>) emits the
        // bytes as a JSON UTF-8 string; hex chars are ASCII, so this is the
        // same as writing a string.
        Span<byte> hex = stackalloc byte[PublicKey.Size * 2];
        WriteHexLowerAscii(pubKey.AsSpan(), hex);
        writer.WriteStringValue(hex);

        writer.WriteNumberValue(createdAt);
        writer.WriteNumberValue(kind);

        writer.WriteStartArray();
        for (int i = 0; i < tags.Count; i++)
        {
            IReadOnlyList<string> tag = tags[i];
            writer.WriteStartArray();
            for (int j = 0; j < tag.Count; j++)
            {
                writer.WriteStringValue(tag[j]);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndArray();

        writer.WriteStringValue(content);
        writer.WriteEndArray();
    }

    // Lookup table for 0..15 → ASCII hex char ('0'-'9', 'a'-'f').
    private static ReadOnlySpan<byte> HexAscii =>
        new byte[] { (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f' };

    private static void WriteHexLowerAscii(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        for (int i = 0; i < source.Length; i++)
        {
            byte b = source[i];
            destination[i * 2] = HexAscii[b >> 4];
            destination[(i * 2) + 1] = HexAscii[b & 0x0F];
        }
    }
}
