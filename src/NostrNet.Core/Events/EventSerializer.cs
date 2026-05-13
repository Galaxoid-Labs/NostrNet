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
    /// Serializes an event's id-input fields into the canonical NIP-01 JSON
    /// byte sequence used to derive the event id.
    /// </summary>
    public static byte[] SerializeForId(
        PublicKey pubKey,
        long createdAt,
        int kind,
        IReadOnlyList<IReadOnlyList<string>> tags,
        string content)
    {
        ArgumentNullException.ThrowIfNull(pubKey);
        ArgumentNullException.ThrowIfNull(tags);
        ArgumentNullException.ThrowIfNull(content);

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, WriterOptions))
        {
            writer.WriteStartArray();
            writer.WriteNumberValue(0);
            writer.WriteStringValue(pubKey.ToHex());
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

        return ms.ToArray();
    }

    /// <summary>
    /// Computes the event id as SHA-256 of the canonical serialization.
    /// </summary>
    public static EventId ComputeId(
        PublicKey pubKey,
        long createdAt,
        int kind,
        IReadOnlyList<IReadOnlyList<string>> tags,
        string content)
    {
        byte[] canonical = SerializeForId(pubKey, createdAt, kind, tags, content);
        Span<byte> hash = stackalloc byte[32];
        int written = SHA256.HashData(canonical, hash);
        if (written != 32)
        {
            throw new InvalidOperationException("SHA-256 produced unexpected output length.");
        }

        return new EventId(hash);
    }
}
