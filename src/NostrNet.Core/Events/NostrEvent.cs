// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Text.Encodings.Web;
using System.Text.Json;
using NostrNet.Cryptography;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Events;

/// <summary>
/// A fully-formed, signed Nostr event as defined by NIP-01.
/// </summary>
/// <remarks>
/// Instances are produced by <see cref="UnsignedEvent.Sign(PrivateKey, ReadOnlySpan{byte})"/>
/// or by parsing wire JSON via <see cref="FromJson"/>. Properties are immutable;
/// modifying any field requires constructing a new event and re-signing.
/// </remarks>
public sealed class NostrEvent
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        SkipValidation = true,
        Indented = false,
    };

    /// <summary>The event id (32-byte SHA-256 of canonical serialization).</summary>
    public required EventId Id { get; init; }

    /// <summary>The author's x-only public key.</summary>
    public required PublicKey PubKey { get; init; }

    /// <summary>Unix timestamp in seconds.</summary>
    public required long CreatedAt { get; init; }

    /// <summary>The NIP-01 event kind.</summary>
    public required int Kind { get; init; }

    /// <summary>Tag rows.</summary>
    public required IReadOnlyList<IReadOnlyList<string>> Tags { get; init; }

    /// <summary>The event content string.</summary>
    public required string Content { get; init; }

    /// <summary>The BIP-340 Schnorr signature over <see cref="Id"/>.</summary>
    public required Signature Sig { get; init; }

    /// <summary>
    /// Verifies that the event id matches the canonical serialization and that
    /// the signature is valid for that id under <see cref="PubKey"/>.
    /// </summary>
    /// <returns><c>true</c> if both checks pass.</returns>
    public bool Verify()
    {
        EventId expectedId = EventSerializer.ComputeId(PubKey, CreatedAt, Kind, Tags, Content);
        if (!expectedId.Equals(Id))
        {
            return false;
        }

        return Secp256k1.SchnorrVerify(Sig.AsSpan(), Id.AsSpan(), PubKey.AsSpan());
    }

    /// <summary>Parses a relay-wire JSON event from a string.</summary>
    /// <exception cref="FormatException">The JSON is malformed or a field is invalid.</exception>
    public static NostrEvent FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using var doc = JsonDocument.Parse(json);
            return FromJsonElement(doc.RootElement);
        }
        catch (JsonException ex)
        {
            throw new FormatException("Event JSON is malformed.", ex);
        }
    }

    /// <summary>
    /// Parses an event from an already-parsed <see cref="JsonElement"/>.
    /// Avoids re-parsing when the caller already holds the element (e.g., when
    /// relay message parsing has the wider envelope).
    /// </summary>
    /// <exception cref="FormatException">The element is not a valid event object.</exception>
    public static NostrEvent FromJsonElement(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("Event must be a JSON object.");
        }

        string id = GetRequiredString(element, "id");
        string pubkey = GetRequiredString(element, "pubkey");
        long createdAt = element.GetProperty("created_at").GetInt64();
        int kind = element.GetProperty("kind").GetInt32();
        string content = GetRequiredString(element, "content");
        string sig = GetRequiredString(element, "sig");

        if (!element.TryGetProperty("tags", out var tagsEl) || tagsEl.ValueKind != JsonValueKind.Array)
        {
            throw new FormatException("Event is missing tags array.");
        }

        int tagCount = tagsEl.GetArrayLength();
        var tags = new IReadOnlyList<string>[tagCount];
        int i = 0;
        foreach (var rowEl in tagsEl.EnumerateArray())
        {
            if (rowEl.ValueKind != JsonValueKind.Array)
            {
                throw new FormatException("Each tag must be a JSON array.");
            }

            var row = new string[rowEl.GetArrayLength()];
            int j = 0;
            foreach (var cellEl in rowEl.EnumerateArray())
            {
                row[j++] = cellEl.GetString() ?? string.Empty;
            }

            tags[i++] = row;
        }

        return new NostrEvent
        {
            Id = EventId.FromHex(id),
            PubKey = PublicKey.FromHex(pubkey),
            CreatedAt = createdAt,
            Kind = kind,
            Tags = tags,
            Content = content,
            Sig = Signature.FromHex(sig),
        };
    }

    /// <summary>Serializes this event into NIP-01 wire JSON.</summary>
    public string ToJson()
    {
        var buffer = new ArrayBufferWriter<byte>(initialCapacity: 512);
        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            WriteTo(writer);
        }

        return SysEncoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>
    /// Writes the full event JSON object directly to a
    /// <see cref="Utf8JsonWriter"/>. Used by the relay-protocol builder to
    /// avoid a string round-trip when embedding the event in an <c>EVENT</c>
    /// or <c>AUTH</c> envelope.
    /// </summary>
    internal void WriteTo(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("id", Id.ToHex());
        writer.WriteString("pubkey", PubKey.ToHex());
        writer.WriteNumber("created_at", CreatedAt);
        writer.WriteNumber("kind", Kind);

        writer.WriteStartArray("tags");
        for (int i = 0; i < Tags.Count; i++)
        {
            var tag = Tags[i];
            writer.WriteStartArray();
            for (int j = 0; j < tag.Count; j++)
            {
                writer.WriteStringValue(tag[j]);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndArray();

        writer.WriteString("content", Content);
        writer.WriteString("sig", Sig.ToHex());
        writer.WriteEndObject();
    }

    private static string GetRequiredString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var prop) || prop.ValueKind != JsonValueKind.String)
        {
            throw new FormatException($"Event is missing '{propertyName}'.");
        }

        return prop.GetString() ?? throw new FormatException($"Event '{propertyName}' is null.");
    }
}
