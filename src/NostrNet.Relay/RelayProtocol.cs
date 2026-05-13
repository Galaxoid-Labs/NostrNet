// SPDX-License-Identifier: MIT
//
// Builders for client-to-relay messages.
//
// Wire shapes:
//   ["EVENT", <event-json>]
//   ["REQ", <subscription_id>, <filter1>, <filter2>...]
//   ["CLOSE", <subscription_id>]
//   ["AUTH", <event-json>]   (NIP-42)

using System.Text.Encodings.Web;
using System.Text.Json;
using NostrNet.Events;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Relay;

/// <summary>
/// Client-to-relay message builders. All methods produce a single JSON string
/// suitable for sending as a WebSocket text frame.
/// </summary>
internal static class RelayProtocol
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false,
        SkipValidation = false,
    };

    public static string BuildPublishMessage(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        return BuildEventLikeMessage("EVENT", ev);
    }

    public static string BuildAuthMessage(NostrEvent authEvent)
    {
        ArgumentNullException.ThrowIfNull(authEvent);
        return BuildEventLikeMessage("AUTH", authEvent);
    }

    public static string BuildSubscribeMessage(string subscriptionId, IReadOnlyList<Filter> filters)
    {
        ArgumentNullException.ThrowIfNull(subscriptionId);
        ArgumentNullException.ThrowIfNull(filters);
        if (filters.Count == 0)
        {
            throw new ArgumentException("At least one filter is required.", nameof(filters));
        }

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, WriterOptions))
        {
            writer.WriteStartArray();
            writer.WriteStringValue("REQ");
            writer.WriteStringValue(subscriptionId);
            foreach (var filter in filters)
            {
                filter.WriteTo(writer);
            }

            writer.WriteEndArray();
        }

        return SysEncoding.UTF8.GetString(ms.ToArray());
    }

    public static string BuildCloseMessage(string subscriptionId)
    {
        ArgumentNullException.ThrowIfNull(subscriptionId);
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, WriterOptions))
        {
            writer.WriteStartArray();
            writer.WriteStringValue("CLOSE");
            writer.WriteStringValue(subscriptionId);
            writer.WriteEndArray();
        }

        return SysEncoding.UTF8.GetString(ms.ToArray());
    }

    private static string BuildEventLikeMessage(string tag, NostrEvent ev)
    {
        // Use the package-internal NostrEvent.WriteTo so we don't round-trip
        // through ToJson → JsonDocument.Parse → WriteTo (which allocated a
        // string and parsed a DOM on every publish).
        var buffer = new System.Buffers.ArrayBufferWriter<byte>(initialCapacity: 512);
        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            writer.WriteStartArray();
            writer.WriteStringValue(tag);
            ev.WriteTo(writer);
            writer.WriteEndArray();
        }

        return SysEncoding.UTF8.GetString(buffer.WrittenSpan);
    }
}
