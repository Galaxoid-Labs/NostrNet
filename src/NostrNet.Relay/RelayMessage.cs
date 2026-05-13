// SPDX-License-Identifier: MIT
//
// NIP-01 relay-to-client messages, parsed from JSON arrays.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/01.md
//
// Wire shapes:
//   ["EVENT", <subscription_id>, <event-json>]
//   ["EOSE", <subscription_id>]
//   ["OK", <event_id>, <accepted-bool>, <message>]
//   ["NOTICE", <message>]
//   ["CLOSED", <subscription_id>, <message>]
//   ["AUTH", <challenge>]   (NIP-42)

using System.Text.Json;
using NostrNet.Events;

namespace NostrNet.Relay;

/// <summary>Base class for relay-to-client messages.</summary>
public abstract record RelayMessage
{
    /// <summary>Parses a single relay-to-client message from its JSON text form.</summary>
    /// <exception cref="FormatException">The message is malformed or unknown.</exception>
    public static RelayMessage Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using var doc = JsonDocument.Parse(json);
            return Parse(doc.RootElement);
        }
        catch (JsonException ex)
        {
            throw new FormatException("Relay message is not valid JSON.", ex);
        }
    }

    /// <summary>Parses a relay-to-client message from a parsed JSON array element.</summary>
    public static RelayMessage Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() < 1)
        {
            throw new FormatException("Relay message must be a JSON array.");
        }

        string tag = root[0].GetString() ?? throw new FormatException("Relay message tag is null.");
        return tag switch
        {
            "EVENT" => ParseEvent(root),
            "EOSE" => ParseEose(root),
            "OK" => ParseOk(root),
            "NOTICE" => ParseNotice(root),
            "CLOSED" => ParseClosed(root),
            "AUTH" => ParseAuth(root),
            _ => throw new FormatException($"Unknown relay message tag: {tag}"),
        };
    }

    private static EventMessage ParseEvent(JsonElement root)
    {
        if (root.GetArrayLength() < 3)
        {
            throw new FormatException("EVENT message requires subscription_id and event payload.");
        }

        string subId = root[1].GetString() ?? throw new FormatException("EVENT subscription_id is null.");
        var ev = NostrEvent.FromJson(root[2].GetRawText());
        return new EventMessage(subId, ev);
    }

    private static EndOfStoredEventsMessage ParseEose(JsonElement root)
    {
        if (root.GetArrayLength() < 2)
        {
            throw new FormatException("EOSE message requires subscription_id.");
        }

        string subId = root[1].GetString() ?? throw new FormatException("EOSE subscription_id is null.");
        return new EndOfStoredEventsMessage(subId);
    }

    private static OkMessage ParseOk(JsonElement root)
    {
        if (root.GetArrayLength() < 4)
        {
            throw new FormatException("OK message requires event_id, accepted, message.");
        }

        string eventId = root[1].GetString() ?? throw new FormatException("OK event_id is null.");
        bool accepted = root[2].GetBoolean();
        string message = root[3].GetString() ?? string.Empty;
        return new OkMessage(eventId, accepted, message);
    }

    private static NoticeMessage ParseNotice(JsonElement root)
    {
        string message = root.GetArrayLength() > 1
            ? (root[1].GetString() ?? string.Empty)
            : string.Empty;
        return new NoticeMessage(message);
    }

    private static ClosedMessage ParseClosed(JsonElement root)
    {
        if (root.GetArrayLength() < 2)
        {
            throw new FormatException("CLOSED message requires subscription_id.");
        }

        string subId = root[1].GetString() ?? throw new FormatException("CLOSED subscription_id is null.");
        string reason = root.GetArrayLength() > 2 ? (root[2].GetString() ?? string.Empty) : string.Empty;
        return new ClosedMessage(subId, reason);
    }

    private static AuthChallengeMessage ParseAuth(JsonElement root)
    {
        if (root.GetArrayLength() < 2)
        {
            throw new FormatException("AUTH message requires challenge.");
        }

        string challenge = root[1].GetString() ?? throw new FormatException("AUTH challenge is null.");
        return new AuthChallengeMessage(challenge);
    }
}

/// <summary>A relay <c>EVENT</c> message delivering an event under a subscription.</summary>
public sealed record EventMessage(string SubscriptionId, NostrEvent Event) : RelayMessage;

/// <summary>A relay <c>EOSE</c> marker signaling end of stored events for a subscription.</summary>
public sealed record EndOfStoredEventsMessage(string SubscriptionId) : RelayMessage;

/// <summary>A relay <c>OK</c> response to a publish.</summary>
public sealed record OkMessage(string EventId, bool Accepted, string Message) : RelayMessage;

/// <summary>A relay <c>NOTICE</c> with a human-readable string.</summary>
public sealed record NoticeMessage(string Message) : RelayMessage;

/// <summary>A relay-initiated <c>CLOSED</c> notification for a subscription.</summary>
public sealed record ClosedMessage(string SubscriptionId, string Reason) : RelayMessage;

/// <summary>A NIP-42 <c>AUTH</c> challenge from the relay.</summary>
public sealed record AuthChallengeMessage(string Challenge) : RelayMessage;
