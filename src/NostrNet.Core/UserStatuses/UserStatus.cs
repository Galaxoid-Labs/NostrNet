// SPDX-License-Identifier: MIT
//
// NIP-38: User Statuses (kind 30315).
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/38.md
//
// Parameterized replaceable: keyed by (kind, pubkey, d). The `d`
// tag is the status TYPE — well-known values include "general"
// (current activity) and "music" (currently playing). Apps MAY use
// custom type strings; per-type latest-`created_at` wins.
//
// Wire format:
//
//   kind     = 30315
//   content  = the status text (free form, may include emoji /
//              NIP-30 custom emoji). Empty content means "clear".
//   tags:
//     ["d", <type>]            required: status type slot
//     ["expiration", <unix>]   optional: NIP-40 expiry. For "music"
//                              statuses this SHOULD be set to the
//                              moment the track will stop playing.
//     ["r", <url>]             optional: external reference URL
//                              (e.g. "spotify:track:...")
//     ["p", <hex-pubkey>]      optional: tagged user
//     ["e", <hex-event-id>]    optional: referenced event
//     ["a", <kind:pub:d>]      optional: referenced replaceable event

using System.Globalization;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Nip19;

namespace NostrNet.UserStatuses;

/// <summary>Kind constants for NIP-38 user statuses.</summary>
public static class Nip38Kinds
{
    /// <summary>User-status event (kind 30315).</summary>
    public const int UserStatus = 30315;
}

/// <summary>Well-known NIP-38 status type strings (the <c>d</c> tag value).</summary>
public static class UserStatusTypes
{
    /// <summary>Free-form current activity (e.g. "Working", "Hiking").</summary>
    public const string General = "general";

    /// <summary>Currently playing track / podcast / video.</summary>
    public const string Music = "music";
}

/// <summary>A typed view of a NIP-38 kind-30315 user-status event.</summary>
public sealed class UserStatus
{
    /// <summary>The status author.</summary>
    public required PublicKey Author { get; init; }

    /// <summary>The status type from the <c>d</c> tag (e.g. <see cref="UserStatusTypes.General"/>).</summary>
    public required string Type { get; init; }

    /// <summary>The free-form status text (may be empty — means "clear").</summary>
    public required string Content { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>NIP-40 expiration timestamp, if set.</summary>
    public DateTimeOffset? Expiration { get; init; }

    /// <summary>External URL reference (e.g. <c>spotify:track:…</c>) from the <c>r</c> tag, if present.</summary>
    public string? ReferenceUrl { get; init; }

    /// <summary>Pubkeys tagged in the status (<c>p</c> tags).</summary>
    public IReadOnlyList<PublicKey> TaggedPubkeys { get; init; } = Array.Empty<PublicKey>();

    /// <summary>Event ids tagged in the status (<c>e</c> tags).</summary>
    public IReadOnlyList<EventId> TaggedEvents { get; init; } = Array.Empty<EventId>();

    /// <summary>Replaceable-event addresses tagged in the status (<c>a</c> tags, raw <c>kind:pubkey:identifier</c>).</summary>
    public IReadOnlyList<string> TaggedAddresses { get; init; } = Array.Empty<string>();

    /// <summary>True when <see cref="Content"/> is empty — per NIP-38 this signals the status should be cleared.</summary>
    public bool IsCleared => string.IsNullOrEmpty(Content);

    /// <summary>True when an <see cref="Expiration"/> is set and is in the past relative to <see cref="DateTimeOffset.UtcNow"/>.</summary>
    public bool HasExpired => Expiration is DateTimeOffset e && e <= DateTimeOffset.UtcNow;

    /// <summary>Returns the NIP-19 <c>naddr</c> coordinate for this status.</summary>
    public NaddrEntity ToNaddr(IReadOnlyList<string>? relays = null)
        => new()
        {
            PubKey = Author,
            Kind = Nip38Kinds.UserStatus,
            Identifier = Type,
            Relays = relays ?? Array.Empty<string>(),
        };

    /// <summary>Parses a kind-30315 event into a typed <see cref="UserStatus"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not kind 30315.</exception>
    /// <exception cref="FormatException">Required <c>d</c> tag is missing or empty.</exception>
    public static UserStatus FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip38Kinds.UserStatus)
        {
            throw new ArgumentException(
                $"Expected NIP-38 kind {Nip38Kinds.UserStatus}; got {ev.Kind}.",
                nameof(ev));
        }

        string? type = null;
        DateTimeOffset? expiration = null;
        string? referenceUrl = null;
        var taggedPubkeys = new List<PublicKey>();
        var taggedEvents = new List<EventId>();
        var taggedAddresses = new List<string>();

        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0) continue;
            switch (tag[0])
            {
                case "d":
                    if (tag.Count >= 2) type = tag[1];
                    break;
                case "expiration":
                    if (tag.Count >= 2
                        && long.TryParse(tag[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out long ts))
                    {
                        expiration = DateTimeOffset.FromUnixTimeSeconds(ts);
                    }
                    break;
                case "r":
                    if (tag.Count >= 2 && !string.IsNullOrEmpty(tag[1])) referenceUrl = tag[1];
                    break;
                case "p":
                    if (tag.Count >= 2 && tag[1]?.Length == 64)
                    {
                        try { taggedPubkeys.Add(PublicKey.FromHex(tag[1])); }
                        catch { /* skip malformed */ }
                    }
                    break;
                case "e":
                    if (tag.Count >= 2 && tag[1]?.Length == 64)
                    {
                        try { taggedEvents.Add(EventId.FromHex(tag[1])); }
                        catch { /* skip malformed */ }
                    }
                    break;
                case "a":
                    if (tag.Count >= 2 && !string.IsNullOrEmpty(tag[1])) taggedAddresses.Add(tag[1]);
                    break;
            }
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new FormatException("NIP-38 user-status event is missing the required 'd' tag.");
        }

        return new UserStatus
        {
            Author = ev.PubKey,
            Type = type,
            Content = ev.Content,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Expiration = expiration,
            ReferenceUrl = referenceUrl,
            TaggedPubkeys = taggedPubkeys,
            TaggedEvents = taggedEvents,
            TaggedAddresses = taggedAddresses,
        };
    }

    /// <summary>Tries to parse <paramref name="ev"/> as a NIP-38 user status. Returns <c>false</c> for wrong-kind or malformed inputs.</summary>
    public static bool TryFromEvent(NostrEvent? ev, out UserStatus? status)
    {
        status = null;
        if (ev is null || ev.Kind != Nip38Kinds.UserStatus)
        {
            return false;
        }

        try
        {
            status = FromEvent(ev);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Starts building a status of the given <paramref name="type"/>.
    /// Use <see cref="UserStatusTypes.General"/> or
    /// <see cref="UserStatusTypes.Music"/> for the well-known slots,
    /// or any other string for a custom slot.
    /// </summary>
    public static UserStatusBuilder Create(string type) => new(type);

    /// <summary>
    /// Builds a "clear" event for the given status type — an empty-content
    /// kind-30315 event that supersedes any prior status under the same
    /// <c>(kind, pubkey, d)</c> slot.
    /// </summary>
    public static UserStatusBuilder Clear(string type) => new(type);
}

/// <summary>Fluent builder for NIP-38 user-status events.</summary>
public sealed class UserStatusBuilder
{
    private readonly string _type;
    private string _content = string.Empty;
    private DateTimeOffset? _expiration;
    private string? _reference;
    private readonly List<PublicKey> _taggedPubkeys = new();
    private readonly List<EventId> _taggedEvents = new();
    private readonly List<string> _taggedAddresses = new();

    internal UserStatusBuilder(string type)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);
        _type = type;
    }

    /// <summary>Sets the status text (the event's <c>content</c>). Empty means "clear this slot".</summary>
    public UserStatusBuilder WithContent(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        _content = content;
        return this;
    }

    /// <summary>Sets the NIP-40 expiration timestamp.</summary>
    public UserStatusBuilder WithExpiration(DateTimeOffset when)
    {
        _expiration = when;
        return this;
    }

    /// <summary>Sets an external reference URL (the <c>r</c> tag) — e.g. <c>spotify:track:…</c>.</summary>
    public UserStatusBuilder WithReference(string url)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);
        _reference = url;
        return this;
    }

    /// <summary>Adds a <c>p</c> tag.</summary>
    public UserStatusBuilder TagProfile(PublicKey pubkey)
    {
        ArgumentNullException.ThrowIfNull(pubkey);
        _taggedPubkeys.Add(pubkey);
        return this;
    }

    /// <summary>Adds an <c>e</c> tag.</summary>
    public UserStatusBuilder TagEvent(EventId eventId)
    {
        ArgumentNullException.ThrowIfNull(eventId);
        _taggedEvents.Add(eventId);
        return this;
    }

    /// <summary>Adds an <c>a</c> tag (<c>kind:pubkey:identifier</c>).</summary>
    public UserStatusBuilder TagAddress(string address)
    {
        ArgumentException.ThrowIfNullOrEmpty(address);
        _taggedAddresses.Add(address);
        return this;
    }

    /// <summary>Builds the unsigned event for the given author + timestamp.</summary>
    public UnsignedEvent BuildUnsigned(PublicKey author, long createdAt)
    {
        ArgumentNullException.ThrowIfNull(author);
        var tags = new List<IReadOnlyList<string>>(
            1 + _taggedPubkeys.Count + _taggedEvents.Count + _taggedAddresses.Count + 2)
        {
            Tag.D(_type),
        };

        if (_expiration is DateTimeOffset exp)
        {
            tags.Add(new[]
            {
                "expiration",
                exp.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            });
        }

        if (_reference is not null)
        {
            tags.Add(new[] { "r", _reference });
        }

        foreach (var p in _taggedPubkeys) tags.Add(Tag.P(p));
        foreach (var e in _taggedEvents) tags.Add(Tag.E(e));
        foreach (var a in _taggedAddresses) tags.Add(new[] { "a", a });

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = createdAt,
            Kind = Nip38Kinds.UserStatus,
            Tags = tags,
            Content = _content,
        };
    }

    /// <summary>Builds and signs the event.</summary>
    public NostrEvent BuildAndSign(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return BuildUnsigned(key.PublicKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds()).Sign(key);
    }
}
