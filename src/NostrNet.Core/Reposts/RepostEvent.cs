// SPDX-License-Identifier: MIT
//
// NIP-18: Reposts.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/18.md
//
// Three flavors:
//
//   kind 6   "Repost": reposts a kind-1 text note. Content is the
//            stringified JSON of the original event.
//   kind 16  "Generic repost": reposts any non-kind-1 event. Content
//            is again the stringified JSON of the original; tags add
//            `k` to identify the reposted kind.
//   q-tag    Quote-repost: a regular note (kind 1 or otherwise) that
//            references another event via a `q` tag. Used so the
//            reference is NOT pulled into the original event's reply
//            thread. Build via `Repost.QuoteTag(...)`.
//
// All flavors share an `e` tag pointing to the reposted event id,
// with the relay URL as the third tag element so consumers can
// fetch the original. A `p` tag with the original author's pubkey
// is recommended.

using System.Text.Json;
using System.Diagnostics.CodeAnalysis;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Reposts;

/// <summary>Kind constants for NIP-18 reposts.</summary>
public static class Nip18Kinds
{
    /// <summary>Kind-1 text-note repost (kind 6).</summary>
    public const int Repost = 6;

    /// <summary>Generic repost of any non-kind-1 event (kind 16).</summary>
    public const int GenericRepost = 16;

    internal static bool IsRepostKind(int kind) => kind is Repost or GenericRepost;
}

/// <summary>A typed view of a NIP-18 kind-6 / kind-16 repost event.</summary>
public sealed class RepostEvent : INostrTypedEvent<RepostEvent>
{
    /// <summary>Nostr kind(s) this type represents (kind 6 for kind-1 notes; kind 16 generic).</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { 6, 16 };

    /// <summary>The author of the repost (the user doing the resharing).</summary>
    public required PublicKey Author { get; init; }

    /// <summary>The repost event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Repost kind — <see cref="Nip18Kinds.Repost"/> (6) or <see cref="Nip18Kinds.GenericRepost"/> (16).</summary>
    public required int Kind { get; init; }

    /// <summary>Event id of the original event being reposted.</summary>
    public required EventId RepostedEventId { get; init; }

    /// <summary>Recommended relay URL (the third value on the <c>e</c> tag).</summary>
    public string? RepostedRelayUrl { get; init; }

    /// <summary>Author of the original event from the <c>p</c> tag, if present.</summary>
    public PublicKey? RepostedAuthor { get; init; }

    /// <summary>Kind number of the original event from the <c>k</c> tag (recommended on kind-16 reposts).</summary>
    public int? RepostedKind { get; init; }

    /// <summary>Replaceable-event coordinate from the <c>a</c> tag, if present (form <c>kind:pubkey:identifier</c>).</summary>
    public string? RepostedAddress { get; init; }

    /// <summary>
    /// The reposted event parsed out of <see cref="NostrEvent.Content"/>, when the
    /// publisher included it (recommended per spec). <c>null</c> when the content
    /// field is empty or not valid Nostr-event JSON.
    /// </summary>
    public NostrEvent? RepostedEvent { get; init; }

    /// <summary>True for kind-16 (any non-kind-1).</summary>
    public bool IsGeneric => Kind == Nip18Kinds.GenericRepost;

    /// <summary>Parses a kind-6 or kind-16 event into a typed <see cref="RepostEvent"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> isn't a NIP-18 kind.</exception>
    /// <exception cref="FormatException">Required <c>e</c> tag is missing or malformed.</exception>
    public static RepostEvent FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (!Nip18Kinds.IsRepostKind(ev.Kind))
        {
            throw new ArgumentException(
                $"Expected NIP-18 kind (6 or 16); got {ev.Kind}.", nameof(ev));
        }

        EventId? repostedId = null;
        string? relayUrl = null;
        PublicKey? repostedAuthor = null;
        int? repostedKind = null;
        string? repostedAddr = null;

        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0) continue;
            switch (tag[0])
            {
                case "e":
                    if (tag.Count >= 2 && repostedId is null)
                    {
                        try { repostedId = EventId.FromHex(tag[1]); }
                        catch { /* skip malformed */ }
                        if (tag.Count >= 3 && !string.IsNullOrEmpty(tag[2]))
                        {
                            relayUrl = tag[2];
                        }
                    }
                    break;
                case "p":
                    if (tag.Count >= 2 && repostedAuthor is null && tag[1]?.Length == 64)
                    {
                        try { repostedAuthor = PublicKey.FromHex(tag[1]); }
                        catch { /* skip malformed */ }
                    }
                    break;
                case "k":
                    if (tag.Count >= 2 && int.TryParse(tag[1], out int k))
                    {
                        repostedKind = k;
                    }
                    break;
                case "a":
                    if (tag.Count >= 2 && repostedAddr is null) repostedAddr = tag[1];
                    break;
            }
        }

        if (repostedId is null)
        {
            throw new FormatException("NIP-18 repost is missing a valid 'e' tag.");
        }

        NostrEvent? innerEvent = null;
        if (!string.IsNullOrEmpty(ev.Content))
        {
            innerEvent = TryParseInnerEvent(ev.Content);
        }

        return new RepostEvent
        {
            Author = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Kind = ev.Kind,
            RepostedEventId = repostedId,
            RepostedRelayUrl = relayUrl,
            RepostedAuthor = repostedAuthor,
            RepostedKind = repostedKind,
            RepostedAddress = repostedAddr,
            RepostedEvent = innerEvent,
        };
    }

    /// <summary>
    /// Tries to parse <paramref name="ev"/> as a NIP-18 repost. Returns <c>false</c>
    /// for wrong-kind or malformed inputs.
    /// </summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out RepostEvent? repost)
    {
        repost = null;
        if (ev is null || !Nip18Kinds.IsRepostKind(ev.Kind))
        {
            return false;
        }

        try
        {
            repost = FromEvent(ev);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Starts building a repost of <paramref name="originalEvent"/>. Kind 6 is
    /// chosen automatically for kind-1 originals; kind 16 for everything else.
    /// </summary>
    public static RepostEventBuilder Create(NostrEvent originalEvent) =>
        new(originalEvent);

    private static NostrEvent? TryParseInnerEvent(string json)
    {
        try
        {
            return NostrEvent.FromJson(json);
        }
        catch (JsonException) { return null; }
        catch (FormatException) { return null; }
        catch (ArgumentException) { return null; }
    }
}

/// <summary>Fluent builder for NIP-18 repost events.</summary>
public sealed class RepostEventBuilder
{
    private readonly NostrEvent _original;
    private string? _relayUrl;
    private bool _embedOriginal = true;

    internal RepostEventBuilder(NostrEvent original)
    {
        ArgumentNullException.ThrowIfNull(original);
        _original = original;
    }

    /// <summary>
    /// Sets the relay URL hint that goes into the <c>e</c> tag's third
    /// position. NIP-18 says clients SHOULD include this so consumers
    /// can fetch the original.
    /// </summary>
    public RepostEventBuilder WithRelayHint(string relayUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(relayUrl);
        _relayUrl = relayUrl;
        return this;
    }

    /// <summary>
    /// When <c>true</c> (the default), serializes the original event
    /// into the repost's <c>content</c> field so consumers can render
    /// it without an extra relay round-trip. Setting <c>false</c>
    /// leaves the content empty — appropriate for NIP-70 protected
    /// originals where embedding would leak the protected payload.
    /// </summary>
    public RepostEventBuilder EmbedOriginal(bool embed)
    {
        _embedOriginal = embed;
        return this;
    }

    /// <summary>Builds the unsigned repost event.</summary>
    public UnsignedEvent BuildUnsigned(PublicKey author, long createdAt)
    {
        ArgumentNullException.ThrowIfNull(author);

        int kind = _original.Kind == 1 ? Nip18Kinds.Repost : Nip18Kinds.GenericRepost;

        var tags = new List<IReadOnlyList<string>>(4);
        tags.Add(_relayUrl is null
            ? new[] { "e", _original.Id.ToHex() }
            : new[] { "e", _original.Id.ToHex(), _relayUrl });
        tags.Add(new[] { "p", _original.PubKey.ToHex() });

        if (kind == Nip18Kinds.GenericRepost)
        {
            tags.Add(new[]
            {
                "k",
                _original.Kind.ToString(System.Globalization.CultureInfo.InvariantCulture),
            });
        }

        string content = _embedOriginal ? _original.ToJson() : string.Empty;

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = createdAt,
            Kind = kind,
            Tags = tags,
            Content = content,
        };
    }

    /// <summary>Builds and signs the repost event.</summary>
    public NostrEvent BuildAndSign(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return BuildUnsigned(key.PublicKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds()).Sign(key);
    }
}

/// <summary>
/// Helpers for the NIP-18 quote-repost <c>q</c> tag, which is added
/// to a regular post (typically kind 1) to reference another event
/// WITHOUT pulling it into the reply thread.
/// </summary>
public static class Repost
{
    /// <summary>
    /// Builds a NIP-18 <c>q</c> tag: <c>["q", &lt;event-id&gt;, &lt;optional-relay&gt;, &lt;optional-pubkey&gt;]</c>.
    /// Per spec the pubkey is included only when quoting a regular (non-replaceable)
    /// event; pass <c>null</c> for replaceable / addressable quotes.
    /// </summary>
    public static IReadOnlyList<string> QuoteTag(
        EventId eventId,
        string? relayUrl = null,
        PublicKey? author = null)
    {
        ArgumentNullException.ThrowIfNull(eventId);
        return (relayUrl, author) switch
        {
            (null, null) => new[] { "q", eventId.ToHex() },
            (string r, null) => new[] { "q", eventId.ToHex(), r },
            (null, PublicKey p) => new[] { "q", eventId.ToHex(), string.Empty, p.ToHex() },
            (string r, PublicKey p) => new[] { "q", eventId.ToHex(), r, p.ToHex() },
        };
    }
}
