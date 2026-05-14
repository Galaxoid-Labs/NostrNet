// SPDX-License-Identifier: MIT
//
// NIP-71: Video events.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/71.md
//
// Four kinds — two regular, two addressable (NIP-33 parameterized
// replaceable):
//
//   21    Normal video (landscape, regular)
//   22    Short video (portrait, regular)
//   34235 Normal video, addressable (`d`-tag, replaceable)
//   34236 Short video, addressable
//
// Required tags: `title`, ≥1 `imeta` (the video itself). Addressable
// kinds additionally require `d`.
//
// Content is the video summary / description (free text), distinct
// from `title` (formal name) and `alt` (accessibility description).

using System.Globalization;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Nip19;

namespace NostrNet.Videos;

/// <summary>Kind constants for NIP-71 video events.</summary>
public static class Nip71Kinds
{
    /// <summary>Normal video (landscape, regular event). Kind 21.</summary>
    public const int NormalVideo = 21;

    /// <summary>Short video (portrait, regular event). Kind 22.</summary>
    public const int ShortVideo = 22;

    /// <summary>Normal video, NIP-33 addressable (replaceable). Kind 34235.</summary>
    public const int NormalVideoAddressable = 34235;

    /// <summary>Short video, NIP-33 addressable (replaceable). Kind 34236.</summary>
    public const int ShortVideoAddressable = 34236;

    internal static bool IsVideoKind(int kind) =>
        kind is NormalVideo or ShortVideo or NormalVideoAddressable or ShortVideoAddressable;

    internal static bool IsAddressableKind(int kind) =>
        kind is NormalVideoAddressable or ShortVideoAddressable;

    internal static bool IsShortFormKind(int kind) =>
        kind is ShortVideo or ShortVideoAddressable;
}

/// <summary>A typed view of a NIP-71 video event.</summary>
public sealed class VideoEvent
{
    /// <summary>The author's pubkey.</summary>
    public required PublicKey Author { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>The kind (21 / 22 / 34235 / 34236).</summary>
    public required int Kind { get; init; }

    /// <summary>Display title (the <c>"title"</c> tag).</summary>
    public required string Title { get; init; }

    /// <summary>Description / summary (the event's <c>content</c>).</summary>
    public required string Description { get; init; }

    /// <summary>Every attached video, in tag-order.</summary>
    public required IReadOnlyList<VideoMediaAttachment> Attachments { get; init; }

    /// <summary>For addressable kinds (34235 / 34236), the <c>"d"</c>-tag value.</summary>
    public string? Identifier { get; init; }

    /// <summary>Original publication timestamp from a <c>"published_at"</c> tag, if present.</summary>
    public DateTimeOffset? PublishedAt { get; init; }

    /// <summary>Accessibility description from an <c>"alt"</c> tag.</summary>
    public string? Alt { get; init; }

    /// <summary>NSFW marker from a <c>"content-warning"</c> tag.</summary>
    public string? ContentWarning { get; init; }

    /// <summary>
    /// Top-level <c>"duration"</c> tag value in seconds, if present.
    /// Note: the per-attachment duration on the imeta is the preferred
    /// place for this; the top-level tag is a duplication some clients
    /// emit for filtering.
    /// </summary>
    public double? DurationSeconds { get; init; }

    /// <summary>Hashtags (every <c>"t"</c> tag).</summary>
    public IReadOnlyList<string> Hashtags { get; init; } = Array.Empty<string>();

    /// <summary>Tagged users (every <c>"p"</c> tag).</summary>
    public IReadOnlyList<PublicKey> TaggedPubkeys { get; init; } = Array.Empty<PublicKey>();

    /// <summary>External reference URLs (every <c>"r"</c> tag).</summary>
    public IReadOnlyList<string> References { get; init; } = Array.Empty<string>();

    /// <summary>True for kinds 22 / 34236.</summary>
    public bool IsShortForm => Nip71Kinds.IsShortFormKind(Kind);

    /// <summary>True for kinds 34235 / 34236.</summary>
    public bool IsAddressable => Nip71Kinds.IsAddressableKind(Kind);

    /// <summary>Returns the NIP-19 <c>naddr</c> coordinate for an addressable video.</summary>
    /// <exception cref="InvalidOperationException">This video isn't addressable.</exception>
    public NaddrEntity ToNaddr(IReadOnlyList<string>? relays = null)
    {
        if (!IsAddressable || Identifier is null)
        {
            throw new InvalidOperationException("ToNaddr() requires an addressable video event (kind 34235 / 34236) with a d-tag.");
        }

        return new NaddrEntity
        {
            PubKey = Author,
            Kind = Kind,
            Identifier = Identifier,
            Relays = relays ?? Array.Empty<string>(),
        };
    }

    /// <summary>Parses a NIP-71 event into a typed <see cref="VideoEvent"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not a NIP-71 kind.</exception>
    /// <exception cref="FormatException">A required tag is missing or malformed.</exception>
    public static VideoEvent FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (!Nip71Kinds.IsVideoKind(ev.Kind))
        {
            throw new ArgumentException(
                $"Expected NIP-71 kind (21 / 22 / 34235 / 34236); got {ev.Kind}.",
                nameof(ev));
        }

        string? title = null;
        string? identifier = null;
        DateTimeOffset? publishedAt = null;
        string? alt = null;
        string? contentWarning = null;
        double? duration = null;
        var attachments = new List<VideoMediaAttachment>();
        var hashtags = new List<string>();
        var tagged = new List<PublicKey>();
        var references = new List<string>();

        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0) continue;
            switch (tag[0])
            {
                case "title":
                    if (tag.Count >= 2) title = tag[1];
                    break;
                case "d":
                    if (tag.Count >= 2) identifier = tag[1];
                    break;
                case "imeta":
                    attachments.Add(VideoMediaAttachment.FromImetaTag(tag));
                    break;
                case "published_at":
                    if (tag.Count >= 2 && long.TryParse(tag[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out long ts))
                    {
                        publishedAt = DateTimeOffset.FromUnixTimeSeconds(ts);
                    }

                    break;
                case "alt":
                    if (tag.Count >= 2) alt = tag[1];
                    break;
                case "content-warning":
                    contentWarning = tag.Count >= 2 ? tag[1] : string.Empty;
                    break;
                case "duration":
                    if (tag.Count >= 2 && double.TryParse(tag[1], NumberStyles.Float, CultureInfo.InvariantCulture, out double d))
                    {
                        duration = d;
                    }

                    break;
                case "t":
                    if (tag.Count >= 2 && !string.IsNullOrEmpty(tag[1])) hashtags.Add(tag[1]);
                    break;
                case "p":
                    if (tag.Count >= 2 && tag[1] is string pk && pk.Length == 64)
                    {
                        try { tagged.Add(PublicKey.FromHex(pk)); }
                        catch { /* skip malformed */ }
                    }

                    break;
                case "r":
                    if (tag.Count >= 2 && !string.IsNullOrEmpty(tag[1])) references.Add(tag[1]);
                    break;
            }
        }

        if (title is null)
        {
            throw new FormatException("NIP-71 event is missing the required 'title' tag.");
        }

        if (attachments.Count == 0)
        {
            throw new FormatException("NIP-71 event must have at least one 'imeta' tag.");
        }

        if (Nip71Kinds.IsAddressableKind(ev.Kind) && identifier is null)
        {
            throw new FormatException(
                $"Addressable NIP-71 event (kind {ev.Kind}) is missing the required 'd' tag.");
        }

        return new VideoEvent
        {
            Author = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Kind = ev.Kind,
            Title = title,
            Description = ev.Content,
            Attachments = attachments,
            Identifier = identifier,
            PublishedAt = publishedAt,
            Alt = alt,
            ContentWarning = contentWarning,
            DurationSeconds = duration,
            Hashtags = hashtags,
            TaggedPubkeys = tagged,
            References = references,
        };
    }

    /// <summary>Tries to parse <paramref name="ev"/> as a NIP-71 video. Returns <c>false</c> for any non-NIP-71 kind or malformed tags.</summary>
    public static bool TryFromEvent(NostrEvent? ev, out VideoEvent? video)
    {
        video = null;
        if (ev is null || !Nip71Kinds.IsVideoKind(ev.Kind))
        {
            return false;
        }

        try
        {
            video = FromEvent(ev);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Builder entry-point. Pass one of the
    /// <see cref="Nip71Kinds"/> values; addressable kinds also need
    /// <paramref name="identifier"/>.
    /// </summary>
    public static VideoEventBuilder Create(int kind, string title, string? identifier = null)
        => new(kind, title, identifier);
}

/// <summary>Fluent builder for NIP-71 video events.</summary>
public sealed class VideoEventBuilder
{
    private readonly int _kind;
    private readonly string _title;
    private readonly string? _identifier;
    private string _description = string.Empty;
    private string? _alt;
    private string? _contentWarning;
    private DateTimeOffset? _publishedAt;
    private double? _duration;
    private readonly List<VideoMediaAttachment> _attachments = new();
    private readonly List<string> _hashtags = new();
    private readonly List<(PublicKey, string?)> _taggedUsers = new();
    private readonly List<string> _references = new();

    internal VideoEventBuilder(int kind, string title, string? identifier)
    {
        if (!Nip71Kinds.IsVideoKind(kind))
        {
            throw new ArgumentException(
                $"Expected one of NIP-71 kinds (21 / 22 / 34235 / 34236); got {kind}.",
                nameof(kind));
        }

        ArgumentException.ThrowIfNullOrEmpty(title);
        if (Nip71Kinds.IsAddressableKind(kind))
        {
            ArgumentException.ThrowIfNullOrEmpty(identifier);
        }

        _kind = kind;
        _title = title;
        _identifier = identifier;
    }

    /// <summary>Sets the description / summary (the event's <c>content</c>).</summary>
    public VideoEventBuilder WithDescription(string description)
    {
        ArgumentNullException.ThrowIfNull(description);
        _description = description;
        return this;
    }

    /// <summary>Appends one video attachment. Must be called at least once.</summary>
    public VideoEventBuilder AddAttachment(VideoMediaAttachment attachment)
    {
        ArgumentNullException.ThrowIfNull(attachment);
        _attachments.Add(attachment);
        return this;
    }

    /// <summary>Sets the accessibility description (<c>"alt"</c> tag).</summary>
    public VideoEventBuilder WithAlt(string alt)
    {
        ArgumentNullException.ThrowIfNull(alt);
        _alt = alt;
        return this;
    }

    /// <summary>Marks the post NSFW with a free-text reason.</summary>
    public VideoEventBuilder WithContentWarning(string reason)
    {
        ArgumentNullException.ThrowIfNull(reason);
        _contentWarning = reason;
        return this;
    }

    /// <summary>Sets the original publication timestamp.</summary>
    public VideoEventBuilder WithPublishedAt(DateTimeOffset publishedAt)
    {
        _publishedAt = publishedAt;
        return this;
    }

    /// <summary>Sets a top-level duration tag (seconds). The per-attachment value is preferred; this is mainly for relay-side filtering.</summary>
    public VideoEventBuilder WithDurationSeconds(double seconds)
    {
        _duration = seconds;
        return this;
    }

    /// <summary>Adds a hashtag.</summary>
    public VideoEventBuilder Hashtag(string tag)
    {
        ArgumentException.ThrowIfNullOrEmpty(tag);
        _hashtags.Add(tag);
        return this;
    }

    /// <summary>Tags a user.</summary>
    public VideoEventBuilder TagUser(PublicKey pubkey, string? recommendedRelay = null)
    {
        ArgumentNullException.ThrowIfNull(pubkey);
        _taggedUsers.Add((pubkey, recommendedRelay));
        return this;
    }

    /// <summary>Adds an external reference URL (<c>"r"</c> tag).</summary>
    public VideoEventBuilder Reference(string url)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);
        _references.Add(url);
        return this;
    }

    /// <summary>Builds the unsigned event for the given author + timestamp.</summary>
    /// <exception cref="InvalidOperationException">No attachments were added.</exception>
    public UnsignedEvent BuildUnsigned(PublicKey author, long createdAt)
    {
        ArgumentNullException.ThrowIfNull(author);
        if (_attachments.Count == 0)
        {
            throw new InvalidOperationException(
                "NIP-71 requires at least one video attachment; call AddAttachment(...) first.");
        }

        var tags = new List<IReadOnlyList<string>>();
        if (Nip71Kinds.IsAddressableKind(_kind) && _identifier is not null)
        {
            tags.Add(Tag.D(_identifier));
        }

        tags.Add(Tag.Title(_title));
        foreach (var attachment in _attachments)
        {
            tags.Add(attachment.ToImetaTag());
        }

        if (_publishedAt is DateTimeOffset pub)
        {
            tags.Add(new[]
            {
                "published_at",
                pub.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            });
        }

        if (_alt is not null) tags.Add(new[] { "alt", _alt });
        if (_contentWarning is not null) tags.Add(new[] { "content-warning", _contentWarning });
        if (_duration is double dur)
        {
            tags.Add(new[] { "duration", dur.ToString("0.###", CultureInfo.InvariantCulture) });
        }

        foreach ((var pk, var relay) in _taggedUsers)
        {
            tags.Add(Tag.P(pk, relay));
        }

        foreach (var t in _hashtags)
        {
            tags.Add(Tag.T(t));
        }

        foreach (var r in _references)
        {
            tags.Add(Tag.R(r));
        }

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = createdAt,
            Kind = _kind,
            Tags = tags,
            Content = _description,
        };
    }

    /// <summary>Builds and signs the event with <paramref name="key"/>.</summary>
    public NostrEvent BuildAndSign(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return BuildUnsigned(key.PublicKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds()).Sign(key);
    }
}
