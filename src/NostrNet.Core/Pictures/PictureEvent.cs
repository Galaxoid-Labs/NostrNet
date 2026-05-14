// SPDX-License-Identifier: MIT
//
// NIP-68: Picture-first feeds (kind 20).
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/68.md
//
// Wire format:
//   kind     = 20
//   content  = description / caption (free text, may be empty)
//   tags:
//     "title"           — required: short title of post
//     "imeta" (≥1)      — required: image attachments, NIP-92 imeta format
//     "content-warning" — optional NSFW reason
//     "p"               — optional, repeatable: tagged users
//     "m" / "x"         — optional aggregate of attachment MIMEs / hashes
//     "t"               — optional, repeatable: hashtags
//     "location" / "g"  — optional location / geohash
//     "L" / "l"         — optional language tags
//
// The event itself is a regular Nostr event (not addressable / not
// replaceable). React via NIP-25, comment via NIP-22 — both work
// without anything NIP-68-specific.

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Pictures;

/// <summary>Kind constants for NIP-68 picture-first events.</summary>
public static class Nip68Kinds
{
    /// <summary>A picture-first post (kind 20).</summary>
    public const int PicturePost = 20;
}

/// <summary>
/// A typed view of a NIP-68 picture-first event.
/// </summary>
/// <remarks>
/// Use <see cref="FromEvent"/> to parse a received event, or
/// <see cref="PictureEventBuilder"/> via <see cref="Create"/> to build
/// a new one.
/// </remarks>
public sealed class PictureEvent
{
    /// <summary>The author's pubkey.</summary>
    public required PublicKey Author { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Display title taken from the <c>"title"</c> tag.</summary>
    public required string Title { get; init; }

    /// <summary>Free-text description / caption, taken from the event's <c>content</c> field.</summary>
    public required string Description { get; init; }

    /// <summary>Every attached image, in tag-order.</summary>
    public required IReadOnlyList<PictureMediaAttachment> Attachments { get; init; }

    /// <summary>Tagged users (every <c>"p"</c> tag).</summary>
    public IReadOnlyList<PublicKey> TaggedPubkeys { get; init; } = Array.Empty<PublicKey>();

    /// <summary>Hashtags (every <c>"t"</c> tag).</summary>
    public IReadOnlyList<string> Hashtags { get; init; } = Array.Empty<string>();

    /// <summary>NSFW marker (the value of the <c>"content-warning"</c> tag) if present.</summary>
    public string? ContentWarning { get; init; }

    /// <summary>Free-form location string from a <c>"location"</c> tag.</summary>
    public string? Location { get; init; }

    /// <summary>Geohash from a <c>"g"</c> tag.</summary>
    public string? Geohash { get; init; }

    /// <summary>Language code from the <c>"l"</c> tag (e.g. <c>"en"</c>).</summary>
    public string? Language { get; init; }

    /// <summary>
    /// Parses a kind-20 event into a typed <see cref="PictureEvent"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not kind 20.</exception>
    /// <exception cref="FormatException">Required <c>"title"</c> or <c>"imeta"</c> tags are missing or malformed.</exception>
    public static PictureEvent FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip68Kinds.PicturePost)
        {
            throw new ArgumentException(
                $"Expected NIP-68 kind {Nip68Kinds.PicturePost}; got {ev.Kind}.",
                nameof(ev));
        }

        string? title = null;
        var attachments = new List<PictureMediaAttachment>();
        var tagged = new List<PublicKey>();
        var hashtags = new List<string>();
        string? contentWarning = null;
        string? location = null;
        string? geohash = null;
        string? language = null;

        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0) continue;
            switch (tag[0])
            {
                case "title":
                    if (tag.Count >= 2) title = tag[1];
                    break;
                case "imeta":
                    attachments.Add(PictureMediaAttachment.FromImetaTag(tag));
                    break;
                case "p":
                    if (tag.Count >= 2 && tag[1] is string pk && pk.Length == 64)
                    {
                        try { tagged.Add(PublicKey.FromHex(pk)); }
                        catch { /* skip malformed p-tag */ }
                    }
                    break;
                case "t":
                    if (tag.Count >= 2 && !string.IsNullOrEmpty(tag[1])) hashtags.Add(tag[1]);
                    break;
                case "content-warning":
                    contentWarning = tag.Count >= 2 ? tag[1] : string.Empty;
                    break;
                case "location":
                    if (tag.Count >= 2) location = tag[1];
                    break;
                case "g":
                    if (tag.Count >= 2) geohash = tag[1];
                    break;
                case "l":
                    if (tag.Count >= 2) language = tag[1];
                    break;
            }
        }

        if (title is null)
        {
            throw new FormatException("NIP-68 event is missing the required 'title' tag.");
        }

        if (attachments.Count == 0)
        {
            throw new FormatException("NIP-68 event must have at least one 'imeta' tag.");
        }

        return new PictureEvent
        {
            Author = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Title = title,
            Description = ev.Content,
            Attachments = attachments,
            TaggedPubkeys = tagged,
            Hashtags = hashtags,
            ContentWarning = contentWarning,
            Location = location,
            Geohash = geohash,
            Language = language,
        };
    }

    /// <summary>
    /// Tries to parse <paramref name="ev"/> as a NIP-68 picture event.
    /// Returns <c>false</c> for any wrong-kind / malformed-tag input
    /// without throwing.
    /// </summary>
    public static bool TryFromEvent(NostrEvent? ev, out PictureEvent? picture)
    {
        picture = null;
        if (ev is null || ev.Kind != Nip68Kinds.PicturePost)
        {
            return false;
        }

        try
        {
            picture = FromEvent(ev);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Starts building a new picture-first event with the given
    /// <paramref name="title"/>. Add attachments + metadata via the
    /// returned builder, then call
    /// <see cref="PictureEventBuilder.BuildAndSign"/> to produce a
    /// publishable event.
    /// </summary>
    public static PictureEventBuilder Create(string title) => new(title);
}

/// <summary>Fluent builder for NIP-68 kind-20 events.</summary>
public sealed class PictureEventBuilder
{
    private readonly string _title;
    private string _description = string.Empty;
    private string? _contentWarning;
    private string? _location;
    private string? _geohash;
    private string? _language;
    private readonly List<PictureMediaAttachment> _attachments = new();
    private readonly List<(PublicKey, string?)> _taggedUsers = new();
    private readonly List<string> _hashtags = new();

    internal PictureEventBuilder(string title)
    {
        ArgumentException.ThrowIfNullOrEmpty(title);
        _title = title;
    }

    /// <summary>Sets the free-text caption (the event's <c>content</c>).</summary>
    public PictureEventBuilder WithDescription(string description)
    {
        ArgumentNullException.ThrowIfNull(description);
        _description = description;
        return this;
    }

    /// <summary>Appends one image attachment. Must be called at least once.</summary>
    public PictureEventBuilder AddAttachment(PictureMediaAttachment attachment)
    {
        ArgumentNullException.ThrowIfNull(attachment);
        _attachments.Add(attachment);
        return this;
    }

    /// <summary>Marks the post NSFW with a free-text reason.</summary>
    public PictureEventBuilder WithContentWarning(string reason)
    {
        ArgumentNullException.ThrowIfNull(reason);
        _contentWarning = reason;
        return this;
    }

    /// <summary>Tags a user (NIP-01 <c>p</c> tag), with an optional recommended relay.</summary>
    public PictureEventBuilder TagUser(PublicKey pubkey, string? recommendedRelay = null)
    {
        ArgumentNullException.ThrowIfNull(pubkey);
        _taggedUsers.Add((pubkey, recommendedRelay));
        return this;
    }

    /// <summary>Adds a hashtag (NIP-12 <c>t</c> tag).</summary>
    public PictureEventBuilder Hashtag(string tag)
    {
        ArgumentException.ThrowIfNullOrEmpty(tag);
        _hashtags.Add(tag);
        return this;
    }

    /// <summary>Sets a free-form location string.</summary>
    public PictureEventBuilder WithLocation(string location)
    {
        ArgumentException.ThrowIfNullOrEmpty(location);
        _location = location;
        return this;
    }

    /// <summary>Sets the location's geohash.</summary>
    public PictureEventBuilder WithGeohash(string geohash)
    {
        ArgumentException.ThrowIfNullOrEmpty(geohash);
        _geohash = geohash;
        return this;
    }

    /// <summary>Sets the post's language (ISO-639-1, e.g. <c>"en"</c>).</summary>
    public PictureEventBuilder WithLanguage(string code)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);
        _language = code;
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
                "NIP-68 requires at least one image attachment; call AddAttachment(...) first.");
        }

        var tags = new List<IReadOnlyList<string>>(
            2 + _attachments.Count + _taggedUsers.Count + _hashtags.Count)
        {
            Tag.Title(_title),
        };

        foreach (var attachment in _attachments)
        {
            tags.Add(attachment.ToImetaTag());
        }

        foreach ((var pk, var relay) in _taggedUsers)
        {
            tags.Add(Tag.P(pk, relay));
        }

        foreach (var t in _hashtags)
        {
            tags.Add(Tag.T(t));
        }

        if (_contentWarning is not null)
        {
            tags.Add(new[] { "content-warning", _contentWarning });
        }

        if (_location is not null) tags.Add(new[] { "location", _location });
        if (_geohash is not null) tags.Add(new[] { "g", _geohash });
        if (_language is not null) tags.Add(new[] { "l", _language });

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = createdAt,
            Kind = Nip68Kinds.PicturePost,
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
