// SPDX-License-Identifier: MIT
//
// NIP-23: Long-form content (markdown articles).
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/23.md
//
// Two kinds:
//   30023 — published article
//   30024 — draft
//
// Both are NIP-33 parameterized replaceable: keyed by (kind, author, "d"-tag
// value). The article body is markdown in `content`. Metadata is in tags:
//   "d"            — identifier / slug   (required by NIP-33)
//   "title"        — display title
//   "summary"      — abstract / description
//   "image"        — cover image URL
//   "published_at" — first-publish unix seconds (defaults to created_at)
//   "t"            — hashtag (repeatable)

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Nip19;

namespace NostrNet.Articles;

/// <summary>
/// Kind constants for NIP-23 long-form content.
/// </summary>
public static class Nip23Kinds
{
    /// <summary>A published long-form article (kind 30023).</summary>
    public const int LongFormArticle = 30023;

    /// <summary>A long-form draft, work-in-progress (kind 30024).</summary>
    public const int LongFormDraft = 30024;
}

/// <summary>
/// A typed view of a NIP-23 long-form article event.
/// </summary>
/// <remarks>
/// Use <see cref="FromEvent"/> to parse a received article event, or
/// <see cref="ArticleBuilder"/> via <see cref="Create"/> to build a new one.
/// </remarks>
public sealed class Article : INostrTypedEvent<Article>
{
    /// <summary>Nostr kind(s) this type represents (published + draft).</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { 30023, 30024 };

    /// <summary>The article's author.</summary>
    public required PublicKey Author { get; init; }

    /// <summary>
    /// The article identifier (the <c>"d"</c>-tag value, e.g., a URL slug).
    /// </summary>
    public required string Identifier { get; init; }

    /// <summary>The markdown body, taken from the event's <c>content</c> field.</summary>
    public required string Markdown { get; init; }

    /// <summary>The event's <c>created_at</c> (always present).</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>True if this is a draft (kind 30024) rather than a published article (kind 30023).</summary>
    public required bool IsDraft { get; init; }

    /// <summary>Display title, if a <c>"title"</c> tag is present.</summary>
    public string? Title { get; init; }

    /// <summary>Abstract / description, if a <c>"summary"</c> tag is present.</summary>
    public string? Summary { get; init; }

    /// <summary>Cover-image URL, if an <c>"image"</c> tag is present.</summary>
    public string? Image { get; init; }

    /// <summary>
    /// First-publish timestamp from the <c>"published_at"</c> tag. <c>null</c>
    /// if the tag was absent — per NIP-23, callers should fall back to
    /// <see cref="CreatedAt"/> in that case.
    /// </summary>
    public DateTimeOffset? PublishedAt { get; init; }

    /// <summary>The article's hashtags (every <c>"t"</c> tag).</summary>
    public IReadOnlyList<string> Hashtags { get; init; } = Array.Empty<string>();

    /// <summary>Returns the NIP-19 <c>naddr</c> coordinate for this article.</summary>
    /// <param name="relays">Optional recommended relays to embed.</param>
    public NaddrEntity ToNaddr(IReadOnlyList<string>? relays = null)
        => new()
        {
            PubKey = Author,
            Kind = IsDraft ? Nip23Kinds.LongFormDraft : Nip23Kinds.LongFormArticle,
            Identifier = Identifier,
            Relays = relays ?? Array.Empty<string>(),
        };

    /// <summary>
    /// Parses a kind-30023 or kind-30024 event into a typed <see cref="Article"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not a NIP-23 kind.</exception>
    /// <exception cref="FormatException">Required <c>"d"</c> tag is missing.</exception>
    public static Article FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind is not (Nip23Kinds.LongFormArticle or Nip23Kinds.LongFormDraft))
        {
            throw new ArgumentException(
                $"Expected a NIP-23 kind ({Nip23Kinds.LongFormArticle} or {Nip23Kinds.LongFormDraft}); got {ev.Kind}.",
                nameof(ev));
        }

        string? identifier = ev.Tags.Identifier();
        if (string.IsNullOrEmpty(identifier))
        {
            throw new FormatException("NIP-23 events require a non-empty 'd' tag.");
        }

        DateTimeOffset? publishedAt = null;
        if (ev.Tags.FirstValue("published_at") is string publishedAtStr
            && long.TryParse(publishedAtStr, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long unix))
        {
            publishedAt = DateTimeOffset.FromUnixTimeSeconds(unix);
        }

        return new Article
        {
            Author = ev.PubKey,
            Identifier = identifier,
            Markdown = ev.Content,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            IsDraft = ev.Kind == Nip23Kinds.LongFormDraft,
            Title = ev.Tags.FirstValue("title"),
            Summary = ev.Tags.FirstValue("summary"),
            Image = ev.Tags.FirstValue("image"),
            PublishedAt = publishedAt,
            Hashtags = ev.Tags.Hashtags().ToArray(),
        };
    }

    /// <summary>Try-parse variant. Returns <c>false</c> on any failure.</summary>
    public static bool TryFromEvent(
        NostrEvent? ev,
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out Article? article)
    {
        article = null;
        if (ev is null)
        {
            return false;
        }

        try
        {
            article = FromEvent(ev);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Starts building a new long-form article with the required identifier
    /// and markdown body.
    /// </summary>
    /// <param name="identifier">A stable slug used for the <c>"d"</c> tag; future revisions reuse this to replace the event.</param>
    /// <param name="markdown">The article body.</param>
    public static ArticleBuilder Create(string identifier, string markdown)
        => new(identifier, markdown);
}

/// <summary>
/// Fluent builder for NIP-23 article events.
/// </summary>
public sealed class ArticleBuilder
{
    private readonly string _identifier;
    private readonly string _markdown;
    private bool _isDraft;
    private string? _title;
    private string? _summary;
    private string? _image;
    private DateTimeOffset? _publishedAt;
    private readonly List<string> _hashtags = new();
    private readonly List<IReadOnlyList<string>> _extraTags = new();

    internal ArticleBuilder(string identifier, string markdown)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException("Article identifier (d-tag) must be non-empty.", nameof(identifier));
        }

        _identifier = identifier;
        _markdown = markdown ?? throw new ArgumentNullException(nameof(markdown));
    }

    /// <summary>Marks this article as a draft (kind 30024) instead of published (30023).</summary>
    public ArticleBuilder AsDraft()
    {
        _isDraft = true;
        return this;
    }

    /// <summary>Sets the <c>"title"</c> tag.</summary>
    public ArticleBuilder WithTitle(string title)
    {
        _title = title;
        return this;
    }

    /// <summary>Sets the <c>"summary"</c> tag.</summary>
    public ArticleBuilder WithSummary(string summary)
    {
        _summary = summary;
        return this;
    }

    /// <summary>Sets the <c>"image"</c> tag with the cover image URL.</summary>
    public ArticleBuilder WithImage(string url)
    {
        _image = url;
        return this;
    }

    /// <summary>Sets the <c>"published_at"</c> tag (unix seconds).</summary>
    public ArticleBuilder WithPublishedAt(DateTimeOffset when)
    {
        _publishedAt = when;
        return this;
    }

    /// <summary>Adds a hashtag (<c>"t"</c> tag).</summary>
    public ArticleBuilder WithHashtag(string hashtag)
    {
        _hashtags.Add(hashtag);
        return this;
    }

    /// <summary>Adds multiple hashtags.</summary>
    public ArticleBuilder WithHashtags(params string[] hashtags)
    {
        _hashtags.AddRange(hashtags);
        return this;
    }

    /// <summary>Adds an arbitrary tag (for non-standard metadata).</summary>
    public ArticleBuilder WithTag(IReadOnlyList<string> tag)
    {
        _extraTags.Add(tag);
        return this;
    }

    /// <summary>
    /// Builds and signs the article event.
    /// </summary>
    public NostrEvent Sign(PrivateKey authorKey, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(authorKey);

        var tags = new List<IReadOnlyList<string>>
        {
            Tag.D(_identifier),
        };

        if (_title is not null)
        {
            tags.Add(Tag.Title(_title));
        }

        if (_summary is not null)
        {
            tags.Add(new[] { "summary", _summary });
        }

        if (_image is not null)
        {
            tags.Add(Tag.Image(_image));
        }

        if (_publishedAt is DateTimeOffset pub)
        {
            tags.Add(new[]
            {
                "published_at",
                pub.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            });
        }

        foreach (string h in _hashtags)
        {
            tags.Add(Tag.T(h));
        }

        foreach (var t in _extraTags)
        {
            tags.Add(t);
        }

        return new UnsignedEvent
        {
            PubKey = authorKey.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = _isDraft ? Nip23Kinds.LongFormDraft : Nip23Kinds.LongFormArticle,
            Tags = tags,
            Content = _markdown,
        }.Sign(authorKey);
    }
}
