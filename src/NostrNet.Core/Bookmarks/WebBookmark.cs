// SPDX-License-Identifier: MIT
//
// NIP-B0: Web bookmarks.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/B0.md
//
// Kind 39701 — parameterized replaceable bookmark of an HTTP/HTTPS URL.
// The `d` tag carries the URL with the scheme stripped (so the same URL
// served over http and https collapses to the same bookmark).
//
//   tags:
//     "d"            — URL without scheme (REQUIRED)
//     "title"        — bookmark title (optional)
//     "published_at" — unix seconds, stringified (optional)
//     "t"            — hashtag, repeatable (optional)
//   content: free-form description (may be empty).

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Nip19;

namespace NostrNet.Bookmarks;

/// <summary>Kind constants for NIP-B0.</summary>
public static class NipB0Kinds
{
    /// <summary>The kind for a NIP-B0 web bookmark event.</summary>
    public const int WebBookmark = 39701;
}

/// <summary>
/// A typed view of a NIP-B0 web bookmark event.
/// </summary>
public sealed class WebBookmark : INostrTypedEvent<WebBookmark>
{
    /// <summary>Nostr kind(s) this type represents.</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { 39701 };

    /// <summary>The author of the bookmark.</summary>
    public required PublicKey Author { get; init; }

    /// <summary>
    /// The bookmarked URL with the scheme stripped (e.g., <c>alice.blog/post</c>).
    /// This is the <c>d</c>-tag value used to address replaceable revisions.
    /// </summary>
    public required string Url { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// Free-form description of the bookmark, from the event's <c>content</c>.
    /// May be empty.
    /// </summary>
    public string Description { get; init; } = string.Empty;

    /// <summary>Bookmark title, if a <c>"title"</c> tag is present.</summary>
    public string? Title { get; init; }

    /// <summary>
    /// First-publish timestamp from the <c>"published_at"</c> tag, if present.
    /// </summary>
    public DateTimeOffset? PublishedAt { get; init; }

    /// <summary>Hashtags (every <c>"t"</c> tag).</summary>
    public IReadOnlyList<string> Hashtags { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Returns the full URL with the given scheme (defaults to <c>https</c>).
    /// </summary>
    public string ToUrl(string scheme = "https")
    {
        ArgumentException.ThrowIfNullOrEmpty(scheme);
        return $"{scheme}://{Url}";
    }

    /// <summary>Returns the NIP-19 <c>naddr</c> coordinate for this bookmark.</summary>
    public NaddrEntity ToNaddr(IReadOnlyList<string>? relays = null)
        => new()
        {
            PubKey = Author,
            Kind = NipB0Kinds.WebBookmark,
            Identifier = Url,
            Relays = relays ?? Array.Empty<string>(),
        };

    /// <summary>Parses a kind-39701 event into a typed <see cref="WebBookmark"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not a NIP-B0 event.</exception>
    /// <exception cref="FormatException">Required <c>d</c> tag is missing.</exception>
    public static WebBookmark FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != NipB0Kinds.WebBookmark)
        {
            throw new ArgumentException(
                $"Expected a NIP-B0 kind ({NipB0Kinds.WebBookmark}); got {ev.Kind}.",
                nameof(ev));
        }

        string? url = ev.Tags.Identifier();
        if (string.IsNullOrEmpty(url))
        {
            throw new FormatException("NIP-B0 events require a non-empty 'd' tag.");
        }

        DateTimeOffset? publishedAt = null;
        if (ev.Tags.FirstValue("published_at") is string publishedAtStr
            && long.TryParse(publishedAtStr, NumberStyles.None, CultureInfo.InvariantCulture, out long unix))
        {
            publishedAt = DateTimeOffset.FromUnixTimeSeconds(unix);
        }

        return new WebBookmark
        {
            Author = ev.PubKey,
            Url = url,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Description = ev.Content,
            Title = ev.Tags.FirstValue("title"),
            PublishedAt = publishedAt,
            Hashtags = ev.Tags.Hashtags().ToArray(),
        };
    }

    /// <summary>Try-parse variant. Returns <c>false</c> on the wrong kind or a missing <c>d</c> tag.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out WebBookmark? bookmark)
    {
        bookmark = null;
        if (ev is null)
        {
            return false;
        }

        try
        {
            bookmark = FromEvent(ev);
            return true;
        }
        catch (Exception e) when (e is ArgumentException or FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Starts building a bookmark event for the given URL. The scheme
    /// (<c>https://</c>, <c>http://</c>, or leading <c>//</c>) is stripped so
    /// the bookmark addresses by host+path only.
    /// </summary>
    public static WebBookmarkBuilder Create(string url) => new(NormalizeUrl(url));

    internal static string NormalizeUrl(string url)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);

        if (url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return url["https://".Length..];
        }

        if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            return url["http://".Length..];
        }

        if (url.StartsWith("//", StringComparison.Ordinal))
        {
            return url[2..];
        }

        return url;
    }
}

/// <summary>Fluent builder for NIP-B0 bookmark events.</summary>
public sealed class WebBookmarkBuilder
{
    private readonly string _url;
    private string _description = string.Empty;
    private string? _title;
    private DateTimeOffset? _publishedAt;
    private readonly List<string> _hashtags = new();
    private readonly List<IReadOnlyList<string>> _extraTags = new();

    internal WebBookmarkBuilder(string normalizedUrl)
    {
        _url = normalizedUrl;
    }

    /// <summary>Sets the event content (the bookmark's description).</summary>
    public WebBookmarkBuilder WithDescription(string description)
    {
        _description = description ?? throw new ArgumentNullException(nameof(description));
        return this;
    }

    /// <summary>Sets the <c>"title"</c> tag.</summary>
    public WebBookmarkBuilder WithTitle(string title)
    {
        _title = title;
        return this;
    }

    /// <summary>Sets the <c>"published_at"</c> tag.</summary>
    public WebBookmarkBuilder WithPublishedAt(DateTimeOffset when)
    {
        _publishedAt = when;
        return this;
    }

    /// <summary>Adds a hashtag (<c>"t"</c> tag).</summary>
    public WebBookmarkBuilder WithHashtag(string hashtag)
    {
        _hashtags.Add(hashtag);
        return this;
    }

    /// <summary>Adds multiple hashtags.</summary>
    public WebBookmarkBuilder WithHashtags(params string[] hashtags)
    {
        _hashtags.AddRange(hashtags);
        return this;
    }

    /// <summary>Adds an arbitrary tag (for non-standard metadata).</summary>
    public WebBookmarkBuilder WithTag(IReadOnlyList<string> tag)
    {
        _extraTags.Add(tag);
        return this;
    }

    /// <summary>Builds and signs the bookmark event.</summary>
    public NostrEvent Sign(PrivateKey key, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        var tags = new List<IReadOnlyList<string>>
        {
            Tag.D(_url),
        };

        if (_title is not null)
        {
            tags.Add(Tag.Title(_title));
        }

        if (_publishedAt is DateTimeOffset pub)
        {
            tags.Add(new[]
            {
                "published_at",
                pub.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
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
            PubKey = key.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = NipB0Kinds.WebBookmark,
            Tags = tags,
            Content = _description,
        }.Sign(key);
    }
}
