// SPDX-License-Identifier: MIT
//
// NIP-94: File metadata events (kind 1063).
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/94.md
//
// A standalone event describing a single file: its download URL,
// MIME type, hash, and optional auxiliary metadata. Used by
// blossom-like file-distribution flows and as the canonical
// reference for the imeta sub-keys NIP-92 reuses inline in other
// events.
//
// Wire format (top-level tags — NOT packed inside an imeta):
//
//   kind     = 1063
//   content  = description of the file (free text)
//   tags:
//     ["url", <url>]                       required
//     ["m", <mime>]                        required
//     ["x", <sha256-hex>]                  required
//     ["ox", <sha256-of-pre-transform>]    optional
//     ["size", <bytes-as-decimal-string>]  optional
//     ["dim", "<W>x<H>"]                   optional
//     ["magnet", <magnet-uri>]             optional
//     ["i", <torrent-infohash>]            optional
//     ["blurhash", <blurhash>]             optional
//     ["thumb", <url>, <optional-sha256>]  optional
//     ["image", <url>, <optional-sha256>]  optional
//     ["summary", <text>]                  optional
//     ["alt", <text>]                      optional
//     ["fallback", <url>]                  optional, repeatable
//     ["service", <service-marker>]        optional (e.g. "nip96")

using System.Globalization;
using System.Diagnostics.CodeAnalysis;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Files;

/// <summary>Kind constant for NIP-94 file metadata events.</summary>
public static class Nip94Kinds
{
    /// <summary>File metadata event (kind 1063).</summary>
    public const int FileMetadata = 1063;
}

/// <summary>A typed view of a NIP-94 file metadata event.</summary>
public sealed class FileMetadata : INostrTypedEvent<FileMetadata>
{
    /// <summary>Nostr kind(s) this type represents.</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { 1063 };

    /// <summary>The event's author.</summary>
    public required PublicKey Author { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>File-description text from the event's <c>content</c> field.</summary>
    public required string Description { get; init; }

    /// <summary>File URL (the <c>"url"</c> tag).</summary>
    public required string Url { get; init; }

    /// <summary>MIME type (the <c>"m"</c> tag).</summary>
    public required string MimeType { get; init; }

    /// <summary>Hex sha256 of the file (the <c>"x"</c> tag).</summary>
    public required string Sha256 { get; init; }

    /// <summary>SHA-256 of the pre-transform original (the <c>"ox"</c> tag), if any.</summary>
    public string? OriginalSha256 { get; init; }

    /// <summary>File size in bytes from the <c>"size"</c> tag, if present and parseable.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>Pixel dimensions as <c>"<i>W</i>x<i>H</i>"</c>, from the <c>"dim"</c> tag.</summary>
    public string? Dim { get; init; }

    /// <summary>BitTorrent magnet URI, if a <c>"magnet"</c> tag is present.</summary>
    public string? Magnet { get; init; }

    /// <summary>Torrent infohash from the <c>"i"</c> tag.</summary>
    public string? TorrentInfohash { get; init; }

    /// <summary>Blurhash placeholder.</summary>
    public string? Blurhash { get; init; }

    /// <summary>Thumbnail URL (from the <c>"thumb"</c> tag's first value).</summary>
    public string? ThumbnailUrl { get; init; }

    /// <summary>Optional sha256 of the thumbnail (the second value of the <c>"thumb"</c> tag).</summary>
    public string? ThumbnailSha256 { get; init; }

    /// <summary>Preview image URL (from the <c>"image"</c> tag's first value).</summary>
    public string? ImageUrl { get; init; }

    /// <summary>Optional sha256 of the preview image (the second value of the <c>"image"</c> tag).</summary>
    public string? ImageSha256 { get; init; }

    /// <summary>Short text excerpt from the <c>"summary"</c> tag.</summary>
    public string? Summary { get; init; }

    /// <summary>Accessibility description from the <c>"alt"</c> tag.</summary>
    public string? Alt { get; init; }

    /// <summary>Alternate file URLs (every <c>"fallback"</c> tag).</summary>
    public IReadOnlyList<string> FallbackUrls { get; init; } = Array.Empty<string>();

    /// <summary>Service marker (e.g. <c>"nip96"</c>) from the <c>"service"</c> tag.</summary>
    public string? Service { get; init; }

    /// <summary>Parses a kind-1063 event into a typed <see cref="FileMetadata"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not kind 1063.</exception>
    /// <exception cref="FormatException">A required <c>url</c> / <c>m</c> / <c>x</c> tag is missing.</exception>
    public static FileMetadata FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip94Kinds.FileMetadata)
        {
            throw new ArgumentException(
                $"Expected NIP-94 kind {Nip94Kinds.FileMetadata}; got {ev.Kind}.",
                nameof(ev));
        }

        string? url = null;
        string? mime = null;
        string? sha = null;
        string? ox = null;
        long? size = null;
        string? dim = null;
        string? magnet = null;
        string? infohash = null;
        string? blurhash = null;
        string? thumbUrl = null;
        string? thumbSha = null;
        string? imageUrl = null;
        string? imageSha = null;
        string? summary = null;
        string? alt = null;
        string? service = null;
        var fallbacks = new List<string>();

        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0) continue;
            switch (tag[0])
            {
                case "url": if (tag.Count >= 2) url = tag[1]; break;
                case "m": if (tag.Count >= 2) mime = tag[1]; break;
                case "x": if (tag.Count >= 2) sha = tag[1]; break;
                case "ox": if (tag.Count >= 2) ox = tag[1]; break;
                case "size":
                    if (tag.Count >= 2 && long.TryParse(tag[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out long s))
                    {
                        size = s;
                    }

                    break;
                case "dim": if (tag.Count >= 2) dim = tag[1]; break;
                case "magnet": if (tag.Count >= 2) magnet = tag[1]; break;
                case "i": if (tag.Count >= 2) infohash = tag[1]; break;
                case "blurhash": if (tag.Count >= 2) blurhash = tag[1]; break;
                case "thumb":
                    if (tag.Count >= 2) thumbUrl = tag[1];
                    if (tag.Count >= 3) thumbSha = tag[2];
                    break;
                case "image":
                    if (tag.Count >= 2) imageUrl = tag[1];
                    if (tag.Count >= 3) imageSha = tag[2];
                    break;
                case "summary": if (tag.Count >= 2) summary = tag[1]; break;
                case "alt": if (tag.Count >= 2) alt = tag[1]; break;
                case "fallback": if (tag.Count >= 2) fallbacks.Add(tag[1]); break;
                case "service": if (tag.Count >= 2) service = tag[1]; break;
            }
        }

        if (url is null) throw new FormatException("NIP-94 event is missing the required 'url' tag.");
        if (mime is null) throw new FormatException("NIP-94 event is missing the required 'm' tag.");
        if (sha is null) throw new FormatException("NIP-94 event is missing the required 'x' tag.");

        return new FileMetadata
        {
            Author = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Description = ev.Content,
            Url = url,
            MimeType = mime,
            Sha256 = sha,
            OriginalSha256 = ox,
            SizeBytes = size,
            Dim = dim,
            Magnet = magnet,
            TorrentInfohash = infohash,
            Blurhash = blurhash,
            ThumbnailUrl = thumbUrl,
            ThumbnailSha256 = thumbSha,
            ImageUrl = imageUrl,
            ImageSha256 = imageSha,
            Summary = summary,
            Alt = alt,
            FallbackUrls = fallbacks,
            Service = service,
        };
    }

    /// <summary>Tries to parse <paramref name="ev"/> as a NIP-94 file event. Returns <c>false</c> for non-1063 or malformed.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out FileMetadata? file)
    {
        file = null;
        if (ev is null || ev.Kind != Nip94Kinds.FileMetadata)
        {
            return false;
        }

        try
        {
            file = FromEvent(ev);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Starts building a new NIP-94 event for a file at <paramref name="url"/> with the given MIME + hash.</summary>
    public static FileMetadataBuilder Create(string url, string mimeType, string sha256)
        => new(url, mimeType, sha256);
}

/// <summary>Fluent builder for NIP-94 kind-1063 file metadata events.</summary>
public sealed class FileMetadataBuilder
{
    private readonly string _url;
    private readonly string _mime;
    private readonly string _sha256;
    private string _description = string.Empty;
    private string? _originalSha;
    private long? _size;
    private string? _dim;
    private string? _magnet;
    private string? _infohash;
    private string? _blurhash;
    private (string Url, string? Sha)? _thumb;
    private (string Url, string? Sha)? _image;
    private string? _summary;
    private string? _alt;
    private string? _service;
    private readonly List<string> _fallbacks = new();

    internal FileMetadataBuilder(string url, string mimeType, string sha256)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);
        ArgumentException.ThrowIfNullOrEmpty(mimeType);
        ArgumentException.ThrowIfNullOrEmpty(sha256);
        _url = url;
        _mime = mimeType;
        _sha256 = sha256;
    }

    /// <summary>Sets the description (the event's <c>content</c>).</summary>
    public FileMetadataBuilder WithDescription(string description)
    {
        ArgumentNullException.ThrowIfNull(description);
        _description = description;
        return this;
    }

    /// <summary>Sets the original (pre-server-transform) sha256.</summary>
    public FileMetadataBuilder WithOriginalSha256(string ox) { ArgumentException.ThrowIfNullOrEmpty(ox); _originalSha = ox; return this; }

    /// <summary>Sets the file size in bytes.</summary>
    public FileMetadataBuilder WithSize(long sizeBytes) { _size = sizeBytes; return this; }

    /// <summary>Sets pixel dimensions as <c>"<i>W</i>x<i>H</i>"</c>.</summary>
    public FileMetadataBuilder WithDim(string dim) { ArgumentException.ThrowIfNullOrEmpty(dim); _dim = dim; return this; }

    /// <summary>Sets a BitTorrent magnet URI.</summary>
    public FileMetadataBuilder WithMagnet(string magnet) { ArgumentException.ThrowIfNullOrEmpty(magnet); _magnet = magnet; return this; }

    /// <summary>Sets a torrent infohash.</summary>
    public FileMetadataBuilder WithTorrentInfohash(string infohash) { ArgumentException.ThrowIfNullOrEmpty(infohash); _infohash = infohash; return this; }

    /// <summary>Sets a blurhash placeholder.</summary>
    public FileMetadataBuilder WithBlurhash(string blurhash) { ArgumentException.ThrowIfNullOrEmpty(blurhash); _blurhash = blurhash; return this; }

    /// <summary>Sets the thumbnail URL plus optional sha256.</summary>
    public FileMetadataBuilder WithThumbnail(string url, string? sha256 = null) { ArgumentException.ThrowIfNullOrEmpty(url); _thumb = (url, sha256); return this; }

    /// <summary>Sets the preview image URL plus optional sha256.</summary>
    public FileMetadataBuilder WithPreviewImage(string url, string? sha256 = null) { ArgumentException.ThrowIfNullOrEmpty(url); _image = (url, sha256); return this; }

    /// <summary>Sets a short text excerpt.</summary>
    public FileMetadataBuilder WithSummary(string summary) { ArgumentException.ThrowIfNullOrEmpty(summary); _summary = summary; return this; }

    /// <summary>Sets accessibility text.</summary>
    public FileMetadataBuilder WithAlt(string alt) { ArgumentException.ThrowIfNullOrEmpty(alt); _alt = alt; return this; }

    /// <summary>Adds an alternate URL (repeatable).</summary>
    public FileMetadataBuilder Fallback(string url) { ArgumentException.ThrowIfNullOrEmpty(url); _fallbacks.Add(url); return this; }

    /// <summary>Sets a service marker (e.g. <c>"nip96"</c>).</summary>
    public FileMetadataBuilder WithService(string service) { ArgumentException.ThrowIfNullOrEmpty(service); _service = service; return this; }

    /// <summary>Builds the unsigned event.</summary>
    public UnsignedEvent BuildUnsigned(PublicKey author, long createdAt)
    {
        ArgumentNullException.ThrowIfNull(author);
        var tags = new List<IReadOnlyList<string>>
        {
            new[] { "url", _url },
            new[] { "m", _mime },
            new[] { "x", _sha256 },
        };

        if (_originalSha is not null) tags.Add(new[] { "ox", _originalSha });
        if (_size is long size) tags.Add(new[] { "size", size.ToString(CultureInfo.InvariantCulture) });
        if (_dim is not null) tags.Add(new[] { "dim", _dim });
        if (_magnet is not null) tags.Add(new[] { "magnet", _magnet });
        if (_infohash is not null) tags.Add(new[] { "i", _infohash });
        if (_blurhash is not null) tags.Add(new[] { "blurhash", _blurhash });

        if (_thumb is { } t)
        {
            tags.Add(t.Sha is null ? new[] { "thumb", t.Url } : new[] { "thumb", t.Url, t.Sha });
        }

        if (_image is { } im)
        {
            tags.Add(im.Sha is null ? new[] { "image", im.Url } : new[] { "image", im.Url, im.Sha });
        }

        if (_summary is not null) tags.Add(new[] { "summary", _summary });
        if (_alt is not null) tags.Add(new[] { "alt", _alt });
        foreach (var f in _fallbacks)
        {
            tags.Add(new[] { "fallback", f });
        }

        if (_service is not null) tags.Add(new[] { "service", _service });

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = createdAt,
            Kind = Nip94Kinds.FileMetadata,
            Tags = tags,
            Content = _description,
        };
    }

    /// <summary>Builds and signs the event.</summary>
    public NostrEvent BuildAndSign(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return BuildUnsigned(key.PublicKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds()).Sign(key);
    }
}
