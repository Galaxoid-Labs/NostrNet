// SPDX-License-Identifier: MIT
//
// NIP-71 imeta-tag attachment for video events. Follows the NIP-92
// imeta format (each entry after "imeta" is a "<key> <value>" string)
// with video-specific sub-keys:
//
//   url         primary video URL                       (required)
//   m           MIME type                                (required)
//   x           sha256 hash per NIP-94                   (optional)
//   dim         resolution as "<W>x<H>"                  (optional)
//   image       poster / preview image URL (repeatable)  (optional)
//   duration    seconds (floating point, recommended)    (optional)
//   bitrate     average bits/second                      (optional)
//   fallback    backup URL (repeatable)                  (optional)
//   service     NIP-96 server marker, e.g. "nip96"       (optional)
//
// Unlike NIP-68 attachments there's no `annotate-user`, no
// `blurhash`/`thumbhash`, and no `alt` (alt is a top-level tag on
// video events instead of per-attachment).

using System.Globalization;

namespace NostrNet.Videos;

/// <summary>
/// One video attachment for a NIP-71 video event. Serialized to an
/// <c>imeta</c> tag with one entry per non-null field plus one entry
/// per <see cref="FallbackUrls"/> and per <see cref="PosterImageUrls"/>.
/// </summary>
public sealed record VideoMediaAttachment
{
    /// <summary>The primary video URL. Required.</summary>
    public required string Url { get; init; }

    /// <summary>The MIME type, e.g. <c>video/mp4</c>. Required.</summary>
    public required string MimeType { get; init; }

    /// <summary>Hex-encoded SHA-256 of the video bytes (per NIP-94). Optional.</summary>
    public string? Sha256 { get; init; }

    /// <summary>Resolution as <c>"<i>W</i>x<i>H</i>"</c>. Optional.</summary>
    public string? Dim { get; init; }

    /// <summary>Duration in seconds (floating point, per NIP-71 recommendation). Optional.</summary>
    public double? DurationSeconds { get; init; }

    /// <summary>Average bitrate in bits per second. Optional.</summary>
    public long? Bitrate { get; init; }

    /// <summary>NIP-96 service marker (e.g. <c>"nip96"</c>) when the URL is hosted by a NIP-96 server. Optional.</summary>
    public string? Service { get; init; }

    /// <summary>Poster / preview image URLs. Repeatable in the imeta tag.</summary>
    public IReadOnlyList<string> PosterImageUrls { get; init; } = Array.Empty<string>();

    /// <summary>Alternate URLs for the same video bytes (e.g. a CDN mirror).</summary>
    public IReadOnlyList<string> FallbackUrls { get; init; } = Array.Empty<string>();

    /// <summary>Serializes this attachment into an imeta tag (a list of string entries; the first is "imeta").</summary>
    public IReadOnlyList<string> ToImetaTag()
    {
        int capacity = 5 + PosterImageUrls.Count + FallbackUrls.Count;
        var tag = new List<string>(capacity)
        {
            "imeta",
            "url " + Url,
            "m " + MimeType,
        };

        if (Sha256 is not null) tag.Add("x " + Sha256);
        if (Dim is not null) tag.Add("dim " + Dim);
        if (DurationSeconds is double dur)
        {
            tag.Add("duration " + dur.ToString("0.###", CultureInfo.InvariantCulture));
        }

        if (Bitrate is long br)
        {
            tag.Add("bitrate " + br.ToString(CultureInfo.InvariantCulture));
        }

        foreach (var img in PosterImageUrls)
        {
            tag.Add("image " + img);
        }

        foreach (var f in FallbackUrls)
        {
            tag.Add("fallback " + f);
        }

        if (Service is not null) tag.Add("service " + Service);
        return tag;
    }

    /// <summary>Parses an imeta tag into a <see cref="VideoMediaAttachment"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="tag"/> isn't an imeta tag.</exception>
    /// <exception cref="FormatException">Required <c>url</c> or <c>m</c> entries are missing.</exception>
    public static VideoMediaAttachment FromImetaTag(IReadOnlyList<string> tag)
    {
        ArgumentNullException.ThrowIfNull(tag);
        if (tag.Count == 0 || !string.Equals(tag[0], "imeta", StringComparison.Ordinal))
        {
            throw new ArgumentException("Tag is not an imeta tag.", nameof(tag));
        }

        string? url = null;
        string? mime = null;
        string? sha = null;
        string? dim = null;
        double? duration = null;
        long? bitrate = null;
        string? service = null;
        var posters = new List<string>();
        var fallbacks = new List<string>();

        for (int i = 1; i < tag.Count; i++)
        {
            string entry = tag[i] ?? string.Empty;
            int sep = entry.IndexOf(' ');
            if (sep <= 0) continue;

            string key = entry[..sep];
            string value = entry[(sep + 1)..];
            switch (key)
            {
                case "url": url = value; break;
                case "m": mime = value; break;
                case "x": sha = value; break;
                case "dim": dim = value; break;
                case "duration":
                    if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out double d))
                    {
                        duration = d;
                    }

                    break;
                case "bitrate":
                    if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long b))
                    {
                        bitrate = b;
                    }

                    break;
                case "image": posters.Add(value); break;
                case "fallback": fallbacks.Add(value); break;
                case "service": service = value; break;
            }
        }

        if (url is null)
        {
            throw new FormatException("imeta tag is missing required 'url' entry.");
        }

        if (mime is null)
        {
            throw new FormatException("imeta tag is missing required 'm' (mime) entry.");
        }

        return new VideoMediaAttachment
        {
            Url = url,
            MimeType = mime,
            Sha256 = sha,
            Dim = dim,
            DurationSeconds = duration,
            Bitrate = bitrate,
            Service = service,
            PosterImageUrls = posters,
            FallbackUrls = fallbacks,
        };
    }
}
