// SPDX-License-Identifier: MIT
//
// NIP-68 imeta-tag attachment. The on-the-wire tag layout follows
// NIP-92 imeta:
//
//   ["imeta",
//    "url <url>",
//    "m <mime/type>",
//    "x <sha256-hex>",
//    "dim <W>x<H>",
//    "blurhash <hash>",
//    "thumbhash <hash>",
//    "alt <text>",
//    "fallback <url>",       // repeatable
//    "fallback <url>",
//    "annotate-user <pubkey-hex>:<posX>:<posY>"  // repeatable
//   ]
//
// Each entry after the leading "imeta" is itself a single string in
// "<key> <value>" form (one space between key and value). NIP-92 keeps
// it that way so it can be carried by any Nostr relay without breaking
// the existing single-string tag-element assumption.

using System.Globalization;
using NostrNet.Keys;

namespace NostrNet.Pictures;

/// <summary>
/// One image attachment for a NIP-68 picture event. Serialized to an
/// <c>imeta</c> tag with one entry per non-null field, plus one entry
/// per <see cref="FallbackUrls"/> and per <see cref="AnnotatedUsers"/>.
/// </summary>
public sealed record PictureMediaAttachment
{
    /// <summary>The image URL. Required.</summary>
    public required string Url { get; init; }

    /// <summary>The MIME type, e.g. <c>image/jpeg</c>. Required.</summary>
    public required string MimeType { get; init; }

    /// <summary>Hex-encoded SHA-256 of the image bytes (per NIP-94). Optional.</summary>
    public string? Sha256 { get; init; }

    /// <summary>Pixel dimensions as <c>"<i>W</i>x<i>H</i>"</c>. Optional.</summary>
    public string? Dim { get; init; }

    /// <summary>Blurhash for low-res placeholder rendering. Optional.</summary>
    public string? Blurhash { get; init; }

    /// <summary>Thumbhash for placeholder rendering. Optional.</summary>
    public string? Thumbhash { get; init; }

    /// <summary>Accessibility text describing the image. Optional.</summary>
    public string? Alt { get; init; }

    /// <summary>Alternate URLs for the same image bytes. Order is preserved.</summary>
    public IReadOnlyList<string> FallbackUrls { get; init; } = Array.Empty<string>();

    /// <summary>Tagged users with on-image coordinates (NIP-68 <c>annotate-user</c>).</summary>
    public IReadOnlyList<PictureUserAnnotation> AnnotatedUsers { get; init; } = Array.Empty<PictureUserAnnotation>();

    /// <summary>Serializes this attachment into an imeta tag (a list of string entries, first one being "imeta").</summary>
    public IReadOnlyList<string> ToImetaTag()
    {
        var tag = new List<string>(8 + FallbackUrls.Count + AnnotatedUsers.Count)
        {
            "imeta",
            "url " + Url,
            "m " + MimeType,
        };

        if (Sha256 is not null) tag.Add("x " + Sha256);
        if (Dim is not null) tag.Add("dim " + Dim);
        if (Blurhash is not null) tag.Add("blurhash " + Blurhash);
        if (Thumbhash is not null) tag.Add("thumbhash " + Thumbhash);
        if (Alt is not null) tag.Add("alt " + Alt);

        foreach (var f in FallbackUrls)
        {
            tag.Add("fallback " + f);
        }

        foreach (var a in AnnotatedUsers)
        {
            tag.Add(
                "annotate-user " + a.Pubkey.ToHex()
                + ":" + a.PosX.ToString(CultureInfo.InvariantCulture)
                + ":" + a.PosY.ToString(CultureInfo.InvariantCulture));
        }

        return tag;
    }

    /// <summary>
    /// Parses an imeta tag into a <see cref="PictureMediaAttachment"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="tag"/> isn't an imeta tag.</exception>
    /// <exception cref="FormatException">Required <c>url</c> or <c>m</c> entries are missing.</exception>
    public static PictureMediaAttachment FromImetaTag(IReadOnlyList<string> tag)
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
        string? blur = null;
        string? thumb = null;
        string? alt = null;
        var fallbacks = new List<string>();
        var annotations = new List<PictureUserAnnotation>();

        for (int i = 1; i < tag.Count; i++)
        {
            string entry = tag[i] ?? string.Empty;
            int sep = entry.IndexOf(' ');
            if (sep <= 0)
            {
                // Malformed entry — skip rather than throw, so a stray
                // garbage element doesn't make the whole tag unreadable.
                continue;
            }

            string key = entry[..sep];
            string value = entry[(sep + 1)..];
            switch (key)
            {
                case "url": url = value; break;
                case "m": mime = value; break;
                case "x": sha = value; break;
                case "dim": dim = value; break;
                case "blurhash": blur = value; break;
                case "thumbhash": thumb = value; break;
                case "alt": alt = value; break;
                case "fallback": fallbacks.Add(value); break;
                case "annotate-user":
                    if (TryParseAnnotation(value, out var ann))
                    {
                        annotations.Add(ann);
                    }

                    break;
                // Unknown keys are ignored so future NIP extensions don't break parsing.
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

        return new PictureMediaAttachment
        {
            Url = url,
            MimeType = mime,
            Sha256 = sha,
            Dim = dim,
            Blurhash = blur,
            Thumbhash = thumb,
            Alt = alt,
            FallbackUrls = fallbacks,
            AnnotatedUsers = annotations,
        };
    }

    private static bool TryParseAnnotation(string value, out PictureUserAnnotation annotation)
    {
        annotation = default!;
        // "<pubkey-hex>:<posX>:<posY>"
        int firstColon = value.IndexOf(':');
        int secondColon = firstColon >= 0 ? value.IndexOf(':', firstColon + 1) : -1;
        if (firstColon != 64 || secondColon < 0)
        {
            return false;
        }

        string hex = value[..firstColon];
        string xs = value[(firstColon + 1)..secondColon];
        string ys = value[(secondColon + 1)..];

        if (!int.TryParse(xs, NumberStyles.Integer, CultureInfo.InvariantCulture, out int x)
            || !int.TryParse(ys, NumberStyles.Integer, CultureInfo.InvariantCulture, out int y))
        {
            return false;
        }

        PublicKey pk;
        try { pk = PublicKey.FromHex(hex); }
        catch { return false; }

        annotation = new PictureUserAnnotation(pk, x, y);
        return true;
    }
}

/// <summary>
/// A user tagged at on-image coordinates within a NIP-68 attachment.
/// </summary>
/// <param name="Pubkey">The tagged user's Nostr pubkey.</param>
/// <param name="PosX">Horizontal pixel offset from the image's top-left.</param>
/// <param name="PosY">Vertical pixel offset from the image's top-left.</param>
public sealed record PictureUserAnnotation(PublicKey Pubkey, int PosX, int PosY);
