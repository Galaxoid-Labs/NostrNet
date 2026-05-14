// SPDX-License-Identifier: MIT
//
// NIP-92: Media attachments via the `imeta` tag.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/92.md
//
// Wire format:
//
//   ["imeta", "url <url>", "m <mime>", "x <hash>", ...]
//
// The first element is always "imeta". Every subsequent element is a
// single string of the form `"<key> <value>"` (one ASCII space between
// the key and the value; the value may itself contain spaces).
//
// Sub-keys may repeat (e.g. multiple `fallback` URLs in one tag).
// Sub-key order is not significant. Per spec, an imeta tag MUST have
// at least a `url` entry plus one other field.
//
// Recognized standard sub-keys (NIP-92 + the NIP-94 set):
//   url       MIME-type-agnostic media URL                          (required)
//   m         MIME type                                              (recommended)
//   x         hex sha256 of the file bytes (per NIP-94)              (optional)
//   ox        hex sha256 of the original (pre-server-transform) file (optional)
//   size      byte length                                            (optional)
//   dim       "<W>x<H>" pixel dimensions                             (optional)
//   alt       accessibility description                              (optional)
//   blurhash  placeholder blurhash                                   (optional)
//   thumbhash placeholder thumbhash                                  (optional)
//   thumb     thumbnail URL (optionally followed by " <sha256>")     (optional)
//   image     full-size preview image URL                            (optional)
//   summary   text excerpt                                           (optional)
//   fallback  alternate URL (repeatable)                             (optional)
//   service   service marker (e.g. "nip96")                          (optional)
//   magnet    BitTorrent magnet URI                                  (optional)
//   i         torrent infohash                                       (optional)
//   duration  seconds (used by NIP-71)                               (optional)
//   bitrate   bits/second (used by NIP-71)                           (optional)
//
// NIP-specific extensions (`annotate-user` for NIP-68, etc.) MAY
// appear and are surfaced as additional entries in the parsed
// dictionary. Unknown keys are preserved on parse.

namespace NostrNet.Encoding;

/// <summary>
/// NIP-92 imeta-tag parser / builder. Returns / accepts a key→values
/// dictionary so consumers don't need to handle the
/// <c>"&lt;key&gt; &lt;value&gt;"</c> string format directly.
/// </summary>
public static class Imeta
{
    /// <summary>Header element every imeta tag starts with.</summary>
    public const string TagName = "imeta";

    /// <summary>
    /// Parses an imeta tag into a key → values dictionary. Multi-value
    /// keys (e.g. <c>fallback</c>) carry every occurrence in tag-order.
    /// Entries that don't match the <c>"&lt;key&gt; &lt;value&gt;"</c>
    /// pattern are silently skipped — preserving the rest of the tag
    /// for callers that want best-effort parsing.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="tag"/> is not an imeta tag.</exception>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> Parse(IReadOnlyList<string> tag)
    {
        ArgumentNullException.ThrowIfNull(tag);
        if (tag.Count == 0 || !string.Equals(tag[0], TagName, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Tag is not an '{TagName}' tag.", nameof(tag));
        }

        var result = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        for (int i = 1; i < tag.Count; i++)
        {
            string entry = tag[i] ?? string.Empty;
            int sep = entry.IndexOf(' ');
            if (sep <= 0)
            {
                continue;
            }

            string key = entry[..sep];
            string value = entry[(sep + 1)..];
            if (!result.TryGetValue(key, out var list))
            {
                list = new List<string>(1);
                result[key] = list;
            }

            list.Add(value);
        }

        // Cast the inner List<string> to IReadOnlyList<string> on the way out.
        var ro = new Dictionary<string, IReadOnlyList<string>>(result.Count, StringComparer.Ordinal);
        foreach (var (k, v) in result)
        {
            ro[k] = v;
        }

        return ro;
    }

    /// <summary>Returns the first value for <paramref name="key"/>, or <c>null</c> if absent.</summary>
    public static string? FirstValue(IReadOnlyDictionary<string, IReadOnlyList<string>> parsed, string key)
    {
        ArgumentNullException.ThrowIfNull(parsed);
        ArgumentException.ThrowIfNullOrEmpty(key);
        return parsed.TryGetValue(key, out var values) && values.Count > 0 ? values[0] : null;
    }

    /// <summary>
    /// Builds an imeta tag from a key → values dictionary. Output is a
    /// list whose first element is <c>"imeta"</c> and whose remaining
    /// elements are <c>"&lt;key&gt; &lt;value&gt;"</c> strings in
    /// insertion order (multi-value keys emit one entry per value).
    /// </summary>
    /// <exception cref="ArgumentException">No <c>url</c> entry was supplied — per NIP-92 it's mandatory.</exception>
    public static IReadOnlyList<string> Build(IReadOnlyDictionary<string, IReadOnlyList<string>> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        if (!entries.TryGetValue("url", out var urls) || urls.Count == 0 || string.IsNullOrEmpty(urls[0]))
        {
            throw new ArgumentException(
                "imeta tag requires a non-empty 'url' entry per NIP-92.", nameof(entries));
        }

        var tag = new List<string>(1 + SumValueCount(entries)) { TagName };
        foreach (var (key, values) in entries)
        {
            foreach (var value in values)
            {
                if (value is null) continue;
                tag.Add(key + " " + value);
            }
        }

        return tag;
    }

    private static int SumValueCount(IReadOnlyDictionary<string, IReadOnlyList<string>> entries)
    {
        int n = 0;
        foreach (var kvp in entries)
        {
            n += kvp.Value.Count;
        }

        return n;
    }
}
