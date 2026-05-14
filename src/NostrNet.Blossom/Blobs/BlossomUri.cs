// SPDX-License-Identifier: MIT
//
// BUD-10: Blossom URI scheme.
//
//   blossom:<sha256>.<ext>[?xs=<server>&xs=...&as=<pubkey>&as=...&sz=<bytes>]
//
//   xs   server hint (domain only; optional scheme).  Repeatable.
//   as   uploader pubkey (hex).                         Repeatable.
//   sz   expected blob size in bytes.
//
// Extension is required; ".bin" is the spec-mandated default when
// the MIME type is unknown.

using System.Globalization;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Blossom.Blobs;

/// <summary>A parsed BUD-10 <c>blossom:</c> URI.</summary>
public sealed record BlossomUri
{
    /// <summary>The URI scheme constant.</summary>
    public const string Scheme = "blossom";

    /// <summary>Lowercase-hex sha256 of the blob (always 64 chars).</summary>
    public required string Sha256 { get; init; }

    /// <summary>File extension excluding the leading dot — e.g. <c>"pdf"</c>, <c>"png"</c>, or <c>"bin"</c> when unknown.</summary>
    public required string Extension { get; init; }

    /// <summary>Server-hint domains (<c>xs</c> params) in declaration order.</summary>
    public IReadOnlyList<string> ServerHints { get; init; } = Array.Empty<string>();

    /// <summary>Author pubkeys (<c>as</c> params) for BUD-03 fallback resolution.</summary>
    public IReadOnlyList<PublicKey> AuthorHints { get; init; } = Array.Empty<PublicKey>();

    /// <summary>Expected blob size in bytes (<c>sz</c> param), if provided.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>Renders the URI back to canonical text form.</summary>
    public override string ToString()
    {
        var sb = new System.Text.StringBuilder(96)
            .Append(Scheme).Append(':')
            .Append(Sha256).Append('.').Append(Extension);

        bool first = true;
        void Append(string key, string value)
        {
            sb.Append(first ? '?' : '&');
            first = false;
            sb.Append(key).Append('=').Append(Uri.EscapeDataString(value));
        }

        foreach (var s in ServerHints) Append("xs", s);
        foreach (var a in AuthorHints) Append("as", a.ToHex());
        if (SizeBytes is long n) Append("sz", n.ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    /// <summary>Parses a <c>blossom:</c> URI.</summary>
    /// <exception cref="FormatException">The input doesn't conform to BUD-10.</exception>
    public static BlossomUri Parse(string uri)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);
        if (!uri.StartsWith("blossom:", StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException("Not a blossom: URI.");
        }

        string body = uri["blossom:".Length..];
        int q = body.IndexOf('?');
        string head = q < 0 ? body : body[..q];
        string queryPart = q < 0 ? string.Empty : body[(q + 1)..];

        int dot = head.IndexOf('.');
        if (dot != 64 || head.Length <= 65)
        {
            throw new FormatException(
                "blossom: URI must contain a 64-char hex sha256 followed by a non-empty file extension (e.g. \".bin\" when unknown).");
        }

        string sha = head[..64];
        if (!IsLowerHex(sha))
        {
            throw new FormatException("blossom: URI sha256 must be 64 lowercase hex chars.");
        }

        string ext = head[(dot + 1)..];
        if (ext.Length == 0)
        {
            throw new FormatException("blossom: URI requires a non-empty file extension.");
        }

        var servers = new List<string>();
        var authors = new List<PublicKey>();
        long? size = null;
        foreach (var pair in queryPart.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            string key = pair[..eq];
            string value = Uri.UnescapeDataString(pair[(eq + 1)..]);
            switch (key)
            {
                case "xs":
                    if (!string.IsNullOrEmpty(value)) servers.Add(value);
                    break;
                case "as":
                    if (value.Length == 64 && IsLowerHex(value))
                    {
                        try { authors.Add(PublicKey.FromHex(value)); }
                        catch { /* skip malformed */ }
                    }
                    break;
                case "sz":
                    if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long n) && n >= 0)
                    {
                        size = n;
                    }
                    break;
                // Unknown keys are ignored (forward-compat).
            }
        }

        return new BlossomUri
        {
            Sha256 = sha,
            Extension = ext,
            ServerHints = servers,
            AuthorHints = authors,
            SizeBytes = size,
        };
    }

    /// <summary>Tries to parse; returns <c>false</c> on any failure.</summary>
    public static bool TryParse(string? uri, out BlossomUri? result)
    {
        result = null;
        if (string.IsNullOrEmpty(uri)) return false;
        try { result = Parse(uri); return true; }
        catch (FormatException) { return false; }
    }

    /// <summary>
    /// Extracts the last 64-char lowercase-hex substring from
    /// <paramref name="url"/> — BUD-03's recommended way to recover a
    /// sha256 from any URL (Blossom or otherwise).
    /// </summary>
    public static string? ExtractSha256(string url)
    {
        ArgumentNullException.ThrowIfNull(url);
        // Scan right to left; first 64-hex run we hit wins.
        int i = url.Length;
        while (i >= 64)
        {
            int end = i;
            while (i > 0 && IsHexChar(url[i - 1])) i--;
            int runLen = end - i;
            if (runLen >= 64)
            {
                // Take the LAST 64 chars of the run (per BUD-03's wording).
                string candidate = url.Substring(end - 64, 64).ToLowerInvariant();
                if (IsLowerHex(candidate))
                {
                    return candidate;
                }
            }

            i--;  // step past the non-hex boundary
        }

        return null;
    }

    private static bool IsLowerHex(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return false;
        }

        return true;
    }

    private static bool IsHexChar(char c) =>
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
