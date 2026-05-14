// SPDX-License-Identifier: MIT
//
// BUD-11: Nostr authorization tokens.
//
// A signed kind-24242 Nostr event proving the user authorized a
// specific Blossom action. Tokens are base64url-encoded (no padding,
// JWT-style) and sent as `Authorization: Nostr <token>`.
//
// Required event fields:
//   kind        = 24242
//   content     = human-readable reason ("Upload Blob", "Delete blob …")
//   tag "t"     = verb: get | upload | list | delete | media
//   tag "expiration" = unix-seconds NIP-40 expiry
// Optional scoping:
//   tag "server" = lowercase domain (repeatable)
//   tag "x"      = lowercase-hex sha256 (repeatable; required by some endpoints)

using System.Buffers.Text;
using System.Globalization;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Blossom.Auth;

/// <summary>The four verbs BUD-11 defines for the <c>t</c> tag.</summary>
public enum BlossomAuthVerb
{
    /// <summary>Permission to fetch blobs (<c>GET /&lt;sha256&gt;</c>, <c>HEAD /&lt;sha256&gt;</c>).</summary>
    Get,

    /// <summary>Permission to upload blobs (<c>PUT /upload</c>, <c>HEAD /upload</c>, <c>PUT /mirror</c>).</summary>
    Upload,

    /// <summary>Permission to list a user's blobs (<c>GET /list/&lt;pubkey&gt;</c>).</summary>
    List,

    /// <summary>Permission to delete blobs (<c>DELETE /&lt;sha256&gt;</c>).</summary>
    Delete,

    /// <summary>Permission for media-optimization endpoints (<c>PUT /media</c>, <c>HEAD /media</c>).</summary>
    Media,
}

/// <summary>Kind constants for Blossom authorization events.</summary>
public static class BlossomAuthKinds
{
    /// <summary>BUD-11 authorization token kind (24242).</summary>
    public const int Authorization = 24242;
}

/// <summary>
/// Builder for kind-24242 BUD-11 authorization tokens. Use
/// <see cref="BuildAndSign"/> to get a signed <see cref="NostrEvent"/>,
/// then <see cref="BlossomAuthToken.ToAuthorizationHeader"/> to
/// produce the <c>Authorization: Nostr …</c> header value.
/// </summary>
public sealed class BlossomAuthTokenBuilder
{
    private readonly BlossomAuthVerb _verb;
    private string _reason;
    private DateTimeOffset _expiration = DateTimeOffset.UtcNow.AddMinutes(5);
    private DateTimeOffset? _createdAt;
    private readonly List<string> _servers = new();
    private readonly List<string> _shas = new();

    internal BlossomAuthTokenBuilder(BlossomAuthVerb verb, string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);
        _verb = verb;
        _reason = reason;
    }

    /// <summary>Sets the human-readable reason carried in <c>content</c>.</summary>
    public BlossomAuthTokenBuilder WithReason(string reason)
    {
        ArgumentException.ThrowIfNullOrEmpty(reason);
        _reason = reason;
        return this;
    }

    /// <summary>Sets the NIP-40 expiration. Default: 5 minutes from now.</summary>
    public BlossomAuthTokenBuilder WithExpiration(DateTimeOffset when)
    {
        _expiration = when;
        return this;
    }

    /// <summary>Sets the event's <c>created_at</c>. Default: now.</summary>
    public BlossomAuthTokenBuilder WithCreatedAt(DateTimeOffset when)
    {
        _createdAt = when;
        return this;
    }

    /// <summary>Restricts the token to a specific server domain. Repeatable.</summary>
    public BlossomAuthTokenBuilder ScopeToServer(string domain)
    {
        ArgumentException.ThrowIfNullOrEmpty(domain);
        _servers.Add(domain.ToLowerInvariant());
        return this;
    }

    /// <summary>Scopes the token to a specific blob hash. Repeatable. Required for upload / delete / media / mirror.</summary>
    public BlossomAuthTokenBuilder ScopeToBlob(string sha256Hex)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha256Hex);
        if (sha256Hex.Length != 64)
        {
            throw new ArgumentException("Blob sha256 must be 64 hex chars.", nameof(sha256Hex));
        }

        _shas.Add(sha256Hex.ToLowerInvariant());
        return this;
    }

    /// <summary>Builds the unsigned authorization event.</summary>
    public UnsignedEvent BuildUnsigned(PublicKey author)
    {
        ArgumentNullException.ThrowIfNull(author);

        long createdAt = (_createdAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        long expiration = _expiration.ToUnixTimeSeconds();
        if (expiration <= createdAt)
        {
            throw new InvalidOperationException("BUD-11 expiration must be in the future.");
        }

        var tags = new List<IReadOnlyList<string>>(2 + _servers.Count + _shas.Count)
        {
            new[] { "t", VerbString(_verb) },
            new[] { "expiration", expiration.ToString(CultureInfo.InvariantCulture) },
        };

        foreach (var s in _servers) tags.Add(new[] { "server", s });
        foreach (var x in _shas) tags.Add(new[] { "x", x });

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = createdAt,
            Kind = BlossomAuthKinds.Authorization,
            Tags = tags,
            Content = _reason,
        };
    }

    /// <summary>Builds and signs the authorization event.</summary>
    public NostrEvent BuildAndSign(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return BuildUnsigned(key.PublicKey).Sign(key);
    }

    internal static string VerbString(BlossomAuthVerb v) => v switch
    {
        BlossomAuthVerb.Get => "get",
        BlossomAuthVerb.Upload => "upload",
        BlossomAuthVerb.List => "list",
        BlossomAuthVerb.Delete => "delete",
        BlossomAuthVerb.Media => "media",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };
}

/// <summary>Helpers for the BUD-11 <c>Authorization: Nostr …</c> header.</summary>
public static class BlossomAuthToken
{
    /// <summary>The HTTP <c>Authorization</c> scheme name for Blossom.</summary>
    public const string Scheme = "Nostr";

    /// <summary>Starts building a token for the given verb + human-readable reason.</summary>
    public static BlossomAuthTokenBuilder Create(BlossomAuthVerb verb, string reason)
        => new(verb, reason);

    /// <summary>
    /// Encodes a kind-24242 event as a base64url-no-padding string
    /// suitable for the <c>Authorization: Nostr …</c> header value.
    /// Throws if the event isn't kind 24242.
    /// </summary>
    public static string ToAuthorizationHeader(NostrEvent token)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (token.Kind != BlossomAuthKinds.Authorization)
        {
            throw new ArgumentException(
                $"Expected kind {BlossomAuthKinds.Authorization}; got {token.Kind}.",
                nameof(token));
        }

        byte[] json = SysEncoding.UTF8.GetBytes(token.ToJson());
        return Base64UrlEncode(json);
    }

    /// <summary>
    /// Decodes a base64url-encoded BUD-11 authorization header value
    /// back into the original kind-24242 event. Returns <c>null</c>
    /// on any decode / parse failure.
    /// </summary>
    public static NostrEvent? TryFromAuthorizationHeader(string headerValue)
    {
        ArgumentNullException.ThrowIfNull(headerValue);
        string token = headerValue;
        // Allow either bare token or "Nostr <token>" form.
        const string prefix = "Nostr ";
        if (token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            token = token[prefix.Length..].Trim();
        }

        byte[] bytes;
        try { bytes = Base64UrlDecode(token); }
        catch (FormatException) { return null; }

        try { return NostrEvent.FromJson(SysEncoding.UTF8.GetString(bytes)); }
        catch (Exception) { return null; }
    }

    // Base64url ("URL-safe base64 without padding", as JWTs use).
    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes)
    {
        // Encode to standard base64 then transform.
        string std = Convert.ToBase64String(bytes);
        return std.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static byte[] Base64UrlDecode(string token)
    {
        string s = token.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
            case 0: break;
            default: throw new FormatException("Invalid base64url length.");
        }

        return Convert.FromBase64String(s);
    }
}
