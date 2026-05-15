// SPDX-License-Identifier: MIT
//
// NIP-98: HTTP Auth.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/98.md
//
// Wire format:
//
//   kind     = 27235
//   content  = ""  (empty per spec)
//   tags:
//     ["u", "<absolute-url>"]            required, exact request URL
//     ["method", "<HTTP-VERB>"]          required, uppercase per RFC
//     ["payload", "<sha256-hex>"]        optional, body hash for POST/PUT/PATCH
//
// Encoded as:
//
//   Authorization: Nostr <base64(event-json)>
//
// (Standard base64 with padding, NOT base64url — distinct from BUD-11.)
//
// Servers MUST:
//   - check kind == 27235
//   - verify the signature
//   - confirm `created_at` is within ~60 s of server time
//   - match `u` against the request's absolute URL
//   - match `method` (case-insensitive) against the verb
//   - if `payload` is present, compute sha256 over the body and compare
//
// Different from NIP-42 (relay AUTH): NIP-98 is per-request HTTP
// authorization, signed off-band before the request is made. NIP-42
// is an interactive challenge/response over an open relay socket.

using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.HttpAuth;

/// <summary>Kind constant for NIP-98 HTTP auth events.</summary>
public static class Nip98Kinds
{
    /// <summary>HTTP Auth event (kind 27235).</summary>
    public const int HttpAuth = 27235;
}

/// <summary>Why <see cref="Nip98HttpAuth.Validate"/> rejected a token.</summary>
public enum Nip98ValidationFailure
{
    /// <summary>The decoded event wasn't kind 27235.</summary>
    WrongKind,

    /// <summary>The event's BIP-340 signature didn't verify against its id.</summary>
    BadSignature,

    /// <summary>The header value couldn't be base64-decoded or parsed as a Nostr event.</summary>
    Malformed,

    /// <summary>The required <c>u</c> tag was missing.</summary>
    MissingUrl,

    /// <summary>The required <c>method</c> tag was missing.</summary>
    MissingMethod,

    /// <summary>The <c>u</c> tag did not match the actual request URL.</summary>
    UrlMismatch,

    /// <summary>The <c>method</c> tag did not match the actual HTTP verb.</summary>
    MethodMismatch,

    /// <summary>The token's <c>created_at</c> was outside the allowed window.</summary>
    Expired,

    /// <summary>A <c>payload</c> tag was present but the hash didn't match the body.</summary>
    PayloadHashMismatch,
}

/// <summary>The outcome of validating a NIP-98 token.</summary>
/// <param name="IsValid">True when every check passed.</param>
/// <param name="Failure">When invalid, which check failed.</param>
/// <param name="Author">When the event was at least parseable + signed, the pubkey it was signed with.</param>
public sealed record Nip98ValidationResult(
    bool IsValid,
    Nip98ValidationFailure? Failure,
    PublicKey? Author)
{
    internal static Nip98ValidationResult Ok(PublicKey author) => new(true, null, author);

    internal static Nip98ValidationResult Fail(Nip98ValidationFailure why, PublicKey? author = null)
        => new(false, why, author);
}

/// <summary>Fluent builder for NIP-98 kind-27235 HTTP-auth tokens.</summary>
public sealed class Nip98AuthTokenBuilder
{
    private readonly string _method;
    private readonly string _url;
    private string? _payloadHashHex;
    private DateTimeOffset? _createdAt;

    internal Nip98AuthTokenBuilder(string method, string url)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentException.ThrowIfNullOrEmpty(url);
        _method = method.ToUpperInvariant();
        _url = url;
    }

    /// <summary>
    /// Attaches a <c>payload</c> tag with the sha256 hex of
    /// <paramref name="body"/>. Use this when the request includes a
    /// non-empty body (POST/PUT/PATCH).
    /// </summary>
    public Nip98AuthTokenBuilder WithPayload(ReadOnlySpan<byte> body)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(body, hash);
        _payloadHashHex = Convert.ToHexStringLower(hash);
        return this;
    }

    /// <summary>Same as <see cref="WithPayload(ReadOnlySpan{byte})"/> but takes a pre-computed sha256 hex.</summary>
    public Nip98AuthTokenBuilder WithPayloadHash(string sha256Hex)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha256Hex);
        if (sha256Hex.Length != 64)
        {
            throw new ArgumentException("payload hash must be a 64-character sha256 hex.", nameof(sha256Hex));
        }

        _payloadHashHex = sha256Hex.ToLowerInvariant();
        return this;
    }

    /// <summary>Overrides the event's <c>created_at</c>. Defaults to <see cref="DateTimeOffset.UtcNow"/>.</summary>
    public Nip98AuthTokenBuilder WithCreatedAt(DateTimeOffset when)
    {
        _createdAt = when;
        return this;
    }

    /// <summary>Builds the unsigned event.</summary>
    public UnsignedEvent BuildUnsigned(PublicKey author)
    {
        ArgumentNullException.ThrowIfNull(author);
        var tags = new List<IReadOnlyList<string>>(3)
        {
            new[] { "u", _url },
            new[] { "method", _method },
        };

        if (_payloadHashHex is not null)
        {
            tags.Add(new[] { "payload", _payloadHashHex });
        }

        long createdAt = (_createdAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = createdAt,
            Kind = Nip98Kinds.HttpAuth,
            Tags = tags,
            Content = string.Empty,
        };
    }

    /// <summary>Builds and signs the event.</summary>
    public NostrEvent BuildAndSign(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return BuildUnsigned(key.PublicKey).Sign(key);
    }
}

/// <summary>Helpers for the NIP-98 <c>Authorization: Nostr …</c> header.</summary>
public static class Nip98HttpAuth
{
    /// <summary>The HTTP <c>Authorization</c> scheme name NIP-98 uses.</summary>
    public const string Scheme = "Nostr";

    /// <summary>Spec-recommended max age for a token's <c>created_at</c> relative to server time.</summary>
    public static readonly TimeSpan DefaultMaxAge = TimeSpan.FromSeconds(60);

    /// <summary>Starts building a NIP-98 token for the given HTTP <paramref name="method"/> and <paramref name="url"/>.</summary>
    public static Nip98AuthTokenBuilder Create(string method, Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        return new Nip98AuthTokenBuilder(method, url.AbsoluteUri);
    }

    /// <summary>Convenience overload for <see cref="HttpMethod"/>.</summary>
    public static Nip98AuthTokenBuilder Create(HttpMethod method, Uri url)
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(url);
        return new Nip98AuthTokenBuilder(method.Method, url.AbsoluteUri);
    }

    /// <summary>
    /// Encodes <paramref name="token"/> as the base64 parameter of an
    /// <c>Authorization: Nostr &lt;value&gt;</c> header. Standard base64
    /// with padding, per NIP-98 (distinct from BUD-11's base64url).
    /// </summary>
    public static string ToAuthorizationHeader(NostrEvent token)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (token.Kind != Nip98Kinds.HttpAuth)
        {
            throw new ArgumentException(
                $"Expected kind {Nip98Kinds.HttpAuth}; got {token.Kind}.", nameof(token));
        }

        return Convert.ToBase64String(SysEncoding.UTF8.GetBytes(token.ToJson()));
    }

    /// <summary>Convenience: returns an <see cref="AuthenticationHeaderValue"/> ready for <c>HttpRequestMessage.Headers.Authorization</c>.</summary>
    public static AuthenticationHeaderValue ToHeaderValue(NostrEvent token)
        => new(Scheme, ToAuthorizationHeader(token));

    /// <summary>
    /// Decodes a base64-encoded NIP-98 header value back into the
    /// original kind-27235 event. Accepts the bare base64 string OR
    /// the full <c>Nostr &lt;…&gt;</c> form. Returns <c>null</c> on any
    /// decode/parse failure.
    /// </summary>
    public static NostrEvent? TryFromAuthorizationHeader(string headerValue)
    {
        ArgumentNullException.ThrowIfNull(headerValue);
        string token = headerValue.Trim();
        const string prefix = "Nostr ";
        if (token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            token = token[prefix.Length..].Trim();
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(token);
        }
        catch (FormatException)
        {
            return null;
        }

        try
        {
            return NostrEvent.FromJson(SysEncoding.UTF8.GetString(bytes));
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Validates a NIP-98 token against the request it was sent for.
    /// Server-side: call this when inspecting an incoming
    /// <c>Authorization: Nostr …</c> header to confirm the token was
    /// minted for THIS request (URL + method + body) within the
    /// allowed age window. The signature is verified too.
    /// </summary>
    /// <param name="token">The parsed kind-27235 event from <see cref="TryFromAuthorizationHeader"/>.</param>
    /// <param name="expectedMethod">The HTTP method of the request that arrived.</param>
    /// <param name="expectedUrl">The absolute URL of the request that arrived.</param>
    /// <param name="requestBody">Optional request-body bytes. When non-null, the token's <c>payload</c> tag (if any) is checked. When null, payload presence is not enforced.</param>
    /// <param name="maxAge">How far in the past <c>created_at</c> can be. Defaults to <see cref="DefaultMaxAge"/>.</param>
    /// <param name="now">Reference "now" for the age check. Defaults to <see cref="DateTimeOffset.UtcNow"/>; tests pass a fixed value.</param>
    public static Nip98ValidationResult Validate(
        NostrEvent token,
        HttpMethod expectedMethod,
        Uri expectedUrl,
        ReadOnlyMemory<byte>? requestBody = null,
        TimeSpan? maxAge = null,
        DateTimeOffset? now = null)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(expectedMethod);
        ArgumentNullException.ThrowIfNull(expectedUrl);

        if (token.Kind != Nip98Kinds.HttpAuth)
        {
            return Nip98ValidationResult.Fail(Nip98ValidationFailure.WrongKind, token.PubKey);
        }

        if (!token.Verify())
        {
            return Nip98ValidationResult.Fail(Nip98ValidationFailure.BadSignature, token.PubKey);
        }

        var age = (now ?? DateTimeOffset.UtcNow) - DateTimeOffset.FromUnixTimeSeconds(token.CreatedAt);
        // Allow small clock skew in BOTH directions — a token created
        // a few seconds in the (server's) future can legitimately
        // arrive due to drift.
        TimeSpan window = maxAge ?? DefaultMaxAge;
        if (age > window || age < -window)
        {
            return Nip98ValidationResult.Fail(Nip98ValidationFailure.Expired, token.PubKey);
        }

        string? urlTag = null;
        string? methodTag = null;
        string? payloadTag = null;
        foreach (var tag in token.Tags)
        {
            if (tag.Count < 2) continue;
            switch (tag[0])
            {
                case "u": urlTag = tag[1]; break;
                case "method": methodTag = tag[1]; break;
                case "payload": payloadTag = tag[1]; break;
            }
        }

        if (urlTag is null) return Nip98ValidationResult.Fail(Nip98ValidationFailure.MissingUrl, token.PubKey);
        if (methodTag is null) return Nip98ValidationResult.Fail(Nip98ValidationFailure.MissingMethod, token.PubKey);

        if (!string.Equals(urlTag, expectedUrl.AbsoluteUri, StringComparison.Ordinal))
        {
            return Nip98ValidationResult.Fail(Nip98ValidationFailure.UrlMismatch, token.PubKey);
        }

        if (!string.Equals(methodTag, expectedMethod.Method, StringComparison.OrdinalIgnoreCase))
        {
            return Nip98ValidationResult.Fail(Nip98ValidationFailure.MethodMismatch, token.PubKey);
        }

        if (payloadTag is not null && requestBody is { } body)
        {
            Span<byte> hash = stackalloc byte[32];
            SHA256.HashData(body.Span, hash);
            string expected = Convert.ToHexStringLower(hash);
            if (!string.Equals(payloadTag, expected, StringComparison.OrdinalIgnoreCase))
            {
                return Nip98ValidationResult.Fail(Nip98ValidationFailure.PayloadHashMismatch, token.PubKey);
            }
        }

        return Nip98ValidationResult.Ok(token.PubKey);
    }
}

/// <summary>
/// <see cref="DelegatingHandler"/> that signs every outgoing request
/// with a fresh NIP-98 token and attaches it as the
/// <c>Authorization: Nostr …</c> header. Wire it into an
/// <see cref="HttpClient"/>:
/// <code>
/// var http = new HttpClient(new Nip98AuthHandler(myKey)
/// {
///     InnerHandler = new HttpClientHandler(),
/// });
/// </code>
/// </summary>
public sealed class Nip98AuthHandler : DelegatingHandler
{
    private readonly PrivateKey _key;
    private readonly bool _hashBodies;

    /// <summary>
    /// Creates a handler that signs every outgoing request with
    /// <paramref name="signingKey"/>.
    /// </summary>
    /// <param name="signingKey">The key used to sign every NIP-98 token. Caller owns its lifetime.</param>
    /// <param name="hashRequestBodies">When true, the handler reads the request body fully into memory, computes its sha256, and attaches a <c>payload</c> tag. Set false to skip — saves a body read for endpoints that don't validate the payload.</param>
    public Nip98AuthHandler(PrivateKey signingKey, bool hashRequestBodies = true)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        _key = signingKey;
        _hashBodies = hashRequestBodies;
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestUri is null)
        {
            throw new InvalidOperationException(
                "Nip98AuthHandler requires HttpRequestMessage.RequestUri to be set.");
        }

        var builder = Nip98HttpAuth.Create(request.Method, request.RequestUri);

        if (_hashBodies && request.Content is not null)
        {
            // Materialize the body so we can hash it AND let the
            // request layer send it. Without this we'd consume the
            // stream and break the inner handler.
            byte[] body = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (body.Length > 0)
            {
                builder.WithPayload(body);
            }

            // Replace the content so a downstream handler can re-read
            // (preserves the original Content-Type/Length headers).
            var fresh = new ByteArrayContent(body);
            foreach (var header in request.Content.Headers)
            {
                fresh.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            request.Content = fresh;
        }

        request.Headers.Authorization = Nip98HttpAuth.ToHeaderValue(builder.BuildAndSign(_key));
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
