// SPDX-License-Identifier: MIT
//
// BUD-01 / BUD-02 / BUD-04 / BUD-05 / BUD-06 / BUD-07 / BUD-09 /
// BUD-12: HTTP client for one Blossom server. Use one
// BlossomClient per server origin; a separate resolver type handles
// multi-server walks (see BlossomResolver, BUD-03 / BUD-10).
//
// All upload-side endpoints accept an optional BUD-11 authorization
// event; the client base64url-encodes it into the
// `Authorization: Nostr …` header automatically.

using System.Net;
using System.Net.Http.Headers;
using NostrNet.Blossom.Auth;
using NostrNet.Blossom.Blobs;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Blossom.Client;

/// <summary>HTTP client for a single Blossom server.</summary>
public sealed class BlossomClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    /// <summary>The server's base URI (always ends with <c>/</c>).</summary>
    public Uri BaseAddress { get; }

    /// <summary>Constructs a client backed by a caller-provided <see cref="HttpClient"/>.</summary>
    /// <remarks>Pass a long-lived shared <see cref="HttpClient"/> for connection-pool reuse. The client is NOT disposed when <see cref="BlossomClient"/> is.</remarks>
    public BlossomClient(Uri baseAddress, HttpClient http)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentNullException.ThrowIfNull(http);
        BaseAddress = NormalizeBase(baseAddress);
        _http = http;
        _ownsHttp = false;
    }

    /// <summary>Constructs a client owning its own <see cref="HttpClient"/>; disposed when <see cref="Dispose"/> is called.</summary>
    public BlossomClient(Uri baseAddress) : this(baseAddress, new HttpClient())
    {
        _ownsHttp = true;
    }

    /// <summary>Disposes the owned <see cref="HttpClient"/> (no-op when an external one was supplied).</summary>
    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    // ─────────────────────────────────────────────────────────────
    // BUD-01: HEAD / GET <sha256>
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// BUD-01 <c>HEAD /&lt;sha256&gt;</c>: checks whether the server has the blob
    /// and returns the metadata headers (Content-Type, Content-Length,
    /// Sunset, Accept-Ranges). Returns <c>null</c> for 404.
    /// </summary>
    public async Task<BlobHead?> HeadBlobAsync(
        string sha256,
        string? fileExtension = null,
        NostrEvent? authorization = null,
        CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Head, BlobUri(sha256, fileExtension));
        AttachAuthorization(req, authorization);

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);

        return new BlobHead
        {
            ContentType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream",
            ContentLength = resp.Content.Headers.ContentLength,
            AcceptsRanges = resp.Headers.AcceptRanges.Count > 0,
            Sunset = resp.Headers.TryGetValues("Sunset", out var s) ? s.FirstOrDefault() : null,
        };
    }

    /// <summary>
    /// BUD-01 <c>GET /&lt;sha256&gt;</c>: fetches blob bytes. The returned
    /// <see cref="HttpResponseMessage"/> is the caller's responsibility
    /// to dispose; use <see cref="GetBlobBytesAsync"/> for a buffered
    /// byte-array result instead.
    /// </summary>
    public async Task<HttpResponseMessage> GetBlobAsync(
        string sha256,
        string? fileExtension = null,
        NostrEvent? authorization = null,
        CancellationToken ct = default)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, BlobUri(sha256, fileExtension));
        AttachAuthorization(req, authorization);

        var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            try { await EnsureSuccessAsync(resp, ct).ConfigureAwait(false); }
            finally { resp.Dispose(); }
        }

        return resp;
    }

    /// <summary>Convenience wrapper: returns the blob bytes as a <c>byte[]</c>.</summary>
    public async Task<byte[]> GetBlobBytesAsync(
        string sha256,
        string? fileExtension = null,
        NostrEvent? authorization = null,
        CancellationToken ct = default)
    {
        using var resp = await GetBlobAsync(sha256, fileExtension, authorization, ct).ConfigureAwait(false);
        return await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }

    // ─────────────────────────────────────────────────────────────
    // BUD-02: PUT /upload
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// BUD-02 <c>PUT /upload</c>: uploads <paramref name="content"/>
    /// and returns the server's descriptor. <paramref name="authorization"/>
    /// should be a BUD-11 token with <c>t=upload</c> and an <c>x</c>
    /// tag matching the uploaded blob's sha256.
    /// </summary>
    public Task<BlobDescriptor> UploadAsync(
        HttpContent content,
        NostrEvent? authorization = null,
        string? expectedSha256 = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        return DescriptorPutAsync("upload", content, authorization, expectedSha256, ct);
    }

    /// <summary>
    /// BUD-06 <c>HEAD /upload</c>: pre-flight check using
    /// <c>X-SHA-256</c> / <c>X-Content-Type</c> / <c>X-Content-Length</c>.
    /// Returns the HTTP status code; 200 means "upload would succeed."
    /// </summary>
    public Task<HttpStatusCode> UploadHeadAsync(
        string sha256,
        string contentType,
        long contentLength,
        NostrEvent? authorization = null,
        CancellationToken ct = default)
        => HeadOptimizationAsync("upload", sha256, contentType, contentLength, authorization, ct);

    // ─────────────────────────────────────────────────────────────
    // BUD-04: PUT /mirror
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// BUD-04 <c>PUT /mirror</c>: asks the server to fetch a remote
    /// URL and store it as its own blob. The auth token should be the
    /// SAME <c>upload</c> token used at the origin server (per BUD-04's
    /// example flow), with an <c>x</c> tag matching the mirrored blob.
    /// </summary>
    public async Task<BlobDescriptor> MirrorAsync(
        string remoteUrl,
        NostrEvent? authorization = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(remoteUrl);
        // Build the one-key body manually; pulling in a source-gen
        // context just for {"url": "<string>"} is overkill.
        string body = "{\"url\":\"" + EscapeJsonString(remoteUrl) + "\"}";
        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        return await DescriptorPutAsync("mirror", content, authorization, expectedSha256: null, ct).ConfigureAwait(false);
    }

    // ─────────────────────────────────────────────────────────────
    // BUD-05: PUT /media + HEAD /media
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// BUD-05 <c>PUT /media</c>: server-side optimization endpoint.
    /// The returned descriptor describes the OPTIMIZED blob, which
    /// may differ from the input bytes.
    /// </summary>
    public Task<BlobDescriptor> MediaUploadAsync(
        HttpContent content,
        NostrEvent? authorization = null,
        string? expectedSha256 = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        return DescriptorPutAsync("media", content, authorization, expectedSha256, ct);
    }

    /// <summary>BUD-05 <c>HEAD /media</c>: pre-flight check for media optimization.</summary>
    public Task<HttpStatusCode> MediaHeadAsync(
        string sha256,
        string contentType,
        long contentLength,
        NostrEvent? authorization = null,
        CancellationToken ct = default)
        => HeadOptimizationAsync("media", sha256, contentType, contentLength, authorization, ct);

    // ─────────────────────────────────────────────────────────────
    // BUD-12: list + delete
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// BUD-12 <c>GET /list/&lt;pubkey&gt;</c>: returns descriptors for blobs
    /// the given user uploaded. <paramref name="cursor"/> is the
    /// sha256 of the last item in the previous page (use <c>null</c>
    /// for the first page). <paramref name="limit"/> caps the page
    /// size. Returns an empty list when the server has nothing for
    /// this user.
    /// </summary>
    public async Task<IReadOnlyList<BlobDescriptor>> ListAsync(
        PublicKey owner,
        string? cursor = null,
        int? limit = null,
        NostrEvent? authorization = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(owner);

        var sb = new System.Text.StringBuilder();
        sb.Append("list/").Append(owner.ToHex());
        bool first = true;
        if (cursor is not null)
        {
            sb.Append(first ? '?' : '&').Append("cursor=").Append(Uri.EscapeDataString(cursor));
            first = false;
        }

        if (limit is int n && n > 0)
        {
            sb.Append(first ? '?' : '&').Append("limit=").Append(n);
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, new Uri(BaseAddress, sb.ToString()));
        AttachAuthorization(req, authorization);
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct).ConfigureAwait(false);
        await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);

        string body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return BlobDescriptor.ArrayFromJson(body);
    }

    /// <summary>
    /// BUD-12 <c>DELETE /&lt;sha256&gt;</c>. Requires a BUD-11 token with
    /// <c>t=delete</c> and an <c>x</c> tag matching <paramref name="sha256"/>.
    /// Returns <c>true</c> on 200/204 and <c>false</c> on 404 (already gone).
    /// </summary>
    public async Task<bool> DeleteBlobAsync(
        string sha256,
        NostrEvent authorization,
        CancellationToken ct = default)
    {
        ValidateSha256(sha256);
        ArgumentNullException.ThrowIfNull(authorization);

        using var req = new HttpRequestMessage(HttpMethod.Delete, new Uri(BaseAddress, sha256));
        AttachAuthorization(req, authorization);
        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);

        if (resp.StatusCode == HttpStatusCode.NotFound) return false;
        await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
        return true;
    }

    // ─────────────────────────────────────────────────────────────
    // BUD-09: PUT /report
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// BUD-09 <c>PUT /report</c>: submits a signed NIP-56 kind-1984
    /// report referencing one or more blob hashes. The Nostr event
    /// itself carries the <c>x</c> tags; this method just publishes
    /// the JSON body.
    /// </summary>
    public async Task ReportAsync(
        NostrEvent reportEvent,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(reportEvent);
        if (reportEvent.Kind != 1984)
        {
            throw new ArgumentException(
                "BUD-09 report requires a NIP-56 kind-1984 event.", nameof(reportEvent));
        }

        using var content = new StringContent(reportEvent.ToJson(), System.Text.Encoding.UTF8, "application/json");
        using var req = new HttpRequestMessage(HttpMethod.Put, new Uri(BaseAddress, "report"))
        {
            Content = content,
        };

        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);
    }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    private async Task<BlobDescriptor> DescriptorPutAsync(
        string path,
        HttpContent content,
        NostrEvent? authorization,
        string? expectedSha256,
        CancellationToken ct)
    {
        if (expectedSha256 is not null)
        {
            ValidateSha256(expectedSha256);
            content.Headers.Add("X-SHA-256", expectedSha256);
        }

        using var req = new HttpRequestMessage(HttpMethod.Put, new Uri(BaseAddress, path))
        {
            Content = content,
        };
        AttachAuthorization(req, authorization);

        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        await EnsureSuccessAsync(resp, ct).ConfigureAwait(false);

        string body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return BlobDescriptor.FromJson(body);
    }

    private async Task<HttpStatusCode> HeadOptimizationAsync(
        string path,
        string sha256,
        string contentType,
        long contentLength,
        NostrEvent? authorization,
        CancellationToken ct)
    {
        ValidateSha256(sha256);
        ArgumentException.ThrowIfNullOrEmpty(contentType);
        if (contentLength < 0) throw new ArgumentOutOfRangeException(nameof(contentLength));

        using var req = new HttpRequestMessage(HttpMethod.Head, new Uri(BaseAddress, path));
        AttachAuthorization(req, authorization);
        req.Headers.Add("X-SHA-256", sha256);
        req.Headers.Add("X-Content-Type", contentType);
        req.Headers.Add("X-Content-Length", contentLength.ToString(System.Globalization.CultureInfo.InvariantCulture));

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.PaymentRequired)
        {
            // Propagate as a typed exception so callers can surface the quote.
            await ThrowPaymentRequiredAsync(resp, ct).ConfigureAwait(false);
        }

        return resp.StatusCode;
    }

    private Uri BlobUri(string sha256, string? fileExtension)
    {
        ValidateSha256(sha256);
        string path = string.IsNullOrEmpty(fileExtension)
            ? sha256
            : sha256 + (fileExtension.StartsWith('.') ? fileExtension : "." + fileExtension);
        return new Uri(BaseAddress, path);
    }

    private static void AttachAuthorization(HttpRequestMessage req, NostrEvent? authorization)
    {
        if (authorization is null) return;
        string token = BlossomAuthToken.ToAuthorizationHeader(authorization);
        req.Headers.Authorization = new AuthenticationHeaderValue(BlossomAuthToken.Scheme, token);
    }

    private static void ValidateSha256(string sha256)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha256);
        if (sha256.Length != 64)
        {
            throw new ArgumentException("sha256 must be 64 hex chars.", nameof(sha256));
        }
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode) return;

        if (resp.StatusCode == HttpStatusCode.PaymentRequired)
        {
            await ThrowPaymentRequiredAsync(resp, ct).ConfigureAwait(false);
        }

        string? reason = resp.Headers.TryGetValues("X-Reason", out var values)
            ? values.FirstOrDefault()
            : null;
        if (reason is null)
        {
            try { reason = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false); }
            catch { /* response body not readable; fall through */ }
            if (string.IsNullOrWhiteSpace(reason)) reason = null;
        }

        throw new BlossomHttpException((int)resp.StatusCode, reason);
    }

    private static async Task ThrowPaymentRequiredAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        string? reason = resp.Headers.TryGetValues("X-Reason", out var values)
            ? values.FirstOrDefault()
            : null;

        var lightning = new List<string>();
        var cashu = new List<string>();
        var other = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var (key, headerValues) in resp.Headers)
        {
            if (!key.StartsWith("X-", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.Equals(key, "X-Reason", StringComparison.OrdinalIgnoreCase)) continue;

            // Skip BUD-06/05 hint headers — they're not payment methods.
            if (string.Equals(key, "X-SHA-256", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.Equals(key, "X-Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.Equals(key, "X-Content-Length", StringComparison.OrdinalIgnoreCase)) continue;

            if (string.Equals(key, "X-Lightning", StringComparison.OrdinalIgnoreCase))
            {
                lightning.AddRange(headerValues);
            }
            else if (string.Equals(key, "X-Cashu", StringComparison.OrdinalIgnoreCase))
            {
                cashu.AddRange(headerValues);
            }
            else
            {
                other[key] = headerValues.ToArray();
            }
        }

        // Consume the body so connection-pool reuse isn't blocked.
        try { _ = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false); }
        catch { /* ignore */ }

        throw new BlossomPaymentRequiredException(reason, lightning, cashu, other);
    }

    private static Uri NormalizeBase(Uri baseAddress)
    {
        string s = baseAddress.AbsoluteUri;
        return s.EndsWith('/') ? baseAddress : new Uri(s + "/");
    }

    /// <summary>
    /// Minimal JSON-string escape: just the chars NIP-01 / JSON requires
    /// (backslash, quote, control chars). Used by the BUD-04 mirror
    /// body since we only need to serialize a single URL string.
    /// </summary>
    private static string EscapeJsonString(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length + 2);
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u").Append(((int)c).ToString("X4", System.Globalization.CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        return sb.ToString();
    }
}

/// <summary>Metadata returned by <see cref="BlossomClient.HeadBlobAsync"/>.</summary>
public sealed record BlobHead
{
    /// <summary>The blob's MIME type as advertised by the server.</summary>
    public required string ContentType { get; init; }

    /// <summary>The blob size in bytes from the <c>Content-Length</c> header.</summary>
    public long? ContentLength { get; init; }

    /// <summary>True when the server advertises <c>Accept-Ranges: bytes</c>.</summary>
    public bool AcceptsRanges { get; init; }

    /// <summary>Optional <c>Sunset</c> header value (advisory deletion time, BUD-01).</summary>
    public string? Sunset { get; init; }
}
