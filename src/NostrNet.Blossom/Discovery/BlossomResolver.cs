// SPDX-License-Identifier: MIT
//
// BUD-03 + BUD-10 multi-server resolution.
//
// Given a sha256 (plus server hints, author hints, and an optional
// expected size), this walks every candidate server in spec-prescribed
// order until one returns the blob:
//
//   1. server hints (BUD-10 `xs` params), in declared order.
//      For domain-only entries, https:// then http:// per BUD-10.
//   2. author server lists (BUD-10 `as` params resolved via the user's
//      kind-10063 NIP-B7 event), each in their declared preference.
//      One TryGetBlossomServerListAsync round-trip per author.
//   3. optional well-known fallback servers supplied by the caller.
//
// Each candidate is checked with HEAD first so we can early-skip on
// mismatched Content-Length when `sz` is supplied (BUD-10). The first
// server that returns matching bytes wins.

using NostrNet.Blossom.Blobs;
using NostrNet.Blossom.Client;
using NostrNet.Blossom.UserServers;
using NostrNet.Client;
using NostrNet.Keys;

namespace NostrNet.Blossom.Discovery;

/// <summary>
/// Walks the BUD-03 / BUD-10 candidate-server order to fetch a blob.
/// </summary>
/// <remarks>
/// Construct one resolver per app session and reuse it across
/// requests — the underlying <see cref="HttpClient"/> is share-safe
/// and benefits from connection pooling. The optional
/// <see cref="NostrClient"/> is only needed when author-hint
/// resolution (BUD-03 / BUD-10 <c>as</c>) is requested; pass
/// <c>null</c> when you only care about explicit server hints.
/// </remarks>
public sealed class BlossomResolver : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly NostrClient? _nostr;

    /// <summary>
    /// Well-known fallback servers to try after BUD-03 / BUD-10 hints
    /// are exhausted. Empty by default — set via the constructor.
    /// </summary>
    public IReadOnlyList<string> FallbackServers { get; }

    /// <summary>
    /// How long to wait for a user's kind-10063 server list when
    /// resolving an <c>as</c> author hint. Defaults to 5 seconds.
    /// </summary>
    public TimeSpan ServerListTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Constructs a resolver. Pass an <see cref="HttpClient"/> for connection-pool reuse; pass a <see cref="NostrClient"/> to enable author-hint fallback.</summary>
    public BlossomResolver(
        HttpClient? http = null,
        NostrClient? nostrClient = null,
        IReadOnlyList<string>? fallbackServers = null)
    {
        _http = http ?? new HttpClient();
        _ownsHttp = http is null;
        _nostr = nostrClient;
        FallbackServers = fallbackServers ?? Array.Empty<string>();
    }

    /// <summary>Disposes the owned <see cref="HttpClient"/> if the resolver created one.</summary>
    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    /// <summary>
    /// Resolves a <see cref="BlossomUri"/>: walks server hints, then
    /// each author's NIP-B7 list, then the configured fallback
    /// servers. Returns <c>null</c> when no candidate produced the
    /// blob.
    /// </summary>
    public Task<BlossomResolvedBlob?> ResolveAsync(BlossomUri uri, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return ResolveAsync(
            sha256: uri.Sha256,
            serverHints: uri.ServerHints,
            authorHints: uri.AuthorHints,
            expectedSize: uri.SizeBytes,
            fileExtension: uri.Extension,
            ct);
    }

    /// <summary>
    /// Generic resolver — any of the hint inputs may be empty. The
    /// resolver tries them in BUD-10 order (server hints → author
    /// lists → fallback). Returns <c>null</c> when nothing succeeded.
    /// </summary>
    public async Task<BlossomResolvedBlob?> ResolveAsync(
        string sha256,
        IReadOnlyList<string>? serverHints = null,
        IReadOnlyList<PublicKey>? authorHints = null,
        long? expectedSize = null,
        string? fileExtension = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha256);
        if (sha256.Length != 64)
        {
            throw new ArgumentException("sha256 must be 64 hex chars.", nameof(sha256));
        }

        // 1. Caller-supplied server hints.
        foreach (var hint in serverHints ?? Array.Empty<string>())
        {
            foreach (var baseUri in EnumerateBaseUris(hint))
            {
                var hit = await TryFetchAsync(baseUri, sha256, fileExtension, expectedSize, ct).ConfigureAwait(false);
                if (hit is not null) return hit;
            }
        }

        // 2. Author-list lookup via NIP-B7 (kind 10063).
        if (authorHints is { Count: > 0 } && _nostr is not null)
        {
            foreach (var author in authorHints)
            {
                BlossomServerList? list;
                try
                {
                    list = await _nostr.TryGetBlossomServerListAsync(author, ServerListTimeout, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // ServerListTimeout fired — move on to the next author.
                    list = null;
                }

                if (list is null) continue;

                foreach (var server in list.Servers)
                {
                    foreach (var baseUri in EnumerateBaseUris(server))
                    {
                        var hit = await TryFetchAsync(baseUri, sha256, fileExtension, expectedSize, ct).ConfigureAwait(false);
                        if (hit is not null) return hit;
                    }
                }
            }
        }

        // 3. Well-known fallback servers.
        foreach (var hint in FallbackServers)
        {
            foreach (var baseUri in EnumerateBaseUris(hint))
            {
                var hit = await TryFetchAsync(baseUri, sha256, fileExtension, expectedSize, ct).ConfigureAwait(false);
                if (hit is not null) return hit;
            }
        }

        return null;
    }

    /// <summary>
    /// Recovers a blob from a URL that has gone 404 by extracting the
    /// last-hex-run sha256 (per BUD-03) and walking the author's
    /// kind-10063 list. Returns <c>null</c> if the URL has no
    /// recoverable sha256 or no candidate produces the bytes.
    /// </summary>
    public Task<BlossomResolvedBlob?> ResolveBrokenUrlAsync(
        string brokenUrl,
        IReadOnlyList<PublicKey>? authorHints,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(brokenUrl);
        string? sha = BlossomUri.ExtractSha256(brokenUrl);
        if (sha is null) return Task.FromResult<BlossomResolvedBlob?>(null);
        return ResolveAsync(sha, serverHints: null, authorHints, expectedSize: null, fileExtension: null, ct);
    }

    private async Task<BlossomResolvedBlob?> TryFetchAsync(
        Uri baseUri,
        string sha256,
        string? fileExtension,
        long? expectedSize,
        CancellationToken ct)
    {
        BlossomClient? client = null;
        try
        {
            client = new BlossomClient(baseUri, _http);

            // BUD-10: if a `sz` hint was provided, prefer HEAD first so
            // we don't spend bandwidth on the wrong file before we
            // know its length matches.
            if (expectedSize is long sz)
            {
                try
                {
                    var head = await client.HeadBlobAsync(sha256, fileExtension, authorization: null, ct).ConfigureAwait(false);
                    if (head is null) return null;
                    if (head.ContentLength is long len && len != sz) return null;
                }
                catch (HttpRequestException) { return null; }
                catch (Client.BlossomHttpException) { return null; }
            }

            HttpResponseMessage? resp = null;
            try
            {
                resp = await client.GetBlobAsync(sha256, fileExtension, authorization: null, ct).ConfigureAwait(false);
                byte[] bytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);

                // Last-line size verification — BUD-10 says clients
                // SHOULD verify the downloaded size matches `sz` when
                // provided. If the HEAD didn't surface Content-Length
                // (some CDNs don't) we still want this guard.
                if (expectedSize is long expected && bytes.LongLength != expected)
                {
                    return null;
                }

                string contentType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
                return new BlossomResolvedBlob
                {
                    Bytes = bytes,
                    Sha256 = sha256,
                    ServerUrl = baseUri.AbsoluteUri,
                    ContentType = contentType,
                };
            }
            finally
            {
                resp?.Dispose();
            }
        }
        catch (HttpRequestException) { return null; }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return null; }
        catch (Client.BlossomHttpException) { return null; }
        finally
        {
            client?.Dispose();
        }
    }

    /// <summary>
    /// BUD-10: server hints MAY include a scheme. When they don't,
    /// try https:// first then http:// per spec.
    /// </summary>
    private static IEnumerable<Uri> EnumerateBaseUris(string hint)
    {
        if (string.IsNullOrEmpty(hint)) yield break;

        if (hint.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || hint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (Uri.TryCreate(hint, UriKind.Absolute, out var explicitUri))
            {
                yield return NormalizeBase(explicitUri);
            }

            yield break;
        }

        // Domain only — try https first.
        if (Uri.TryCreate("https://" + hint, UriKind.Absolute, out var https))
        {
            yield return NormalizeBase(https);
        }

        if (Uri.TryCreate("http://" + hint, UriKind.Absolute, out var http))
        {
            yield return NormalizeBase(http);
        }
    }

    private static Uri NormalizeBase(Uri u)
    {
        string s = u.AbsoluteUri;
        return s.EndsWith('/') ? u : new Uri(s + "/");
    }
}

/// <summary>The successful output of <see cref="BlossomResolver.ResolveAsync(BlossomUri, CancellationToken)"/>.</summary>
public sealed record BlossomResolvedBlob
{
    /// <summary>The fetched blob bytes.</summary>
    public required byte[] Bytes { get; init; }

    /// <summary>The blob's sha256 (echoed back from the input for caller convenience).</summary>
    public required string Sha256 { get; init; }

    /// <summary>The base URL of the server that produced the bytes.</summary>
    public required string ServerUrl { get; init; }

    /// <summary>The blob's MIME type as advertised by the serving server.</summary>
    public required string ContentType { get; init; }
}
