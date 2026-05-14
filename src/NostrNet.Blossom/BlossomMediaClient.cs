// SPDX-License-Identifier: MIT
//
// High-level Blossom façade that bundles every piece of the
// NostrNet.Blossom package — auth token construction, per-server
// HTTP, multi-server resolution, and NIP-B7 server-list management —
// behind one ergonomic API.
//
// One BlossomMediaClient per logical "user". Construct it via the
// builder, attach the user's preferred servers, and call high-level
// methods: UploadAsync, DownloadAsync, DeleteAsync, ListMyBlobsAsync.
//
//   await using var media = BlossomMediaClient.Builder(myKey)
//       .UseServers("https://cdn.satellite.earth", "https://blossom.primal.net")
//       .UseNostrClient(nostrClient)            // for NIP-B7 publish/discover
//       .Build();
//
//   var upload = await media.UploadAsync(imageBytes, "image/png");
//   var blob   = await media.DownloadAsync(upload.PrimaryDescriptor.Sha256);

using System.Collections.Concurrent;
using System.Security.Cryptography;
using NostrNet.Blossom.Auth;
using NostrNet.Blossom.Blobs;
using NostrNet.Blossom.Client;
using NostrNet.Blossom.Discovery;
using NostrNet.Blossom.UserServers;
using NostrNet.Client;
using NostrNet.Keys;
using NostrNet.Relay;

namespace NostrNet.Blossom;

/// <summary>
/// High-level Blossom façade. One instance per signed-in user; reuse
/// across operations to share connections.
/// </summary>
public sealed class BlossomMediaClient : IDisposable
{
    private readonly PrivateKey _key;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly NostrClient? _nostr;
    private readonly List<string> _servers;
    private readonly BlossomResolver _resolver;
    private readonly ConcurrentDictionary<string, BlossomClient> _clientsByServer = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    internal BlossomMediaClient(
        PrivateKey key,
        HttpClient http,
        bool ownsHttp,
        NostrClient? nostr,
        List<string> servers,
        BlossomResolver resolver)
    {
        _key = key;
        _http = http;
        _ownsHttp = ownsHttp;
        _nostr = nostr;
        _servers = servers;
        _resolver = resolver;
    }

    /// <summary>Starts building a Blossom façade for the given identity.</summary>
    public static BlossomMediaClientBuilder Builder(PrivateKey identityKey) => new(identityKey);

    /// <summary>The signed-in user's public key.</summary>
    public PublicKey Identity => _key.PublicKey;

    /// <summary>Preferred Blossom servers, in declared order (first = primary upload target).</summary>
    public IReadOnlyList<string> Servers => _servers;

    /// <summary>Underlying multi-server resolver used by <see cref="DownloadAsync(BlossomUri, CancellationToken)"/>.</summary>
    public BlossomResolver Resolver => _resolver;

    /// <summary>Disposes the cached per-server <see cref="BlossomClient"/> instances and the resolver.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        foreach (var c in _clientsByServer.Values) c.Dispose();
        _clientsByServer.Clear();
        _resolver.Dispose();
        if (_ownsHttp) _http.Dispose();
    }

    // ─────────────────────────────────────────────────────────────
    // Upload
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Uploads <paramref name="bytes"/> to the primary server, then
    /// (when <paramref name="mirrorToAllServers"/> is true)
    /// mirrors via BUD-04 <c>PUT /mirror</c> to every additional
    /// configured server. The sha256 is computed locally and pinned
    /// via the <c>X-SHA-256</c> request header.
    /// </summary>
    public async Task<BlossomUploadResult> UploadAsync(
        ReadOnlyMemory<byte> bytes,
        string mimeType,
        bool mirrorToAllServers = true,
        CancellationToken ct = default)
    {
        EnsureNotDisposed();
        ArgumentException.ThrowIfNullOrEmpty(mimeType);
        if (_servers.Count == 0)
        {
            throw new InvalidOperationException(
                "BlossomMediaClient was built without any servers — call UseServers(...) on the builder.");
        }

        string sha = ComputeSha256(bytes.Span);

        var auth = BlossomAuthToken
            .Create(BlossomAuthVerb.Upload, "Upload Blob")
            .ScopeToBlob(sha)
            .BuildAndSign(_key);

        // Primary upload — fail if this one fails.
        string primaryServer = _servers[0];
        BlobDescriptor primary;
        using (var content = new ByteArrayContent(bytes.ToArray()))
        {
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mimeType);
            content.Headers.ContentLength = bytes.Length;
            primary = await ClientFor(primaryServer).UploadAsync(content, auth, sha, ct).ConfigureAwait(false);
        }

        if (!mirrorToAllServers || _servers.Count <= 1)
        {
            return new BlossomUploadResult(
                Sha256: sha,
                PrimaryServer: primaryServer,
                PrimaryDescriptor: primary,
                Mirrors: new Dictionary<string, BlossomMirrorOutcome>(StringComparer.OrdinalIgnoreCase));
        }

        // Mirror to the remaining servers in parallel. BUD-04 says
        // the same upload-scoped auth token works at every server.
        var mirrors = new ConcurrentDictionary<string, BlossomMirrorOutcome>(StringComparer.OrdinalIgnoreCase);
        var tasks = new List<Task>(_servers.Count - 1);
        for (int i = 1; i < _servers.Count; i++)
        {
            string server = _servers[i];
            tasks.Add(MirrorOneAsync(server, primary.Url, auth, mirrors, ct));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return new BlossomUploadResult(
            Sha256: sha,
            PrimaryServer: primaryServer,
            PrimaryDescriptor: primary,
            Mirrors: mirrors);
    }

    /// <summary>
    /// Stream-based upload. Reads <paramref name="stream"/> fully
    /// into memory to compute the sha256 (required for the BUD-11
    /// authorization token), then delegates to the byte-array
    /// overload. For very large blobs, prefer pre-computing the
    /// sha256 yourself and using the low-level
    /// <see cref="BlossomClient"/>.
    /// </summary>
    public async Task<BlossomUploadResult> UploadAsync(
        Stream stream,
        string mimeType,
        bool mirrorToAllServers = true,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
        return await UploadAsync(ms.ToArray(), mimeType, mirrorToAllServers, ct).ConfigureAwait(false);
    }

    private async Task MirrorOneAsync(
        string server,
        string sourceUrl,
        Events.NostrEvent auth,
        ConcurrentDictionary<string, BlossomMirrorOutcome> sink,
        CancellationToken ct)
    {
        try
        {
            var descriptor = await ClientFor(server).MirrorAsync(sourceUrl, auth, ct).ConfigureAwait(false);
            sink[server] = new BlossomMirrorOutcome(descriptor, null);
        }
        catch (Exception ex)
        {
            sink[server] = new BlossomMirrorOutcome(null, ex);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Download
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Downloads a blob by sha256. Resolves through the user's own
    /// servers first, then the optional <paramref name="authorHints"/>,
    /// then the resolver's configured fallback servers.
    /// </summary>
    public Task<BlossomResolvedBlob?> DownloadAsync(
        string sha256,
        IReadOnlyList<PublicKey>? authorHints = null,
        long? expectedSize = null,
        string? fileExtension = null,
        CancellationToken ct = default)
    {
        EnsureNotDisposed();
        // Prefer the user's own servers; the resolver then walks
        // author hints (if any) and the fallback list internally.
        return _resolver.ResolveAsync(
            sha256: sha256,
            serverHints: _servers,
            authorHints: authorHints,
            expectedSize: expectedSize,
            fileExtension: fileExtension,
            ct: ct);
    }

    /// <summary>Resolves a <c>blossom:</c> URI via the underlying multi-server walker.</summary>
    public Task<BlossomResolvedBlob?> DownloadAsync(BlossomUri uri, CancellationToken ct = default)
    {
        EnsureNotDisposed();
        ArgumentNullException.ThrowIfNull(uri);
        // The URI's xs hints take priority by spec; we still pass our
        // own servers as additional candidates after them.
        var combined = new List<string>(uri.ServerHints.Count + _servers.Count);
        combined.AddRange(uri.ServerHints);
        foreach (var s in _servers)
        {
            if (!combined.Contains(s, StringComparer.OrdinalIgnoreCase))
            {
                combined.Add(s);
            }
        }

        return _resolver.ResolveAsync(
            sha256: uri.Sha256,
            serverHints: combined,
            authorHints: uri.AuthorHints,
            expectedSize: uri.SizeBytes,
            fileExtension: uri.Extension,
            ct: ct);
    }

    /// <summary>Recovers a 404'd URL via the BUD-03 author-list fallback.</summary>
    public Task<BlossomResolvedBlob?> DownloadBrokenUrlAsync(
        string brokenUrl,
        IReadOnlyList<PublicKey>? authorHints,
        CancellationToken ct = default)
    {
        EnsureNotDisposed();
        ArgumentException.ThrowIfNullOrEmpty(brokenUrl);
        // Add the user's own servers to the candidate set even when
        // resolving someone else's broken URL — many blobs live on
        // overlapping servers.
        string? sha = BlossomUri.ExtractSha256(brokenUrl);
        if (sha is null) return Task.FromResult<BlossomResolvedBlob?>(null);
        return DownloadAsync(sha, authorHints, expectedSize: null, fileExtension: null, ct);
    }

    // ─────────────────────────────────────────────────────────────
    // List + Delete
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Lists every blob the local user has uploaded to any of their
    /// configured servers, deduplicated by sha256. The first
    /// descriptor per sha256 (in server order) wins on conflict.
    /// </summary>
    public async Task<IReadOnlyList<BlobDescriptor>> ListMyBlobsAsync(
        int? perServerLimit = null,
        CancellationToken ct = default)
    {
        EnsureNotDisposed();
        if (_servers.Count == 0) return Array.Empty<BlobDescriptor>();

        // List endpoints don't require an auth token by spec, but
        // some servers ask for one — supply it preemptively.
        var auth = BlossomAuthToken
            .Create(BlossomAuthVerb.List, "List Blobs")
            .BuildAndSign(_key);

        var byHash = new Dictionary<string, BlobDescriptor>(StringComparer.OrdinalIgnoreCase);
        foreach (var server in _servers)
        {
            string? cursor = null;
            while (true)
            {
                IReadOnlyList<BlobDescriptor> page;
                try
                {
                    page = await ClientFor(server)
                        .ListAsync(_key.PublicKey, cursor, perServerLimit, auth, ct)
                        .ConfigureAwait(false);
                }
                catch (BlossomHttpException)
                {
                    // Server doesn't support /list, doesn't authorize us, etc. — skip.
                    break;
                }

                if (page.Count == 0) break;

                foreach (var d in page)
                {
                    byHash.TryAdd(d.Sha256, d);
                }

                if (perServerLimit is null || page.Count < perServerLimit.Value)
                {
                    break;
                }

                cursor = page[^1].Sha256;
            }
        }

        return byHash.Values.ToList();
    }

    /// <summary>
    /// Deletes the blob from every configured server. Returns a
    /// per-server map of (server URL → outcome): <c>true</c> when
    /// deleted (or already absent), <c>false</c> when the server
    /// rejected the request, <c>null</c> when the call failed for
    /// network / other reasons.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, bool?>> DeleteAsync(
        string sha256,
        CancellationToken ct = default)
    {
        EnsureNotDisposed();
        ArgumentException.ThrowIfNullOrEmpty(sha256);
        if (sha256.Length != 64) throw new ArgumentException("sha256 must be 64 hex chars.", nameof(sha256));

        var auth = BlossomAuthToken
            .Create(BlossomAuthVerb.Delete, "Delete Blob")
            .ScopeToBlob(sha256)
            .BuildAndSign(_key);

        var result = new Dictionary<string, bool?>(StringComparer.OrdinalIgnoreCase);
        foreach (var server in _servers)
        {
            try
            {
                bool ok = await ClientFor(server).DeleteBlobAsync(sha256, auth, ct).ConfigureAwait(false);
                result[server] = ok;
            }
            catch (BlossomHttpException)
            {
                result[server] = false;
            }
            catch (HttpRequestException)
            {
                result[server] = null;
            }
        }

        return result;
    }

    // ─────────────────────────────────────────────────────────────
    // NIP-B7 server list
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Publishes a NIP-B7 (kind 10063) server list event with the
    /// currently-configured <see cref="Servers"/>. Requires a
    /// <see cref="NostrClient"/> attached at build time.
    /// </summary>
    public Task<IReadOnlyDictionary<Uri, PublishResult>> PublishServerListAsync(
        CancellationToken ct = default)
    {
        EnsureNotDisposed();
        if (_nostr is null)
        {
            throw new InvalidOperationException(
                "PublishServerListAsync requires a NostrClient — pass one to the builder via UseNostrClient(...).");
        }

        if (_servers.Count == 0)
        {
            throw new InvalidOperationException("No servers configured to publish.");
        }

        return _nostr.PublishBlossomServerListAsync(_servers, ct);
    }

    /// <summary>
    /// Fetches another user's NIP-B7 server list via the attached
    /// <see cref="NostrClient"/>.
    /// </summary>
    public Task<BlossomServerList?> GetServerListAsync(
        PublicKey owner,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        EnsureNotDisposed();
        ArgumentNullException.ThrowIfNull(owner);
        if (_nostr is null)
        {
            throw new InvalidOperationException(
                "GetServerListAsync requires a NostrClient — pass one to the builder via UseNostrClient(...).");
        }

        return _nostr.TryGetBlossomServerListAsync(owner, timeout, ct);
    }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    private BlossomClient ClientFor(string serverUrl)
    {
        return _clientsByServer.GetOrAdd(serverUrl, s =>
        {
            var baseUri = new Uri(s.EndsWith('/') ? s : s + "/");
            return new BlossomClient(baseUri, _http);
        });
    }

    private void EnsureNotDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(BlossomMediaClient));
    }

    internal static string ComputeSha256(ReadOnlySpan<byte> bytes)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes, hash);
        return Convert.ToHexStringLower(hash);
    }
}

/// <summary>Fluent builder for <see cref="BlossomMediaClient"/>.</summary>
public sealed class BlossomMediaClientBuilder
{
    private readonly PrivateKey _key;
    private HttpClient? _http;
    private NostrClient? _nostr;
    private readonly List<string> _servers = new();
    private readonly List<string> _fallbackServers = new();
    private TimeSpan? _serverListTimeout;

    internal BlossomMediaClientBuilder(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _key = key;
    }

    /// <summary>Adds preferred Blossom servers in order — first one is the primary upload target.</summary>
    public BlossomMediaClientBuilder UseServers(params string[] serverUrls)
    {
        ArgumentNullException.ThrowIfNull(serverUrls);
        foreach (var s in serverUrls)
        {
            ArgumentException.ThrowIfNullOrEmpty(s);
            _servers.Add(s);
        }

        return this;
    }

    /// <summary>Adds well-known fallback servers consulted only after the user's own + author hints fail.</summary>
    public BlossomMediaClientBuilder UseFallbackServers(params string[] urls)
    {
        ArgumentNullException.ThrowIfNull(urls);
        foreach (var s in urls)
        {
            ArgumentException.ThrowIfNullOrEmpty(s);
            _fallbackServers.Add(s);
        }

        return this;
    }

    /// <summary>Supplies the shared <see cref="HttpClient"/>; one is created internally if omitted.</summary>
    public BlossomMediaClientBuilder UseHttpClient(HttpClient http)
    {
        ArgumentNullException.ThrowIfNull(http);
        _http = http;
        return this;
    }

    /// <summary>
    /// Attaches a Nostr client for NIP-B7 server-list publish /
    /// discovery. Optional — without it, the corresponding
    /// <see cref="BlossomMediaClient"/> methods throw and resolver
    /// author-hint fallback is skipped.
    /// </summary>
    public BlossomMediaClientBuilder UseNostrClient(NostrClient nostrClient)
    {
        ArgumentNullException.ThrowIfNull(nostrClient);
        _nostr = nostrClient;
        return this;
    }

    /// <summary>Overrides the resolver's server-list lookup timeout (default 5s).</summary>
    public BlossomMediaClientBuilder WithServerListTimeout(TimeSpan timeout)
    {
        _serverListTimeout = timeout;
        return this;
    }

    /// <summary>Builds the façade. Reuses the supplied <see cref="HttpClient"/>; creates one when omitted.</summary>
    public BlossomMediaClient Build()
    {
        HttpClient http = _http ?? new HttpClient();
        bool ownsHttp = _http is null;
        var resolver = new BlossomResolver(http, _nostr, _fallbackServers);
        if (_serverListTimeout is TimeSpan t)
        {
            resolver = new BlossomResolver(http, _nostr, _fallbackServers)
            {
                ServerListTimeout = t,
            };
        }

        return new BlossomMediaClient(_key, http, ownsHttp, _nostr, _servers, resolver);
    }
}

/// <summary>The result of <see cref="BlossomMediaClient.UploadAsync(ReadOnlyMemory{byte}, string, bool, CancellationToken)"/>.</summary>
/// <param name="Sha256">Locally-computed sha256 hex of the uploaded bytes.</param>
/// <param name="PrimaryServer">URL of the first server (the primary upload target).</param>
/// <param name="PrimaryDescriptor">The descriptor returned by the primary server. Always present on success.</param>
/// <param name="Mirrors">Per-additional-server outcome — keyed by server URL. Empty when mirroring was disabled.</param>
public sealed record BlossomUploadResult(
    string Sha256,
    string PrimaryServer,
    BlobDescriptor PrimaryDescriptor,
    IReadOnlyDictionary<string, BlossomMirrorOutcome> Mirrors);

/// <summary>One server's mirror attempt. Exactly one of the two fields is non-null.</summary>
/// <param name="Descriptor">The descriptor the mirror server returned, on success.</param>
/// <param name="Failure">The exception thrown by the mirror attempt, on failure.</param>
public sealed record BlossomMirrorOutcome(
    BlobDescriptor? Descriptor,
    Exception? Failure)
{
    /// <summary>True when this mirror server accepted the blob.</summary>
    public bool IsSuccess => Descriptor is not null;
}
