# NostrNet.Blossom

[Blossom](https://github.com/hzrd149/blossom) (content-addressed media
on Nostr) for .NET. Implements every published Blossom Upgrade
Document (BUD-00 through BUD-12) plus the matching NIP-B7 event-side
plumbing, behind a one-call high-level façade and a smaller layer of
direct primitives for when you need them.

## Coverage

| BUD | Area | API |
|----|------|-----|
| 00 | Terminology — sha256-addressed blobs | n/a |
| 01 | `HEAD /<sha256>`, `GET /<sha256>`, ranges, Sunset | `BlossomClient.HeadBlobAsync`, `.GetBlobAsync`, `.GetBlobBytesAsync` |
| 02 | `PUT /upload` + `BlobDescriptor` | `BlossomClient.UploadAsync` + `BlobDescriptor` |
| 03 | NIP-B7 user server list (kind 10063) | `BlossomServerList`, `NostrClient.PublishBlossomServerListAsync` / `TryGetBlossomServerListAsync` |
| 04 | `PUT /mirror` | `BlossomClient.MirrorAsync` |
| 05 | `PUT /media` + `HEAD /media` | `BlossomClient.MediaUploadAsync` / `.MediaHeadAsync` |
| 06 | `HEAD /upload` preflight | `BlossomClient.UploadHeadAsync` |
| 07 | 402 Payment Required + `X-Lightning` / `X-Cashu` | `BlossomPaymentRequiredException` |
| 08 | Optional `nip94` field on descriptors | `BlobDescriptor.Nip94Tags` |
| 09 | `PUT /report` (NIP-56 kind-1984) | `BlossomClient.ReportAsync` |
| 10 | `blossom:` URI scheme | `BlossomUri.Parse` / `.ToString()`, `BlossomUri.ExtractSha256` |
| 11 | kind-24242 Nostr authorization tokens | `BlossomAuthToken.Create(...).BuildAndSign().ToAuthorizationHeader()` |
| 12 | `GET /list/<pubkey>`, `DELETE /<sha256>` | `BlossomClient.ListAsync`, `.DeleteBlobAsync` |

## Quickstart — `BlossomMediaClient`

One ergonomic entry point that bundles auth-token construction,
per-server HTTP, the multi-server resolver, and NIP-B7 server-list
management behind a builder + handful of high-level methods:

```csharp
using NostrNet.Blossom;
using NostrNet.Blossom.Blobs;
using NostrNet.Client;
using NostrNet.Keys;

using var http = new HttpClient();
using var key = PrivateKey.FromNsec("nsec1…");

// NostrClient is optional — only needed for NIP-B7 publish / discover.
await using var nostr = await NostrClient.Builder(key)
    .UseRelays("wss://relay.damus.io")
    .ConnectAsync();

using var media = BlossomMediaClient.Builder(key)
    .UseServers(
        "https://cdn.satellite.earth",     // primary upload target
        "https://blossom.primal.net")      // mirror target(s)
    .UseHttpClient(http)
    .UseNostrClient(nostr)
    .UseFallbackServers("https://blossom.nostr.build")  // optional
    .Build();

// Upload: computes sha256 locally, PUTs to the primary,
// then PUT /mirrors to the rest in parallel (BUD-04).
byte[] image = await File.ReadAllBytesAsync("photo.jpg");
var upload = await media.UploadAsync(image, "image/jpeg");
// upload.PrimaryDescriptor.Url is a CDN URL ready for a post.
// upload.Mirrors carries per-server outcomes (descriptor or thrown exception).

// Download: walks the user's own servers first, then BUD-03 author
// hints (kind-10063), then the fallback list.
var blob = await media.DownloadAsync(upload.Sha256);

// Or resolve a blossom: URI someone else shared
var fromUri = await media.DownloadAsync(BlossomUri.Parse("blossom:…"));

// List every blob across my servers, deduped by sha256
foreach (var d in await media.ListMyBlobsAsync())
    Console.WriteLine($"{d.Sha256} {d.Type} {d.Size} {d.Url}");

// Delete from every server I'm on
var outcomes = await media.DeleteAsync(upload.Sha256);
//   true  = deleted
//   false = server refused (404, 403, etc.)
//   null  = network error

// NIP-B7: publish my current server list so others can discover me
await media.PublishServerListAsync();
```

### Upload semantics

`UploadAsync` computes the sha256 of the input bytes locally and:

1. Mints a BUD-11 authorization event scoped to that hash with the
   `upload` verb.
2. Uploads to the **primary** server (first in your `UseServers`
   list). A primary failure throws — that's the canonical version.
3. If `mirrorToAllServers` is `true` (the default), fires off
   `PUT /mirror` against every other configured server **in
   parallel**, reusing the same auth token per BUD-04's example flow.
   Mirror failures are captured per-server in `Mirrors[server]`
   rather than thrown, so callers can render "uploaded to A, mirror
   to B failed" UX without losing the primary outcome.

### Download semantics

`DownloadAsync(sha256, authorHints?, expectedSize?, fileExtension?)`
delegates to the underlying `BlossomResolver`, which walks the
BUD-03 / BUD-10 candidate order:

1. The user's own configured servers (because that's where you
   actually uploaded the blob).
2. The author hints' kind-10063 server lists (one round-trip per
   author via the attached `NostrClient`).
3. The fallback server list configured via `UseFallbackServers(...)`.

The `BlossomUri` overload prepends the URI's `xs` hints to step 1
(spec says they take priority), then merges your own servers as
additional candidates.

For 404'd legacy URLs:

```csharp
var blob = await media.DownloadBrokenUrlAsync(
    "https://dead-cdn.example/b1674…f553.pdf",
    authorHints: new[] { eventAuthorPubkey });
```

uses BUD-03's "last 64-char hex run" rule to recover the sha256
from the URL and then walks the candidate list.

## Direct primitives

When the façade isn't the right level (custom flows, advanced auth,
testing), use the layers directly:

### Per-server HTTP — `BlossomClient`

```csharp
using var client = new BlossomClient(new Uri("https://cdn.example.com"), http);

// BUD-01
var head = await client.HeadBlobAsync(sha256);
byte[] body = await client.GetBlobBytesAsync(sha256, "pdf");

// BUD-02 with explicit auth
using var content = new ByteArrayContent(bytes);
content.Headers.ContentType = new MediaTypeHeaderValue("image/png");
var auth = BlossomAuthToken
    .Create(BlossomAuthVerb.Upload, "Upload Blob")
    .ScopeToBlob(sha256)
    .BuildAndSign(myKey);
BlobDescriptor desc = await client.UploadAsync(content, auth, expectedSha256: sha256);

// BUD-04
var mirrored = await client.MirrorAsync(desc.Url, auth);

// BUD-06 preflight
HttpStatusCode ok = await client.UploadHeadAsync(sha256, "image/png", contentLength: 184292);

// BUD-12
foreach (var d in await client.ListAsync(myPubkey, cursor: null, limit: 100, auth))
    Console.WriteLine(d.Url);

await client.DeleteBlobAsync(sha256, deleteAuth);
```

### Multi-server resolver — `BlossomResolver`

```csharp
using var resolver = new BlossomResolver(
    http,
    nostrClient: nostr,
    fallbackServers: new[] { "https://blossom.nostr.build" });

var blob = await resolver.ResolveAsync(
    sha256,
    serverHints: new[] { "cdn.example.com" },        // BUD-10 xs hints
    authorHints: new[] { authorPubkey },             // BUD-10 as hints
    expectedSize: 184292,                            // BUD-10 sz
    fileExtension: "pdf");

if (blob is not null)
    Console.WriteLine($"served by {blob.ServerUrl} ({blob.ContentType})");
```

### Auth tokens — `BlossomAuthToken`

```csharp
var ev = BlossomAuthToken
    .Create(BlossomAuthVerb.Upload, "Upload Blob")
    .ScopeToServer("cdn.example.com")
    .ScopeToBlob(sha256)
    .WithExpiration(DateTimeOffset.UtcNow.AddMinutes(5))
    .BuildAndSign(myKey);

string headerValue = BlossomAuthToken.ToAuthorizationHeader(ev);
// → "Nostr <base64url(event json)>"

// Round-trip:
NostrEvent? decoded = BlossomAuthToken.TryFromAuthorizationHeader(headerValue);
```

### Payment-required (BUD-07)

```csharp
try
{
    await media.UploadAsync(bytes, mime);
}
catch (BlossomPaymentRequiredException pq)
{
    foreach (var invoice in pq.LightningInvoices) ShowQr(invoice);
    foreach (var quote in pq.CashuQuotes) HandoffToCashuWallet(quote);
    // After settlement, retry the request with an X-Lightning / X-Cashu
    // request header containing the proof.
}
```

## Design notes

- **Source-generated JSON.** `BlobDescriptor` parsing/serialization
  uses `System.Text.Json` source generators (`BlossomJsonContext`) so
  the package stays AOT- and trim-clean per NostrNet's overall rules.
- **HttpClient is injected, never hidden.** Both `BlossomClient` and
  `BlossomResolver` accept an external `HttpClient` for connection-
  pool reuse, custom DelegatingHandlers, and test mocking via
  `HttpMessageHandler` fakes. `BlossomMediaClient.Builder.UseHttpClient`
  threads it down.
- **Auth tokens are kind-24242 Nostr events**, signed with the
  identity key. The client serializes them to base64url-no-padding
  and attaches them as `Authorization: Nostr …` automatically.
- **No live-server tests.** Every HTTP path is covered against an
  in-process `HttpMessageHandler` fake, so the suite stays offline
  and reproducible.

## Status

Pre-1.0 preview. Every BUD currently published is implemented;
58 unit tests in `NostrNet.Blossom.Tests`. APIs may move before 1.0.
