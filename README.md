# NostrNet

A cross-platform .NET 10 [Nostr](https://github.com/nostr-protocol/nostr)
client library. Pure managed code, single TFM (`net10.0`), AOT-compatible,
minimal dependencies.

```csharp
using NostrNet.Client;
using NostrNet.Keys;

using var key = PrivateKey.Generate();

await using var client = await NostrClient.Builder(key)
    .UseRelays("wss://relay.damus.io", "wss://nos.lol")
    .ConnectAsync();

await client.PostNoteAsync("Hello, Nostr!");
```

## Supported NIPs

| NIP | Feature |
|----|---------|
| [01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Core protocol — events, BIP-340 Schnorr signing, relay messaging (`EVENT`, `REQ`, `EOSE`, `OK`, `NOTICE`, `CLOSED`) |
| [04](https://github.com/nostr-protocol/nips/blob/master/04.md) | Legacy DM decoding (encryption marked `[Obsolete]` — prefer NIP-17) |
| [05](https://github.com/nostr-protocol/nips/blob/master/05.md) | DNS-based identifier verification |
| [11](https://github.com/nostr-protocol/nips/blob/master/11.md) | Relay information document |
| [13](https://github.com/nostr-protocol/nips/blob/master/13.md) | Proof of work (mining + validation) |
| [17](https://github.com/nostr-protocol/nips/blob/master/17.md) | Private direct messages |
| [19](https://github.com/nostr-protocol/nips/blob/master/19.md) | Bech32 entities (`npub`, `nsec`, `note`, `nprofile`, `nevent`, `naddr`) |
| [21](https://github.com/nostr-protocol/nips/blob/master/21.md) | `nostr:` URI scheme |
| [22](https://github.com/nostr-protocol/nips/blob/master/22.md) | Comments (kind 1111) with threaded uppercase/lowercase root and parent tags |
| [23](https://github.com/nostr-protocol/nips/blob/master/23.md) | Long-form markdown articles & drafts (kinds 30023 / 30024) |
| [51](https://github.com/nostr-protocol/nips/blob/master/51.md) | Lists & sets (mute lists, bookmarks, follow sets, …) with public + NIP-44 self-encrypted private items |
| [65](https://github.com/nostr-protocol/nips/blob/master/65.md) | Relay list metadata (kind 10002 read/write relay advertisements) |
| [B0](https://github.com/nostr-protocol/nips/blob/master/B0.md) | Web bookmarks (kind 39701; parameterized replaceable by URL) |
| [42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Client-relay AUTH (challenge capture + auth event builder + send/await OK) |
| [44](https://github.com/nostr-protocol/nips/blob/master/44.md) | v2 encrypted payloads (ChaCha20 + HMAC-SHA256 + HKDF) |
| [59](https://github.com/nostr-protocol/nips/blob/master/59.md) | Gift wrap |

Tested against the official BIP-340, BIP-173, RFC 8439, NIP-44, and Galaxoid
Labs Swift Nostr interop vectors — **300+ tests, zero warnings.**

## Install

> _Not yet on NuGet._ Requires the **.NET 10 SDK**. Two ways to consume it
> from your own app:

### Option A — Project reference (active development)

Best when you want to step into NostrNet's source from your debugger and
edit it locally.

```sh
# 1. Clone NostrNet alongside your app
git clone <repo> NostrNet

# 2. From your app's solution folder, reference NostrNet.Client
dotnet add YourApp.csproj reference ../NostrNet/src/NostrNet.Client/NostrNet.Client.csproj
```

`NostrNet.Client` brings in `NostrNet.Core`, `NostrNet.Crypto`, and
`NostrNet.Relay` transitively — most apps need only that one reference. Add
the others (e.g. `NostrNet.Relay` for direct `RelayPool` / NIP-05 use)
only if you call into them directly.

In Visual Studio / Rider: **Add → Existing Project** for the NostrNet
csprojs you want in Solution Explorer, then **Add → Project Reference**
from your app to `NostrNet.Client`.

### Option B — Local NuGet feed (pinned consumption)

Best for CI, multiple consumers, or treating NostrNet as a versioned
dependency.

```sh
# 1. Build all four packages into a local folder
dotnet pack src/NostrNet.Core   -c Release -o ./local-feed
dotnet pack src/NostrNet.Crypto -c Release -o ./local-feed
dotnet pack src/NostrNet.Relay  -c Release -o ./local-feed
dotnet pack src/NostrNet.Client -c Release -o ./local-feed
```

Add a `nuget.config` at the root of your app's solution (next to the `.sln`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
    <add key="NostrNet-Local" value="/abs/path/to/NostrNet/local-feed" />
  </packageSources>
</configuration>
```

Then install like any NuGet package:

```sh
dotnet add YourApp.csproj package NostrNet.Client --version 1.0.0
```

Bump `<Version>` in `src/Directory.Build.props` and re-run `dotnet pack`
when you release a new build; consumers update with `dotnet restore --force`.

### Target framework compatibility

NostrNet targets **`net10.0`**. Your app's TFM must be `net10.0` or higher
to reference it (`net10.0-windows10.0.19041.0` for WinUI 3 / Windows App
SDK, plain `net10.0` for console / ASP.NET, `net10.0-android` /
`net10.0-ios` for MAUI, etc.). Check your app's `.csproj`:

```xml
<TargetFramework>net10.0</TargetFramework>
```

If you're stuck on .NET 8 / 9, NostrNet doesn't currently multi-target —
you'd need to back-port (mostly C# 14 syntax → C# 12 equivalents and a few
BCL polyfills).

### Using with Godot

NostrNet works in Godot 4.x C# projects with no special setup. On desktop
platforms (Windows / macOS / Linux) the integration above (project
reference or local NuGet feed) applies unchanged.

Things to be aware of:

**TFM.** Godot 4.x defaults to `net8.0`. Bump your project to `net10.0`:

```xml
<TargetFramework>net10.0</TargetFramework>
```

This requires Godot 4.5+ — earlier versions pin you to older .NET runtimes.

**Mobile (iOS / Android).** NostrNet is AOT-safe so the library won't break
Godot's mobile AOT pipeline. If a stripped build throws
`MissingMethodException`, add NostrNet assemblies to your trim/AOT
exclusion list.

**Web (HTML5 / WASM).** Browser .NET runtimes have intermittent support for
`HKDF` and some `System.Security.Cryptography` APIs that NIP-44 / NIP-17
depend on. Test those specifically on the WASM export before committing —
NIP-44 will either work fully or fail at the HKDF call.

**Threading.** Godot installs its own `SynchronizationContext` on the main
thread, so `await` inside `_Ready()` / `_Process()` resumes on the main
thread — you can touch nodes directly after the await:

```csharp
using Godot;
using NostrNet.Client;
using NostrNet.Keys;

public partial class NostrNode : Node
{
    private NostrClient? _client;
    private PrivateKey? _key;

    public override async void _Ready()
    {
        _key = PrivateKey.Generate();
        _client = await NostrClient.Builder(_key)
            .UseRelays("wss://relay.damus.io")
            .ConnectAsync();

        await foreach (var received in _client.SubscribeNotesAsync(limit: 20))
        {
            // Back on the main thread — node access is safe.
            GD.Print($"[{received.Relay.Host}] {received.Event.Content}");
        }
    }

    public override void _ExitTree()
    {
        _key?.Dispose();
        _client?.DisposeAsync().AsTask().Wait();
    }
}
```

For work started on a background thread (e.g. NIP-13 mining), use
`CallDeferred` to marshal scene access back to the main thread:

```csharp
_ = Task.Run(() =>
{
    var mined = ProofOfWork.Mine(template, targetDifficulty: 20, ct);
    var signed = mined.Sign(_key);
    CallDeferred(MethodName.OnMined, signed.Id.ToHex());
});

private void OnMined(string idHex) => _label.Text = $"mined: {idHex}";
```

(Same `CallDeferred` pattern WPF/WinUI uses with `Dispatcher.Invoke`. See
the "Threading model" section below for the general rules.)

### Building from source

```sh
git clone <repo>
cd NostrNet
dotnet build
dotnet test
```

## Project layout

| Package | Responsibility |
|---------|---------------|
| `NostrNet.Core`   | Keys, events, canonical serialization, NIP-19 bech32, `Profile`, internal secp256k1 wrapper |
| `NostrNet.Crypto` | ChaCha20, NIP-44 v2, NIP-17/59 gift wrap, NIP-51 lists |
| `NostrNet.Relay`  | WebSocket client, `RelayPool`, `Filter`, NIP-11 fetch, NIP-05 verify |
| `NostrNet.Client` | High-level `NostrClient` façade |

For most apps, reference only `NostrNet.Client` — it pulls in everything you
need transitively.

---

## Quickstart

### Connect with or without a key

The client can be constructed with a signing key (full feature set) or
without one (read-only — subscribe, fetch relay info, publish pre-signed
events). A key can also be attached later without rebuilding the
connection.

```csharp
// Full client: post / DM / subscribe to own DMs all available
await using var client = await NostrClient.Builder(myKey)
    .UseRelays("wss://relay.damus.io")
    .ConnectAsync();

// Read-only client: subscribe to public events while the user hasn't
// imported a key yet
await using var anon = await NostrClient.Builder()
    .UseRelays("wss://relay.damus.io")
    .ConnectAsync();

await foreach (var received in anon.SubscribeNotesAsync(limit: 50))
    Console.WriteLine(received.Event.Content);

// Later — user creates / imports a key. Attach it without reconnecting:
var newKey = PrivateKey.Generate();
anon.SetKey(newKey);
await anon.PostNoteAsync("now I'm signed in");

// Sign out (without disposing the client):
anon.ClearKey();
```

Helpers that need to sign or decrypt (`PostNoteAsync`,
`SendDirectMessageAsync`, `SubscribeDirectMessagesAsync`) throw
`InvalidOperationException` when called on a key-less client — guard with
`client.HasKey` if you're unsure of state.

### Generate or load a key

```csharp
using NostrNet.Keys;

// Fresh CSPRNG-generated key
using var key = PrivateKey.Generate();

// Or load an existing one
using var key = PrivateKey.FromNsec("nsec1...");
using var key = PrivateKey.FromHex("1fb9778c...");

Console.WriteLine(key.PublicKey.ToNpub());   // npub1...
Console.WriteLine(key.PublicKey.ToHex());    // 32-byte hex
```

`PrivateKey` implements `IDisposable` and zeros its in-memory secret on
`Dispose`. `ToString()` returns a redacted placeholder; it will never leak
the secret in logs or stack traces. Use `ToHex()` / `ToNsec()` to obtain the
secret explicitly when you need it.

### Post a note

```csharp
using NostrNet.Client;

await using var client = await NostrClient.Builder(key)
    .UseRelays("wss://relay.damus.io", "wss://nos.lol")
    .ConnectAsync();

var results = await client.PostNoteAsync("hello nostr");
foreach (var (uri, result) in results)
    Console.WriteLine($"{uri}: {(result.Accepted ? "OK" : "REJECTED")} {result.Message}");
```

**Incoming events are verified automatically.** `RelayClient` checks the
event id (SHA-256 of canonical serialization) and the Schnorr signature
on every event it receives from a relay; events that fail either check
are silently dropped before they reach a subscriber. You don't need to
call `.Verify()` on events yielded from `SubscribeAsync`. (Events parsed
manually from JSON via `NostrEvent.FromJson` are not verified — call
`.Verify()` yourself in that case.)

### Subscribe to events

```csharp
using NostrNet.Relay;

var filter = new Filter
{
    Authors = [key.PublicKey.ToHex()],
    Kinds = [1],
    Since = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds(),
    Limit = 50,
};

await foreach (var received in client.SubscribeAsync([filter]))
{
    Console.WriteLine($"[{received.Relay.Host}] {received.Event.CreatedAt}  {received.Event.Content}");
}

// Convenience for the common case
await foreach (var received in client.SubscribeNotesAsync(
    authors: [key.PublicKey], limit: 50))
{
    Console.WriteLine(received.Event.Content);
}
```

Each yielded item is a `ReceivedEvent(NostrEvent Event, Uri Relay)` —
**the relay that delivered this occurrence is exposed**. The library
intentionally **does not store or dedup events**; that's your call as the
consumer. When multiple relays carry the same event, you'll see it once
per relay, each with a different `Relay`. For a UI feed that should show
each event once, dedup explicitly:

```csharp
var seen = new HashSet<NostrNet.Events.EventId>();
await foreach (var received in client.SubscribeNotesAsync(limit: 100))
{
    if (!seen.Add(received.Event.Id)) continue;   // already shown
    feedListBox.Items.Add(received.Event.Content);
}
```

For relay-coverage analytics, **don't** dedup — track which relays carry
which event ids.

Subscriptions are `IAsyncEnumerable<ReceivedEvent>` — they yield as events
arrive and complete when all relays close the subscription or the
`CancellationToken` fires.

### NIP-17 direct messages

```csharp
var bob = PublicKey.FromNpub("npub1...");

// Send
await client.SendDirectMessageAsync(bob, "hey bob");

// Receive — gift wraps are unwrapped automatically; `dm.Relay` tells you
// which relay carried this delivery (handy for multi-relay setups).
await foreach (var dm in client.SubscribeDirectMessagesAsync())
    Console.WriteLine($"[{dm.Relay?.Host}] {dm.Sender.ToNpub()}: {dm.Plaintext}");
```

Under the hood: `NostrNet.Crypto.Nip17.CreateDirectMessage` builds a rumor
(kind 14) → seal (kind 13, signed by sender) → gift wrap (kind 1059, signed
by an ephemeral key, addressed by `p` tag). Recipient verifies the seal's
signature and the rumor's pubkey before yielding the plaintext.

---

## Building events manually

```csharp
using NostrNet.Events;

var unsigned = new UnsignedEvent
{
    PubKey = key.PublicKey,
    CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    Kind = 1,
    Tags = new IReadOnlyList<string>[]
    {
        new[] { "t", "nostr" },
        new[] { "client", "my-app" },
    },
    Content = "manually constructed",
};

NostrEvent signed = unsigned.Sign(key);
Console.WriteLine(signed.Id.ToHex());

// Verify a received event
if (signed.Verify())
    Console.WriteLine("signature OK");

// Wire JSON
string json = signed.ToJson();
var parsed = NostrEvent.FromJson(json);
```

---

## Working with tags

Build tags with the `Tag` factory and query them with extensions on the
event's tag list:

```csharp
using NostrNet.Events;

// Building
var note = new UnsignedEvent
{
    PubKey = key.PublicKey,
    CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    Kind = 1,
    Tags = new[]
    {
        Tag.P(recipient),                          // ["p", "<hex>"]
        Tag.E(parentId, "wss://relay.example.com", "reply"),  // NIP-10 reply marker
        Tag.T("nostr"),
        Tag.A(30023, articleAuthor, "my-slug"),    // addressable coordinate
    },
    Content = "...",
}.Sign(key);

// Querying
foreach (var p in ev.Tags.Pubkeys())              // every "p" tag as PublicKey
    Console.WriteLine(p.ToNpub());

foreach (var id in ev.Tags.EventIds())            // every "e" tag as EventId
    Console.WriteLine(id.ToHex());

string? articleSlug = ev.Tags.Identifier();        // the "d" tag's value
string? title = ev.Tags.FirstValue("title");
IEnumerable<string> hashtags = ev.Tags.Hashtags();
IEnumerable<string> mentioned = ev.Tags.AllValues("p");
bool hasReply = ev.Tags.Has("e");

// Drop down to raw rows when you need the third/fourth column (relay, marker):
foreach (var eTag in ev.Tags.Named("e"))
{
    var id = eTag[1];
    var relay = eTag.Count > 2 ? eTag[2] : null;
    var marker = eTag.Count > 3 ? eTag[3] : null;
}
```

The `Tag.*` factories never produce a tag with the wrong shape; the query
extensions silently skip malformed rows so you never need defensive
length-checking on the happy path.

---

## NIP-19 bech32 entities

```csharp
using NostrNet.Nip19;
using NostrNet.Events;
using NostrNet.Keys;

// Simple identifiers — direct on the typed value
var npub = key.PublicKey.ToNpub();
var note = signed.Id.ToNote();
var pub = PublicKey.FromNpub("npub1...");
var id = EventId.FromNote("note1...");

// TLV entities
var nprofile = new NprofileEntity
{
    PubKey = pub,
    Relays = new[] { "wss://relay.example.com" },
}.Encode();

var naddr = new NaddrEntity
{
    PubKey = pub,
    Kind = 30023,            // long-form article
    Identifier = "my-slug",
    Relays = new[] { "wss://relay.example.com" },
}.Encode();

// Parse anything (npub/note/nprofile/nevent/naddr)
var entity = Nip19.Parse("nevent1qqs...");
switch (entity)
{
    case NpubEntity n:     Console.WriteLine(n.PubKey.ToHex()); break;
    case NeventEntity e:   Console.WriteLine($"{e.Id} from {e.Relays.Count} relays"); break;
    case NaddrEntity a:    Console.WriteLine($"kind {a.Kind} d={a.Identifier}"); break;
}

// nostr: URI scheme
var uri = Nip21.ToUri(entity);                   // "nostr:nevent1qqs..."
var parsed = Nip21.Parse("nostr:npub1...");
```

`nsec` is deliberately NOT decoded by `Nip19.Parse` — callers must use
`PrivateKey.FromNsec` explicitly so secret lifetime stays visible.

---

## NIP-22 comments

Kind 1111 comments for threading on **anything except kind:1 notes** (use
NIP-10 reply markers for those). Comments can scope to:

- a specific event (e.g. a long-form article)
- an addressable / parameterized-replaceable event (kind 30000+)
- an external resource per NIP-73 (URL, hashtag, geohash, …)

The thread structure uses paired tag sets: **uppercase** (`E`/`A`/`I` + `K` + `P`)
identifies the original target; **lowercase** (`e`/`a`/`i` + `k` + `p`)
identifies the direct parent. For top-level comments they reference the
same target.

```csharp
using NostrNet.Comments;

// Top-level comment on someone's article
var top = Comment.ReplyTo(articleEvent)
    .WithContent("nice post!")
    .Sign(myKey);

// Nested reply — the builder inherits the root scope from the parent comment
var nested = Comment.ReplyTo(top)
    .WithContent("agreed")
    .Mention(otherPubkey)        // adds an extra "p" tag
    .Quote(someEventId)          // adds a NIP-21 "q" citation
    .Sign(myKey);

// Comment on an addressable (kind 30023 article) without holding the event
var byCoord = Comment.Create()
    .OnAddressable(kind: 30023, author: articleAuthorPub, identifier: "my-slug")
    .WithContent("found this via search")
    .Sign(myKey);

// Comment on an external URL (NIP-73)
var external = Comment.Create()
    .OnExternal("https://example.com/article", kind: "url")
    .WithContent("commenting on a blog post")
    .Sign(myKey);

// Reading
var parsed = Comment.FromEvent(receivedComment);
Console.WriteLine(parsed.Content);
Console.WriteLine(parsed.IsTopLevel ? "(top)" : $"(reply to {parsed.Parent})");

switch (parsed.Root)
{
    case EventCommentTarget e:
        Console.WriteLine($"thread root: event {e.Id}");
        break;
    case AddressableCommentTarget a:
        Console.WriteLine($"thread root: {a.ToCoordinate()}");
        break;
    case ExternalCommentTarget x:
        Console.WriteLine($"thread root: external {x.Identifier} ({x.Kind})");
        break;
}
```

**Important:** `ReplyTo(kind:1 note)` throws — NIP-22 explicitly defers to
NIP-10 for note threading. `Comment.TryFromEvent(...)` is the non-throwing
variant.

---

## NIP-23 long-form articles

Markdown articles (kind 30023) and drafts (kind 30024). Both are
parameterized-replaceable, keyed by a stable `d`-tag identifier (slug) —
republishing with the same slug replaces the previous version.

```csharp
using NostrNet.Articles;

// Build & publish
var ev = Article.Create("my-first-article", File.ReadAllText("post.md"))
    .WithTitle("My First Article")
    .WithSummary("An introduction to my new blog")
    .WithImage("https://example.com/cover.png")
    .WithPublishedAt(DateTimeOffset.UtcNow)
    .WithHashtags("intro", "nostr")
    .Sign(authorKey);

await client.PublishAsync(ev);

// As a draft (kind 30024) — same shape, different kind
var draft = Article.Create("my-first-article", workInProgress)
    .AsDraft()
    .Sign(authorKey);

// Read a received article event
var article = Article.FromEvent(receivedEvent);
Console.WriteLine($"{article.Title} by {article.Author.ToNpub()}");
Console.WriteLine(article.Markdown);

if (article.PublishedAt is DateTimeOffset pub)
    Console.WriteLine($"originally published {pub}");
else
    Console.WriteLine($"created {article.CreatedAt}");

// Share via a nostr:naddr1… URI
var naddr = article.ToNaddr(relays: new[] { "wss://relay.example.com" });
Console.WriteLine($"link: nostr:{naddr.Encode()}");
```

`Article.TryFromEvent(ev, out var article)` is the non-throwing variant
for events that may or may not be NIP-23. Articles missing the required
`d` tag are rejected.

---

## NIP-B0 web bookmarks

Editable per-URL web bookmarks (kind 39701). The bookmark is keyed by its
URL with the scheme stripped, so the same page over `http://` and
`https://` collapses to a single addressable bookmark.

```csharp
using NostrNet.Bookmarks;

// Build & publish
var ev = WebBookmark.Create("https://alice.blog/marvelous-post")
    .WithTitle("Alice's marvelous post")
    .WithDescription("a great insight into nostr lists")
    .WithHashtags("nostr", "long-form")
    .WithPublishedAt(DateTimeOffset.UtcNow)
    .Sign(key);

await client.PublishAsync(ev);

// Parse a received bookmark
var bm = WebBookmark.FromEvent(receivedEvent);
Console.WriteLine($"{bm.Title}  ({bm.ToUrl()})");
Console.WriteLine(bm.Description);
foreach (var tag in bm.Hashtags) Console.Write($"#{tag} ");

// Share as a nostr:naddr1... URI
var naddr = bm.ToNaddr(relays: new[] { "wss://relay.example.com" });
Console.WriteLine($"link: nostr:{naddr.Encode()}");
```

`Create` strips `https://`, `http://`, or leading `//` from the URL so
revisions of the same bookmark land at the same `d`-tag value.
`bookmark.ToUrl()` adds the scheme back (defaults to `https`, or pass
`"http"` for HTTP-only sources).

---

## NIP-51 lists

Build mute lists, bookmarks, pinned notes, follow sets, etc. — with both
public items (in tags) and private items (NIP-44 self-encrypted in the
event's `content`).

```csharp
using NostrNet.Lists;

// Mute list (replaceable, one per author)
var muteEvent = NostrList.Create(Nip51Kinds.MuteList)
    .AddPubkey(spammer)                       // public — anyone can see
    .AddHashtag("crypto-scam")                // public
    .AddPrivatePubkey(secretBlock)            // encrypted in content
    .AddPrivateWord("personal-trigger-word")  // encrypted in content
    .Sign(key);

await client.PublishAsync(muteEvent);

// Parameterized set (multiple per author, distinguished by identifier)
var friends = NostrList.Create(Nip51Kinds.FollowSets, identifier: "close-friends")
    .WithTitle("Close Friends")
    .WithDescription("people I actually talk to")
    .WithImage("https://example.com/friends.png")
    .AddPubkey(alicePub)
    .AddPubkey(bobPub)
    .Sign(key);

// Reading
var list = NostrList.FromEvent(receivedEvent);          // public items only
var fullList = NostrList.FromEvent(receivedEvent, key); // public + decrypted private

foreach (var muted in fullList.Pubkeys)  Console.WriteLine(muted.ToNpub());
foreach (var tag in fullList.Hashtags)   Console.WriteLine($"#{tag}");
foreach (var word in fullList.Words)     Console.WriteLine($"muted word: {word}");

if (list.HasEncryptedContent && !fullList.PrivateItems.Any())
    Console.WriteLine("(legacy NIP-04 encrypted content — not yet supported)");
```

`Nip51Kinds` exposes constants for every documented kind (`MuteList`,
`PinnedNotes`, `Bookmarks`, `Communities`, `Interests`, `DmRelays`,
`GoodWikiAuthors`, `FollowSets`, `RelaySets`, `BookmarkSets`,
`ArticleCurationSets`, `KindMuteSets`, `EmojiSets`, `StarterPacks`, …).
Parameterized-set kinds (≥ 30000) require an identifier;
`Nip51Kinds.IsParameterizedSet(kind)` checks the range.

Encryption uses **NIP-44 self-encryption** (modern, what current clients
write). Lists encrypted by older NIP-04 clients leave `PrivateItems` empty;
public items remain readable. NIP-04 backward-decoding is on the roadmap.

---

## NIP-65 relay list metadata

A user advertises their preferred read/write relays via a single
replaceable kind-10002 event. Other clients fetch this to know where to
publish events that should reach them, and where to look for events they
authored.

```csharp
using NostrNet.RelayList;

// Build and publish
var ev = RelayListMetadata.Create()
    .AddRelay("wss://relay.damus.io")          // both read and write
    .AddReadRelay("wss://relay.nostr.band")    // read-only
    .AddWriteRelay("wss://nos.lol")            // write-only
    .Sign(key);

await client.PublishAsync(ev);

// Parse a received event
var list = RelayListMetadata.FromEvent(receivedEvent);
Console.WriteLine($"{list.Owner.ToNpub()} writes to: {string.Join(", ", list.WriteRelays)}");
Console.WriteLine($"{list.Owner.ToNpub()} reads from: {string.Join(", ", list.ReadRelays)}");

// Each entry carries the original URL + usage marker
foreach (var entry in list.Relays)
    Console.WriteLine($"{entry.Url} ({entry.Usage})");
```

`RelayListMetadata.TryFromEvent(ev, out var list)` is the non-throwing
variant for events that may or may not be NIP-65.

---

## NIP-42 relay AUTH

Some relays require NIP-42 authentication before they'll serve
subscriptions or accept publishes. **Auto-auth is on by default** — when
`NostrClient` is constructed with a key, every `AUTH` challenge is answered
in the background, and any publish or subscription rejected with
`auth-required` is transparently retried once AUTH succeeds. **You don't
need to write any retry code.**

```csharp
await using var client = await NostrClient.Builder(key)
    .UseRelays("wss://auth-required-relay.example.com")
    .ConnectAsync();

// Just publish. If the relay rejects with auth-required, the library
// waits for AUTH and resends. You only see the final result.
var results = await client.PostNoteAsync("hello");

// Same for subscriptions — if a relay closes the sub with auth-required,
// the library re-subscribes after AUTH. The consumer never sees the gap.
await foreach (var received in client.SubscribeNotesAsync(limit: 50))
    Console.WriteLine(received.Event.Content);
```

Auto-auth follows the key. If you call `client.SetKey(...)` later (the
user signed in after browsing anonymously), auto-auth activates with the
new key. `client.ClearKey()` disables it. You can also toggle at runtime:
`client.AutoAuth = false;`.

**Opt out** if you want explicit control — e.g., to prompt the user
before AUTHing, log every AUTH attempt, or skip AUTH on specific relays:

```csharp
await using var client = await NostrClient.Builder(key)
    .UseRelays(...)
    .WithAutoAuth(false)
    .ConnectAsync();

// Manual flow — surface the rejection, AUTH explicitly, retry yourself
var results = await client.PostNoteAsync("hello");
if (results.Values.Any(r => !r.Accepted && r.Message.StartsWith("auth-required")))
{
    var authResults = await client.AuthenticateAllAsync();
    foreach (var (uri, r) in authResults)
        Console.WriteLine($"{uri}: AUTH {(r.Accepted ? "OK" : r.Message)}");

    results = await client.PostNoteAsync("hello");
}
```

### How auto-retry works

- The receive loop captures each `["AUTH", "<challenge>"]` into per-relay
  state (`RelayClient.LatestAuthChallenge`).
- When auto-auth is on and a key is set, `RelayClient` fires a background
  `Task.Run` that signs the kind-22242 event and sends `["AUTH", <event>]`.
- **Publishes:** if `PublishAsync` gets a rejection whose message starts
  with `auth-required`, it awaits the in-flight AUTH (or triggers one if a
  challenge has just arrived) and resends the event once. Only the result
  of the second attempt is surfaced.
- **Subscriptions:** each per-relay pump task in `RelayPool` watches for
  `CLOSED auth-required`. When it sees one (with auto-auth on), it waits
  for AUTH then transparently re-issues the `REQ` — the consumer's
  `await foreach` keeps yielding events without breaking.
- Retry is **capped at one attempt per operation** so an unresolvable
  AUTH (key not on the relay's allow-list, expired payment, etc.) doesn't
  loop forever. The second rejection surfaces to the caller normally.

### Single-relay control

Drop down to `RelayClient` (via the `IRelayClient` returned by
`RelayPool` or constructed manually) when you need per-relay visibility:

```csharp
string? challenge = relayClient.LatestAuthChallenge;
PublishResult r = await relayClient.AuthenticateAsync(myKey);
await relayClient.WaitForAuthAsync();   // block until current auto-auth finishes
```

For remote-signer flows (where signing happens elsewhere), use
`NostrNet.Auth.Nip42.BuildAuthEvent(key, relayUri, challenge)` directly —
returns the signed kind-22242 event ready to wrap in `["AUTH", ...]`.

---

## NIP-05 verification

Given a kind-0 metadata event, verify the user's claimed identifier:

```csharp
using NostrNet.Profiles;
using NostrNet.Relay;

// Parse kind-0 content into a typed Profile
var profile = Profile.FromEvent(kind0Event);
Console.WriteLine($"{profile.Name} ({profile.Nip05}) — {profile.About}");
Console.WriteLine($"picture: {profile.Picture}");
Console.WriteLine($"lightning: {profile.Lud16}");

// Verify the nip05 field
var r = await Nip05.VerifyAsync(profile);
if (r.IsVerified)
    Console.WriteLine($"✓ {r.Identifier} verified, suggested relays: {string.Join(", ", r.Relays)}");
else
    Console.WriteLine($"✗ {r.FailureReason}");
```

Other entry points:

```csharp
// Verify directly without parsing a Profile
await Nip05.VerifyAsync(kind0Event);

// Verify a known pubkey ↔ identifier mapping
await Nip05.VerifyAsync(pubkey, "bob@example.com");

// Just fetch the document
Nip05Document doc = await Nip05.FetchAsync("bob@example.com");
```

The shared `HttpClient` has auto-redirect **disabled** per the NIP-05
"fetchers MUST ignore HTTP redirects" rule. Pass your own `HttpClient` for
custom timeouts or proxies.

---

## NIP-11 relay info

```csharp
using NostrNet.Relay;

var info = await RelayInformation.FetchAsync(new Uri("wss://relay.damus.io"));

Console.WriteLine($"{info.Name} ({info.Software} {info.Version})");
Console.WriteLine($"limits: max_message={info.Limitation?.MaxMessageLength}, " +
                  $"max_subs={info.Limitation?.MaxSubscriptions}");

if (info.SupportsNip(44))
    Console.WriteLine("modern DMs OK");

if (info.Limitation?.AuthRequired == true)
    Console.WriteLine("relay requires NIP-42 AUTH");
```

`RelayInformation` is a strongly-typed record covering every documented
NIP-11 field including limits and fees. Use `RelayInformation.Parse(string)`
if you already have the JSON in hand.

---

## NIP-13 proof of work

```csharp
using NostrNet.Events;

var template = new UnsignedEvent
{
    PubKey = key.PublicKey,
    CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    Kind = 1,
    Tags = Array.Empty<IReadOnlyList<string>>(),
    Content = "mine me",
};

// Mine until the id has 20 leading zero bits. Pass a CancellationToken
// to enforce a time budget.
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
var mined = ProofOfWork.Mine(template, targetDifficulty: 20, cts.Token);
var signed = mined.Sign(key);

Console.WriteLine($"id={signed.Id} difficulty={ProofOfWork.Difficulty(signed)}");

// Validation
bool ok = ProofOfWork.MeetsCommittedDifficulty(signed);
```

`MeetsCommittedDifficulty` returns `true` for events with no nonce tag (no
PoW is claimed). For a minimum-difficulty policy regardless of what the
event claims, compare `ProofOfWork.Difficulty(ev)` directly.

---

## Lower-level access

### Direct relay control

`NostrClient` is built on `RelayPool`, which is built on `RelayClient`. Drop
down a layer when you need per-relay control:

```csharp
await using var pool = new RelayPool();
var failures = await pool.ConnectAsync(new[]
{
    new Uri("wss://relay.damus.io"),
    new Uri("wss://nos.lol"),
});
foreach (var (uri, error) in failures)
    Console.WriteLine($"{uri} failed: {error.Message}");

var results = await pool.PublishAsync(signedEvent);

await foreach (var msg in pool.SubscribeAsync("sub1", new[] { filter }))
{
    switch (msg)
    {
        case SubscriptionEventReceived e:        /* event */ break;
        case SubscriptionEndOfStoredEvents:      /* all stored delivered */ break;
        case SubscriptionClosed c:               /* server closed */ break;
    }
}
```

### Raw NIP-44 encryption

```csharp
using NostrNet.Crypto;

string ciphertext = Nip44.Encrypt("hello", senderKey, recipientPubKey);
string plaintext = Nip44.Decrypt(ciphertext, recipientKey, senderPubKey);

// Cacheable conversation key (HKDF-Extract over ECDH x-coord)
Span<byte> ck = stackalloc byte[32];
Nip44.DeriveConversationKey(senderKey, recipientPubKey, ck);
```

---

## Sample CLI

A working command-line app lives in `samples/NostrNet.Sample.Console`.

```sh
# Generate a fresh keypair
dotnet run --project samples/NostrNet.Sample.Console -- gen

# Post a note
dotnet run --project samples/NostrNet.Sample.Console -- post nsec1... "hello"

# Send a NIP-17 DM
dotnet run --project samples/NostrNet.Sample.Console -- dm nsec1... npub1... "hey"

# Listen to your own feed for 30 seconds
dotnet run --project samples/NostrNet.Sample.Console -- feed nsec1... --seconds 30

# Mine a 20-bit PoW note and publish
dotnet run --project samples/NostrNet.Sample.Console -- mine nsec1... "PoW message" 20

# Fetch a relay's NIP-11 document
dotnet run --project samples/NostrNet.Sample.Console -- info wss://relay.damus.io

# Verify a NIP-05 identifier
dotnet run --project samples/NostrNet.Sample.Console -- verify npub1... bob@example.com
```

---

## Threading model

All I/O is async; the library never blocks the calling thread on a network
operation. `RelayClient` runs its send and receive loops on the thread pool
internally, so WebSocket traffic doesn't share a thread with your UI or
request handler.

### Async I/O is safe from any thread

`PublishAsync`, `SubscribeAsync`, `Nip05.VerifyAsync`,
`RelayInformation.FetchAsync`, and friends are all properly async — await
them from anywhere. Continuations marshal back to the caller's
`SynchronizationContext` by default, so on a UI thread you can touch UI
state directly after the await.

```csharp
private async void PostButton_Click(object sender, EventArgs e)
{
    var results = await client.PostNoteAsync(textBox.Text);
    statusLabel.Text = results.Values.Any(r => r.Accepted) ? "Posted" : "Rejected";
}
```

For pure background work (worker services, console apps), add
`.ConfigureAwait(false)` to keep continuations on the thread pool.

### Subscriptions: `await foreach` doesn't block the thread, but does park the method

`SubscribeAsync` returns `IAsyncEnumerable<ReceivedEvent>` and yields each
relay's delivery as it arrives. **The UI thread stays responsive during a
subscription** (the message pump keeps running between awaits), but **any
code after the `await foreach` won't run until the subscription ends** —
when all relays close it, your `CancellationToken` fires, or the stream
completes naturally.

```csharp
// Code after the loop is parked until the subscription ends.
async Task RunFeedAsync(CancellationToken ct)
{
    await foreach (var received in client.SubscribeNotesAsync(authors: [pub], cancellationToken: ct))
        feedListBox.Items.Add(received.Event.Content);

    statusLabel.Text = "Subscription closed";   // runs only after the loop ends
}
```

If you want other work to proceed *while* the subscription runs, fire it on
a separate task:

```csharp
private void Start_Click(object sender, EventArgs e)
{
    _ = ConsumeFeedAsync(_appCts.Token);   // fire-and-forget
    statusLabel.Text = "Listening...";     // runs immediately
}

private async Task ConsumeFeedAsync(CancellationToken ct)
{
    try
    {
        await foreach (var received in client.SubscribeNotesAsync(authors: [pub], cancellationToken: ct))
            feedListBox.Items.Add(received.Event.Content);
    }
    catch (OperationCanceledException) { /* clean shutdown */ }
}
```

For multi-consumer or producer/consumer scenarios, decouple via a
`Channel<T>`:

```csharp
var feed = Channel.CreateUnbounded<ReceivedEvent>();

_ = Task.Run(async () =>
{
    await foreach (var received in client.SubscribeAsync(filters, ct).ConfigureAwait(false))
        await feed.Writer.WriteAsync(received, ct).ConfigureAwait(false);
}, ct);

// One or more consumers, possibly on different threads
await foreach (var received in feed.Reader.ReadAllAsync(ct))
    ProcessEvent(received.Event, received.Relay);
```

### CPU-bound work: wrap in `Task.Run`

`ProofOfWork.Mine` is synchronous and CPU-bound — it will block the calling
thread until it finds a satisfying nonce. Wrap it in `Task.Run` for UI apps
or anywhere blocking is unacceptable:

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

NostrEvent signed = await Task.Run(() =>
{
    var mined = ProofOfWork.Mine(template, targetDifficulty: 20, cts.Token);
    return mined.Sign(key);
}, cts.Token);

await client.PublishAsync(signed);
```

The library deliberately ships only the synchronous `Mine` — wrapping it in
a `MineAsync` would just be `Task.Run(() => Mine(...))`, which the caller
can do better themselves (they know their threading model). See [Stephen
Toub on async wrappers over sync methods](https://devblogs.microsoft.com/pfxteam/should-i-expose-asynchronous-wrappers-for-synchronous-methods/).

NIP-44 encrypt/decrypt is synchronous too but typically fast (microseconds
for small messages); only wrap in `Task.Run` if you're encrypting maximum-size
payloads (64 KiB) on a UI thread and care about smoothness.

### Concurrent operations on a single client are safe

You can have many concurrent subscriptions and in-flight publishes on the
same `RelayClient` or `RelayPool`. Internal state uses `ConcurrentDictionary`
and the send queue is an `UnboundedChannel<string>` configured for multiple
writers. The same `NostrClient` instance is shared across your app — don't
create one per call.

### Cancellation

Every async method takes a `CancellationToken`. Wire one app-scoped
`CancellationTokenSource` to your shutdown signal and pass it everywhere:

```csharp
using var appCts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { appCts.Cancel(); e.Cancel = true; };

await using var client = await NostrClient.Builder(key)
    .UseRelays("wss://relay.damus.io")
    .ConnectAsync(appCts.Token);

// ... run subscriptions / publishes / mining with appCts.Token ...
```

`await using var client` ensures the receive/send loops are torn down and
the WebSocket is closed cleanly. Pending publishes fail with
`OperationCanceledException`; subscription enumerators complete; `Mine`
throws on its next iteration check.

## Design notes

- **AOT-safe.** All JSON uses `System.Text.Json` source generators
  (`JsonSerializerContext`). No reflection-based serialization. Trim and AOT
  analyzers are on; AOT/trim warnings fail the build.
- **Strong types over strings.** `PublicKey`, `PrivateKey`, `EventId`, and
  `Signature` are distinct types. The compiler refuses to swap them. An
  `UnsignedEvent` cannot be published — only signing produces a `NostrEvent`,
  which is what `RelayClient.PublishAsync` accepts.
- **Span-based crypto, no ambient state.** No DI required. No static
  registration. Construct what you need, pass it where needed.
- **Memory hygiene.** `PrivateKey` zeros its buffer on `Dispose`. All
  intermediate buffers in NIP-44 are zeroed. `ToString()` on `PrivateKey`
  returns `"PrivateKey(****)"`.
- **Async-first.** Everything I/O-bound is `Task` / `ValueTask` with optional
  `CancellationToken`. Event streams are `IAsyncEnumerable<T>`.

## Dependencies

Only one external NuGet package: **`NBitcoin.Secp256k1`** — a pure managed
implementation of secp256k1 (BIP-340 Schnorr, ECDH). Wrapped behind an
`internal` seam in `NostrNet.Core/Secp256k1/` so the choice of curve library
is a single-file swap. Everything else uses the BCL: `System.Net.WebSockets`,
`System.Net.Http`, `System.Security.Cryptography` (HKDF, HMAC-SHA256,
SHA-256, AES, CSPRNG), `System.Text.Json`.

## License

MIT.
