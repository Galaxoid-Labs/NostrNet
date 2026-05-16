---
name: nostrnet
description: Build .NET 10 apps against the NostrNet library — the high-level NostrClient façade (post / DM / subscribe / search), per-relay connection observation with auto-reconnect, local event store with reactive typed Observe<T>, NostrMarmotClient for MLS group chat (Marmot protocol), and BlossomMediaClient for content-addressed media. Use whenever the user writes C#/.NET code that touches Nostr or NIPs (NIP-01, NIP-17 DMs, NIP-44 v2 crypto, NIP-19 bech32, NIP-23 articles, NIP-65 relay lists, NIP-98 HTTP auth, etc.), Marmot MLS groups (kinds 30443 / 444 / 445, KeyPackages, Welcomes), Blossom blobs (BUD-01 through BUD-12, sha256-addressed media), relay status / reconnect logic, or asks "how do I use NostrNet" / "post a note from C#" / "MLS chat in .NET" / "build a Nostr app with NostrNet" / "show relay connection status" / "upload a blob with Blossom".
---

# NostrNet — app developer guide

NostrNet is a cross-platform .NET 10 Nostr library. This skill is for **app
authors consuming the library**, not for contributors to NostrNet itself.
The internals are intentionally kept off this surface; everything below
goes through the public, AOT-compatible façades.

When this skill applies: someone is writing a console / WinUI / MAUI /
Godot / ASP.NET app and wants to talk Nostr from it. They've added (or
are about to add) `NostrNet.Client` to their `.csproj` and need to know
how to drive it.

## Picking the right package

Most apps need only one package — the rest are opt-in.

| Goal | Package |
|---|---|
| Anything (post, subscribe, DMs, articles, reactions, etc.) | `NostrNet.Client` — pulls Core + Crypto + Relay transitively |
| Marmot MLS group chat (1:1 + N-party) | `NostrNet.Client` **+** `NostrNet.Marmot` **+** `NostrNet.Marmot.Mls.Native` |
| Blossom content-addressed media | `NostrNet.Client` **+** `NostrNet.Blossom` |

```sh
dotnet add package NostrNet.Client --prerelease
# optional:
dotnet add package NostrNet.Marmot              --prerelease
dotnet add package NostrNet.Marmot.Mls.Native   --prerelease   # ships native bins for 6 RIDs
dotnet add package NostrNet.Blossom             --prerelease
```

`--prerelease` is required until v0.1.0. The target framework must be
`net10.0` or higher (`net10.0-windows10.0.19041.0` for WinUI 3, etc.).
The library does **not** multi-target down to net8/9.

## Cardinal patterns

Before showing APIs, three patterns drive everything below:

1. **`NostrClient.Builder(...)`** — fluent builder. Optional key. Always
   `await ConnectAsync()` and `await using` the result so the relay pool
   disposes cleanly.
2. **Store + Attach + Observe** — recommended for any UI / multi-screen
   app. Attach a `MemoryEventStore` to the client, fire-and-forget
   `AttachAsync` to fill it from relays, then bind UI to live
   `store.ObserveAsync<T>()` queries. One-way data flow, automatic
   cross-relay dedup, reactive typed updates.
3. **`PrivateKey` is `IDisposable`** — it zeros its secret on dispose.
   Use `using var key = PrivateKey.Generate()` / `FromNsec(...)` / `FromHex(...)`.

## NostrClient — the high-level façade

### Connect (with or without a key)

```csharp
using NostrNet.Client;
using NostrNet.Keys;

using var key = PrivateKey.Generate();

await using var client = await NostrClient.Builder(key)
    .UseRelays("wss://relay.damus.io", "wss://nos.lol")
    .ConnectAsync();
```

A keyless client supports subscribe / fetch / publish-pre-signed but
throws `InvalidOperationException` from anything that needs to sign or
decrypt (`PostNoteAsync`, `SendDirectMessageAsync`,
`SubscribeDirectMessagesAsync`). Guard with `client.HasKey`. A key can
be attached later without reconnecting via `client.SetKey(newKey)` —
useful for "connect first, sign in later" flows; `client.ClearKey()`
detaches.

### Publish

`PostNoteAsync` returns one `PublishResult` per relay so callers can
render partial-success states:

```csharp
var results = await client.PostNoteAsync("hello nostr");
foreach (var (uri, r) in results)
    Console.WriteLine($"{uri}: {(r.Accepted ? "OK" : "REJECTED")} {r.Message}");
```

Other publish helpers on `NostrClient`: `PostPictureAsync`,
`RepostAsync`, `QuoteRepostAsync`, `PublishUserStatusAsync`,
`ClearUserStatusAsync`, badge methods (`PublishBadgeDefinitionAsync`,
`AwardBadgeAsync`, `AcceptBadgeAsync`), `SendDirectMessageAsync` (NIP-17),
and the generic `PublishAsync(NostrEvent)` for hand-built events.

### Subscribe

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
    // received.Relay is the Uri that delivered THIS occurrence
    Console.WriteLine($"[{received.Relay.Host}] {received.Event.Content}");
}
```

Each yielded `ReceivedEvent(NostrEvent Event, Uri Relay)` exposes which
relay delivered the event. **`RelayPool` does not dedup** — when N
relays carry the same event, you'll see it N times. Two ways to handle
that:

- App-side: a `HashSet<EventId>` filter on the caller side.
- Recommended for any non-trivial app: attach an event store (next
  section). `SubscribeAsync` and `AttachAsync` auto-dedup when a store
  is configured, and you get typed reactive reads for free.

Incoming events from relays are **automatically Schnorr-verified** in
`RelayClient.Dispatch` — bad id or bad sig → silently dropped. You do
*not* need to call `.Verify()` on yielded events. Events parsed
manually via `NostrEvent.FromJson` are the exception — verify those
yourself.

Convenience: `client.SubscribeNotesAsync(authors: ..., limit: ...)`
for the kind-1 common case, `client.SearchAsync(query, ...)` for NIP-50
full-text search (auto-checks NIP-11 capability), and
`client.SubscribeDirectMessagesAsync()` for NIP-17 inbound DMs.

## Per-relay connection status + auto-reconnect + auto-resubscribe

Multi-relay apps almost always want status indicators ("3/5 relays
online") and retry UX. `client.ObserveRelayConnectionsAsync()` is the
primitive — and by default, both the transport reconnect and the
subscription resume happen automatically.

```csharp
using NostrNet.Relay;

_ = Task.Run(async () =>
{
    await foreach (var s in client.ObserveRelayConnectionsAsync(ct))
    {
        // s.Relay, s.State, s.Reason, s.Error, s.AttemptNumber
        UpdateDot(s.Relay, s.State);
    }
});
```

### What's in `RelayConnectionEvent`

| Field | Meaning |
|---|---|
| `Relay` | The URI this event is about. |
| `State` | `Connecting`, `Connected`, or `Disconnected`. |
| `Reason` | For `Disconnected`: `Disposed` (terminal — owner disposed the client/pool), `ConnectFailed` (handshake / DNS / TCP refused), `TransportError` (WebSocket errored after being open), `ServerClosed` (clean close from the relay). `None` for other states. |
| `Error` | The underlying exception for transport errors and connect failures. Null for clean transitions. |
| `AttemptNumber` | `1` for the initial connect, increments on each reconnect attempt. Useful for "retrying… (attempt N)" UI. |

### Snapshot-on-subscribe

The stream emits one event per relay currently in the pool **before**
yielding live transitions, so UI doesn't start empty. Multi-consumer:
two UI surfaces can call `ObserveRelayConnectionsAsync` independently
without stealing events from each other.

### Auto-reconnect

On by default. When a relay drops with a non-`Disposed` reason, the
pool retries with exponential backoff (1s, 2s, 4s, 8s, 16s, 30s,
repeating at 30s). Each attempt emits `Connecting → Connected` on
success or `Connecting → Disconnected(ConnectFailed)` on failure, so
the observer sees the full retry timeline.

### Auto-resubscribe

Also on by default. In-flight `SubscribeAsync` / `AttachAsync` calls
transparently re-issue their REQ on the relay after it reconnects —
the caller's `await foreach` keeps yielding events from the new
connection without surfacing a `SubscriptionClosed` for the transient
drop. "Attach and forget" patterns survive flaky networks without any
caller intervention.

Filters are re-issued **as-supplied**. If your filter uses `Since` or
`Limit`, you'll see overlap with events received before the drop.
Pair with an event store (which auto-dedups by event id) for live
feeds — the store-+-attach pattern shown earlier handles this
automatically.

### Opting out

Both behaviors are independently controllable on the builder:

```csharp
await using var client = await NostrClient.Builder(key)
    .UseRelays("wss://relay.damus.io", "wss://nos.lol")
    .WithAutoReconnect(false)     // transport drops are terminal
    .WithAutoResubscribe(false)   // subscriptions end on disconnect
    .ConnectAsync();
```

`WithAutoResubscribe(false)` is useful if the app does fine-grained
subscription lifecycle management itself; you still get reconnect for
the status indicator. `WithAutoReconnect(false)` implies no resubscribe
(there's no reconnect to resume over).

Per-call opt-out isn't needed: one-shot fetches that `break` out of the
`await foreach` or cancel their `CancellationToken` don't trigger
resume, because the pump cancels with the caller.

## The recommended app pattern — store + Attach + Observe

For any app with UI or multi-screen state, **do this** instead of
iterating `SubscribeAsync` directly. It's the equivalent of
SwiftData / Realm-style reactive queries on top of a Nostr stream.

```csharp
using NostrNet.Client;
using NostrNet.Client.Storage;   // store.ObserveAsync<T> / QueryAsync<T> / GetAsync<T>
using NostrNet.Keys;
using NostrNet.Profiles;
using NostrNet.Articles;
using NostrNet.Relay;
using NostrNet.Relay.Storage;

using var key = PrivateKey.Generate();
var store = new MemoryEventStore();          // INostrEventStore — swap for SQLite later

await using var client = await NostrClient.Builder(key)
    .WithEventStore(store)
    .UseRelays("wss://relay.damus.io", "wss://nos.lol")
    .ConnectAsync();

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { cts.Cancel(); e.Cancel = true; };

// 1. Subscribe — events flow into the store. Fire-and-forget; no yield loop.
_ = client.AttachAsync(new[]
{
    new Filter { Kinds = new[] { 0, 1 } },               // profiles + text notes
    new Filter { Kinds = new[] { 30023 }, Limit = 50 },  // recent long-form articles
}, cts.Token);

// 2. Read typed values live — yields snapshot first, then keeps yielding
//    as new matches arrive. Bind UI here, not to the raw relay stream.
_ = Task.Run(async () =>
{
    await foreach (var profile in store.ObserveAsync<Profile>(cancellationToken: cts.Token))
        Console.WriteLine($"profile: {profile.Owner!.ToNpub()[..16]}… — {profile.Name}");
});

_ = Task.Run(async () =>
{
    await foreach (var article in store.ObserveAsync<Article>(cancellationToken: cts.Token))
        Console.WriteLine($"article: {article.Title} by {article.Author.ToNpub()[..16]}…");
});

// 3. Publish — same connection, same key.
await client.PostNoteAsync("hello from a real app");

try { await Task.Delay(Timeout.Infinite, cts.Token); }
catch (OperationCanceledException) { }
```

### Why this beats the raw loop

- **Automatic dedup** across relays — the store keys on event id.
- **Replaceable / addressable upsert** is built in. New kind-0 from
  the same pubkey replaces the old one; new kind-30023 with the same
  `(pubkey, d-tag)` replaces the old article. Same for NIP-09
  tombstones and NIP-40 expiration.
- **Typed reactive reads.** `store.ObserveAsync<Profile>()` yields
  `Profile` instances directly, not `NostrEvent` you have to parse.
  Any type implementing `INostrTypedEvent<TSelf>` lights up.
- **Survives "key not yet known" UI flows** — start without a key,
  attach later via `client.SetKey(...)`, subscriptions and the store
  keep humming.

### Typed event types that work with `Observe<T>` / `Query<T>` / `Get<T>`

Anything implementing `INostrTypedEvent<TSelf>`. Shipping with the
library:

| Type | Namespace | Kinds |
|---|---|---|
| `Profile` | `NostrNet.Profiles` | 0 |
| `Article` | `NostrNet.Articles` | 30023, 30024 |
| `ContactList` | `NostrNet.Contacts` | 3 |
| `Reaction` | `NostrNet.Reactions` | 7 |
| `Repost` | `NostrNet.Reposts` | 6, 16 |
| `Comment` | `NostrNet.Comments` | 1111 |
| `UserStatus` | `NostrNet.UserStatuses` | 30315 |
| `Bookmark` | `NostrNet.Bookmarks` | 39701 |
| `Picture` | `NostrNet.Pictures` | 20 |
| `VideoEvent` | `NostrNet.Videos` | 21, 22, 34235, 34236 |
| `FileMetadata` | `NostrNet.Files` | 1063 |
| `DeletionRequest` | `NostrNet.Deletions` | 5 (uses explicit interface impl) |
| `RelayList` | `NostrNet.RelayList` | 10002 |
| `BadgeDefinition` / `BadgeAward` / `ProfileBadges` | `NostrNet.Badges` | 30009 / 8 / 30008 |

Custom types you write also light up — implement the static
`Kinds` property + static `TryFromEvent` and the extension methods
work automatically.

### One-shot reads (no observe)

```csharp
// Snapshot — yields what's in the store right now, newest-first.
await foreach (var p in store.QueryAsync<Profile>())
    Console.WriteLine(p.Name);

// Single value by author (uses replaceable-event semantics).
var meProfile = await store.GetAsync<Profile>(key.PublicKey);
```

### Writing a custom event store backend

Don't implement `INostrEventStore` from scratch — derive from
**`EventStoreBase`**. The base owns the entire NIP-01 / NIP-09 / NIP-40
semantics layer (dedup, replaceable / addressable upsert, deletion
tombstones, expiration filtering, ephemeral fan-out, observer registry,
snapshot+live merge for `ObserveAsync`). Your subclass only implements
seven raw-persistence primitives:

```csharp
public sealed class SqliteEventStore : EventStoreBase
{
    protected override bool TryAddRaw(NostrEvent ev)               { /* INSERT */ }
    protected override bool TryRemoveRaw(EventId id)               { /* DELETE WHERE id = ? */ }
    protected override NostrEvent? TryGetRaw(EventId id)           { /* SELECT WHERE id = ? */ }
    protected override IEnumerable<NostrEvent> ScanByAuthorAndKind(PublicKey author, int kind) { /* replaceable upsert */ }
    protected override IEnumerable<NostrEvent> ScanByAuthorKindAndIdentifier(PublicKey author, int kind, string id) { /* addressable upsert + a-tag delete */ }
    protected override IEnumerable<NostrEvent> ScanForQuery(Filter filter) { /* push as much of `filter` into SQL as possible */ }
    protected override int CountRaw()                              { /* SELECT COUNT(*) */ }
    protected override void OnDispose()                            { /* close connection */ }
}
```

That's it. Tombstones are derived automatically from your persisted
kind-5 events on first use (the base scans them via your `ScanForQuery`
and builds an in-memory tombstone set), so persistent backends get
correct NIP-09 semantics across restarts without a separate tombstones
table. Writes are serialized by the base's internal semaphore; reads are
lock-free so your primitives must be thread-safe.

`MemoryEventStore` is the reference subclass (~140 lines, all
"translate primitives to a `ConcurrentDictionary`"). Point your subclass
at `tests/NostrNet.Relay.Tests/Storage/MemoryEventStoreTests.cs` to
validate compliance.

## NIP-17 direct messages

`SendDirectMessageAsync` handles the full rumor → seal → gift-wrap chain
and publishes both the recipient-addressed and sender-addressed wraps
(per the spec, the self-wrap is what lets the sender's other devices
reconstruct sent-message history). Returns `Nip17PublishResult` with
per-relay outcomes for each wrap.

```csharp
var bob = PublicKey.FromNpub("npub1...");
var results = await client.SendDirectMessageAsync(bob, "hey bob");

// Receive — `dm.Kind` distinguishes chat / file / reaction;
// `dm.RumorId` is what to reference in replies and reactions.
await foreach (var dm in client.SubscribeDirectMessagesAsync())
{
    bool mine = dm.Sender.Equals(key.PublicKey);
    switch (dm.Kind)
    {
        case Nip17.RumorKind:                  // 14 — chat message
            Render(dm.Plaintext, mine);
            break;
        case Nip17.ReactionRumorKind:          // 7 — reaction (NIP-25 inside the wrap)
            string targetId = dm.Tags.FirstValue("e") ?? "";
            RenderReaction(dm.Sender, dm.Plaintext, targetId);
            break;
    }
}
```

`UnwrappedDirectMessage` carries `RumorId`, `Kind`, `Sender`, `Plaintext`,
`CreatedAt`, `Tags`, and `Relay`. Subscribers see **their own sent DMs
in the stream** (the self-wrap is addressed to them) — distinguish via
`dm.Sender == myKey.PublicKey`.

### Replying (NIP-10 markers, inside the wrap)

```csharp
await client.SendDirectMessageAsync(
    recipient: bob,
    content: "yes!",
    replyTo: parentDm.RumorId);              // → ["e", id, "", "reply"]
// For deeper threads: also pass `replyRoot: threadRootId` → ["e", id, "", "root"]
```

The `e` tag points at the **inner rumor id**, not the kind-1059 gift wrap.
Only DM participants know that id, so threading stays as private as the
messages. Markers only — the library doesn't emit legacy positional `e`
tags.

### Reacting (NIP-25 wrapped, never in the clear)

A clear kind-7 reaction would leak the conversation's existence. So
reactions go through the same wrap pipeline:

```csharp
await client.SendDirectMessageReactionAsync(
    targetRumorId: receivedDm.RumorId,
    targetAuthor: receivedDm.Sender,
    reaction: "👍");                          // or "+", "-", a :shortcode:
```

The receiver sees `dm.Kind == 7` arriving on the same stream — switch on
kind in the consumer.

### Low-level: arbitrary rumor kinds

For file messages (kind 15), edits, typing indicators, read receipts, or
any app-specific rumor kind:

```csharp
await client.SendWrappedDmAsync(
    recipient: bob,
    kind: Nip17.FileRumorKind,
    content: "https://blossom.example/abc...def.jpg",
    tags: new IReadOnlyList<string>[]
    {
        new[] { "p", bob.ToHex() },
        new[] { "file-type", "image/jpeg" },
    });
```

`SubscribeDirectMessagesAsync` surfaces only DM-family kinds (chat 14 /
file 15 / reaction 7) — non-family wraps like Marmot's kind-444 Welcomes
are filtered out at unwrap time so they don't pollute the DM stream. If
you need full kind flexibility on receive, drop down to
`Nip59.Unwrap(giftWrap, recipientKey)` directly.

The **seal signature is re-verified on unwrap**, so `dm.Sender` can't be
spoofed by a malicious outer wrap.

### Legacy NIP-04 DMs (decode only)

For apps that need to read kind-4 DMs sent by clients older than
mid-2024, `Nip04.TryDecrypt` is the primitive. There is **no encrypt
counterpart** — the spec is deprecated; new DMs should use NIP-17.

```csharp
using NostrNet.Crypto;

// Subscribe to legacy DMs addressed to me.
var filter = new Filter
{
    Kinds = new[] { Nip04.Kind },
    TagFilters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
    {
        ["p"] = new[] { myKey.PublicKey.ToHex() },
    },
};

await foreach (var received in client.SubscribeAsync(new[] { filter }))
{
    if (Nip04.TryDecrypt(received.Event, myKey, out string? text, out PublicKey? peer))
        Console.WriteLine($"{peer.ToNpub()[..16]}…: {text}");
}
```

`TryDecrypt` resolves the peer automatically (sender when inbound,
recipient from the `p` tag when reading your own outbound) and is
fail-closed — non-kind-4 events, wrong key, malformed payloads all
return `false` without throwing.

## Marmot — MLS group chat over Nostr

Use `NostrMarmotClient` for everything end-user-facing; drop down to
`MarmotChat.*` static helpers only when you need to drive the
provider directly without a relay pool.

### Setup — provider + client

The Marmot provider holds MLS state (KeyPackages, joined groups,
signature keys, current exporter). For production use a file path so
state survives restarts; in-memory is fine for tests.

```csharp
using NostrNet.Marmot;
using NostrNet.Marmot.Mls.Native;     // OpenMLS-backed provider

// In-memory — state evaporates on dispose. Good for tests.
using IMarmotMlsProvider provider = new OpenMlsProvider();

// Persistent — state survives restarts. Path is a SQLite db file.
using var provider = OpenMlsProvider.OpenAtPath("/var/app/marmot.sqlite");

using var myKey = PrivateKey.Generate();

await using var marmot = await NostrMarmotClient.Builder(myKey, provider)
    .UseRelays("wss://relay.example")
    .AutoPublishKeyPackage(true)              // publish KP on connect
    .RotateKeyPackageAfterAccept(true)        // forward secrecy on accept
    .ConnectAsync();
```

### Connection resilience (inherited from `NostrClient`)

Marmot built via `UseRelays(...)` rides on a regular `NostrClient` and
inherits **auto-reconnect + auto-resubscribe** automatically — both on
by default. The inbox pump (kind-1059 invites) and per-conversation
pumps (kind-445 group events) transparently re-issue REQ on reconnect,
so a flaky WebSocket in the middle of a chat is invisible to the app.

For per-relay status indicators in chat UI:

```csharp
_ = Task.Run(async () =>
{
    await foreach (var s in marmot.ObserveRelayConnectionsAsync(ct))
        UpdateDot(s.Relay, s.State);
});
```

Same opt-out shape as `NostrClient`:

```csharp
await using var marmot = await NostrMarmotClient.Builder(myKey, provider)
    .UseRelays("wss://relay.example")
    .WithAutoReconnect(false)      // transport drops are terminal
    .WithAutoResubscribe(false)    // pumps end on disconnect
    .ConnectAsync();
```

When built via `UseRelayBridge(...)` (custom `IMarmotRelay`), the
toggles are no-ops and `ObserveRelayConnectionsAsync` returns an empty
stream — the bridge owns its own transport.

### Publish your KeyPackage so people can invite you

```csharp
var kp = await marmot.PublishKeyPackageAsync();
// kind-30443 addressable event, deterministic `d` slot derived from pubkey.
// Re-calling replaces the previous KP on relays.
```

### Start a conversation (1:1 or group)

You need the *peer's* KeyPackage event (kind-30443) before you can
invite them. Fetch via `marmot.TryGetKeyPackageAsync(peerPubkey)`.

```csharp
// 1:1
var bobKp = await marmot.TryGetKeyPackageAsync(bobPubkey);
var convo = await marmot.StartConversationAsync(bobKp!, conversationName: "Alice <> Bob");

// N-party
var group = await marmot.StartGroupAsync(
    new[] { bobKp!, carolKp!, daveKp! },
    name: "Project channel");
```

`StartConversationAsync` builds the MLS group, generates the Welcomes,
and **publishes the kind-1059 gift wraps to each peer's inbox relays**
for you. The returned `MarmotConversation` is already registered for
subscriptions.

### Receive — invites, messages, state changes — one stream

```csharp
await foreach (var ev in marmot.SubscribeAsync(ct))
{
    switch (ev)
    {
        case MarmotInviteReceived invite:
            var c = await marmot.AcceptInviteAsync(invite);
            if (c is not null) Console.WriteLine($"joined: {invite.Sender.ToNpub()}");
            // Returns null on expected-stale failures (rotated KP, dup welcome).
            // Don't surface those as errors — they're relay-cached noise.
            break;

        case MarmotMessageReceived msg:
            Console.WriteLine($"{msg.Sender?.ToNpub()}: {msg.Plaintext}");
            break;

        case MarmotGroupStateChanged change:
            // Add / remove / key rotation. Provider state already advanced.
            break;
    }
}
```

`MarmotMessageReceived.Sender` is resolved through the **MLS layer**
(the member that produced the application message), not the
ephemeral outer signature — so spoofing the outer envelope can't
change the surfaced sender.

### Send

```csharp
await marmot.SendAsync(convo, "hello group");
```

The plaintext fed to MLS is a JSON-serialized unsigned Nostr kind-9
rumor; the receive path unwraps it transparently before exposing
`Plaintext`.

### Add / remove / rotate

```csharp
await marmot.AddPeerAsync(convo, daveKpEvent);
await marmot.RemovePeersAsync(convo, new[] { evePubkey });
await marmot.RotateKeysAsync(convo);        // MLS self-update — forward secrecy refresh
```

All three advance the MLS epoch. Existing members process the Commit
via `SubscribeAsync` automatically; the provider's state advances and
subsequent sends use the new exporter.

### Resume on startup

```csharp
// LoadExistingConversationsAsync auto-tracks each returned conversation
// with the inbox/per-conversation pumps — do NOT call TrackConversation
// yourself. The subsequent SubscribeAsync yields MarmotMessageReceived
// for every conversation without further setup.
foreach (var c in await marmot.LoadExistingConversationsAsync())
{
    var label = c.IsGroup ? (c.Name ?? "(group)") : c.Peer!.ToNpub();
    Console.WriteLine($"resumed {Convert.ToHexStringLower(c.NostrGroupId)} — {label}");
}

// Then run the inbound pump as normal:
_ = Task.Run(async () =>
{
    await foreach (var ev in marmot.SubscribeAsync(ct)) { /* ... */ }
});
```

`MarmotConversation` carries `NostrGroupId`, `Peer` (nullable for groups),
plus `Name` / `Description` / `IsGroup` lifted from the MIP-01
NostrGroupData extension. `Peer == null` is equivalent to `IsGroup`;
use whichever reads better in the call site.

### Cold-start history (`IMarmotMessageLog`)

**MLS forward secrecy destroys old exporters as the epoch advances**,
so the kind-445 ciphertext on relays cannot be re-decrypted on a future
session. To render history on cold start (or chat-list previews), the
app must capture plaintext at the moment of decryption. The library
gives you a hook:

```csharp
await using var marmot = await NostrMarmotClient.Builder(myKey, provider)
    .UseRelays("wss://relay.example")
    .WithMessageLog(new MemoryMarmotMessageLog())    // or your SQLite/Realm impl
    .ConnectAsync();
```

When a log is attached, every successfully-decrypted application
message is appended automatically before being yielded from
`SubscribeAsync`. On startup, replay per-conversation history before
live traffic flows:

```csharp
foreach (var c in await marmot.LoadExistingConversationsAsync())
{
    await foreach (var msg in marmot.LoadHistoryAsync(c))
        Render(c, msg);

    var preview = await marmot.GetLastMessageAsync(c);   // for chat list
}
```

The default `MemoryMarmotMessageLog` is fine for tests; for production,
implement `IMarmotMessageLog` against your own persistent storage
(SQLite, Realm, encrypted-at-rest, whatever your app uses). The
interface has four methods — `AppendAsync`, `LoadAsync`, `GetLastAsync`,
`DeleteGroupAsync` — and implementations dedup on
`MarmotMessageReceived.EventId` so the same kind-445 from multiple
relays only stores once. Call `DeleteGroupAsync` after a clean leave or
"delete chat" UI action so the log doesn't outlive the MLS state.

### Constraint worth knowing

Commits must be processed **before** application messages from the
new epoch. If relays deliver out of order, an app message will
decrypt as null until the Commit arrives. The standard fix is
park-and-retry: queue the message, wait for the next Commit on the
group, retry. `SubscribeAsync` doesn't enforce ordering across
relays — that's your event-loop's job if you stop using it.

## Blossom — content-addressed media

```csharp
using NostrNet.Blossom;
using NostrNet.Blossom.Blobs;
using NostrNet.Client;
using NostrNet.Keys;

using var http = new HttpClient();
using var key = PrivateKey.FromNsec("nsec1…");

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
```

### Upload, download, list, delete

```csharp
// Upload: computes sha256 locally, PUTs to primary, mirrors to the rest in parallel.
byte[] image = await File.ReadAllBytesAsync("photo.jpg");
var upload = await media.UploadAsync(image, "image/jpeg");
// upload.PrimaryDescriptor.Url is a CDN URL ready for a post.
// upload.Mirrors has per-server outcomes (descriptor or exception).

// Download: walks user's servers → BUD-03 author hints → fallback list.
var blob = await media.DownloadAsync(upload.Sha256);

// Or resolve a blossom: URI someone else shared
var fromUri = await media.DownloadAsync(BlossomUri.Parse("blossom:…"));

// List every blob across my servers (deduped by sha256)
foreach (var d in await media.ListMyBlobsAsync())
    Console.WriteLine($"{d.Sha256} {d.Type} {d.Size} {d.Url}");

// Delete from every server I'm on
var outcomes = await media.DeleteAsync(upload.Sha256);
//   true  = deleted     false = server refused     null = network error

// NIP-B7: advertise my server list so others can discover me
await media.PublishServerListAsync();
```

A primary-upload failure throws; mirror failures are captured per-server
in `upload.Mirrors[serverUri]` so apps can render "uploaded to A, mirror
to B failed" UX without losing the primary outcome.

For 404'd legacy URLs:

```csharp
var blob = await media.DownloadBrokenUrlAsync(
    "https://dead-cdn.example/b1674…f553.pdf",
    authorHints: new[] { eventAuthorPubkey });
```

Uses BUD-03's "last 64-char hex run" rule to recover the sha256 from
the URL and then walks the candidate list.

## Tags — build and read

```csharp
using NostrNet.Events;

// Build
var note = new UnsignedEvent
{
    PubKey = key.PublicKey,
    CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    Kind = 1,
    Tags = new[]
    {
        Tag.P(recipient),                                   // ["p", "<hex>"]
        Tag.E(parentId, "wss://relay.example", "reply"),    // NIP-10 reply marker
        Tag.T("nostr"),
        Tag.A(30023, articleAuthor, "my-slug"),             // addressable coordinate
    },
    Content = "…",
}.Sign(key);

// Read
foreach (var p in ev.Tags.Pubkeys())  Console.WriteLine(p.ToNpub());
foreach (var id in ev.Tags.EventIds()) Console.WriteLine(id.ToHex());
string? slug = ev.Tags.Identifier();        // the "d" tag value
string? title = ev.Tags.FirstValue("title");
bool hasReply = ev.Tags.Has("e");
```

## NIP-19 / NIP-21 — bech32 + nostr: URIs

```csharp
using NostrNet.Nip19;

var npub = key.PublicKey.ToNpub();                   // "npub1..."
PublicKey decoded = PublicKey.FromNpub(npub);

string note = EventId.ToNote(eventId);               // "note1..."
string nprofile = Nip19.EncodeProfile(pubkey, relays);
string nevent   = Nip19.EncodeEvent(eventId, relays, authorPubkey);
string naddr    = Nip19.EncodeAddress(kind, author, "slug", relays);

// Round-trips:
var entity = Nip19.Decode("nprofile1…");             // discriminated by enum
```

`nostr:` URIs (NIP-21): `Nip21.TryParse(uri, out var entity)` /
`Nip21.Encode(entity)`.

## NIP-98 HTTP auth — for talking to HTTP endpoints that gate on Nostr

```csharp
using NostrNet.HttpAuth;

using var http = new HttpClient(new Nip98AuthHandler(key) { InnerHandler = new HttpClientHandler() });
var resp = await http.GetAsync("https://gated.example/api/foo");
// every request automatically carries `Authorization: Nostr <b64-kind-27235>`
```

## Vanity keys (PoW / npub prefix / hex suffix)

Multi-threaded, cancellable, with `IProgress<T>` reporting designed for
UI throttling (~one report per 500ms regardless of throughput):

```csharp
using NostrNet.Keys;

using var pow = await VanityKeyGenerator.MinePowAsync(leadingZeroBits: 20);
using var alice = await VanityKeyGenerator.MineNpubPrefixAsync("alce");
using var dead = await VanityKeyGenerator.MineHexSuffixAsync("dead");
```

Bech32 charset is **validated up front** — `MineNpubPrefixAsync("bob")`
throws `ArgumentException` immediately (b/i/o/1 are not in the bech32
alphabet) rather than running forever.

## Gotchas worth knowing before they bite

- **Pool yields once per relay.** `RelayPool` and the raw
  `SubscribeAsync` intentionally don't dedup. Either attach an event
  store (auto-dedups) or filter on `EventId` in the caller.
- **`SubscribeAsync` is verified, `FromJson` is not.** Anything yielded
  from a relay is auto-verified. Events you parse from JSON via
  `NostrEvent.FromJson` must call `.Verify()` themselves.
- **No DI, no logger.** The library does not reference
  `Microsoft.Extensions.*`. Don't expect `AddNostr()` in an
  `IServiceCollection`.
- **`PrivateKey.Dispose` zeros memory.** Always `using var` it. Avoid
  storing the raw hex/nsec longer than you need it — `ToHex()` /
  `ToNsec()` allocate fresh strings.
- **Threading.** Subscriptions yield on thread-pool threads. In WPF /
  WinUI use `Dispatcher` / `DispatcherQueue`, in MAUI use
  `MainThread.BeginInvokeOnMainThread`, in Godot use `CallDeferred`
  for scene access. `Progress<T>` constructed on the UI thread
  captures the sync context for you.
- **Marmot Commit ordering.** If a Commit and an app message from the
  new epoch arrive out of order, the app message decrypts as null on
  `MarmotMessageReceived` until the Commit lands. Park-and-retry.
- **`MarmotConversation.Peer` is nullable.** Multi-member groups and
  rehydrated conversations leave it null; don't deref it
  unconditionally.
- **State-DB lifecycle.** `OpenMlsProvider.OpenAtPath(path)` opens a
  SQLite db. `WipeStateAsync()` deletes `.db` + `-shm` + `-wal`
  sidecars — that's the "sign out / reset chat" primitive. There's
  also `StateInfoAsync()` for diagnostics (size + group count) and
  `VacuumAsync()` for compaction.
- **Blossom mirror failures don't throw.** Only the primary upload
  failing throws. Inspect `upload.Mirrors[server]` for per-server
  results so you can render partial-success UX.
- **`AcceptInviteAsync` returns null on expected-stale failures.**
  NoMatchingKeyPackage (your KP rotated since the welcome was sent)
  and GroupAlreadyExists (relay-cached duplicate welcome) come back
  as `null`. Don't surface those as user-visible errors — they're
  relay noise.

## When in doubt

The repo root `README.md` has expanded walkthroughs (vanity perf
numbers, Godot threading, build-from-source for the Native crate).
Per-package READMEs cover deeper Marmot / Blossom topics
(`src/NostrNet.Marmot/README.md`, `src/NostrNet.Blossom/README.md`).
The contributor-facing `CLAUDE.md` documents internal design and is
**not** what you want for app code — it's for people patching the
library itself.
