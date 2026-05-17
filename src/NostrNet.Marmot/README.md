<p align="center">
  <img src="https://raw.githubusercontent.com/Galaxoid-Labs/NostrNet/main/logo.png" alt="NostrNet" width="320" />
</p>

# NostrNet.Marmot

[Marmot](https://github.com/marmot-protocol/marmot) is a protocol for MLS
([RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420)) group messaging
over Nostr. This package implements the **Nostr-wire envelope** layer of
Marmot — the event kinds, TLS-encoded extension, and NIP-59 gift-wrap
plumbing — but **does not include an MLS engine**. MLS itself is pluggable
via the `IMarmotMlsProvider` interface.

To actually run Marmot, pair this package with an MLS provider:

- **`NostrNet.Marmot.Mls.Native`** — OpenMLS-backed provider via an
  in-tree Rust FFI bridge (`nostrnet-marmot-native/`). RFC-9420
  compliant wire bytes. Supports 1:1 and N-party groups, adds, removes,
  key rotation, and persistent (SQLite-backed) state. Building from
  source requires the Rust toolchain on PATH.

## MIPs implemented

| MIP | What | Where |
|----|------|-------|
| 00 | KeyPackage publication (kind 30443) | `Events/KeyPackageEvent.cs` |
| 01 | Marmot Group Data extension (0xF2EE) | `GroupData/MarmotGroupDataExtension.cs` |
| 02 | Welcome event (kind 444 inside NIP-59 gift wrap) | `Events/WelcomeEvent.cs` |
| 03 | Group event content encryption (kind 445, ChaCha20-Poly1305 keyed off MLS exporter) | `Events/GroupEvent.cs` |

MIPs 04 (encrypted media) and 05 (push notification rumor, kind 446) are
optional and not yet implemented.

## Quickstart — high-level 1:1 helper

For one-to-one conversations (DMs / private chats), the `MarmotChat`
static helpers collapse the provider + envelope + NIP-59 plumbing into
five async calls:

```csharp
using NostrNet.Marmot;
using NostrNet.Marmot.Mls.Native;     // OpenMLS-backed provider
using NostrNet.Keys;

// In-memory provider (state evaporates on dispose):
using IMarmotMlsProvider provider = new OpenMlsProvider();
// — or — persistent across restarts:
//   using var provider = OpenMlsProvider.OpenAtPath("/var/app/marmot.sqlite");

using var myKey = PrivateKey.Generate();
var myRelays = new[] { "wss://relay.example" };

// 1. Publish a KeyPackage so others can start a conversation with you.
//    Pass slot: null to auto-generate a deterministic 64-char hex
//    derived from your pubkey — re-publishing replaces the previous
//    KeyPackage event on relays. Pass an explicit 64-hex string for a
//    separate "device slot".
var myKeyPackage = await MarmotChat.BuildKeyPackageEventAsync(
    provider, myKey, slot: null, myRelays);
// publish myKeyPackage (kind 30443) to your inbox relays...

// 2. Start a 1:1 conversation with a peer whose KeyPackage event you've fetched.
var started = await MarmotChat.StartConversationAsync(
    provider, myKey, peerKeyPackageEvent, conversationName: "Alice <> Bob", myRelays);
// publish started.WelcomeGiftWrap (kind 1059) to the peer's inbox...

// 3. Accept an inbound invite by trying to unwrap every kind-1059 you receive.
var convo = await MarmotChat.TryAcceptInviteAsync(provider, myKey, inboundGiftWrap);
if (convo is not null) { /* joined */ }

// 4. Send a message. Per Marmot MIP-03 the plaintext fed to MLS is a
//    JSON-serialized unsigned Nostr rumor (kind 9); EncryptMessageAsync
//    builds the rumor for you, so you pass the user's text + your
//    PrivateKey (used as the rumor's pubkey).
var ev = await MarmotChat.EncryptMessageAsync(provider, convo, myKey, "hello!");
// publish ev (kind 445) to the conversation's relays...

// 5. Decrypt an inbound kind-445. TryDecryptMessageAsync transparently
//    unwraps the rumor and returns the chat text from its content field.
string? text = await MarmotChat.TryDecryptMessageAsync(provider, convo, inboundEvent);
```

Bidirectional and replay-protected: both sides run their own outbound
ratchet (keyed for their leaf) and track the peer's inbound generation
independently. See `samples/NostrNet.Sample.Console` for an end-to-end
demo (`marmot-mls-smoke` subcommand) and the `marmot-chat` interactive
REPL for talking to real Marmot clients (e.g.
[White Noise](https://github.com/marmot-protocol/whitenoise-rs)) over
live relays.

### Multi-member groups

For 3+ member groups, use `StartGroupAsync` to create with multiple
initial members and `AddPeerAsync` to grow an existing group:

```csharp
// Start a group with multiple initial members.
var started = await MarmotChat.StartGroupAsync(
    provider, myKey,
    peerKeyPackageEvents: new[] { bobKpEvent, carolKpEvent },
    "Project channel",
    relays);
// publish each of started.WelcomeGiftWraps[i] to the corresponding peer's inbox.

// Add a peer to an existing conversation.
var added = await MarmotChat.AddPeerAsync(
    provider, myKey, convo, davesKpEvent, relays);
// publish added.WelcomeGiftWrap to Dave's inbox.
// publish added.CommitGroupEvent (kind-445) to the group — existing
// members process it to advance their epoch.

// Existing members process the inbound Commit:
var processed = await MarmotChat.TryProcessMessageAsync(provider, convo, kind445Event);
if (processed?.Kind == MarmotMessageKind.Commit && processed.EpochAdvanced)
{
    // Group state changed. Subsequent EncryptMessageAsync uses the new exporter.
}
```

`TryProcessMessageAsync` is the richer counterpart to
`TryDecryptMessageAsync`: it tells you whether the inbound message was
an Application message (with plaintext), a Commit (group state changed),
or a Proposal (queued for a future Commit). `TryDecryptMessageAsync`
returns just the plaintext for app-developer convenience when you don't
care about Commits.

**Important constraint**: Commits must be processed before application
messages from the new epoch, because the new app messages are keyed to
the new exporter. If a relay delivers events out of order, your receive
loop will see decrypt failures on app messages until the Commit arrives
— park-and-retry is the standard fix.

### Removing members + rotating keys

Both operations advance the epoch and produce a kind-445 Commit
GroupEvent for existing members to process:

```csharp
// Admin removes a peer (or peers). The removed peer loses access:
// future kind-445 events fail to decrypt on their side.
var removed = await MarmotChat.RemovePeerAsync(
    provider, convo, new[] { eveKey.PublicKey });
// publish removed.CommitGroupEvent to the group's relays.

// A member rotates their own leaf keys (MLS self-update). Existing
// members process the Commit and advance to the new epoch.
var rotated = await MarmotChat.RotateKeysAsync(provider, convo);
// publish rotated.CommitGroupEvent.
```

Forward secrecy works the way MLS promises: removed members can no
longer derive the new epoch's exporter, so they can't decrypt any
post-removal traffic.

### Persistence

`new OpenMlsProvider()` keeps state in an in-memory SQLite database —
fine for tests, lost when the provider is disposed.

For production, open the provider at a filesystem path. The file is
**SQLCipher-encrypted** with a 32-byte raw AES-256 key the caller
supplies. State (groups, signature keypairs, HPKE init keys, current
exporter secrets) is persisted across process restarts and encrypted
at rest:

```csharp
using System.Security.Cryptography;

// Derive a 32-byte raw key from the user's nsec via HKDF-SHA256.
// The library doesn't run a KDF — it consumes these 32 bytes
// verbatim as the SQLCipher AES key.
Span<byte> nsecBytes = stackalloc byte[32];
Span<byte> mlsKey = stackalloc byte[32];
try
{
    privateKey.CopyTo(nsecBytes);
    HKDF.DeriveKey(
        HashAlgorithmName.SHA256,
        ikm: nsecBytes,
        output: mlsKey,
        salt: "myapp:marmot-mls/v1"u8,
        info: "mls-state-encryption"u8);

    using var provider = OpenMlsProvider.OpenAtPath("/var/app/marmot.sqlite", mlsKey);
    // ... use provider as normal ...
}
finally
{
    CryptographicOperations.ZeroMemory(nsecBytes);
    CryptographicOperations.ZeroMemory(mlsKey);
}
```

Wrong-key reopens throw `InvalidMlsKeyException` — apps can prompt the
user to re-enter a passphrase or fall back to a sign-in flow without
catching a generic storage failure. A wrong-length key (anything other
than exactly 32 bytes) throws `ArgumentException`.

Why encryption is mandatory for file-backed providers: the MLS state DB
holds the highest-value material on disk (current epoch exporter
secrets, per-leaf signature keys, ratchet state). Forward secrecy is
only meaningful if that file isn't readable by anyone who can read your
local filesystem. SQLCipher closes the obvious file-leak vectors —
OneDrive Backup, stolen laptop without BitLocker, forensic file
extraction — without claiming to defend against same-user infostealer
malware (out of scope for any chat client).

### Resuming conversations on startup

`ListGroupsAsync` enumerates every group the provider has in storage
(MLS group state + members + the parsed NostrGroupData extension).
`NostrMarmotClient` builds on this with
`LoadExistingConversationsAsync`, which converts each into a
`MarmotConversation`, derives the 1:1 peer when unambiguous, **and
automatically registers each conversation with the inbox/per-conversation
pumps** — callers do NOT call `TrackConversation` themselves.

```csharp
await using var client = await NostrMarmotClient.Builder(myKey, provider)
    .UseRelays("wss://relay.example")
    .ConnectAsync();

// Restore prior conversations before subscribing for new traffic.
foreach (var c in await client.LoadExistingConversationsAsync())
{
    string label = c.IsGroup ? (c.Name ?? "(unnamed group)") : c.Peer!.ToNpub();
    Console.WriteLine($"resumed {Convert.ToHexStringLower(c.NostrGroupId)} — {label}");
}

// Then start the inbound pump as normal — kind-445 traffic for every
// returned conversation flows here automatically.
await foreach (var ev in client.SubscribeAsync(ct)) { /* ... */ }
```

`MarmotConversation` carries:

- `NostrGroupId` — 32-byte group id used as the `h` tag on kind-445 events.
- `Members` — every current member of the MLS group, **including your own
  identity**. Refreshed automatically on every Commit (add / remove / key
  rotation) so the value on a freshly-yielded `MarmotGroupStateChanged`
  reflects the post-Commit membership. Use this for interop-correct
  "is this effectively a 1:1?" detection (see below).
- `Peer` — convenience for 1:1 conversations created via
  `StartConversationAsync`. **Not set by `StartGroupAsync`, even at N=2**
  — that's a meaningful gotcha when interoperating with other Marmot
  clients (Whitenoise always uses `StartGroupAsync`). Apps that want
  "2-member groups render as 1:1" should derive the counterpart from
  `Members`, not `Peer`:

  ```csharp
  var counterpart = conv.Members.Count == 2
      ? conv.Members.First(p => !p.Equals(myPub))
      : conv.Peer;

  if (counterpart is not null) RenderAsDirectChat(counterpart);
  else                          RenderAsGroup(conv.Name, conv.Members);
  ```

- `IsGroup` — equivalent to `Peer is null`. Convenient but **not
  protocol-correct** for the 2-member-group-vs-1:1 distinction; see
  `Members.Count` for that.
- `Name` / `Description` — lifted from the MIP-01 NostrGroupData
  extension. Populated whenever the extension is present on the
  underlying MLS group. Empty string is permitted by the spec for
  "unnamed groups" — render empty the same as null.

Every Marmot conversation is structurally an MLS group with N members
(N ≥ 2 for any usable chat). "1:1" is a UI affordance for N=2 — there's
no separate wire shape. The sender chooses between
`StartConversationAsync` (sets `Peer`) and `StartGroupAsync` (doesn't);
receivers should make rendering decisions from `Members.Count`, not from
which entry point the sender happened to choose.

### Cold-start chat history (`IMarmotMessageLog`)

MLS forward secrecy destroys old exporters as the epoch advances, so
kind-445 ciphertext on relays cannot be re-decrypted on a future
session. Anything you want to render on cold start — chat history,
chat-list previews, last-activity timestamps — must be captured at the
moment of decryption. The `IMarmotMessageLog` hook does this:

```csharp
await using var client = await NostrMarmotClient.Builder(myKey, provider)
    .UseRelays("wss://relay.example")
    .WithMessageLog(new MemoryMarmotMessageLog())   // or your SQLite-backed impl
    .ConnectAsync();
```

When a log is attached, every successfully-decrypted application
message is appended automatically before being yielded from
`SubscribeAsync`. On startup, replay per-conversation history:

```csharp
foreach (var c in await client.LoadExistingConversationsAsync())
{
    await foreach (var msg in client.LoadHistoryAsync(c))
        Render(c, msg);

    // For chat-list "last message + last activity" rendering:
    var preview = await client.GetLastMessageAsync(c);
}
```

`MemoryMarmotMessageLog` is fine for tests; for production, implement
`IMarmotMessageLog` (four methods: `AppendAsync`, `LoadAsync`,
`GetLastAsync`, `DeleteGroupAsync`) over your persistent store.
Implementations dedup on `MarmotMessageReceived.EventId` so the same
kind-445 from multiple relays only stores once. Call `DeleteGroupAsync`
after a clean leave or "delete chat" UI action so the log doesn't
outlive the MLS state.

Without a log, `LoadHistoryAsync` returns an empty stream and
`GetLastMessageAsync` returns null — both are still safe to call.

### Connection resilience (inherited from `NostrClient`)

Marmot built via `UseRelays(...)` rides on a regular `NostrClient`,
so it inherits the underlying transport-resilience defaults
automatically:

- **Auto-reconnect** is on. If a relay drops, the pool reconnects
  with exponential backoff (1s → 30s cap).
- **Auto-resubscribe** is on. The inbox pump (kind-1059 invites)
  and every per-conversation pump (kind-445 group events)
  transparently re-issue their REQ after a reconnect. A transient
  WebSocket drop in the middle of a chat is invisible to the app —
  messages keep flowing once the relay is back.

For status indicators in chat UI (a green/yellow/red dot per relay):

```csharp
_ = Task.Run(async () =>
{
    await foreach (var s in client.ObserveRelayConnectionsAsync(ct))
    {
        // s.Relay, s.State (Connecting | Connected | Disconnected),
        // s.Reason, s.Error, s.AttemptNumber
        UpdateDot(s.Relay, s.State);
    }
});
```

Both behaviors are independently opt-out-able on the builder:

```csharp
await using var client = await NostrMarmotClient.Builder(key, provider)
    .UseRelays("wss://relay.example")
    .WithAutoReconnect(false)     // transport drops are terminal
    .WithAutoResubscribe(false)   // pumps end on disconnect
    .ConnectAsync();
```

When the client is built via `UseRelayBridge(...)` instead, the
custom `IMarmotRelay` owns its own transport policy — the builder
toggles are no-ops, and `ObserveRelayConnectionsAsync` returns an
empty stream.

### State-DB management

| Helper | What it does |
|---|---|
| `IMarmotMlsProvider.DeleteGroupAsync(nostrGroupId)` | Removes a single group's MLS state + the `marmot_group_map` row. Idempotent. Local-only — call `BuildSelfRemoveProposalAsync` first to announce the leave on the wire. |
| `IMarmotMlsProvider.VacuumAsync()` | Runs SQLite VACUUM to reclaim space after deletes. No-op for in-memory providers. |
| `OpenMlsProvider.StateInfoAsync()` | Returns `MarmotStateInfo(Path, SizeOnDiskBytes, GroupCount)` for diagnostics. |
| `OpenMlsProvider.WipeStateAsync()` | Disposes the provider and deletes the `.db` + `-shm` + `-wal` sidecars. Throws on in-memory. Standard "sign out / reset" flow. |

### Invite delivery semantics

`MarmotInviteReceived.Sender` is the **NIP-59 seal pubkey** — library-
verified (the seal signature over the inner rumor passed), but **not
necessarily the inviter's identity pubkey**. NIP-59 says the seal
SHOULD be signed by the sender's identity key, but some Marmot
clients (notably some Whitenoise builds) seal welcomes with
non-identity keys. After the receiver calls `AcceptInviteAsync`, the
returned `MarmotConversation.Members` is the MLS-bound member list and
that's the canonical place to identify the counterpart:

```csharp
var conv = await marmot.AcceptInviteAsync(invite);
if (conv is not null)
{
    var counterpart = conv.Members.Count == 2
        ? conv.Members.First(p => !p.Equals(myPub))
        : conv.Peer;
    // Hydrate kind-0 profile, render display name, etc. — using
    // `counterpart`, not `invite.Sender`.
}
```

Don't feed `invite.Sender` into kind-0 author filters or identity-
keyed UX; reserve those for post-accept `Members`.

The inbox pump pre-filters welcomes whose target KeyPackage has been
rotated away or wiped from local state (`CanJoinWelcomeAsync` checks
the welcome's `EncryptedGroupSecrets.new_member` refs against the
provider's stored KeyPackageBundles). Apps therefore don't see
zombie pending invites that `AcceptInviteAsync` would just null-return
on.

### Acceptance semantics

`NostrMarmotClient.AcceptInviteAsync` returns `MarmotConversation?`.
It returns `null` (no exception) on the two expected-stale outcomes
common in long-lived inboxes:

- **`NoMatchingKeyPackage`** — the Welcome targets a local
  KeyPackage that has since rotated away (e.g., the state DB was
  wiped between when the inviter cached our KP and when their
  Welcome was delivered). The inbox-pump pre-filter (above) catches
  most of these before they surface, but a TOCTOU window exists if
  the KP is rotated between the pump's probe and the user's accept
  click — that's the residual null case.
- **`GroupAlreadyExists`** — the same Welcome was redelivered by a
  second relay; we've already joined the group locally. The library
  scans `ListGroupsAsync` for the inviter and returns the existing
  conversation.

Apps should treat `null` as "skip silently" rather than as an
error to surface, the way the `marmot-chat` sample does.

### Automatic KeyPackage rotation

MIP-00 says clients SHOULD rotate KeyPackages periodically and after
they're consumed. `NostrMarmotClient` does this on app-launch
cadence (no background timers, no scheduler infrastructure):

- **On `ConnectAsync`** the builder fires `PublishKeyPackageAsync`
  immediately after the underlying `NostrClient` connects. The
  deterministic per-identity slot (sha256 of pubkey + a fixed domain
  separator) means the new event *replaces* the previous one on
  every cooperating relay rather than orphaning init keys.
- **After every successful `AcceptInviteAsync`** the client kicks off
  a background `PublishKeyPackageAsync` so the KeyPackage the new
  peer just consumed gets replaced. Anyone caching it on a relay
  receives the fresh one on next fetch; the old init key never
  serves a second inviter.
- **`AcceptInviteAsync` also prunes the consumed `KeyPackageBundle`
  from local provider storage**, per MLS's single-use init-key
  contract. This is what makes the preview13 inbox-pump stale-welcome
  filter catch relay-cached re-deliveries of the just-consumed welcome
  on a future session: the bundle is gone, the probe returns false,
  the ghost invite never resurfaces in the UI.

Failures are best-effort — a relay hiccup at startup or after a
join doesn't break the active session. The most recent error (if
any) is exposed via `NostrMarmotClient.LastAutoPublishError` for
apps that care about diagnostics. To turn either behavior off:

```csharp
NostrMarmotClient.Builder(key, provider)
    .UseRelays("wss://relay.example")
    .AutoPublishKeyPackage(false)         // don't publish on Connect
    .RotateKeyPackageAfterAccept(false)   // don't rotate after a join
    .ConnectAsync();
```

This matches WN's pattern (`key_package_maintenance` republishes on
boot, plus inline-rotate-on-consume), minus the periodic 10-minute
scheduler. Apps that need timer-based rotation can build their own
loop on top of the manual `PublishKeyPackageAsync` /
`RotateKeysAsync` APIs.

### Out-of-order delivery + offline catch-up

When a client comes back online — or just talks to a relay that
batches historical events newest-first — kind-445 group events can
arrive out of causal order. An application message from a new epoch
may show up *before* the Commit that advances members into that
epoch; without help, the receiver can't decrypt it (the new
exporter doesn't exist yet) and drops it.

`NostrMarmotClient` parks such events in a per-conversation buffer
and replays them every time a Commit advances the local epoch:

- Buffer is bounded (200 events per group, oldest evicted on
  overflow) so an adversarial / spam-heavy relay can't grow memory
  without limit.
- Each parked event gets up to 8 retry passes; events that remain
  undecryptable after that (true duplicates, payloads from before
  we joined the group, etc.) are dropped.
- Replays are sorted by `created_at` so chains of missed commits
  walk forward correctly when a long-offline client reconnects.

The behavior is transparent — apps don't see anything different from
the inbound event stream. A delayed application message just shows
up after its enabling Commit's `MarmotGroupStateChanged` event,
rather than being silently lost.

Caveat: MLS itself can't decrypt *past*-epoch messages once the
group has rolled forward, beyond OpenMLS's `max_past_epochs`
window. Park-and-retry helps with future-epoch deliveries that
arrived early. A client who's been offline so long that the relay's
event-cap truncates a critical Commit from history may need a fresh
invite to recover.

## Low-level flow

The flow always has the same shape regardless of MLS provider:

```csharp
using NostrNet.Marmot;
using NostrNet.Marmot.Events;
using NostrNet.Marmot.GroupData;
using NostrNet.Keys;

// Wire in your MLS provider of choice (OpenMLS-backed is the default).
using IMarmotMlsProvider provider = new OpenMlsProvider();

// ── Sender ("Alice") ────────────────────────────────────────────────
using var alice = PrivateKey.Generate();

byte[] groupId = RandomNumberGenerator.GetBytes(32);
var groupData = new MarmotGroupDataExtension
{
    NostrGroupId = groupId,
    Name = "Friends",
    AdminPubkeys = new[] { alice.PublicKey },
    Relays = new[] { "wss://relay.example" },
};
await provider.CreateGroupAsync(alice.PublicKey, groupData, ciphersuite: 0x0001);

// Alice receives Bob's KeyPackage event (kind 30443) off relays:
var bobKpEvent = /* ... fetched from a relay ... */;
var bobKp = KeyPackageEvent.FromEvent(bobKpEvent);

var add = await provider.AddMembersAsync(
    nostrGroupId: groupId,
    keyPackageBundles: new ReadOnlyMemory<byte>[] { bobKp.KeyPackageBundleBytes });

// Gift-wrap the Welcome and publish to Bob's inbox.
var giftWrap = WelcomeEvent.Build(
    mlsWelcomeBytes: add.Welcomes[0].WelcomeMlsMessageBytes,
    keyPackageEventId: bobKpEvent.Id.ToHex(),
    senderKey: alice,
    recipientPubkey: bobKp.Author,
    recommendedRelays: groupData.Relays.ToList());
// publish giftWrap to Bob's relays...

// ── Recipient ("Bob") ────────────────────────────────────────────────
using var bob = PrivateKey.Generate();

// Bob subscribes to kind-1059 gift wraps addressed to his pubkey,
// then tries to unwrap them as Marmot Welcomes:
if (WelcomeEvent.TryUnwrap(giftWrap, bob, out var unwrapped))
{
    var joined = await bobProvider.JoinGroupFromWelcomeAsync(unwrapped.MlsWelcomeBytes);
    Console.WriteLine($"Joined group {Convert.ToHexString(joined.NostrGroupId)}");
}

// ── Send a message ──────────────────────────────────────────────────
byte[] exporter = await provider.CurrentExporterSecretAsync(groupId);
byte[] payload = SysEncoding.UTF8.GetBytes("hello, group");
var ev = GroupEvent.Build(payload, exporter, groupId);
// publish ev (kind 445) to the group's relays

// ── Receive ─────────────────────────────────────────────────────────
byte[] bobExp = await bobProvider.CurrentExporterSecretAsync(groupId);
var decrypted = GroupEvent.Decrypt(ev, bobExp);
Console.WriteLine(SysEncoding.UTF8.GetString(decrypted.MlsMessageBytes));
```

## IMarmotMlsProvider

`IMarmotMlsProvider` is the boundary between this package (which only
touches Nostr) and your MLS engine. The interface is intentionally small;
opaque blobs (KeyPackage bundles, MLSMessage bytes, Welcome bytes, exporter
secrets) cross it as `ReadOnlyMemory<byte>` / `byte[]`. Group state is
keyed by the 32-byte `nostr_group_id`.

| Method | Purpose |
|--------|---------|
| `BuildKeyPackageAsync` | Generate a fresh KeyPackage for a Nostr identity |
| `ParseKeyPackageAsync` | Validate an inbound KeyPackage |
| `CreateGroupAsync` | Bootstrap a new MLS group with the Marmot Group Data extension |
| `AddMembersAsync` | Issue Add proposals + Commit; produces a Welcome blob per recipient |
| `JoinGroupFromWelcomeAsync` | Process an inbound Welcome to join a group |
| `RemoveMembersAsync` | Issue Remove proposals + Commit for the named members |
| `SelfUpdateAsync` | Rotate the local member's leaf keys |
| `BuildSelfRemoveProposalAsync` | Issue a SelfRemove proposal for the local member |
| `EncryptApplicationMessageAsync` | Encrypt an application MLSMessage to publish as kind-445 content |
| `ProcessIncomingMlsMessageAsync` | Process any inbound MLSMessage (proposal/commit/application) |
| `CurrentExporterSecretAsync` | Derive `MLS-Exporter("marmot", "group-event", 32)` for the current epoch |
| `ListGroupsAsync` | Enumerate every group in storage along with member identities |
| `DeleteGroupAsync` | Wipe a single group's local state |
| `VacuumAsync` | SQLite VACUUM to reclaim freed pages |

A minimum-viable provider only needs the create/add/join/exporter quartet
to support a two-member group (the rest can throw `NotSupportedException`
during prototyping). `ListGroupsAsync` returning an empty list and
`DeleteGroupAsync` / `VacuumAsync` as no-ops are valid stubs.

## Security guarantees

- Welcome unwrap re-verifies the inner seal and ensures the rumor's
  pubkey matches the seal's pubkey — an attacker can't replay another
  sender's seal with a forged rumor pubkey.
- KeyPackage events use `encoding: base64` per MIP-00 (hex is rejected).
- kind-445 events use a fresh ephemeral keypair per event; the
  `created_at` is the real send time (no jitter at this layer — that's
  what the Marmot Group Data extension's `disappearing_message_duration`
  is for).
