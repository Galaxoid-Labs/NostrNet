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

For production, open the provider at a filesystem path. State (groups,
signature keypairs, HPKE init keys) is persisted across process
restarts:

```csharp
using var provider = OpenMlsProvider.OpenAtPath("/var/app/marmot.sqlite");
// ... use provider as normal ...
// dispose. Next time the process starts:
using var provider2 = OpenMlsProvider.OpenAtPath("/var/app/marmot.sqlite");
// All previously-built KeyPackages, joined groups, and current
// exporter secrets are immediately available.
```

### Resuming conversations on startup

`ListGroupsAsync` enumerates every group the provider has in storage
(MLS group state + members). `NostrMarmotClient` builds on this with
`LoadExistingConversationsAsync`, which converts each into a
`MarmotConversation`, derives the 1:1 peer when unambiguous, and
starts kind-445 subscriptions automatically:

```csharp
await using var client = await NostrMarmotClient.Builder(myKey, provider)
    .UseRelays("wss://relay.example")
    .ConnectAsync();

// Restore prior conversations before subscribing for new traffic.
foreach (var c in await client.LoadExistingConversationsAsync())
{
    Console.WriteLine($"resumed group {Convert.ToHexStringLower(c.NostrGroupId)} (peer: {c.Peer?.ToNpub()})");
}

// Then start the inbound pump as normal.
await foreach (var ev in client.SubscribeAsync(ct)) { /* ... */ }
```

`MarmotConversation.Peer` is nullable: for multi-member groups or
conversations rehydrated from storage where the 1:1 peer is
ambiguous, it's `null`. Use the `MarmotStoredGroup.Members` list
returned by `ListGroupsAsync` if you need the full membership.

### State-DB management

| Helper | What it does |
|---|---|
| `IMarmotMlsProvider.DeleteGroupAsync(nostrGroupId)` | Removes a single group's MLS state + the `marmot_group_map` row. Idempotent. Local-only — call `BuildSelfRemoveProposalAsync` first to announce the leave on the wire. |
| `IMarmotMlsProvider.VacuumAsync()` | Runs SQLite VACUUM to reclaim space after deletes. No-op for in-memory providers. |
| `OpenMlsProvider.StateInfoAsync()` | Returns `MarmotStateInfo(Path, SizeOnDiskBytes, GroupCount)` for diagnostics. |
| `OpenMlsProvider.WipeStateAsync()` | Disposes the provider and deletes the `.db` + `-shm` + `-wal` sidecars. Throws on in-memory. Standard "sign out / reset" flow. |

### Acceptance semantics

`NostrMarmotClient.AcceptInviteAsync` returns `MarmotConversation?`.
It returns `null` (no exception) on the two expected-stale outcomes
common in long-lived inboxes:

- **`NoMatchingKeyPackage`** — the Welcome targets a local
  KeyPackage that has since rotated away (e.g., the state DB was
  wiped between when the inviter cached our KP and when their
  Welcome was delivered).
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
