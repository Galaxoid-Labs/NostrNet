# NostrNet.Marmot

[Marmot](https://github.com/marmot-protocol/marmot) is a protocol for MLS
([RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420)) group messaging
over Nostr. This package implements the **Nostr-wire envelope** layer of
Marmot — the event kinds, TLS-encoded extension, and NIP-59 gift-wrap
plumbing — but **does not include an MLS engine**. MLS itself is pluggable
via the `IMarmotMlsProvider` interface.

To actually run Marmot, pair this package with an MLS provider:

- **`NostrNet.Marmot.Mls.Reference`** — an in-tree, experimental
  pure-managed implementation supporting one ciphersuite and two-member
  groups. Good for prototyping; not for production.
- _(Planned)_ `NostrNet.Marmot.Mls.Native` — an FFI wrapper around
  [openmls](https://github.com/openmls/openmls) for full MLS coverage.

## MIPs implemented

| MIP | What | Where |
|----|------|-------|
| 00 | KeyPackage publication (kind 30443) | `Events/KeyPackageEvent.cs` |
| 01 | Marmot Group Data extension (0xF2EE) | `GroupData/MarmotGroupDataExtension.cs` |
| 02 | Welcome event (kind 444 inside NIP-59 gift wrap) | `Events/WelcomeEvent.cs` |
| 03 | Group event content encryption (kind 445, ChaCha20-Poly1305 keyed off MLS exporter) | `Events/GroupEvent.cs` |

MIPs 04 (encrypted media) and 05 (push notification rumor, kind 446) are
optional and not yet implemented.

## Quickstart

The flow always has the same shape regardless of MLS provider:

```csharp
using NostrNet.Marmot;
using NostrNet.Marmot.Events;
using NostrNet.Marmot.GroupData;
using NostrNet.Keys;

// Wire in your MLS provider of choice. For prototyping:
//   #pragma warning disable NMARMOT0001
IMarmotMlsProvider provider = new ReferenceMarmotMlsProvider();
//   #pragma warning restore NMARMOT0001

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
| `BuildSelfRemoveProposalAsync` | Issue a SelfRemove proposal for the local member |
| `EncryptApplicationMessageAsync` | Encrypt an application MLSMessage to publish as kind-445 content |
| `ProcessIncomingMlsMessageAsync` | Process any inbound MLSMessage (proposal/commit/application) |
| `CurrentExporterSecretAsync` | Derive `MLS-Exporter("marmot", "group-event", 32)` for the current epoch |

A minimum-viable provider only needs the create/add/join/exporter quartet
to support a two-member group (the rest can throw `NotSupportedException`
during prototyping).

## Security guarantees

- Welcome unwrap re-verifies the inner seal and ensures the rumor's
  pubkey matches the seal's pubkey — an attacker can't replay another
  sender's seal with a forged rumor pubkey.
- KeyPackage events use `encoding: base64` per MIP-00 (hex is rejected).
- kind-445 events use a fresh ephemeral keypair per event; the
  `created_at` is the real send time (no jitter at this layer — that's
  what the Marmot Group Data extension's `disappearing_message_duration`
  is for).
