# NostrNet — Maintainer Notes

Cross-platform .NET 10 Nostr library. This file is for AI assistants /
maintainers; user-facing docs live in `README.md`.

## Architecture

```
src/
  NostrNet.Core/                Keys, events, NIP-01 canonical id, NIP-19 bech32,
                                Profile (kind 0), Articles (NIP-23), Contacts,
                                Deletions, Reactions, Threading, internal Secp256k1
                                wrapper. No I/O.
  NostrNet.Crypto/              ChaCha20 (RFC 8439), NIP-44 v2, NIP-17 DMs,
                                NIP-59 gift wrap, NIP-51 lists. Uses Core's
                                internal Secp256k1.
  NostrNet.Relay/               ClientWebSocket-based RelayClient, RelayPool,
                                Filter (with local-side Matches() for stores),
                                RelayInformation (NIP-11), Nip05. Includes
                                Storage/ subnamespace: INostrEventStore +
                                MemoryEventStore — local dedup, NIP-01
                                replaceable / addressable upsert, NIP-09
                                tombstones, NIP-40 expiration, NIP-01
                                ephemeral fan-out.
  NostrNet.Client/              NostrClient façade — RelayPool + optional key + helpers.
  NostrNet.Blossom/             Blossom protocol — NIP-B7 user server list (kind
                                10063) typed events + (future) HTTP client for
                                upload / download / list / delete against
                                Blossom servers. Extension methods on NostrClient
                                live here (not in Client) so the core packages
                                don't pull Blossom-specific code transitively.
  NostrNet.Marmot/              Marmot wire envelopes (kinds 30443/444/445),
                                IMarmotMlsProvider interface, MarmotChat 1:1 + group
                                helpers, NIP-59 wrap/unwrap of Welcomes. No MLS engine.
  NostrNet.Marmot.Mls.Native/   IMarmotMlsProvider implementation backed by OpenMLS
                                via the in-tree Rust FFI bridge. Sole MLS provider.
nostrnet-marmot-native/         Rust crate (cdylib + rlib). Wraps openmls 0.8 with
                                a C ABI consumed by NostrNet.Marmot.Mls.Native via
                                LibraryImport. SQLite-backed persistence.
tests/                          xUnit; vectors as embedded resources where applicable.
samples/                        CLI: gen post dm feed mine info verify vanity-* marmot-mls-smoke.
```

Single TFM `net10.0`. Central Package Management.
`<IsAotCompatible>true</IsAotCompatible>` on every shippable lib; AOT/trim
warnings fail the build. MIT license, Galaxoid Labs.

The Rust crate is required to build `NostrNet.Marmot.Mls.Native` from
source: `cargo` must be on PATH, plus a C compiler (rusqlite's
`bundled` feature compiles SQLite from C source via the `cc` crate —
macOS: Xcode CLI tools; Linux: build-essential; Windows: VS Build
Tools 2022 with the C++ workload). CI installs the Rust toolchain via
`dtolnay/rust-toolchain@stable`; the C compilers are pre-installed on
the GitHub Actions runners we use. Other shippable projects build
without either.

## Locked-in decisions

1. **Internal first.** Most non-essential public surface is `internal` +
   `[InternalsVisibleTo]` to siblings.
2. **secp256k1 is `NBitcoin.Secp256k1`**, wrapped behind a single internal
   `Secp256k1` static class in `NostrNet.Core/Secp256k1/`. **Do not leak the
   curve library type out of that file.** Swapping backends = rewriting one
   file.
3. **AOT-compatible.** All JSON via STJ source generators or hand-rolled
   `JsonElement`/`Utf8JsonWriter`. No reflection-based serialization.
4. **No DI / no logger dep.** No `IServiceCollection.AddNostr`, no
   `Microsoft.Extensions.Logging` reference.
5. **Span-based crypto, memory hygiene.** `PrivateKey.Dispose` zeros memory
   via `CryptographicOperations.ZeroMemory`. NIP-44 zeros conversation key
   + ECDH shared x in `finally`.
6. **Exceptions, not `Result<T,E>`.** `Try*` variants for parsing untrusted
   input; bool/nullable for normal protocol outcomes (relay rejection,
   sig-verify result).
7. **OpenMLS is the only MLS engine.** The earlier in-tree reference
   provider (`NostrNet.Marmot.Mls.Reference`) was a stepping stone and is
   gone. Don't reintroduce a pure-managed MLS — channel proposals through
   `IMarmotMlsProvider` so OpenMLS does the work.
8. **Storage is an interface, not a feature.** `INostrEventStore` lives
   in `NostrNet.Relay/Storage/` next to `Filter` (which it depends on
   for `Matches`). `MemoryEventStore` is the only in-tree impl.
   `IMarmotMlsProvider`-style: future `NostrNet.Storage.Sqlite` etc. are
   separate packages implementing the same interface. The interface
   semantics (NIP-01 replaceable + addressable upsert, NIP-09
   tombstones, NIP-40 expiration, NIP-01 ephemeral fan-out-but-no-persist)
   are spec-level guarantees; don't add `MemoryEventStoreOptions`-style
   knobs that diverge per-implementation. **`NostrClient.SubscribeAsync`
   auto-dedups when a store is attached**; `AttachAsync` is the
   fire-and-forget "fill the store" entry. The recommended app pattern
   is `AttachAsync` to subscribe + `store.ObserveAsync` to read.
9. **Typed access via static abstract interface members.** Every typed
   wrapper that maps to specific kind(s) implements
   `INostrTypedEvent<TSelf>` (Core/Events/) — a static `Kinds` property
   + static `TryFromEvent`. The generic extensions in
   `NostrNet.Client/Storage/TypedStoreExtensions.cs` (`ObserveAsync<T>`,
   `QueryAsync<T>`, `GetAsync<T>`) light up for any conforming type
   automatically. Adding a new typed wrapper means implementing the
   interface — no per-type extension methods to maintain.
   **`DeletionRequest` uses explicit interface implementation** because
   it has an instance `Kinds` property (the deletion's `k` tags) that
   would collide with the static interface `Kinds`. Future types with
   the same conflict should follow that pattern. Conversion failures
   (`TryFromEvent` returns false) are silently skipped — apps shouldn't
   see malformed events bubble up through the typed surface.

## NIPs implemented

| NIP | What | Where |
|----|------|-------|
| 01 | events, canonical id, BIP-340, relay protocol | Core + Relay |
| 02 | contact / follow list (kind 3) | Core/Contacts/ |
| 04 | legacy DM **decode only** (no encrypt method by design — spec obsolete) | Crypto/Nip04.cs |
| 05 | DNS-based identifier verification | Relay |
| 09 | event deletion requests (kind 5) with Targets() rule | Core/Deletions/ |
| 10 | thread/reply tagging (marker + legacy positional) | Core/Threading/ |
| 11 | relay info document | Relay |
| 13 | proof of work | Core/Events/ProofOfWork.cs |
| 17 | private DMs (over NIP-59) | Crypto/Nip17.cs |
| 18 | reposts (kinds 6 / 16) + quote-repost `q`-tag helper | Core/Reposts/ |
| 19 | bech32 entities (npub/nsec/note/nprofile/nevent/naddr) | Core/Nip19/ |
| 21 | `nostr:` URI scheme | Core/Nip19/Nip21.cs |
| 22 | threaded comments (kind 1111; E/A/I + e/a/i tag pairs) | Core/Comments/ |
| 23 | long-form articles & drafts (30023/30024) | Core/Articles/ |
| 25 | reactions (kind 7) with custom-emoji support | Core/Reactions/ |
| 38 | user statuses (kind 30315, parameterized replaceable by type) | Core/UserStatuses/ |
| 39 | external identity claims (`i` tags on kind-0 profile) | Core/Profiles/ExternalIdentity.cs |
| 42 | client-relay AUTH (challenge capture + auth event + send) | Core/Auth/ + Relay |
| 44 | v2 encrypted payloads | Crypto/Nip44.cs |
| 50 | full-text search (filter `search` field + capability check) | Relay/Filter.cs + Relay/RelayInformation.cs |
| 58 | badges (kinds 30009 Definition, 8 Award, 30008 Profile Badges) | Core/Badges/ |
| 51 | lists & sets (public + NIP-44 self-encrypted private items) | Crypto/Lists/ |
| 59 | gift wrap (used by NIP-17 and Marmot Welcomes) | Crypto/Nip59.cs |
| 65 | relay list metadata (kind 10002) | Core/RelayList/ |
| 98 | HTTP Auth (kind 27235, `Authorization: Nostr <b64>` + DelegatingHandler) | Core/HttpAuth/ |
| 68 | picture-first feeds (kind 20, imeta image attachments) | Core/Pictures/ |
| 71 | video events (kinds 21 / 22 regular + 34235 / 34236 addressable) | Core/Videos/ |
| 92 | media attachments via imeta tag (shared parser/builder) | Core/Encoding/Imeta.cs |
| 94 | file metadata events (kind 1063) | Core/Files/ |
| B0 | web bookmarks (kind 39701, parameterized replaceable by URL) | Core/Bookmarks/ |
| B7 | Blossom user server list (kind 10063) | **`NostrNet.Blossom`** package — `UserServers/` |
| Blossom BUDs 00–12 | HTTP client + auth events + URI scheme + resolver + `BlossomMediaClient` façade | `NostrNet.Blossom/{Blobs,Auth,Client,Discovery}/` + `BlossomMediaClient.cs` |

**Deferred:** NIP-07/46 (signers), NIP-57 zaps. Mechanical once needed.

## Marmot MIPs (MLS over Nostr)

| MIP | What | Where |
|----|------|-------|
| 00 | KeyPackage publication (kind 30443) | Marmot/Events/KeyPackageEvent.cs |
| 01 | Marmot Group Data extension (0xF2EE) | Marmot/GroupData/MarmotGroupDataExtension.cs |
| 02 | Welcome events (kind 444 in NIP-59 gift wrap) | Marmot/Events/WelcomeEvent.cs |
| 03 | Group event content encryption (kind 445, exporter-keyed) | Marmot/Events/GroupEvent.cs |

`IMarmotMlsProvider` (in `NostrNet.Marmot`) is the boundary between
envelope and MLS engine. The one provided implementation is
`NostrNet.Marmot.Mls.Native.OpenMlsProvider`, which wraps OpenMLS
through the Rust FFI in `nostrnet-marmot-native/`.

Group ops the provider implements (all RFC-9420 wire-compliant):

| Op | IMarmotMlsProvider method | MarmotChat helper |
|----|---------------------------|--------------------|
| publish KeyPackage | `BuildKeyPackageAsync` | `BuildKeyPackageEventAsync` |
| parse received KeyPackage | `ParseKeyPackageAsync` | (used by `StartConversationAsync` / `StartGroupAsync`) |
| create + start 1:1 | `CreateGroupAsync` + `AddMembersAsync` | `StartConversationAsync` |
| create + start N-party | `CreateGroupAsync` + `AddMembersAsync` (N kp) | `StartGroupAsync` |
| add peer to existing group | `AddMembersAsync` | `AddPeerAsync` |
| accept invite | `JoinGroupFromWelcomeAsync` | `TryAcceptInviteAsync` |
| send | `EncryptApplicationMessageAsync` | `EncryptMessageAsync` (wraps text in kind-9 rumor) |
| receive (richer) | `ProcessIncomingMlsMessageAsync` | `TryProcessMessageAsync` (unwraps rumor) |
| receive (plaintext-only) | (combines above) | `TryDecryptMessageAsync` |
| remove peer | `RemoveMembersAsync` | `RemovePeerAsync` |
| rotate own keys | `SelfUpdateAsync` | `RotateKeysAsync` |
| current exporter (kind-445 key) | `CurrentExporterSecretAsync` | (implicit via send/receive) |
| **enumerate groups** | `ListGroupsAsync` | (used by `NostrMarmotClient.LoadExistingConversationsAsync`) |
| **delete local group state** | `DeleteGroupAsync` | (call after `BuildSelfRemoveProposalAsync` for clean leave) |
| **vacuum SQLite** | `VacuumAsync` | — |

Concrete-only helpers on `OpenMlsProvider` (not on the interface,
because they need the file path):
- `Path` (string?) — the file path the provider was opened from.
- `StateInfoAsync()` → `MarmotStateInfo(Path, SizeOnDiskBytes, GroupCount)` — diagnostics.
- `WipeStateAsync()` — Dispose + delete the `.db` + `-shm` + `-wal` sidecars.

`MarmotConversation.Peer` is **nullable**: 1:1 conversations set it
to the other party; multi-member groups and conversations rehydrated
via `ListGroupsAsync` leave it null.

`NostrMarmotClient.AcceptInviteAsync` returns `MarmotConversation?`.
Returns `null` on expected-stale failures (NoMatchingKeyPackage —
local KP rotated away; GroupAlreadyExists — duplicate welcome) so
consumers don't surface protocol-noise errors for relay-cached
welcomes from earlier sessions.

`NostrMarmotClient.LoadExistingConversationsAsync` enumerates groups
on startup, derives the 1:1 peer where unambiguous, and starts
per-group kind-445 subscriptions. Standard "open the chat list"
primitive for apps.

State persistence:
- `new OpenMlsProvider()` — in-memory SQLite (lost on dispose).
- `OpenMlsProvider.OpenAtPath(path)` — file-backed SQLite. State survives restart.

Two distinct group identifiers, never conflate them:
- **`nostr_group_id`** (32 bytes): the `h`-tag value on kind-445
  events. Lives inside the NostrGroupData GroupContextExtension.
  This is what `MarmotConversation.NostrGroupId` carries and what
  every .NET-side API operates on.
- **MLS GroupId** (opaque, variable length): the inviter chose it.
  mdk-core / White Noise use 16-byte random ids. Our own
  `CreateGroupAsync` reuses the 32-byte `nostr_group_id` as the MLS
  GroupId, but joined groups don't.

The Rust crate maintains a `marmot_group_map(nostr_group_id BLOB
PRIMARY KEY, mls_group_id BLOB)` table on a second rusqlite
Connection so every FFI op can translate from the 32-byte
`nostr_group_id` to the right OpenMLS GroupId via
`group_map::lookup_mls`. The `lookup_mls` helper falls back to
returning the input unchanged when no row exists, preserving
backward compat with state DBs that predate the mapping table.

## FFI conventions (nostrnet-marmot-native ↔ NostrNet.Marmot.Mls.Native)

- All entry points return `i32`. `0` = success, negative = error.
  Last error message stored thread-local; surface via
  `marmot_last_error_message()` → `*const c_char`.
- ABI version is reported by `marmot_abi_version() -> u32`; managed
  side asserts on it at startup. **Bump the constant in
  `nostrnet-marmot-native/src/lib.rs` and the matching test
  (`LifecycleTests.NativeAbiVersion_IsN`) whenever the FFI surface
  changes — adding an export, changing a signature, or altering
  wire bytes.** Current value: `4`.
- Output buffers are Rust-allocated as `Box<[u8]>` then transferred to
  managed via `(out *mut u8, out usize)`. Managed copies + calls
  `marmot_buffer_free(ptr, len)`.
- Inputs are read-only `(*const u8, usize)`; no ownership transfer.
- Multi-element inputs (e.g. multiple KeyPackages for `add_members`,
  multiple pubkeys for `remove_members`) use length-prefixed blobs:
  `[u32 BE count] [u32 BE len_i] [bytes_i] ...` or
  `[u32 BE count] [32 bytes id_i] ...`.
- `marmot_list_groups` output: `[u32 BE count] { [32 bytes
  nostr_group_id] [u32 BE member_count] [member_count*32 bytes
  identity] }*`.
- Provider handle is opaque `*mut Provider`. `marmot_provider_new` for
  in-memory; `marmot_provider_open_at_path(c_char*)` for SQLite-backed.
- Storage is OpenMLS's storage trait, backed by SqliteStorageProvider
  with a JSON codec. **Single source of truth** — there is no
  in-memory state to "rehydrate." Signature keys for any group are
  looked up by `SignatureKeyPair::read(storage, own_leaf_pubkey, scheme)`.
- A **second** rusqlite Connection on the same path holds the
  `marmot_group_map` table (nostr_group_id ↔ MLS GroupId) and any
  future Marmot-specific metadata. Wrapped in `Mutex<Connection>`
  because rusqlite is `!Sync`.
- **Every FFI entry that touches the OpenMLS provider takes
  `provider.ffi_lock` first** via the `provider::lock_ffi` helper.
  openmls_sqlite_storage wraps its Connection in a `RefCell`; without
  the mutex, two concurrent FFI calls (an invite + a kind-445
  message arriving on different pump threads) would hit "RefCell
  already borrowed" and abort the process across the no-unwind FFI
  boundary. Lock is coarse-grained per Provider but MLS ops are
  sub-millisecond so contention is negligible.

## Marmot wire-format details

Hard-won during the White Noise / mdk-core interop work. Each
deviates from "obvious" and breaks silently if you get it wrong:

- **kind-30443 content** is the raw `KeyPackage` TLS bytes,
  base64-encoded — NOT wrapped in `MLSMessage(KeyPackage)`. The
  spec says "TLS-serialized `KeyPackageBundle`" which is loose
  wording; what mdk-core actually emits and consumes is the bare
  KeyPackage struct.
- **`d` tag** must be exactly 64 hex chars (32 bytes). mdk-core
  rejects anything else as a hard error before MLS validation.
  `MarmotChat.BuildKeyPackageEventAsync` auto-generates a
  **deterministic** slot from `sha256("marmot/keypackage-default-slot/v1"
  || pubkey)` when `slot` is null, so re-publishing replaces the
  previous addressable event under `(kind, pubkey, d)` instead of
  stacking new ones (which orphans old init keys after a state
  wipe).
- **`mls_extensions` tag** MUST include `0x000a` (LastResort) AND
  `0xf2ee` (NostrGroupData). The hex format is lowercase
  `0x` + 4 chars; mdk-core's validator is strict.
- **`mls_proposals` tag** MUST include `0x000a` (SelfRemove).
- **LeafNode capabilities** MUST advertise the same extensions +
  proposals (mdk-core / White Noise enforce this on inbound
  KeyPackages). KeyPackages we build are always marked
  `last_resort` for reusability.
- **GroupContext extensions** on every group: a 0xF2EE Unknown
  extension carrying the TLS-serialized
  `MarmotGroupDataExtension`, plus a `RequiredCapabilities`
  extension listing `Unknown(0xF2EE)` so non-Marmot members are
  refused.
- **wire_format_policy** is `MIXED_CIPHERTEXT_WIRE_FORMAT_POLICY`
  on group create (outgoing ciphertext, inbound accepts either).
- **kind-444 (Welcome rumor)** wire is an `MLSMessage(Welcome)` —
  this IS wrapped, unlike kind-30443. Content is base64.
- **kind-445 application payload** decrypts to a JSON-serialized
  **unsigned Nostr rumor** with `kind: 9` (Marmot chat message,
  per MIP-03 / NIP-C7). The chat content is the rumor's `.content`
  field. `MarmotChat.EncryptMessageAsync(..., senderKey, text)`
  builds the rumor via `SerializeChatRumor`; the receive path
  unwraps via `ExtractChatRumor` and falls back to raw UTF-8 for
  non-rumor payloads.

## Test vectors

| Suite | Source | Location |
|-------|--------|----------|
| BIP-173 bech32 | BIP-173 appendix | inline in `Bech32Tests.cs` |
| BIP-340 Schnorr | bitcoin/bips test-vectors.csv | embedded resource in Core.Tests |
| RFC 8439 ChaCha20 | RFC | inline in `ChaCha20Tests.cs` |
| NIP-44 official | paulmillr/nip44 | embedded resource in Crypto.Tests |
| MLS interop | _(deferred — no cross-impl vectors yet)_ | n/a |

**Rule:** find an interop vector before writing impl. Tests must pass
against external implementations.

## Security guarantees

- **Incoming events are verified automatically** in `RelayClient.Dispatch`
  before being written to the subscription channel. Bad id or bad sig →
  silently dropped. `NostrEvent.FromJson` is **not** auto-verified — caller
  responsibility.
- **NIP-17 unwrap re-verifies the inner seal** (sig + rumor-pubkey-equals-seal-author),
  so the surfaced `Sender` can't be spoofed by a malicious outer wrap.
- **NIP-05 verification is fail-closed.** Decode/HTTP/parse errors →
  `IsVerified=false` + `FailureReason`, never an exception bubbling out.
- **`RelayPool` does NOT dedup events.** It yields every relay's delivery
  of every event as a separate `SubscriptionEventReceived(Event, Relay)`.
  Consumers dedup if they want; `NostrClient.SubscribeAsync` exposes the
  relay info via `ReceivedEvent(Event, Relay)`.
- **Marmot MLS forward secrecy** is what OpenMLS gives us. Removed members
  lose access automatically (proven by `RemovePeer_RemovedMemberLosesAccess`).
  Key rotation is `MarmotChat.RotateKeysAsync` (MLS self-update). Commits
  must be processed BEFORE application messages from the new epoch — if
  relays deliver out of order, `TryDecryptMessage` returns null and the
  caller should park-and-retry.

## Vanity key generation

`Core/Keys/VanityKeyGenerator.cs` brute-forces a private key whose pubkey
matches a pattern: PoW leading-zero bits, npub bech32 prefix/suffix, or
hex prefix/suffix.

- Multi-threaded — one worker per logical core by default. Workers
  generate random scalars, derive pubkeys via the internal `Secp256k1`,
  and check the matcher. First match wins; the linked CTS cancels the rest.
- Progress is throttled to ~500ms cadence regardless of throughput. Workers
  only `Interlocked.Add` to a shared counter; a dedicated reporter task
  fires `IProgress<T>.Report`.
- Charset validation is **eager** — `MineNpubPrefixAsync("bob")` throws
  immediately because `b` isn't in the bech32 alphabet. This is the
  difference between a clear error and the loop running forever.
- Found `byte[]` private-key copies are zeroed with
  `CryptographicOperations.ZeroMemory` once they've been wrapped in
  `PrivateKey`. The losing workers also zero their `byte[]` copy if
  `TrySetResult` failed.

## Performance — hot-path notes

The receive→verify→dispatch path is where almost all CPU goes. Key
decisions to know before editing:

- **`EventSerializer.ComputeId`** writes canonical JSON into an
  `ArrayBufferWriter<byte>` and hashes its `WrittenSpan` — no
  `ToArray()` copy. Pubkey hex written via stack buffer + `HexAscii` LUT,
  never a `string`.
- **`NostrEvent.FromJsonElement(JsonElement)`** is the parse path used by
  `RelayMessage.ParseEvent` — no `GetRawText()` re-parse.
  **`NostrEvent.WriteTo(Utf8JsonWriter)`** is the serialize path used by
  `RelayProtocol.BuildEventLikeMessage` — no `ToJson()` round-trip.
- **`RelayClient.ReceiveLoopAsync`** stays in bytes throughout: pooled
  receive buffer + `ArrayBufferWriter<byte>` for multi-frame assembly +
  `JsonDocument.Parse(memory)` direct from bytes. Call
  `pending.ResetWrittenCount()` between messages (not `Clear`).
- **`Bech32.Encode`** stack-allocates a 256-char buffer for typical NIP-19
  outputs; `ArrayPool<char>` for the rare large `naddr`.

If you change `ComputeId` or `FromJsonElement`, run the full test suite —
they're load-bearing for every NIP that builds or parses events.

## Gotchas / footguns

- **`Encoding` namespace clash.** `NostrNet.Encoding` and
  `NostrNet.Marmot.Encoding` (bech32, TLV) shadow `System.Text.Encoding`.
  Files needing `Encoding.UTF8` must add
  `using SysEncoding = System.Text.Encoding;` and use `SysEncoding.UTF8`.
  In test files near the Marmot namespace this also bites
  `Encoding.ASCII` etc. Same fix.
- **xUnit `Assert.Throws<T>(() => F())` and value-returning lambdas.** The
  compiler may bind to the obsolete `Func<Task>` overload. Wrap in a
  statement block: `Assert.Throws<T>(() => { F(); });`.
- **STJ source-gen rejects ref-like types in serialized records.**
  `PublicKey` (ctor takes `ReadOnlySpan<byte>`) trips SYSLIB1225. Mark such
  properties `[JsonIgnore]` and set them after deserialization
  (`Profile.Owner` does this).
- **`stackalloc` into ref-struct method args.** Methods on `ref struct`
  taking `ReadOnlySpan<byte>` need the parameter declared `scoped`
  (`TlvWriter.TryWrite`).
- **Raw-string `$$"""..."""` with JSON.** A `}}` at the end of a JSON
  literal is parsed as an interpolation close. Use string concatenation or
  bump to `$$$"""..."""`.
- **NIP-01 canonical content escapes** must use
  `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` — do NOT escape `<`, `>`,
  `&`, `/`, non-ASCII.
- **NIP-05 `HttpClient` has `AllowAutoRedirect = false`** (spec MUST).
  Don't replace the shared instance with a default client.
- **Internal `Secp256k1` access.** Consumers outside `NostrNet.Core` add
  themselves to `Core.csproj`'s `<InternalsVisibleTo>` (already done for
  Crypto, Relay, Marmot, both test projects). **Never make it public.**
  `NostrNet.Marmot` is on the list so `MarmotChat.SerializeChatRumor`
  can reuse `EventSerializer.ComputeId`.
- **MLS Commit ordering.** If a Commit (epoch-advance) and an
  application message from the new epoch are delivered out of order,
  `TryDecryptMessage` on the app message returns null because the
  receiver doesn't have the new exporter yet. App code should park-and-retry
  on null; the next Commit fires the exporter rotation.
- **Cargo build is required** to compile NostrNet.Marmot.Mls.Native from
  source. The csproj's `CargoBuild` MSBuild target shells out to
  `cargo build`. If Rust isn't on PATH, the project fails fast at build
  time. Other projects (Core, Crypto, Relay, Client, Marmot) build
  without it.
- **Test FakeProviders must implement the full `IMarmotMlsProvider`
  surface.** Adding a method here without updating
  `tests/NostrNet.Marmot.Tests/MarmotChatTests.cs` `FakeProvider`
  fails the build with CS0535. The CLI sample's fake relay
  (`NostrMarmotClientTests.FakeRelay`) similarly tracks
  `IMarmotRelay`.
- **State-DB wipe ritual.** Wire-format changes (preview2 → preview7)
  invalidate previously-stored state. When in doubt during interop
  testing, call `OpenMlsProvider.WipeStateAsync()` or delete the
  `.db` + `-shm` + `-wal` files manually. Stale entries (signature
  keys for KPs published under old capabilities, joined groups with
  wrong required-capabilities, etc.) get reused by OpenMLS and
  produce confusing failures.
- **White Noise interop is tested manually**, not in CI. The
  reference implementation (`mdk-core` / `whitenoise-rs`) lives at
  github.com/marmot-protocol; check there when fixing a new
  interop break. Wire-form decisions visible in
  `crates/mdk-core/src/{key_packages,welcomes,groups,messages,extension/types}.rs`.

## Documentation, file layout, build

- Every `public` API has an XML doc comment; `GenerateDocumentationFile=true`
  + `TreatWarningsAsErrors=true` makes missing docs a build error.
  `<summary>` is one sentence; `<exception>` on anything that throws.
  Code comments are for *why*, never *what*.
- One public type per file. Folder = sub-namespace.
  `tests/Foo/FooTests.cs` mirrors `src/.../Foo.cs`.
- `dotnet build` and `dotnet test` from repo root. CLI sample:
  `dotnet run --project samples/NostrNet.Sample.Console -- <cmd>`. Test
  discovery via `NostrNet.slnx` (slnx is the new XML solution format).
- CI: `.github/workflows/ci.yml` (matrix on ubuntu/windows/macos +
  AOT smoke). Each runner installs Rust via `dtolnay/rust-toolchain@stable`
  and caches cargo registry + target dir.
- Docs site: `.github/workflows/docs.yml` builds a DocFX site from XML
  doc comments + the `docs/` markdown content and deploys to GitHub
  Pages on every push to main. Site lives at
  https://galaxoid-labs.github.io/NostrNet/. Local preview:
  `dotnet tool install -g docfx`, then `cp logo.png docs/images/`,
  then `docfx docs/docfx.json --serve`. Generated `docs/api/*.yml` and
  `docs/_site/` are gitignored.
- Release: `release.yml` (v* tags → `.nupkg` files attached to a
  GitHub release AND pushed to nuget.org via `NUGET_API_KEY` secret).
  The Native package is multi-RID: the workflow cross-compiles six
  artifacts (osx/linux/win × x64/arm64) in parallel and the csproj
  packs them under `runtimes/<rid>/native/` via the `prebuilt/` glob.
  `--skip-duplicate` on the push step makes re-running the workflow
  on the same tag a no-op.
