# NostrNet.Marmot.Mls.Reference

> ⚠️ **EXPERIMENTAL — diagnostic id `NMARMOT0001`.** This is a minimal,
> in-tree, pure-managed MLS implementation suitable for prototyping a
> two-member [Marmot](https://github.com/marmot-protocol/marmot) group.
> It is **not audited**, **not constant-time hardened**, and **does not
> interop with OpenMLS** or any other MLS implementation. Use a real MLS
> provider (e.g. an OpenMLS FFI wrapper) for production.

An in-tree `IMarmotMlsProvider` implementation backed by pure-managed
[BouncyCastle](https://www.bouncycastle.org/csharp/index.html) crypto.

Useful as:

- A working reference for what `IMarmotMlsProvider` should do.
- A smoke test that the rest of `NostrNet.Marmot` (envelopes, NIP-59,
  kind-445 encryption) plumbs correctly to a real MLS exporter secret.
- A prototype harness when you're iterating on Marmot client code and
  don't want to bring an MLS engine to the table yet.

## What's supported

- **One MLS ciphersuite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
  (0x0001) — X25519, HKDF-SHA-256, AES-128-GCM, Ed25519.
- **HPKE base mode** per RFC 9180 (DHKEM(X25519, HKDF-SHA-256) + AES-128-GCM).
- **MLS key schedule** per RFC 9420 §9 — `joiner_secret`, `welcome_secret`,
  `member_secret`, `epoch_secret`, and all leaf derivations including
  `exporter_secret` and `MLS-Exporter`.
- **KeyPackages**: build, sign (`LeafNodeTBS` / `KeyPackageTBS`), verify, ref-hash.
- **Group lifecycle**: founder bootstrap → single Add → Welcome →
  joiner-side processing with signature + tree-hash + confirmation-tag verification.
- **2-member groups** end-to-end: after `AddMembersAsync` +
  `JoinGroupFromWelcomeAsync`, both sides derive identical
  `MLS-Exporter("marmot", "group-event", 32)` outputs that Marmot
  kind-445 GroupEvent content encryption keys off.
- **Per-leaf application-message ratchet** for `EncryptApplicationMessageAsync` /
  `ProcessIncomingMlsMessageAsync` — forward secrecy per message, plus
  replay protection via a high-water-mark generation counter. Uses a
  simplified subset of RFC 9420 §6.3 + §15 (no sender-data encryption,
  no ciphersuite-sample binding, no reuse_guard) and a private-use wire
  format (`0xFE02`); see `Wire/ApplicationMessage.cs`.
- **Standard MLSMessage envelope** for KeyPackage and Welcome bytes
  (RFC 9420 §6.1): `uint16(version) || uint16(wire_format) || body`.
  This is the form Marmot kind-30443 and the Welcome rumor content
  carry on the wire, and is parseable by any RFC-9420 MLS library.

## What's NOT supported

These all throw `NotSupportedException`:

- Groups with more than two members (no TreeKEM at depth > 1).
- Member removal, Update proposals, PSK injections, ReInit, external joins.
- Interop with OpenMLS or any other RFC 9420 implementation. Several
  intentional simplifications make this self-interop only (KeyPackage
  and Welcome bytes are now MLSMessage-wrapped, but the deeper layers
  still diverge):
  1. `confirmed_transcript_hash` is the empty byte string (no real
     transcript hashing across Commits).
  2. The founder's leaf travels in a **private-use** extension type
     (`0xFE01`) inside `GroupInfo` instead of the standard
     `ratchet_tree` extension.
  3. HPKE `info` for `encrypted_group_secrets` is the
     `encrypted_group_info` bytes (not `encoded(GroupContext)`), to
     sidestep the joiner-side chicken-and-egg between GroupContext and
     GroupInfo.

## Using it

The class is annotated with `[Experimental("NMARMOT0001")]`. Consumers
must explicitly acknowledge the warning, either at the call site:

```csharp
#pragma warning disable NMARMOT0001
IMarmotMlsProvider provider = new ReferenceMarmotMlsProvider();
#pragma warning restore NMARMOT0001
```

or globally in the consuming csproj:

```xml
<PropertyGroup>
  <NoWarn>$(NoWarn);NMARMOT0001</NoWarn>
</PropertyGroup>
```

## Source layout

| Folder | What |
|--------|------|
| `Crypto/`  | X25519, Ed25519, HKDF + labeled variants, HPKE base mode |
| `Wire/`    | TLS-encoded MLS structs (BasicCredential, LeafNode, KeyPackage, GroupContext, GroupInfo, GroupSecrets, Welcome) and tree-hash helpers |
| `KeySchedule.cs` | RFC 9420 §9 derivations |
| `Group.cs` | The group state machine — `CreateAsFounder`, `AddMember`, `JoinFromWelcome` |
| `ReferenceMarmotMlsProvider.cs` | `IMarmotMlsProvider` implementation glue |

Most of these types are `internal` — the only public surface is
`ReferenceMarmotMlsProvider` plus `ExperimentalDiagnostics`. Tests reach
the internals via `[InternalsVisibleTo]`.

## Sample CLI

The repo's sample app exposes a `marmot-mls-smoke` subcommand that runs
the full Alice/Bob/Welcome/exporter/kind-445 round-trip without touching
the network. CI runs the AOT-published binary's smoke test on every push.

```sh
dotnet run --project samples/NostrNet.Sample.Console -- marmot-mls-smoke
```
