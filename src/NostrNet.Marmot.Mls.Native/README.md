# NostrNet.Marmot.Mls.Native

OpenMLS-backed `IMarmotMlsProvider` implementation for
[NostrNet.Marmot](https://www.nuget.org/packages/NostrNet.Marmot). Wire
bytes are RFC 9420 compliant by construction — the package wraps
[OpenMLS](https://github.com/openmls/openmls) (Rust) via an in-tree FFI
bridge.

## Install

```sh
dotnet add package NostrNet.Marmot.Mls.Native
```

The package ships pre-built native binaries for the supported runtime
identifiers. No Rust toolchain required at consume time.

Supported RIDs:

- `linux-x64`, `linux-arm64`
- `osx-x64`, `osx-arm64`
- `win-x64`, `win-arm64`

(Mobile RIDs `ios-arm64` / `android-arm64` aren't shipped yet — iOS
needs static linking + .NET workload integration; Android needs NDK
packaging. Tracking separately.)

## Quickstart

```csharp
using NostrNet.Marmot;
using NostrNet.Marmot.Mls.Native;

// In-memory state (lost on dispose):
using var provider = new OpenMlsProvider();

// — or — persisted across process restarts:
//   using var provider = OpenMlsProvider.OpenAtPath("/var/app/marmot.sqlite");

// Use the MarmotChat helpers exactly as documented in NostrNet.Marmot:
var ev = await MarmotChat.BuildKeyPackageEventAsync(provider, myKey, "default", relays);
// ... StartConversationAsync, StartGroupAsync, AddPeerAsync, RemovePeerAsync,
//     RotateKeysAsync, EncryptMessageAsync, TryDecryptMessageAsync, ...
```

See [`NostrNet.Marmot`'s README](https://github.com/Galaxoid-Labs/NostrNet/blob/main/src/NostrNet.Marmot/README.md)
for the full API walkthrough including group operations.

## What's inside the box

| Subsystem | Provided by |
|----|----|
| MLS protocol (RFC 9420) | OpenMLS 0.8 + RustCrypto |
| Storage backend | SQLite via `openmls_sqlite_storage` (rusqlite, bundled — no system SQLite required) |
| Crypto primitives | RustCrypto (X25519, Ed25519, AES-GCM, HKDF-SHA-256) |
| Wire format | OpenMLS-native (Welcomes, KeyPackages, Commits, PrivateMessages all in `MLSMessage` envelopes) |

## Building from source

The Rust crate lives at [`nostrnet-marmot-native/`](https://github.com/Galaxoid-Labs/NostrNet/tree/main/nostrnet-marmot-native).
A source build of this package requires `cargo` on PATH; the
`NostrNet.Marmot.Mls.Native.csproj` invokes `cargo build` before the
.NET build via an MSBuild target.

## Status

Pre-1.0 preview. Wire format is RFC 9420 (= what other MLS
implementations produce), but cross-implementation interop hasn't been
verified against an external client yet. API may change before 1.0.
