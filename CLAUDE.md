# NostrNet — Maintainer Notes

Cross-platform .NET 10 Nostr library. This file is for AI assistants /
maintainers; user-facing docs live in `README.md`.

## Architecture

```
src/
  NostrNet.Core/      Keys, events, NIP-01 canonical id, NIP-19 bech32,
                      Profile (kind 0), Articles (NIP-23), internal Secp256k1
                      wrapper. No I/O.
  NostrNet.Crypto/    ChaCha20 (RFC 8439), NIP-44 v2, NIP-17/59 gift wrap,
                      NIP-51 lists. Uses Core's internal Secp256k1.
  NostrNet.Relay/     ClientWebSocket-based RelayClient, RelayPool, Filter,
                      RelayInformation (NIP-11), Nip05.
  NostrNet.Client/    NostrClient façade — RelayPool + optional key + helpers.
tests/                xUnit; vectors as embedded resources where applicable.
samples/              CLI: gen post dm feed mine info verify.
```

Single TFM `net10.0`. Central Package Management.
`<IsAotCompatible>true</IsAotCompatible>` on every shippable lib; AOT/trim
warnings fail the build. MIT license, Galaxoid Labs.

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

## NIPs implemented

| NIP | What | Where |
|----|------|-------|
| 01 | events, canonical id, BIP-340, relay protocol | Core + Relay |
| 04 | legacy DM **decode only** (encrypt obsoleted) | (placeholder) |
| 05 | DNS-based identifier verification | Relay |
| 11 | relay info document | Relay |
| 13 | proof of work | Core/Events/ProofOfWork.cs |
| 17 | private DMs (over NIP-59) | Crypto/Nip17.cs |
| 19 | bech32 entities (npub/nsec/note/nprofile/nevent/naddr) | Core/Nip19/ |
| 21 | `nostr:` URI scheme | Core/Nip19/Nip21.cs |
| 22 | threaded comments (kind 1111; E/A/I + e/a/i tag pairs) | Core/Comments/ |
| 23 | long-form articles & drafts (30023/30024) | Core/Articles/ |
| 42 | client-relay AUTH (challenge capture + auth event + send) | Core/Auth/ + Relay |
| 44 | v2 encrypted payloads | Crypto/Nip44.cs |
| 51 | lists & sets (public + NIP-44 self-encrypted private items) | Crypto/Lists/ |
| 59 | gift wrap (used by NIP-17) | Crypto/Nip17.cs |
| 65 | relay list metadata (kind 10002) | Core/RelayList/ |
| B0 | web bookmarks (kind 39701, parameterized replaceable by URL) | Core/Bookmarks/ |

**Deferred:** NIP-02 contacts, NIP-07/46, NIP-57 zaps, NIP-09/25/10.
Mechanical once needed.

## Test vectors

| Suite | Source | Location |
|-------|--------|----------|
| BIP-173 bech32 | BIP-173 appendix | inline in `Bech32Tests.cs` |
| BIP-340 Schnorr | bitcoin/bips test-vectors.csv | embedded resource in Core.Tests |
| RFC 8439 ChaCha20 | RFC | inline in `ChaCha20Tests.cs` |
| NIP-44 official | paulmillr/nip44 | embedded resource in Crypto.Tests |
| NIP-19 / event id interop | Galaxoid Labs Swift Nostr | inline |

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

- **`Encoding` namespace clash.** `NostrNet.Encoding` (bech32, TLV) shadows
  `System.Text.Encoding`. Files needing `Encoding.UTF8` must add
  `using SysEncoding = System.Text.Encoding;` and use `SysEncoding.UTF8`.
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
  Crypto, Relay, both test projects). **Never make it public.**

## Documentation, file layout, build

- Every `public` API has an XML doc comment; `GenerateDocumentationFile=true`
  + `TreatWarningsAsErrors=true` makes missing docs a build error.
  `<summary>` is one sentence; `<exception>` on anything that throws.
  Code comments are for *why*, never *what*.
- One public type per file. Folder = sub-namespace.
  `tests/Foo/FooTests.cs` mirrors `src/.../Foo.cs`.
- `dotnet build && dotnet test` from repo root. CLI sample:
  `dotnet run --project samples/NostrNet.Sample.Console -- <cmd>`.
- CI: `.github/workflows/ci.yml` (matrix + AOT smoke) and
  `release.yml` (v* tags → `.nupkg` files attached to GitHub release).
