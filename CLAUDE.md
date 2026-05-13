# NostrNet — Maintainer Notes

A cross-platform .NET 10 Nostr library. This file is the working brief for
Claude/AI assistants modifying the codebase. User-facing docs live in
`README.md`.

## Architecture at a glance

```
NostrNet.sln
├── src/
│   ├── NostrNet.Core/      Keys, events, NIP-01 canonical serialization,
│   │                       NIP-19 (bech32 entities), Profile (kind-0),
│   │                       internal Secp256k1 wrapper. No I/O.
│   ├── NostrNet.Crypto/    ChaCha20 (RFC 8439), NIP-44 v2, NIP-17/59 gift wrap.
│   │                       Depends on Core's internal Secp256k1 via InternalsVisibleTo.
│   ├── NostrNet.Relay/     WebSocket relay client, RelayPool, Filter, NIP-11,
│   │                       NIP-05 (HTTPS-based identifier verification).
│   └── NostrNet.Client/    NostrClient façade — combines key + RelayPool +
│                           ergonomic helpers.
├── tests/
│   └── *.Tests/            xUnit; vectors embedded as resources where applicable.
└── samples/
    └── NostrNet.Sample.Console/   CLI: gen, post, dm, feed, mine, info, verify.
```

Single TFM (`net10.0`). Central Package Management via `Directory.Packages.props`.
`<IsAotCompatible>true</IsAotCompatible>` is enforced on every shippable
library; AOT/trim warnings fail the build.

## Locked-in decisions

1. **Internal first, NuGet later.** Public surface is intentionally tight.
   Most helpers are `internal` with `InternalsVisibleTo` to sibling projects
   and test projects.
2. **secp256k1 is `NBitcoin.Secp256k1`**, wrapped behind a single internal
   `Secp256k1` static class in `NostrNet.Core/Secp256k1/`. Swapping to
   libsecp256k1 P/Invoke later means rewriting that one file. **Do not
   leak the curve library type out of that file.**
3. **AOT-compatible.** All JSON goes through STJ source generators
   (`JsonSerializerContext` partials). No reflection-based serialization
   anywhere in shippable code.
4. **No `IServiceCollection.AddNostr`**, no `ILogger` dep. Optional
   `ILogger` injected via ctor parameter only if warranted (currently
   nothing logs).
5. **Span-based crypto.** Every crypto API takes/returns `ReadOnlySpan<byte>`/`Span<byte>`.
   `PrivateKey` zeros memory on `Dispose` (via `CryptographicOperations.ZeroMemory`).
6. **No `Result<T, E>`.** Exceptions for malformed-input / unreachable cases,
   `Try*` variants for parsing untrusted input, bool/nullable for normal
   protocol outcomes (relay rejection, signature-verify result, etc.).
7. **MIT license.** Copyright Galaxoid Labs.

## NIPs implemented

| NIP | What | Where |
|----|------|-------|
| 01 | events, canonical id, BIP-340 signing, relay protocol | Core + Relay |
| 04 | legacy DM **decode only** (encrypt marked `[Obsolete]`) | Crypto (not in tests yet) |
| 05 | DNS-based identifier verification + Profile (kind 0) | Relay |
| 11 | relay information document | Relay |
| 13 | proof of work | Core/Events/ProofOfWork.cs |
| 17 | private DMs (over NIP-59) | Crypto/Nip17.cs |
| 19 | bech32 entities (`npub`, `nsec`, `note`, `nprofile`, `nevent`, `naddr`) | Core/Nip19/ |
| 21 | `nostr:` URI scheme | Core/Nip19/Nip21.cs |
| 42 | AUTH messages parsed; client-side helper not yet exposed | Relay (parser only) |
| 44 | v2 encrypted payloads | Crypto/Nip44.cs |
| 59 | gift wrap (used by NIP-17) | Crypto/Nip17.cs |

**Not implemented (deferred):** NIP-02 (contact list helpers), NIP-07/46/65,
NIP-57 zaps, NIP-09 deletion helpers, NIP-25 reactions, NIP-10 reply
threading helpers. Adding them is mechanical given the building blocks.

## Test vector sources

| Suite | Source | Where embedded |
|-------|--------|---------------|
| BIP-173 bech32 valid/invalid | bitcoin/bips bip-0173 appendix | `Bech32Tests.cs` inline |
| BIP-340 Schnorr | bitcoin/bips bip-0340/test-vectors.csv | `tests/NostrNet.Core.Tests/TestVectors/` (embedded resource) |
| RFC 8439 ChaCha20 §2.3.2 + §2.4.2 | RFC 8439 | `ChaCha20Tests.cs` inline |
| NIP-44 v2 official | paulmillr/nip44 nip44.vectors.json | `tests/NostrNet.Crypto.Tests/TestVectors/` (embedded resource) |
| NIP-19 nprofile/nevent/naddr | Galaxoid Labs Swift Nostr tests | `Nip19Tests.cs` + `Bech32Tests.cs` inline |
| Event id / signature interop | Swift Nostr (`da036de7…`, `f603166e…`) | `NostrEventTests.cs` inline |
| NIP-13 partial-byte bit count | NIP-13 spec examples | `ProofOfWorkTests.cs` inline |

**When adding new code that interacts with a NIP, find an interop vector
before writing the impl.** Tests must pass against external implementations,
not just round-trip their own output.

## Gotchas / footguns

- **`Encoding` namespace clash.** We have `NostrNet.Encoding` (bech32, TLV).
  Any file that uses `System.Text.Encoding.UTF8` must add
  `using SysEncoding = System.Text.Encoding;` and write `SysEncoding.UTF8`.
  Otherwise `Encoding.UTF8` resolves to the nonexistent
  `NostrNet.Encoding.UTF8` and the compiler complains.
- **xUnit `Assert.Throws<T>(() => F())` and value-returning lambdas.**
  When the lambda returns a non-`Task` value, the compiler may bind to the
  obsolete `Func<Task>` overload. Wrap in a statement block:
  `Assert.Throws<T>(() => { F(); });`
- **STJ source-gen rejects ref-like types in serialized records.**
  `Profile.Owner` is a `PublicKey` (constructed from `ReadOnlySpan<byte>`),
  which trips the SYSLIB1225 generator error. Mark such properties
  `[JsonIgnore]` — set them programmatically after deserialization.
- **`stackalloc` into ref-struct method args.** Methods on `ref struct`
  taking `ReadOnlySpan<byte>` need the parameter declared `scoped` so
  callers can pass a stackalloc'd buffer (`TlvWriter.TryWrite`).
- **Raw string interpolation `$$"""..."""` with JSON.** A `}}` at the end
  of a JSON literal is parsed as an interpolation close, even with no
  matching `{{`. Either escape with `$$$` and triple-brace interpolation,
  or use plain string concatenation.
- **NIP-01 canonical content escapes.** Use
  `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` — do NOT escape `<`, `>`,
  `&`, `/`, or non-ASCII. The 7 NIP-01 short-form escapes (`\n \r \t \b \f \" \\`)
  are produced automatically.
- **NIP-05 redirect ban.** The shared `HttpClient` in `Nip05.cs` is
  constructed with `AllowAutoRedirect = false`. Don't replace it with a
  default client.
- **Internal Secp256k1 leaks.** If you need ECDH/sign/verify outside
  `NostrNet.Core`, add the calling assembly to `Core`'s `InternalsVisibleTo`
  (already done for `NostrNet.Crypto`, `NostrNet.Core.Tests`,
  `NostrNet.Crypto.Tests`). Do **not** make `Secp256k1` public.

## Documentation standards

- Every `public` API has an XML doc comment. `GenerateDocumentationFile=true`
  + `TreatWarningsAsErrors=true` make CS1591 a build error.
- `<summary>` is one sentence. What it does, not how. If more is needed,
  add `<remarks>`.
- `<exception>` on anything that throws (except trivial `ArgumentNullException`
  covered by NRT). `<param>` on non-obvious parameters (lengths, formats,
  lifetime).
- Cite the NIP/BIP/RFC in `<remarks>` with section numbers when behavior is
  spec-defined.
- Tone: factual, present tense. "Signs the event." not "This method will sign
  the event."
- **In code comments are for *why*, not *what*.** Default to none.

## File layout conventions

- One public type per file (small private helpers can co-locate).
- Folder = sub-namespace. `Events/` → `NostrNet.Events`.
- Test file name mirrors source: `Foo.cs` → `FooTests.cs`.
- Cross-project test discoverability: tests reach internals via
  `[InternalsVisibleTo("…")]` declared in the target project's csproj.

## Build / CI

- `dotnet restore && dotnet build && dotnet test` from repo root.
- Sample CLI: `dotnet run --project samples/NostrNet.Sample.Console -- <cmd>`.
- CI target: GitHub Actions matrix on `windows-latest` / `macos-latest` /
  `ubuntu-latest` (Mac + Windows are the priority platforms). Not yet
  wired; deferred until publishing.
- `Directory.Build.props` (root): TFM, nullable, warnings-as-errors,
  code-style enforcement.
- `src/Directory.Build.props`: AOT/trim, doc generation, NuGet metadata.
- `tests/Directory.Build.props`: relax doc generation, mark `IsTestProject`.
