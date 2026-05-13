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
| [42](https://github.com/nostr-protocol/nips/blob/master/42.md) | AUTH (challenge parsed; client-side helper pending) |
| [44](https://github.com/nostr-protocol/nips/blob/master/44.md) | v2 encrypted payloads (ChaCha20 + HMAC-SHA256 + HKDF) |
| [59](https://github.com/nostr-protocol/nips/blob/master/59.md) | Gift wrap |

Tested against the official BIP-340, BIP-173, RFC 8439, NIP-44, and Galaxoid
Labs Swift Nostr interop vectors — **300+ tests, zero warnings.**

## Install

> _Not yet on NuGet._ Build from source:

```sh
git clone <repo>
cd NostrNet
dotnet build
dotnet test
```

Requires the **.NET 10 SDK**.

## Project layout

| Package | Responsibility |
|---------|---------------|
| `NostrNet.Core`   | Keys, events, canonical serialization, NIP-19 bech32, `Profile`, internal secp256k1 wrapper |
| `NostrNet.Crypto` | ChaCha20, NIP-44 v2, NIP-17/59 gift wrap |
| `NostrNet.Relay`  | WebSocket client, `RelayPool`, `Filter`, NIP-11 fetch, NIP-05 verify |
| `NostrNet.Client` | High-level `NostrClient` façade |

For most apps, reference only `NostrNet.Client` — it pulls in everything you
need transitively.

---

## Quickstart

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

### Subscribe to events

```csharp
using NostrNet.Relay;

// Your own notes from the last hour
var filter = new Filter
{
    Authors = [key.PublicKey.ToHex()],
    Kinds = [1],
    Since = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds(),
    Limit = 50,
};

await foreach (var ev in client.SubscribeAsync([filter]))
    Console.WriteLine($"{ev.CreatedAt}  {ev.Content}");

// Convenience for the common case
await foreach (var note in client.SubscribeNotesAsync(
    authors: [key.PublicKey], limit: 50))
    Console.WriteLine(note.Content);
```

Subscriptions are `IAsyncEnumerable<NostrEvent>` — they yield events as they
arrive and complete when the relay closes the subscription or the
`CancellationToken` fires.

### NIP-17 direct messages

```csharp
var bob = PublicKey.FromNpub("npub1...");

// Send
await client.SendDirectMessageAsync(bob, "hey bob");

// Receive — gift wraps are unwrapped automatically
await foreach (var dm in client.SubscribeDirectMessagesAsync())
    Console.WriteLine($"{dm.Sender.ToNpub()}: {dm.Plaintext}");
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
