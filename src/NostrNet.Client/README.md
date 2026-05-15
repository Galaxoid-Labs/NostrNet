<p align="center">
  <img src="https://raw.githubusercontent.com/Galaxoid-Labs/NostrNet/main/logo.png" alt="NostrNet" width="320" />
</p>

# NostrNet.Client

High-level façade for the [NostrNet](https://github.com/Galaxoid-Labs/NostrNet)
.NET 10 Nostr client library. Pulls in `NostrNet.Core`, `NostrNet.Crypto`,
and `NostrNet.Relay` transitively — most apps need only this one
reference.

```csharp
using NostrNet.Client;
using NostrNet.Keys;

using var key = PrivateKey.Generate();
await using var client = await NostrClient.Builder(key)
    .UseRelays("wss://relay.damus.io", "wss://nos.lol")
    .ConnectAsync();

await client.PostNoteAsync("Hello, Nostr!");
```

## With a local event store

Attach an `INostrEventStore` for auto-dedup across relays, NIP-01
replaceable / addressable upsert, NIP-09 deletion handling, NIP-40
expiration, and live reactive queries:

```csharp
using NostrNet.Client.Storage;     // generic typed accessors
using NostrNet.Profiles;
using NostrNet.Relay;
using NostrNet.Relay.Storage;

var store = new MemoryEventStore();

await using var client = await NostrClient.Builder(key)
    .WithEventStore(store)
    .UseRelays("wss://relay.damus.io", "wss://nos.lol")
    .ConnectAsync();

// Subscribe — events flow into the store; you don't iterate this call.
_ = client.AttachAsync(new[]
{
    new Filter { Kinds = new[] { 0, 1 }, Authors = new[] { key.PublicKey.ToHex() } },
}, ct);

// Read typed values — Profile.Kinds = [0] is applied automatically.
await foreach (var profile in store.ObserveAsync<Profile>(ct: ct))
    cache[profile.Owner!] = profile;
```

For Marmot (MLS-over-Nostr) group messaging, additionally reference
`NostrNet.Marmot` + an MLS provider package (`NostrNet.Marmot.Mls.Native`).

Full quickstart and the typed-access reference table: see the main project
[README](https://github.com/Galaxoid-Labs/NostrNet).
