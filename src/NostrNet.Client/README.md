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

For Marmot (MLS-over-Nostr) group messaging, additionally reference
`NostrNet.Marmot` + an MLS provider package (`NostrNet.Marmot.Mls.Native`).

Full quickstart: see the main project
[README](https://github.com/Galaxoid-Labs/NostrNet).
