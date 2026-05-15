---
_layout: landing
title: NostrNet
---

<p align="center">
  <img src="images/logo.png" alt="NostrNet" width="320" />
</p>

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

## Packages

| Package | What it is |
|---------|------------|
| [**NostrNet.Core**](https://github.com/Galaxoid-Labs/NostrNet/tree/main/src/NostrNet.Core) | Keys, events, NIP-01, NIP-19 bech32, profiles, articles, threading, reactions |
| [**NostrNet.Crypto**](https://github.com/Galaxoid-Labs/NostrNet/tree/main/src/NostrNet.Crypto) | ChaCha20, NIP-44 v2, NIP-17 DMs, NIP-59 gift wrap, NIP-51 lists |
| [**NostrNet.Relay**](https://github.com/Galaxoid-Labs/NostrNet/tree/main/src/NostrNet.Relay) | WebSocket relay client, RelayPool, NIP-11 info, NIP-05 verification |
| [**NostrNet.Client**](https://github.com/Galaxoid-Labs/NostrNet/tree/main/src/NostrNet.Client) | High-level `NostrClient` façade — pool + key + helpers |
| [**NostrNet.Blossom**](https://github.com/Galaxoid-Labs/NostrNet/tree/main/src/NostrNet.Blossom) | Blossom content-addressed media (BUDs 00–12) + NIP-B7 user servers |
| [**NostrNet.Marmot**](https://github.com/Galaxoid-Labs/NostrNet/tree/main/src/NostrNet.Marmot) | Marmot MLS-over-Nostr envelopes + chat helpers (kinds 443/444/445) |
| [**NostrNet.Marmot.Mls.Native**](https://github.com/Galaxoid-Labs/NostrNet/tree/main/src/NostrNet.Marmot.Mls.Native) | OpenMLS provider via in-tree Rust FFI bridge |

## Links

- [API reference](api/index.md)
- [Source on GitHub](https://github.com/Galaxoid-Labs/NostrNet)
- [Releases / NuGet](https://www.nuget.org/profiles/Galaxoid-Labs)
