<p align="center">
  <img src="https://raw.githubusercontent.com/Galaxoid-Labs/NostrNet/main/logo.png" alt="NostrNet" width="320" />
</p>

# NostrNet.Core

Foundational types for the [NostrNet](https://github.com/Galaxoid-Labs/NostrNet)
.NET 10 Nostr client library: BIP-340 keys, canonical event serialization,
NIP-19 bech32 entities, profiles (NIP-01), long-form articles (NIP-23),
web bookmarks (NIP-B0), contact lists (NIP-02), event deletions (NIP-09),
thread/reply tagging (NIP-10), reactions (NIP-25), and more.

Also defines `INostrTypedEvent<TSelf>` — the static-abstract-interface
marker every typed wrapper (`Profile`, `Article`, `WebBookmark`,
`UserStatus`, …) implements so the generic store extensions
(`store.ObserveAsync<T>()` / `QueryAsync<T>()` / `GetAsync<T>()` in
[NostrNet.Client](https://www.nuget.org/packages/NostrNet.Client)) can
project raw events into typed values without per-type extension methods.

Most apps don't reference this package directly — install
[NostrNet.Client](https://www.nuget.org/packages/NostrNet.Client) which
pulls Core in transitively along with relay support and the typed
accessors.

See the main project [README](https://github.com/Galaxoid-Labs/NostrNet)
for usage.
