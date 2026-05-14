# NostrNet.Core

Foundational types for the [NostrNet](https://github.com/Galaxoid-Labs/NostrNet)
.NET 10 Nostr client library: BIP-340 keys, canonical event serialization,
NIP-19 bech32 entities, profiles (NIP-23), web bookmarks (NIP-B0),
contact lists (NIP-02), event deletions (NIP-09), thread/reply tagging
(NIP-10), reactions (NIP-25), and more.

Most apps don't reference this package directly — install
[NostrNet.Client](https://www.nuget.org/packages/NostrNet.Client) which
pulls Core in transitively along with relay support.

See the main project [README](https://github.com/Galaxoid-Labs/NostrNet)
for usage.
