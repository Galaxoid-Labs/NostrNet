<p align="center">
  <img src="https://raw.githubusercontent.com/Galaxoid-Labs/NostrNet/main/logo.png" alt="NostrNet" width="320" />
</p>

# NostrNet.Relay

WebSocket relay client for the [NostrNet](https://github.com/Galaxoid-Labs/NostrNet)
.NET 10 Nostr client library: `RelayClient`, `RelayPool`, `Filter` (with
local-side `Filter.Matches(NostrEvent)` for stores), NIP-11 (relay
information document) and NIP-05 (DNS-based identifier verification)
helpers.

Also contains the local event-store abstraction in
`NostrNet.Relay.Storage`:

- **`INostrEventStore`** — interface for a local Nostr event store
  (dedup, NIP-01 replaceable / addressable upsert, NIP-09 deletion
  tombstones, NIP-40 expiration, NIP-01 ephemeral fan-out, snapshot
  + reactive queries).
- **`MemoryEventStore`** — bounded in-memory implementation, the
  default for apps that don't need persistence yet.

Most apps don't reference this package directly — install
[NostrNet.Client](https://www.nuget.org/packages/NostrNet.Client) which
pulls Relay in transitively along with a higher-level façade and the
generic typed-access extensions (`store.ObserveAsync<Profile>()`).

See the main project [README](https://github.com/Galaxoid-Labs/NostrNet)
for usage.
