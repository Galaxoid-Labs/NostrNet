// SPDX-License-Identifier: MIT

using NostrNet.Events;

namespace NostrNet.Relay.Storage;

/// <summary>
/// Abstraction over a local Nostr event store. Implementations decide
/// persistence (in-memory, SQLite, etc.); semantics are fixed:
/// <list type="bullet">
///   <item>NIP-01 dedup by event id.</item>
///   <item>NIP-01 replaceable (kinds 0, 3, 10000–19999) and
///         parameterized-replaceable (30000–39999) upsert keyed by
///         <c>(kind, author)</c> or <c>(kind, author, d-tag)</c>.</item>
///   <item>NIP-09 deletion tombstones — a kind-5 deletion from the
///         original author removes targeted events and prevents future
///         insertions of the same id (or addressable coordinate).</item>
///   <item>NIP-40 expiration — events whose <c>expiration</c> tag is in
///         the past are not stored and are not yielded by queries.</item>
///   <item>NIP-01 ephemeral kinds (20000–29999) — fanned out live to
///         <see cref="ObserveAsync"/> subscribers but not persisted, so
///         a presence-ping flood cannot evict durable events.</item>
/// </list>
/// Implementations are thread-safe: concurrent <see cref="StoreAsync"/>,
/// <see cref="QueryAsync"/>, and <see cref="ObserveAsync"/> calls are safe.
/// </summary>
public interface INostrEventStore
{
    /// <summary>
    /// Add an event to the store. The returned <see cref="StoreResult"/>
    /// describes the disposition; see the enum for the full set of cases.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ev"/> is null.</exception>
    ValueTask<StoreResult> StoreAsync(NostrEvent ev, CancellationToken cancellationToken = default);

    /// <summary>
    /// Look up a single event by its id. Returns <c>null</c> when the
    /// store does not have a matching event (including events that were
    /// previously stored but evicted due to capacity or NIP-09 deletion).
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="id"/> is null.</exception>
    ValueTask<NostrEvent?> GetAsync(EventId id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enumerate currently-stored events matching <paramref name="filter"/>,
    /// ordered by <see cref="NostrEvent.CreatedAt"/> descending and capped
    /// by <see cref="Filter.Limit"/>. Completes after the snapshot is
    /// exhausted — see <see cref="ObserveAsync"/> for a live stream that
    /// continues to yield as new matching events arrive.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="filter"/> is null.</exception>
    IAsyncEnumerable<NostrEvent> QueryAsync(Filter filter, CancellationToken cancellationToken = default);

    /// <summary>
    /// Live, reactive query. Yields the current snapshot of matching events
    /// first (oldest-first within the snapshot so consumers can append),
    /// then keeps yielding each newly-stored event that matches as it is
    /// added. Completes when <paramref name="cancellationToken"/> fires.
    /// </summary>
    /// <remarks>
    /// <see cref="Filter.Limit"/> is honored only on the initial snapshot;
    /// live updates ignore it (a 50-event limit doesn't make sense for
    /// "all future matches"). Apply your own bound at the consumer if needed.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="filter"/> is null.</exception>
    IAsyncEnumerable<NostrEvent> ObserveAsync(Filter filter, CancellationToken cancellationToken = default);

    /// <summary>
    /// Number of events currently held (post-dedup, post-eviction).
    /// Intended for diagnostics; cost varies by implementation.
    /// </summary>
    ValueTask<int> CountAsync(CancellationToken cancellationToken = default);
}
