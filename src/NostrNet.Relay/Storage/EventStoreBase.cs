// SPDX-License-Identifier: MIT
//
// Abstract base for INostrEventStore implementations. Handles the entire
// spec-semantics layer — NIP-01 dedup, replaceable / parameterized-
// replaceable upsert, NIP-09 deletion tombstones, NIP-40 expiration,
// ephemeral kind fan-out, observer registry, snapshot+live merge for
// ObserveAsync — and asks subclasses for a minimal set of raw
// persistence primitives.
//
// A new backend (SQLite, LiteDB, Redis, whatever) only needs to implement:
//   TryAddRaw / TryRemoveRaw / TryGetRaw       — basic insert/delete/lookup
//   ScanByAuthorAndKind                         — replaceable upsert
//   ScanByAuthorKindAndIdentifier               — addressable upsert + a-tag deletion
//   ScanForQuery                                — Filter matching for QueryAsync / ObserveAsync snapshot
//   CountRaw                                    — diagnostics
// and optionally override OnDispose. The subclass is also responsible for
// thread-safety of its own primitives (e.g. a SQLite backend uses
// transactions; the in-memory backend uses ConcurrentDictionary).

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using NostrNet.Deletions;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Relay.Storage;

/// <summary>
/// Abstract base for <see cref="INostrEventStore"/> implementations. Owns
/// the NIP-01 / NIP-09 / NIP-40 spec semantics so subclasses only have to
/// implement raw persistence primitives.
/// </summary>
/// <remarks>
/// <para>
/// Subclasses must implement <see cref="TryAddRaw"/>, <see cref="TryRemoveRaw"/>,
/// <see cref="TryGetRaw"/>, <see cref="ScanByAuthorAndKind"/>,
/// <see cref="ScanByAuthorKindAndIdentifier"/>, <see cref="ScanForQuery"/>,
/// and <see cref="CountRaw"/>. Each primitive must be safe to call concurrently
/// with itself — the base serializes writes via a semaphore, but reads
/// (<see cref="QueryAsync"/>, <see cref="ObserveAsync"/>'s snapshot,
/// <see cref="GetAsync"/>, <see cref="CountAsync"/>) run lock-free.
/// </para>
/// <para>
/// Tombstones for "e"-tag deletions are rehydrated lazily on first use
/// by scanning persisted kind-5 events via <see cref="ScanForQuery"/>.
/// Subclasses that persist across restarts get correct tombstone semantics
/// "for free" by virtue of persisting their kind-5 events; they do not
/// need their own tombstones table.
/// </para>
/// </remarks>
public abstract class EventStoreBase : INostrEventStore, IDisposable
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly HashSet<EventId> _eventTombstones = new();
    private readonly List<Observer> _observers = new();
    private readonly object _observerLock = new();
    private int _hydrated;   // 0 = no, 1 = yes
    private bool _disposed;

    /// <inheritdoc/>
    public async ValueTask<StoreResult> StoreAsync(NostrEvent ev, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ev);
        ThrowIfDisposed();

        if (IsExpired(ev))
        {
            return StoreResult.Expired;
        }

        await EnsureHydratedAsync(cancellationToken).ConfigureAwait(false);

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_eventTombstones.Contains(ev.Id))
            {
                return StoreResult.Deleted;
            }

            if (ev.Kind == Nip09Kinds.DeletionRequest)
            {
                return ProcessDeletion(ev);
            }

            // NIP-01 dedup by id.
            if (TryGetRaw(ev.Id) is not null)
            {
                return StoreResult.Duplicate;
            }

            // NIP-01 ephemeral kinds: never persisted, just fanned out live.
            if (IsEphemeralKind(ev.Kind))
            {
                NotifyObservers(ev);
                return StoreResult.Ephemeral;
            }

            // NIP-01 replaceable: keyed by (kind, author).
            if (IsReplaceableKind(ev.Kind))
            {
                return UpsertReplaceable(ev, parameterized: false);
            }

            // NIP-01 parameterized-replaceable: keyed by (kind, author, d-tag).
            if (IsParameterizedReplaceableKind(ev.Kind))
            {
                return UpsertReplaceable(ev, parameterized: true);
            }

            // Regular kind: just insert.
            if (TryAddRaw(ev))
            {
                NotifyObservers(ev);
                return StoreResult.Stored;
            }

            return StoreResult.Duplicate;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc/>
    public async ValueTask<NostrEvent?> GetAsync(EventId id, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(id);
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        await EnsureHydratedAsync(cancellationToken).ConfigureAwait(false);

        var ev = TryGetRaw(id);
        if (ev is null || IsExpired(ev))
        {
            return null;
        }

        return ev;
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<NostrEvent> QueryAsync(
        Filter filter,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ThrowIfDisposed();
        await EnsureHydratedAsync(cancellationToken).ConfigureAwait(false);

        // Subclass returns matches in any order; we sort + limit here so
        // every backend gets identical query semantics.
        var matches = new List<NostrEvent>();
        foreach (var ev in ScanForQuery(filter))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (IsExpired(ev))
            {
                continue;
            }

            matches.Add(ev);
        }

        matches.Sort(static (a, b) => b.CreatedAt.CompareTo(a.CreatedAt));
        int limit = filter.Limit ?? matches.Count;
        int count = Math.Min(limit, matches.Count);
        for (int i = 0; i < count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return matches[i];
        }
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<NostrEvent> ObserveAsync(
        Filter filter,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ThrowIfDisposed();
        await EnsureHydratedAsync(cancellationToken).ConfigureAwait(false);

        var observer = new Observer(filter);
        lock (_observerLock)
        {
            _observers.Add(observer);
        }

        try
        {
            // Take the snapshot AFTER registering so events arriving during
            // the snapshot read are also delivered via the channel; we dedup
            // via the `seen` set when consuming the channel.
            var snapshot = new List<NostrEvent>();
            foreach (var ev in ScanForQuery(filter))
            {
                if (IsExpired(ev))
                {
                    continue;
                }

                snapshot.Add(ev);
            }

            snapshot.Sort(static (a, b) => b.CreatedAt.CompareTo(a.CreatedAt));
            int limit = filter.Limit ?? snapshot.Count;
            if (snapshot.Count > limit)
            {
                snapshot.RemoveRange(limit, snapshot.Count - limit);
            }

            // Emit oldest-first so consumers can append to a list/UI naturally.
            snapshot.Reverse();

            var seen = new HashSet<EventId>();
            foreach (var ev in snapshot)
            {
                cancellationToken.ThrowIfCancellationRequested();
                seen.Add(ev.Id);
                yield return ev;
            }

            await foreach (var ev in observer.Channel.Reader
                               .ReadAllAsync(cancellationToken)
                               .ConfigureAwait(false))
            {
                if (IsExpired(ev))
                {
                    continue;
                }

                if (seen.Add(ev.Id))
                {
                    yield return ev;
                }
            }
        }
        finally
        {
            lock (_observerLock)
            {
                _observers.Remove(observer);
            }

            observer.Dispose();
        }
    }

    /// <inheritdoc/>
    public ValueTask<int> CountAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        return new ValueTask<int>(CountRaw());
    }

    /// <summary>Releases observer channels, the write lock, and any subclass-owned resources via <see cref="OnDispose"/>.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        Observer[] toComplete;
        lock (_observerLock)
        {
            toComplete = _observers.ToArray();
            _observers.Clear();
        }

        foreach (var observer in toComplete)
        {
            observer.Dispose();
        }

        try
        {
            OnDispose();
        }
        finally
        {
            _writeLock.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Subclass primitives
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>
    /// Insert <paramref name="ev"/>. Returns <c>false</c> if an event with the
    /// same id is already present. The base has already filtered out duplicates,
    /// tombstones, expiration, and replaceable / addressable upserts — this
    /// primitive is unconditional insert.
    /// </summary>
    protected abstract bool TryAddRaw(NostrEvent ev);

    /// <summary>
    /// Remove the event with the given id. Returns <c>true</c> if removed,
    /// <c>false</c> if no such event existed.
    /// </summary>
    protected abstract bool TryRemoveRaw(EventId id);

    /// <summary>
    /// Look up a single event by id. Returns <c>null</c> when not present.
    /// </summary>
    protected abstract NostrEvent? TryGetRaw(EventId id);

    /// <summary>
    /// Enumerate currently-stored events with the given author and kind.
    /// Used for NIP-01 replaceable upsert (kinds 0, 3, 10000–19999). The
    /// base expects at most one match in well-maintained storage, but
    /// defensively iterates and replaces all.
    /// </summary>
    protected abstract IEnumerable<NostrEvent> ScanByAuthorAndKind(PublicKey author, int kind);

    /// <summary>
    /// Enumerate currently-stored events matching the parameterized-replaceable
    /// address (kind 30000–39999): author, kind, and the value of the <c>d</c>
    /// tag.
    /// </summary>
    protected abstract IEnumerable<NostrEvent> ScanByAuthorKindAndIdentifier(PublicKey author, int kind, string identifier);

    /// <summary>
    /// Enumerate every currently-stored event that matches <paramref name="filter"/>.
    /// Order doesn't matter — the base sorts newest-first and applies
    /// <see cref="Filter.Limit"/>. Implementations should push as much of
    /// <paramref name="filter"/> into the storage layer as possible (e.g. SQL
    /// WHERE clauses, index lookups) and only return events that pass
    /// <see cref="Filter.Matches"/> at minimum.
    /// </summary>
    protected abstract IEnumerable<NostrEvent> ScanForQuery(Filter filter);

    /// <summary>Total event count (post-dedup, post-eviction).</summary>
    protected abstract int CountRaw();

    /// <summary>
    /// Override to dispose subclass-owned resources (e.g. SQLite connections).
    /// Called after observer channels are completed but before the write lock
    /// is disposed.
    /// </summary>
    protected virtual void OnDispose()
    {
    }

    // ═══════════════════════════════════════════════════════════════════
    // Spec classification helpers — exposed as public statics because
    // they're useful to subclasses (e.g. SQLite index strategies) and
    // application code that wants to mirror the library's semantics.
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>NIP-01 replaceable kinds: 0 (profile), 3 (contacts), 10000–19999.</summary>
    public static bool IsReplaceableKind(int kind) =>
        kind is 0 or 3 || (kind >= 10000 && kind < 20000);

    /// <summary>NIP-01 parameterized-replaceable kinds: 30000–39999.</summary>
    public static bool IsParameterizedReplaceableKind(int kind) =>
        kind >= 30000 && kind < 40000;

    /// <summary>NIP-01 ephemeral kinds: 20000–29999. Not persisted; fanned out live.</summary>
    public static bool IsEphemeralKind(int kind) =>
        kind >= 20000 && kind < 30000;

    /// <summary>Extract the value of the first <c>d</c> tag, or empty string if absent.</summary>
    public static string GetIdentifier(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        foreach (var row in ev.Tags)
        {
            if (row.Count >= 2 && string.Equals(row[0], "d", StringComparison.Ordinal))
            {
                return row[1];
            }
        }

        return string.Empty;
    }

    /// <summary>True if <paramref name="ev"/> carries an <c>expiration</c> tag (NIP-40) whose timestamp is in the past.</summary>
    public static bool IsExpired(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        foreach (var row in ev.Tags)
        {
            if (row.Count >= 2
                && string.Equals(row[0], "expiration", StringComparison.Ordinal)
                && long.TryParse(row[1], out long ts))
            {
                return ts < DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            }
        }

        return false;
    }

    // ═══════════════════════════════════════════════════════════════════
    // Internal mechanics
    // ═══════════════════════════════════════════════════════════════════

    private StoreResult UpsertReplaceable(NostrEvent ev, bool parameterized)
    {
        var existing = parameterized
            ? ScanByAuthorKindAndIdentifier(ev.PubKey, ev.Kind, GetIdentifier(ev))
            : ScanByAuthorAndKind(ev.PubKey, ev.Kind);

        bool replaced = false;
        foreach (var prev in existing)
        {
            if (prev.CreatedAt >= ev.CreatedAt)
            {
                return StoreResult.Outdated;
            }

            TryRemoveRaw(prev.Id);
            replaced = true;
        }

        if (TryAddRaw(ev))
        {
            NotifyObservers(ev);
            return replaced ? StoreResult.Replaced : StoreResult.Stored;
        }

        return StoreResult.Duplicate;
    }

    private StoreResult ProcessDeletion(NostrEvent ev)
    {
        // Caller already verified id wasn't tombstoned and holds the write lock.
        if (TryGetRaw(ev.Id) is not null)
        {
            return StoreResult.Duplicate;
        }

        var request = DeletionRequest.FromEvent(ev);
        string requesterHex = ev.PubKey.ToHex();

        // "e"-tag deletions: permanent tombstone keyed by event id. Per NIP-09
        // we only honor deletion of events that match the requester's pubkey,
        // but the canonical event id already commits to the author, so we can
        // safely add the tombstone regardless — a different author's event
        // will have a different id.
        foreach (var targetId in request.EventIds)
        {
            _eventTombstones.Add(targetId);
            TryRemoveRaw(targetId);
        }

        // "a"-tag deletions: evict the matching addressable if its created_at
        // is older than the deletion. Do NOT tombstone — a newer event at the
        // same address should still be storable per NIP-09's "newer events
        // SHOULD NOT be considered deleted" clause.
        foreach (var coord in request.AddressableEvents)
        {
            string coordHex = coord.Author.ToHex();
            if (!string.Equals(coordHex, requesterHex, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var match in ScanByAuthorKindAndIdentifier(coord.Author, coord.Kind, coord.Identifier))
            {
                if (match.CreatedAt <= ev.CreatedAt)
                {
                    TryRemoveRaw(match.Id);
                }
            }
        }

        if (TryAddRaw(ev))
        {
            NotifyObservers(ev);
        }

        return StoreResult.Stored;
    }

    private async ValueTask EnsureHydratedAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _hydrated) == 1)
        {
            return;
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_hydrated == 1)
            {
                return;
            }

            // Rebuild the e-tag tombstone set from persisted kind-5 events.
            // This is idempotent: kind-5s persist in the backing store, so on
            // every restart we re-derive what was deleted. In-memory subclasses
            // start with an empty store, so this is a no-op for them.
            foreach (var ev in ScanForQuery(new Filter { Kinds = new[] { Nip09Kinds.DeletionRequest } }))
            {
                if (IsExpired(ev))
                {
                    continue;
                }

                var request = DeletionRequest.FromEvent(ev);
                foreach (var targetId in request.EventIds)
                {
                    _eventTombstones.Add(targetId);
                }
            }

            _hydrated = 1;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private void NotifyObservers(NostrEvent ev)
    {
        Observer[] snapshot;
        lock (_observerLock)
        {
            if (_observers.Count == 0)
            {
                return;
            }

            snapshot = _observers.ToArray();
        }

        foreach (var observer in snapshot)
        {
            if (observer.Filter.Matches(ev))
            {
                observer.Channel.Writer.TryWrite(ev);
            }
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private sealed class Observer : IDisposable
    {
        public Filter Filter { get; }

        public Channel<NostrEvent> Channel { get; }

        public Observer(Filter filter)
        {
            Filter = filter;
            Channel = System.Threading.Channels.Channel.CreateUnbounded<NostrEvent>(
                new UnboundedChannelOptions
                {
                    SingleReader = true,
                    SingleWriter = false,
                });
        }

        public void Dispose() => Channel.Writer.TryComplete();
    }
}
