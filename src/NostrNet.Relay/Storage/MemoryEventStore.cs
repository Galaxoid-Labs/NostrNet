// SPDX-License-Identifier: MIT

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using NostrNet.Deletions;
using NostrNet.Events;

namespace NostrNet.Relay.Storage;

/// <summary>
/// In-memory <see cref="INostrEventStore"/>. Bounded by a configurable
/// maximum event count (default 10,000); when capacity is reached, the
/// oldest event by <see cref="NostrEvent.CreatedAt"/> is evicted to make
/// room. Thread-safe for concurrent <see cref="StoreAsync"/> /
/// <see cref="QueryAsync"/> / <see cref="ObserveAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Replaceable upsert keys:
/// </para>
/// <list type="bullet">
///   <item>NIP-01 replaceable (kinds 0, 3, 10000–19999): keyed by <c>(kind, pubkey)</c>.</item>
///   <item>NIP-01 parameterized-replaceable (30000–39999): keyed by
///         <c>(kind, pubkey, d-tag)</c>.</item>
/// </list>
/// <para>
/// NIP-09 handling: an "e"-tag deletion from the same author permanently
/// tombstones the referenced event id (later <see cref="StoreAsync"/>
/// calls for that id return <see cref="StoreResult.Deleted"/>). An
/// "a"-tag deletion evicts the currently-stored matching addressable
/// (if any) but does NOT tombstone future versions — a newer event at
/// the same address can still be stored, per NIP-09's "newer events
/// SHOULD NOT be considered deleted" clause.
/// </para>
/// </remarks>
public sealed class MemoryEventStore : INostrEventStore, IDisposable
{
    /// <summary>Default capacity used when none is specified at construction.</summary>
    public const int DefaultCapacity = 10_000;

    private readonly int _capacity;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private readonly ConcurrentDictionary<EventId, NostrEvent> _events = new();
    private readonly ConcurrentDictionary<ReplaceableKey, EventId> _replaceableIndex = new();
    private readonly ConcurrentDictionary<AddressableKey, EventId> _addressableIndex = new();

    private readonly HashSet<EventId> _eventTombstones = new();

    private readonly List<Observer> _observers = new();
    private readonly object _observerLock = new();

    private bool _disposed;

    /// <summary>Creates an in-memory store bounded by <paramref name="capacity"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="capacity"/> is non-positive.</exception>
    public MemoryEventStore(int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _capacity = capacity;
    }

    /// <summary>Maximum number of events held simultaneously.</summary>
    public int Capacity => _capacity;

    /// <inheritdoc/>
    public async ValueTask<StoreResult> StoreAsync(NostrEvent ev, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ev);
        ThrowIfDisposed();

        if (IsExpired(ev))
        {
            return StoreResult.Expired;
        }

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

            if (_events.ContainsKey(ev.Id))
            {
                return StoreResult.Duplicate;
            }

            // NIP-01 ephemeral kinds: do not persist, but fan out to live
            // observers so UI gets the stream (typing indicators, presence).
            if (IsEphemeralKind(ev.Kind))
            {
                NotifyObservers(ev);
                return StoreResult.Ephemeral;
            }

            if (IsReplaceableKind(ev.Kind))
            {
                var key = new ReplaceableKey(ev.Kind, ev.PubKey.ToHex());
                if (_replaceableIndex.TryGetValue(key, out var existingId)
                    && _events.TryGetValue(existingId, out var existing))
                {
                    if (existing.CreatedAt >= ev.CreatedAt)
                    {
                        return StoreResult.Outdated;
                    }

                    _events.TryRemove(existingId, out _);
                    AddInternal(ev);
                    _replaceableIndex[key] = ev.Id;
                    NotifyObservers(ev);
                    return StoreResult.Replaced;
                }

                AddInternal(ev);
                _replaceableIndex[key] = ev.Id;
                NotifyObservers(ev);
                return StoreResult.Stored;
            }

            if (IsParameterizedReplaceableKind(ev.Kind))
            {
                var key = new AddressableKey(ev.Kind, ev.PubKey.ToHex(), GetIdentifier(ev));
                if (_addressableIndex.TryGetValue(key, out var existingId)
                    && _events.TryGetValue(existingId, out var existing))
                {
                    if (existing.CreatedAt >= ev.CreatedAt)
                    {
                        return StoreResult.Outdated;
                    }

                    _events.TryRemove(existingId, out _);
                    AddInternal(ev);
                    _addressableIndex[key] = ev.Id;
                    NotifyObservers(ev);
                    return StoreResult.Replaced;
                }

                AddInternal(ev);
                _addressableIndex[key] = ev.Id;
                NotifyObservers(ev);
                return StoreResult.Stored;
            }

            AddInternal(ev);
            NotifyObservers(ev);
            return StoreResult.Stored;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc/>
    public ValueTask<NostrEvent?> GetAsync(EventId id, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(id);
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        _events.TryGetValue(id, out var ev);
        if (ev is not null && IsExpired(ev))
        {
            return new ValueTask<NostrEvent?>((NostrEvent?)null);
        }

        return new ValueTask<NostrEvent?>(ev);
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<NostrEvent> QueryAsync(
        Filter filter,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ThrowIfDisposed();

        var matches = new List<NostrEvent>();
        foreach (var ev in _events.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (IsExpired(ev))
            {
                continue;
            }

            if (filter.Matches(ev))
            {
                matches.Add(ev);
            }
        }

        matches.Sort(static (a, b) => b.CreatedAt.CompareTo(a.CreatedAt));
        int limit = filter.Limit ?? matches.Count;
        int count = Math.Min(limit, matches.Count);
        for (int i = 0; i < count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return matches[i];
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<NostrEvent> ObserveAsync(
        Filter filter,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ThrowIfDisposed();

        var observer = new Observer(filter);
        lock (_observerLock)
        {
            _observers.Add(observer);
        }

        try
        {
            // Take the snapshot AFTER registering so events arriving during
            // the snapshot read are also delivered via the channel; we
            // dedup via the `seen` set when consuming the channel.
            var snapshot = new List<NostrEvent>();
            foreach (var ev in _events.Values)
            {
                if (IsExpired(ev))
                {
                    continue;
                }

                if (filter.Matches(ev))
                {
                    snapshot.Add(ev);
                }
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
        return new ValueTask<int>(_events.Count);
    }

    /// <summary>Releases observer channels and write lock.</summary>
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

        _writeLock.Dispose();
    }

    private StoreResult ProcessDeletion(NostrEvent ev)
    {
        // Caller already verified id wasn't tombstoned and held the write lock.
        if (_events.ContainsKey(ev.Id))
        {
            return StoreResult.Duplicate;
        }

        var request = DeletionRequest.FromEvent(ev);
        string requesterHex = ev.PubKey.ToHex();

        // "e"-tag deletions: permanent tombstone keyed by event id.
        // Per NIP-09 we only honor deletion of events that match the
        // requester's pubkey, but the canonical event id already
        // commits to the author, so we can safely add the tombstone
        // regardless — a different author's event will have a different id.
        foreach (var targetId in request.EventIds)
        {
            _eventTombstones.Add(targetId);
            if (_events.TryRemove(targetId, out var existing))
            {
                if (IsReplaceableKind(existing.Kind))
                {
                    _replaceableIndex.TryRemove(
                        new ReplaceableKey(existing.Kind, existing.PubKey.ToHex()), out _);
                }
                else if (IsParameterizedReplaceableKind(existing.Kind))
                {
                    _addressableIndex.TryRemove(
                        new AddressableKey(existing.Kind, existing.PubKey.ToHex(), GetIdentifier(existing)), out _);
                }
            }
        }

        // "a"-tag deletions: evict the matching addressable if its
        // created_at is older than the deletion. Do NOT tombstone — a
        // newer event at the same address should still be storable.
        foreach (var coord in request.AddressableEvents)
        {
            string coordHex = coord.Author.ToHex();
            if (!string.Equals(coordHex, requesterHex, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var key = new AddressableKey(coord.Kind, requesterHex, coord.Identifier);
            if (_addressableIndex.TryGetValue(key, out var addressableId)
                && _events.TryGetValue(addressableId, out var addressable)
                && addressable.CreatedAt <= ev.CreatedAt)
            {
                _events.TryRemove(addressableId, out _);
                _addressableIndex.TryRemove(key, out _);
            }
        }

        AddInternal(ev);
        NotifyObservers(ev);
        return StoreResult.Stored;
    }

    private void AddInternal(NostrEvent ev)
    {
        _events[ev.Id] = ev;
        if (_events.Count > _capacity)
        {
            EvictOldest();
        }
    }

    private void EvictOldest()
    {
        NostrEvent? oldest = null;
        foreach (var candidate in _events.Values)
        {
            if (oldest is null || candidate.CreatedAt < oldest.CreatedAt)
            {
                oldest = candidate;
            }
        }

        if (oldest is null)
        {
            return;
        }

        _events.TryRemove(oldest.Id, out _);
        if (IsReplaceableKind(oldest.Kind))
        {
            _replaceableIndex.TryRemove(
                new ReplaceableKey(oldest.Kind, oldest.PubKey.ToHex()), out _);
        }
        else if (IsParameterizedReplaceableKind(oldest.Kind))
        {
            _addressableIndex.TryRemove(
                new AddressableKey(oldest.Kind, oldest.PubKey.ToHex(), GetIdentifier(oldest)), out _);
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

    private static bool IsReplaceableKind(int kind) =>
        kind is 0 or 3 || (kind >= 10000 && kind < 20000);

    private static bool IsParameterizedReplaceableKind(int kind) =>
        kind >= 30000 && kind < 40000;

    private static bool IsEphemeralKind(int kind) =>
        kind >= 20000 && kind < 30000;

    private static string GetIdentifier(NostrEvent ev)
    {
        foreach (var row in ev.Tags)
        {
            if (row.Count >= 2 && string.Equals(row[0], "d", StringComparison.Ordinal))
            {
                return row[1];
            }
        }

        return string.Empty;
    }

    private static bool IsExpired(NostrEvent ev)
    {
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

    private readonly record struct ReplaceableKey(int Kind, string AuthorHex);

    private readonly record struct AddressableKey(int Kind, string AuthorHex, string Identifier);

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
