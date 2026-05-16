// SPDX-License-Identifier: MIT

using System.Collections.Concurrent;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Relay.Storage;

/// <summary>
/// In-memory <see cref="INostrEventStore"/>. Bounded by a configurable
/// maximum event count (default 10,000); when capacity is reached, the
/// oldest event by <see cref="NostrEvent.CreatedAt"/> is evicted to make
/// room. Thread-safe.
/// </summary>
/// <remarks>
/// All spec semantics — NIP-01 dedup / replaceable / addressable upsert,
/// NIP-09 tombstones, NIP-40 expiration, NIP-01 ephemeral fan-out,
/// observer registry — live in <see cref="EventStoreBase"/>. This class
/// only adds: in-memory storage (a dictionary keyed by event id, plus
/// two indexes for the replaceable / addressable upsert scans) and the
/// capacity-based eviction policy.
/// </remarks>
public sealed class MemoryEventStore : EventStoreBase
{
    /// <summary>Default capacity used when none is specified at construction.</summary>
    public const int DefaultCapacity = 10_000;

    private readonly int _capacity;
    private readonly ConcurrentDictionary<EventId, NostrEvent> _events = new();
    private readonly ConcurrentDictionary<ReplaceableKey, EventId> _replaceableIndex = new();
    private readonly ConcurrentDictionary<AddressableKey, EventId> _addressableIndex = new();

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
    protected override bool TryAddRaw(NostrEvent ev)
    {
        if (!_events.TryAdd(ev.Id, ev))
        {
            return false;
        }

        // Maintain the replaceable / addressable lookup indexes so the
        // by-author/by-kind scans below stay O(1) instead of O(n).
        if (IsReplaceableKind(ev.Kind))
        {
            _replaceableIndex[new ReplaceableKey(ev.Kind, ev.PubKey.ToHex())] = ev.Id;
        }
        else if (IsParameterizedReplaceableKind(ev.Kind))
        {
            _addressableIndex[new AddressableKey(ev.Kind, ev.PubKey.ToHex(), GetIdentifier(ev))] = ev.Id;
        }

        if (_events.Count > _capacity)
        {
            EvictOldest();
        }

        return true;
    }

    /// <inheritdoc/>
    protected override bool TryRemoveRaw(EventId id)
    {
        if (!_events.TryRemove(id, out var existing))
        {
            return false;
        }

        if (IsReplaceableKind(existing.Kind))
        {
            _replaceableIndex.TryRemove(new ReplaceableKey(existing.Kind, existing.PubKey.ToHex()), out _);
        }
        else if (IsParameterizedReplaceableKind(existing.Kind))
        {
            _addressableIndex.TryRemove(
                new AddressableKey(existing.Kind, existing.PubKey.ToHex(), GetIdentifier(existing)), out _);
        }

        return true;
    }

    /// <inheritdoc/>
    protected override NostrEvent? TryGetRaw(EventId id) =>
        _events.TryGetValue(id, out var ev) ? ev : null;

    /// <inheritdoc/>
    protected override IEnumerable<NostrEvent> ScanByAuthorAndKind(PublicKey author, int kind)
    {
        if (_replaceableIndex.TryGetValue(new ReplaceableKey(kind, author.ToHex()), out var id)
            && _events.TryGetValue(id, out var ev))
        {
            yield return ev;
        }
    }

    /// <inheritdoc/>
    protected override IEnumerable<NostrEvent> ScanByAuthorKindAndIdentifier(
        PublicKey author, int kind, string identifier)
    {
        if (_addressableIndex.TryGetValue(new AddressableKey(kind, author.ToHex(), identifier), out var id)
            && _events.TryGetValue(id, out var ev))
        {
            yield return ev;
        }
    }

    /// <inheritdoc/>
    protected override IEnumerable<NostrEvent> ScanForQuery(Filter filter)
    {
        foreach (var ev in _events.Values)
        {
            if (filter.Matches(ev))
            {
                yield return ev;
            }
        }
    }

    /// <inheritdoc/>
    protected override int CountRaw() => _events.Count;

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

        if (oldest is not null)
        {
            TryRemoveRaw(oldest.Id);
        }
    }

    private readonly record struct ReplaceableKey(int Kind, string AuthorHex);

    private readonly record struct AddressableKey(int Kind, string AuthorHex, string Identifier);
}
