// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using NostrNet.Events;
using NostrNet.Relay;
using NostrNet.Relay.Storage;

namespace NostrNet.Client.Storage;

/// <summary>
/// Generic typed accessors over <see cref="INostrEventStore"/>. Any type
/// that implements <see cref="INostrTypedEvent{TSelf}"/> can be queried,
/// observed, or fetched directly without going through raw
/// <see cref="NostrEvent"/> + <c>FromEvent</c>.
/// </summary>
/// <remarks>
/// <para>
/// All three methods auto-default <see cref="Filter.Kinds"/> to
/// <c>T.Kinds</c> when the caller omits it, so
/// <c>store.ObserveAsync&lt;Profile&gt;()</c> just works. Callers who
/// pass an explicit <see cref="Filter"/> with their own <c>Kinds</c>
/// are respected — useful for narrowing a multi-kind type (e.g.,
/// articles vs. drafts, or published vs. addressable video kinds).
/// </para>
/// <para>
/// Events that fail <c>TryFromEvent</c> are silently skipped — the
/// store yields whatever raw matches the filter, but the generic
/// surface only surfaces values the type system can confirm. This
/// matches how relay subscriptions normally treat malformed events.
/// </para>
/// </remarks>
public static class TypedStoreExtensions
{
    /// <summary>
    /// Snapshot of currently-stored events of type
    /// <typeparamref name="T"/>, projected through
    /// <see cref="INostrTypedEvent{TSelf}.TryFromEvent"/>. Honors
    /// <see cref="Filter.Limit"/> and orders newest-first via the
    /// underlying <see cref="INostrEventStore.QueryAsync"/>.
    /// </summary>
    public static async IAsyncEnumerable<T> QueryAsync<T>(
        this INostrEventStore store,
        Filter? filter = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
        where T : INostrTypedEvent<T>
    {
        ArgumentNullException.ThrowIfNull(store);
        var effective = ApplyKinds<T>(filter);
        await foreach (var ev in store.QueryAsync(effective, cancellationToken).ConfigureAwait(false))
        {
            if (T.TryFromEvent(ev, out var typed))
            {
                yield return typed;
            }
        }
    }

    /// <summary>
    /// Live, reactive query over events of type <typeparamref name="T"/>.
    /// Emits the current snapshot first (oldest-first) then keeps
    /// yielding new matches as they arrive in the store. Completes
    /// when <paramref name="cancellationToken"/> fires.
    /// </summary>
    public static async IAsyncEnumerable<T> ObserveAsync<T>(
        this INostrEventStore store,
        Filter? filter = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
        where T : INostrTypedEvent<T>
    {
        ArgumentNullException.ThrowIfNull(store);
        var effective = ApplyKinds<T>(filter);
        await foreach (var ev in store.ObserveAsync(effective, cancellationToken).ConfigureAwait(false))
        {
            if (T.TryFromEvent(ev, out var typed))
            {
                yield return typed;
            }
        }
    }

    /// <summary>
    /// Look up a single event by id and project to
    /// <typeparamref name="T"/>. Returns <c>null</c> when the id is
    /// not in the store or when the stored event does not match
    /// <typeparamref name="T"/>'s shape.
    /// </summary>
    public static async ValueTask<T?> GetAsync<T>(
        this INostrEventStore store,
        EventId id,
        CancellationToken cancellationToken = default)
        where T : INostrTypedEvent<T>
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(id);
        var ev = await store.GetAsync(id, cancellationToken).ConfigureAwait(false);
        if (ev is null)
        {
            return default;
        }

        return T.TryFromEvent(ev, out var typed) ? typed : default;
    }

    private static Filter ApplyKinds<T>(Filter? filter) where T : INostrTypedEvent<T>
    {
        if (filter is null)
        {
            return new Filter { Kinds = T.Kinds };
        }

        return filter.Kinds is null ? filter with { Kinds = T.Kinds } : filter;
    }
}
