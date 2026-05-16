// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using NostrNet.Events;

namespace NostrNet.Marmot;

/// <summary>
/// In-memory <see cref="IMarmotMessageLog"/>. State is lost on dispose;
/// use this for tests or short-lived sessions where cold-start history
/// across process restarts isn't required.
/// </summary>
/// <remarks>
/// <para>
/// For production use, write a persistent backend the same way you'd
/// implement <see cref="Relay.Storage.EventStoreBase"/> — implement
/// <see cref="IMarmotMessageLog"/> over SQLite / LiteDB / Realm /
/// whatever your app already stores data in.
/// </para>
/// <para>
/// Dedup keys on <see cref="MarmotMessageReceived.EventId"/>: the same
/// kind-445 event arriving from multiple relays is collapsed to a single
/// log entry. Per-group storage; <see cref="DeleteGroupAsync"/> is O(n)
/// in the number of stored messages for that group.
/// </para>
/// </remarks>
public sealed class MemoryMarmotMessageLog : IMarmotMessageLog
{
    // Per-group ordered list (oldest first) keyed by hex(nostr_group_id).
    // We key on the hex string rather than the raw byte[] to avoid the
    // reference-equality trap on byte arrays as Dictionary keys.
    private readonly Dictionary<string, List<MarmotMessageReceived>> _byGroup = new(StringComparer.Ordinal);

    // Seen kind-445 event ids per group for O(1) dedup on Append.
    private readonly Dictionary<string, HashSet<EventId>> _seenByGroup = new(StringComparer.Ordinal);

    private readonly object _lock = new();

    /// <inheritdoc/>
    public ValueTask AppendAsync(MarmotMessageReceived message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        cancellationToken.ThrowIfCancellationRequested();

        string key = Convert.ToHexStringLower(message.Conversation.NostrGroupId);
        lock (_lock)
        {
            if (!_seenByGroup.TryGetValue(key, out var seen))
            {
                seen = new HashSet<EventId>();
                _seenByGroup[key] = seen;
            }

            if (!seen.Add(message.EventId))
            {
                return ValueTask.CompletedTask;
            }

            if (!_byGroup.TryGetValue(key, out var list))
            {
                list = new List<MarmotMessageReceived>();
                _byGroup[key] = list;
            }

            // Maintain oldest-first ordering. Most arrivals are in order
            // so the common case is an append; out-of-order arrivals
            // (relay backfill) get a small insertion-sort pass.
            if (list.Count == 0 || list[^1].ServerTimestamp <= message.ServerTimestamp)
            {
                list.Add(message);
            }
            else
            {
                int idx = list.FindLastIndex(m => m.ServerTimestamp <= message.ServerTimestamp);
                list.Insert(idx + 1, message);
            }
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<MarmotMessageReceived> LoadAsync(
        byte[] nostrGroupId,
        DateTimeOffset? since = null,
        int? limit = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nostrGroupId);

        MarmotMessageReceived[] snapshot;
        string key = Convert.ToHexStringLower(nostrGroupId);
        lock (_lock)
        {
            snapshot = _byGroup.TryGetValue(key, out var list) ? list.ToArray() : Array.Empty<MarmotMessageReceived>();
        }

        int yielded = 0;
        foreach (var msg in snapshot)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (since is { } s && msg.ServerTimestamp < s)
            {
                continue;
            }

            yield return msg;
            yielded++;
            if (limit is { } lim && yielded >= lim)
            {
                break;
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public ValueTask<MarmotMessageReceived?> GetLastAsync(byte[] nostrGroupId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nostrGroupId);
        cancellationToken.ThrowIfCancellationRequested();

        string key = Convert.ToHexStringLower(nostrGroupId);
        lock (_lock)
        {
            if (_byGroup.TryGetValue(key, out var list) && list.Count > 0)
            {
                return new ValueTask<MarmotMessageReceived?>(list[^1]);
            }
        }

        return new ValueTask<MarmotMessageReceived?>((MarmotMessageReceived?)null);
    }

    /// <inheritdoc/>
    public ValueTask DeleteGroupAsync(byte[] nostrGroupId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nostrGroupId);
        cancellationToken.ThrowIfCancellationRequested();

        string key = Convert.ToHexStringLower(nostrGroupId);
        lock (_lock)
        {
            _byGroup.Remove(key);
            _seenByGroup.Remove(key);
        }

        return ValueTask.CompletedTask;
    }
}
