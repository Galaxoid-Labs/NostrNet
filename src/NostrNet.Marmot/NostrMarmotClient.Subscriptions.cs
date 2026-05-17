// SPDX-License-Identifier: MIT
//
// Dynamic per-conversation subscription multiplex for NostrMarmotClient.
//
// Strategy:
//   - One background pump for kind-1059 (invites), filtered by p-tag = my pubkey.
//     Started lazily on first call to SubscribeAsync.
//   - One background pump per joined conversation for kind-445 filtered by
//     h-tag = group_id (hex). Started when StartConversation / StartGroup /
//     AcceptInvite registers the conversation.
//   - All pumps write typed MarmotInboundEvent values into a single
//     Channel that SubscribeAsync exposes as IAsyncEnumerable.
//
// All pumps share a single CancellationTokenSource (`_pumpsCts`). Disposing
// the client cancels it, which terminates each pump's underlying relay
// SubscribeAsync. The shared Channel is then completed.

using System.Threading.Channels;
using NostrNet.Events;
using NostrNet.Marmot.Events;
using NostrNet.Relay;

namespace NostrNet.Marmot;

public sealed partial class NostrMarmotClient
{
    private readonly object _subLock = new();
    private CancellationTokenSource? _pumpsCts;
    private Channel<MarmotInboundEvent>? _inboundChannel;
    private readonly List<Task> _pumpTasks = new();
    private readonly Dictionary<string, MarmotConversation> _conversations = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Subscribes to all inbound Marmot traffic — invites (kind-1059
    /// gift wraps with p-tag = our pubkey) and group events (kind-445
    /// with an <c>h</c> tag matching any of our joined conversations).
    ///
    /// Yields one typed <see cref="MarmotInboundEvent"/> per relay
    /// delivery; the consumer should dedup on
    /// <see cref="MarmotMessageReceived.ServerTimestamp"/> or similar
    /// if they care.
    ///
    /// The first call starts background pumps; subsequent calls share
    /// the same underlying channel. <see cref="DisposeAsync"/> cancels
    /// all pumps.
    /// </summary>
    public IAsyncEnumerable<MarmotInboundEvent> SubscribeAsync(CancellationToken ct = default)
    {
        EnsureNotDisposed();
        EnsurePumpsStarted();
        return _inboundChannel!.Reader.ReadAllAsync(ct);
    }

    private void EnsurePumpsStarted()
    {
        lock (_subLock)
        {
            if (_inboundChannel is not null)
            {
                return;
            }

            _inboundChannel = Channel.CreateUnbounded<MarmotInboundEvent>(new UnboundedChannelOptions
            {
                SingleReader = false,
                SingleWriter = false,
            });
            _pumpsCts = new CancellationTokenSource();

            // Inbox pump: every kind-1059 addressed to us.
            _pumpTasks.Add(Task.Run(() => InboxPumpAsync(_pumpsCts.Token)));

            // For each conversation that was registered BEFORE
            // SubscribeAsync was first called, start a pump now.
            foreach (var convo in _conversations.Values)
            {
                _pumpTasks.Add(Task.Run(() => GroupPumpAsync(convo, _pumpsCts.Token)));
            }
        }
    }

    /// <summary>
    /// Called by Start*/AcceptInvite to register a conversation. If
    /// pumps are running, starts a per-group pump immediately.
    /// </summary>
    private void TrackConversation(MarmotConversation conversation)
    {
        string key = Convert.ToHexStringLower(conversation.NostrGroupId);
        lock (_subLock)
        {
            _conversations[key] = conversation;
            if (_inboundChannel is not null && _pumpsCts is not null)
            {
                _pumpTasks.Add(Task.Run(() => GroupPumpAsync(conversation, _pumpsCts.Token)));
            }
        }
    }

    private async Task InboxPumpAsync(CancellationToken ct)
    {
        var filter = new Filter
        {
            Kinds = new[] { 1059 },
            TagFilters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["p"] = new[] { Identity.ToHex() },
            },
        };

        // Multi-relay setups deliver the same kind-1059 event once per relay
        // carrying it. Dedup at the outer event-id level so we yield one
        // MarmotInviteReceived per unique welcome, not N. Local to the pump
        // (single-reader, no concurrency concerns) and cleared when the
        // pump exits.
        var seen = new HashSet<EventId>();

        try
        {
            await foreach (var ev in _relay.SubscribeAsync(new[] { filter }, ct).ConfigureAwait(false))
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                if (ev.Kind != 1059)
                {
                    continue;
                }

                if (!seen.Add(ev.Id))
                {
                    continue;
                }

                // Try to unwrap as a Marmot Welcome. Non-Marmot gift
                // wraps (e.g., NIP-17 DMs) fail unwrap silently and
                // are skipped.
                if (!WelcomeEvent.TryUnwrap(ev, _identityKey, out var welcome))
                {
                    continue;
                }

                var invite = new MarmotInviteReceived(
                    Sender: welcome.Sender,
                    KeyPackageEventId: welcome.KeyPackageEventId,
                    RecommendedRelays: welcome.RecommendedRelays,
                    OriginalGiftWrap: ev);
                await _inboundChannel!.Writer.WriteAsync(invite, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // expected during shutdown
        }
    }

    // ────────────────────────────────────────────────────────────
    // Out-of-order / offline-catchup handling.
    //
    // When a relay delivers a group event from an epoch the
    // receiver hasn't advanced into yet, `TryProcessMessageAsync`
    // returns null because the local exporter for that epoch
    // doesn't exist. This is common when:
    //   - a relay batches historical events newest-first after the
    //     client reconnects;
    //   - app messages from a new epoch arrive before the Commit
    //     that advances members into that epoch.
    //
    // We park the event in a per-group buffer and retry whenever a
    // Commit lands (which is the only event that can move the
    // receiver's epoch forward). Bounded by MaxParkedPerGroup and
    // MaxRetriesPerParked so adversarial or genuinely stuck events
    // can't grow the buffer without limit.
    // ────────────────────────────────────────────────────────────

    /// <summary>Cap on the per-group parked buffer; oldest evicted on overflow.</summary>
    private const int MaxParkedPerGroup = 200;

    /// <summary>How many epoch advances we'll retry a parked event before discarding it.</summary>
    private const int MaxRetriesPerParked = 8;

    private sealed class ParkedEvent
    {
        public required NostrEvent Event { get; init; }
        public int Attempts { get; set; }
    }

    private readonly object _parkedLock = new();
    private readonly Dictionary<string, List<ParkedEvent>> _parkedByGroup = new(StringComparer.OrdinalIgnoreCase);

    private async Task GroupPumpAsync(MarmotConversation conversation, CancellationToken ct)
    {
        string groupIdHex = Convert.ToHexStringLower(conversation.NostrGroupId);
        var filter = new Filter
        {
            Kinds = new[] { MarmotKinds.GroupEvent },
            TagFilters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["h"] = new[] { groupIdHex },
            },
        };

        // Per-group dedup: same kind-445 event delivered by N relays must
        // yield one MarmotMessageReceived (or MarmotGroupStateChanged for a
        // Commit), not N. Local to this pump task. MLS itself replay-rejects
        // duplicate application messages once the ratchet advances, so the
        // primary breakage without this set is duplicate state-change events
        // for Commits and (in some edge cases) a confused user-facing log.
        var seen = new HashSet<EventId>();

        try
        {
            await foreach (var ev in _relay.SubscribeAsync(new[] { filter }, ct).ConfigureAwait(false))
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                if (ev.Kind != MarmotKinds.GroupEvent)
                {
                    continue;
                }

                // Sanity-check h-tag; a misbehaving relay might send unrelated events.
                if (!MarmotChat.LooksLikeGroupEventFor(conversation, ev))
                {
                    continue;
                }

                if (!seen.Add(ev.Id))
                {
                    continue;
                }

                bool epochAdvanced = await ProcessOneAsync(conversation, ev, ct).ConfigureAwait(false);
                if (epochAdvanced)
                {
                    // The receiver just moved to a new epoch — replay
                    // every previously-undecryptable event for this
                    // group, in created_at order so any chain of
                    // commits + app messages walks forward correctly.
                    await ReplayParkedAsync(conversation, groupIdHex, ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // expected during shutdown
        }
    }

    /// <summary>
    /// Tries to process one inbound kind-445 event. On success, emits the
    /// typed inbound event. On undecryptable (most often: epoch
    /// mismatch), parks the event for replay after the next Commit.
    /// Returns <c>true</c> when the receiver's MLS epoch advanced.
    /// </summary>
    private async Task<bool> ProcessOneAsync(MarmotConversation conversation, NostrEvent ev, CancellationToken ct)
    {
        MarmotInboundMessage? processed;
        try
        {
            processed = await MarmotChat.TryProcessMessageAsync(_provider, conversation, ev, ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Genuine processing exception (bad state, malformed
            // payload that survived TryProcess's catches). Drop —
            // re-parking would just loop.
            return false;
        }

        if (processed is null)
        {
            ParkEvent(conversation.NostrGroupId, ev);
            return false;
        }

        MarmotInboundEvent? typed = processed.Kind switch
        {
            MarmotMessageKind.Application => new MarmotMessageReceived(
                Conversation: conversation,
                EventId: ev.Id,
                Sender: processed.Sender,
                Plaintext: processed.Plaintext ?? string.Empty,
                ServerTimestamp: DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt)),
            MarmotMessageKind.Commit => new MarmotGroupStateChanged(
                Conversation: conversation,
                Sender: processed.Sender),
            _ => null,
        };

        if (typed is not null)
        {
            // Append to the message log BEFORE yielding so apps observing
            // the stream + reading the log see a consistent ordering: a
            // message can't be visible in MarmotMessageReceived yet absent
            // from GetLastMessageAsync. The log call is fail-soft — log
            // backends that throw don't block message delivery.
            if (_messageLog is not null && typed is MarmotMessageReceived appMsg)
            {
                try
                {
                    await _messageLog.AppendAsync(appMsg, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    // Swallow log-impl failures so a broken backend doesn't
                    // poison the receive pump. Apps that care can wrap their
                    // own IMarmotMessageLog with telemetry.
                }
            }

            await _inboundChannel!.Writer.WriteAsync(typed, ct).ConfigureAwait(false);
        }

        return processed.EpochAdvanced;
    }

    private void ParkEvent(byte[] groupId, NostrEvent ev)
    {
        string key = Convert.ToHexStringLower(groupId);
        lock (_parkedLock)
        {
            if (!_parkedByGroup.TryGetValue(key, out var list))
            {
                list = new List<ParkedEvent>();
                _parkedByGroup[key] = list;
            }

            // De-dup by event id so a relay redelivering the same
            // event during reconnect doesn't bloat the buffer.
            for (int i = 0; i < list.Count; i++)
            {
                if (list[i].Event.Id.Equals(ev.Id))
                {
                    return;
                }
            }

            // Cap: evict oldest when full. 200 events covers a long
            // offline window without unbounded memory growth.
            if (list.Count >= MaxParkedPerGroup)
            {
                list.RemoveAt(0);
            }

            list.Add(new ParkedEvent { Event = ev, Attempts = 0 });
        }
    }

    private async Task ReplayParkedAsync(MarmotConversation conversation, string groupIdHex, CancellationToken ct)
    {
        // Drain the current buffer, sort by created_at so causal
        // order is preserved across replays, then re-feed every
        // event through ProcessOneAsync. Anything that's STILL
        // undecryptable goes back into the buffer (via ParkEvent
        // inside ProcessOneAsync), with the attempt counter bumped.
        //
        // If a replay produces another epoch advance, we recurse —
        // bounded by the parked retry counter — so a chain of
        // missed commits + app messages walks forward in one go.
        List<ParkedEvent> snapshot;
        lock (_parkedLock)
        {
            if (!_parkedByGroup.TryGetValue(groupIdHex, out var list) || list.Count == 0)
            {
                return;
            }

            snapshot = list.ToList();
            list.Clear();
        }

        snapshot.Sort((a, b) => a.Event.CreatedAt.CompareTo(b.Event.CreatedAt));

        bool advancedDuringReplay = false;
        foreach (var parked in snapshot)
        {
            if (parked.Attempts >= MaxRetriesPerParked)
            {
                // Give up on this one — likely a replayed duplicate,
                // a malformed payload, or an event from before our
                // join that we'll never decrypt.
                continue;
            }

            parked.Attempts++;
            bool advanced = await ProcessOneAsync(conversation, parked.Event, ct).ConfigureAwait(false);
            advancedDuringReplay = advancedDuringReplay || advanced;
        }

        // If we just advanced the epoch again during replay, anything
        // that was still parked might now be decryptable.
        if (advancedDuringReplay)
        {
            await ReplayParkedAsync(conversation, groupIdHex, ct).ConfigureAwait(false);
        }
    }

    private async ValueTask DisposeSubscriptionsAsync()
    {
        CancellationTokenSource? cts;
        Channel<MarmotInboundEvent>? channel;
        Task[] pumps;

        lock (_subLock)
        {
            cts = _pumpsCts;
            channel = _inboundChannel;
            pumps = _pumpTasks.ToArray();
            _pumpsCts = null;
            _inboundChannel = null;
            _pumpTasks.Clear();
        }

        cts?.Cancel();
        if (pumps.Length > 0)
        {
            try
            {
                await Task.WhenAll(pumps).ConfigureAwait(false);
            }
            catch
            {
                // pump exceptions during shutdown are non-fatal
            }
        }

        channel?.Writer.TryComplete();
        cts?.Dispose();
    }
}
