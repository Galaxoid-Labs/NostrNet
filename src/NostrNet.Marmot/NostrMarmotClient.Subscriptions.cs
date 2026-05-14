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

                MarmotInboundMessage? processed;
                try
                {
                    processed = await MarmotChat.TryProcessMessageAsync(_provider, conversation, ev, ct).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // TryProcess swallows expected failures and returns null;
                    // genuine exceptions (e.g., bad state) we just drop the event.
                    continue;
                }

                if (processed is null)
                {
                    // Common case: epoch mismatch — relay delivered an
                    // application message from a new epoch before the
                    // Commit. The app may want to retry once the Commit
                    // arrives; for now we just drop and let the Commit
                    // (which will be delivered on the same subscription)
                    // catch the receiver up.
                    continue;
                }

                MarmotInboundEvent typed = processed.Kind switch
                {
                    MarmotMessageKind.Application => new MarmotMessageReceived(
                        Conversation: conversation,
                        Sender: processed.Sender,
                        Plaintext: processed.Plaintext ?? string.Empty,
                        ServerTimestamp: DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt)),
                    MarmotMessageKind.Commit => new MarmotGroupStateChanged(
                        Conversation: conversation,
                        Sender: processed.Sender),
                    _ => null!,
                };

                if (typed is null)
                {
                    continue;
                }

                await _inboundChannel!.Writer.WriteAsync(typed, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // expected during shutdown
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
