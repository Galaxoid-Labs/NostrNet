// SPDX-License-Identifier: MIT
//
// NostrMarmotClient — high-level façade that ties an IMarmotRelay
// together with an IMarmotMlsProvider to deliver a one-call experience
// for 1:1 and group Marmot conversations.
//
// This file: builder, lifecycle, core async operations. Dynamic
// subscription multiplexing lives in NostrMarmotClientSubscriptions.cs.

using System.Threading.Channels;
using NostrNet.Client;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot.Events;
using NostrNet.Marmot.GroupData;
using NostrNet.Relay;

namespace NostrNet.Marmot;

/// <summary>
/// High-level Marmot client. Combines a <see cref="IMarmotRelay"/>
/// (typically a <see cref="NostrClientMarmotRelay"/> wrapping a
/// real <see cref="NostrClient"/>) with an <see cref="IMarmotMlsProvider"/>
/// and exposes the full 1:1 / group conversation flow as async methods.
/// </summary>
public sealed partial class NostrMarmotClient : IAsyncDisposable
{
    /// <summary>Default MLS ciphersuite for new groups + KeyPackages.</summary>
    public const ushort DefaultCiphersuite = MarmotChat.DefaultCiphersuite;

    private readonly IMarmotRelay _relay;
    private readonly IMarmotMlsProvider _provider;
    private readonly PrivateKey _identityKey;
    private readonly IReadOnlyList<string> _advertisedRelays;
    private readonly NostrClient? _ownedClient;
    private readonly bool _rotateAfterAccept;
    private bool _disposed;

    private readonly IMarmotMessageLog? _messageLog;

    internal NostrMarmotClient(
        IMarmotRelay relay,
        IMarmotMlsProvider provider,
        PrivateKey identityKey,
        IReadOnlyList<string> advertisedRelays,
        NostrClient? ownedClient,
        bool rotateAfterAccept,
        IMarmotMessageLog? messageLog)
    {
        _relay = relay ?? throw new ArgumentNullException(nameof(relay));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _identityKey = identityKey ?? throw new ArgumentNullException(nameof(identityKey));
        _advertisedRelays = advertisedRelays ?? Array.Empty<string>();
        _ownedClient = ownedClient;
        _rotateAfterAccept = rotateAfterAccept;
        _messageLog = messageLog;
    }

    /// <summary>
    /// The configured <see cref="IMarmotMessageLog"/>, or <c>null</c> when
    /// none was supplied. When non-null, every successfully-decrypted
    /// application message (kind-445 Application) is appended automatically
    /// before being yielded from <see cref="SubscribeAsync"/>.
    /// </summary>
    public IMarmotMessageLog? MessageLog => _messageLog;

    /// <summary>
    /// The most recent failure (if any) from the auto-publish step
    /// triggered by <c>AutoPublishKeyPackage</c> on the builder or
    /// from rotate-after-accept. Apps that care can surface it; most
    /// can ignore — a missing KeyPackage on relays only impacts
    /// inbound invites, not existing conversations.
    /// </summary>
    public Exception? LastAutoPublishError { get; private set; }

    internal void SetAutoPublishError(Exception? ex) => LastAutoPublishError = ex;

    /// <summary>The local Nostr identity (public counterpart of the key passed to <c>Builder</c>).</summary>
    public PublicKey Identity => _identityKey.PublicKey;

    /// <summary>The relays this client advertises in KeyPackage events and Welcomes.</summary>
    public IReadOnlyList<string> AdvertisedRelays => _advertisedRelays;

    /// <summary>The underlying <see cref="NostrClient"/> when built via <c>UseRelays</c>; <c>null</c> when a custom <see cref="IMarmotRelay"/> was supplied via <c>UseRelayBridge</c>.</summary>
    public NostrClient? NostrClient => _ownedClient;

    /// <summary>
    /// Yields per-relay connection state changes (Connecting / Connected /
    /// Disconnected) for the underlying transport, including a snapshot of
    /// the current state on subscribe. Drives status indicators in chat UIs
    /// ("3/5 relays online", "reconnecting…", etc.).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Auto-reconnect and auto-resubscribe are on by default (see
    /// <see cref="NostrMarmotClientBuilder.WithAutoReconnect"/> /
    /// <see cref="NostrMarmotClientBuilder.WithAutoResubscribe"/>), so a
    /// transient drop in the middle of a conversation doesn't surface to
    /// app code — messages keep flowing once the relay is back. This
    /// stream is the hook for showing transient state in the UI.
    /// </para>
    /// <para>
    /// When the client was built via <see cref="NostrMarmotClientBuilder.UseRelayBridge"/>,
    /// this returns an empty stream — the custom <see cref="IMarmotRelay"/>
    /// owns its own transport and doesn't expose state observation.
    /// </para>
    /// </remarks>
    public IAsyncEnumerable<RelayConnectionEvent> ObserveRelayConnectionsAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        return _ownedClient is null
            ? EmptyConnectionEvents(cancellationToken)
            : _ownedClient.ObserveRelayConnectionsAsync(cancellationToken);
    }

    private static async IAsyncEnumerable<RelayConnectionEvent> EmptyConnectionEvents(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        yield break;
    }

    /// <summary>
    /// Begins building a Marmot client. Supply the local identity key,
    /// an MLS provider, and either a set of relay URIs (typical) or a
    /// custom <see cref="IMarmotRelay"/> (for tests / advanced use).
    /// </summary>
    public static NostrMarmotClientBuilder Builder(PrivateKey identityKey, IMarmotMlsProvider provider)
    {
        ArgumentNullException.ThrowIfNull(identityKey);
        ArgumentNullException.ThrowIfNull(provider);
        return new NostrMarmotClientBuilder(identityKey, provider);
    }

    // ──────────────────────────────────────────────────────────────
    // KeyPackage publication + discovery.
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a fresh KeyPackage via the bound provider, signs the
    /// kind-30443 KeyPackage event, publishes it. Returns the event so
    /// you can keep its id for later (e.g. to log what slot was used).
    /// </summary>
    public async Task<NostrEvent> PublishKeyPackageAsync(
        string? slot = null,
        ushort ciphersuite = DefaultCiphersuite,
        CancellationToken ct = default)
    {
        EnsureNotDisposed();
        var ev = await MarmotChat.BuildKeyPackageEventAsync(
            _provider, _identityKey, slot, _advertisedRelays, ciphersuite, ct).ConfigureAwait(false);
        await _relay.PublishAsync(ev, ct).ConfigureAwait(false);
        return ev;
    }

    /// <summary>
    /// Briefly subscribes for kind-30443 events from <paramref name="peer"/>
    /// and returns the most recent one (or <c>null</c> if none arrived
    /// before the timeout). Intended for "I want to start a conversation
    /// with someone; do they have a published KeyPackage?" lookups.
    /// </summary>
    public async Task<NostrEvent?> TryGetKeyPackageAsync(
        PublicKey peer,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(peer);
        EnsureNotDisposed();

        var filter = new Filter
        {
            Kinds = new[] { MarmotKinds.KeyPackage },
            Authors = new[] { peer.ToHex() },
            Limit = 1,
        };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(5));

        try
        {
            await foreach (var ev in _relay.SubscribeAsync(new[] { filter }, cts.Token).ConfigureAwait(false))
            {
                if (ev.Kind == MarmotKinds.KeyPackage && ev.PubKey.Equals(peer))
                {
                    return ev;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Treat timeout as "not found" rather than an error.
        }

        return null;
    }

    // ──────────────────────────────────────────────────────────────
    // Conversation lifecycle.
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Starts a 1:1 conversation with <paramref name="peerKeyPackageEvent"/>'s
    /// author. Creates the MLS group, sends the NIP-59 Welcome to the peer,
    /// and (if <c>SubscribeAsync</c> is running) starts a per-group
    /// subscription for kind-445 traffic.
    /// </summary>
    public async Task<MarmotConversation> StartConversationAsync(
        NostrEvent peerKeyPackageEvent,
        string? conversationName = null,
        ushort ciphersuite = DefaultCiphersuite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(peerKeyPackageEvent);
        EnsureNotDisposed();

        var started = await MarmotChat.StartConversationAsync(
            _provider, _identityKey, peerKeyPackageEvent, conversationName,
            _advertisedRelays, ciphersuite, ct).ConfigureAwait(false);

        await _relay.PublishAsync(started.WelcomeGiftWrap, ct).ConfigureAwait(false);
        TrackConversation(started.Conversation);
        return started.Conversation;
    }

    /// <summary>
    /// Starts an N-member group conversation. Publishes one gift-wrap
    /// per peer.
    /// </summary>
    public async Task<MarmotConversation> StartGroupAsync(
        IReadOnlyList<NostrEvent> peerKeyPackageEvents,
        string? conversationName = null,
        ushort ciphersuite = DefaultCiphersuite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(peerKeyPackageEvents);
        EnsureNotDisposed();

        var started = await MarmotChat.StartGroupAsync(
            _provider, _identityKey, peerKeyPackageEvents, conversationName,
            _advertisedRelays, ciphersuite, ct).ConfigureAwait(false);

        foreach (var giftWrap in started.WelcomeGiftWraps)
        {
            await _relay.PublishAsync(giftWrap, ct).ConfigureAwait(false);
        }

        TrackConversation(started.Conversation);
        return started.Conversation;
    }

    /// <summary>
    /// Accepts a previously-received <see cref="MarmotInviteReceived"/>
    /// by processing the wrapped Welcome and joining the group. Returns
    /// <c>null</c> when the invite is stale (the local KeyPackage it
    /// references has been rotated away) or otherwise unprocessable, so
    /// consumers can silently skip relay-cached old Welcomes instead of
    /// surfacing an error. When the Welcome is a duplicate of one we
    /// already accepted, the existing conversation is returned.
    /// </summary>
    public async Task<MarmotConversation?> AcceptInviteAsync(
        MarmotInviteReceived invite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(invite);
        EnsureNotDisposed();

        var convo = await MarmotChat.TryAcceptInviteAsync(
            _provider, _identityKey, invite.OriginalGiftWrap, ct).ConfigureAwait(false);
        if (convo is null)
        {
            return null;
        }

        TrackConversation(convo);

        // The KeyPackage that addressed this Welcome is now "consumed"
        // — once a peer has used it, its init key shouldn't be served
        // to anyone else. Publish a fresh KeyPackage under the same
        // deterministic slot so the relay replaces the old event with
        // an init key the new peer can't address. Best-effort: a
        // failure here only impacts future invites, not the chat we
        // just joined.
        if (_rotateAfterAccept)
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await PublishKeyPackageAsync(ct: ct).ConfigureAwait(false);
                    LastAutoPublishError = null;
                }
                catch (Exception ex)
                {
                    LastAutoPublishError = ex;
                }
            }, ct);
        }

        return convo;
    }

    /// <summary>
    /// Enumerate every Marmot conversation already in the underlying
    /// MLS store, register each one with the live subscription pump, and
    /// return the resulting handles. Intended for app startup — calling
    /// this lets the app restore conversations from a previous session
    /// without each having to be re-accepted from a Welcome.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each returned conversation is <em>already tracked</em> by the
    /// inbox/per-conversation pumps — callers do not (and should not)
    /// call <see cref="TrackConversation"/> on them. A subsequent
    /// <see cref="SubscribeAsync"/> will yield
    /// <see cref="MarmotMessageReceived"/> for kind-445 traffic on every
    /// returned conversation automatically.
    /// </para>
    /// <para>
    /// <see cref="MarmotConversation.Name"/> and
    /// <see cref="MarmotConversation.Description"/> are populated from
    /// the underlying group's NostrGroupData extension when available.
    /// </para>
    /// </remarks>
    /// <returns>The list of conversations now being tracked.</returns>
    public async Task<IReadOnlyList<MarmotConversation>> LoadExistingConversationsAsync(CancellationToken ct = default)
    {
        EnsureNotDisposed();
        IReadOnlyList<MarmotStoredGroup> stored = await _provider.ListGroupsAsync(ct).ConfigureAwait(false);

        var conversations = new List<MarmotConversation>(stored.Count);
        foreach (var g in stored)
        {
            // For a 1:1 conversation the "peer" is the single other
            // member. For multi-member groups we leave Peer null —
            // the caller can read .Members itself if it cares.
            PublicKey? peer = null;
            PublicKey self = Identity;
            int otherCount = 0;
            foreach (var m in g.Members)
            {
                if (!m.Equals(self))
                {
                    otherCount++;
                    if (otherCount == 1)
                    {
                        peer = m;
                    }
                    else
                    {
                        peer = null;
                        break;
                    }
                }
            }

            var convo = new MarmotConversation(g.NostrGroupId, peer)
            {
                Name = g.GroupData?.Name,
                Description = g.GroupData?.Description,
                Members = g.Members,
            };
            TrackConversation(convo);
            conversations.Add(convo);
        }

        return conversations;
    }

    /// <summary>
    /// Replay persisted application-message history for
    /// <paramref name="conversation"/> from the attached
    /// <see cref="IMarmotMessageLog"/>. Returns an empty stream when no
    /// log was configured. Intended for cold-start rendering — call
    /// this for each conversation immediately after
    /// <see cref="LoadExistingConversationsAsync"/> to populate the UI
    /// before live kind-445 events start flowing.
    /// </summary>
    /// <param name="conversation">The conversation to load history for.</param>
    /// <param name="since">Inclusive lower bound on <see cref="MarmotMessageReceived.ServerTimestamp"/>. <c>null</c> = beginning of stored history.</param>
    /// <param name="limit">Optional cap on the number of messages yielded.</param>
    /// <param name="cancellationToken">Cancels enumeration.</param>
    public IAsyncEnumerable<MarmotMessageReceived> LoadHistoryAsync(
        MarmotConversation conversation,
        DateTimeOffset? since = null,
        int? limit = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        EnsureNotDisposed();
        return _messageLog is null
            ? EmptyHistory(cancellationToken)
            : _messageLog.LoadAsync(conversation.NostrGroupId, since, limit, cancellationToken);
    }

    /// <summary>
    /// The most recent persisted application message for
    /// <paramref name="conversation"/>, or <c>null</c> when none is stored.
    /// Use for chat-list previews and last-activity timestamps.
    /// Returns <c>null</c> when no <see cref="IMarmotMessageLog"/> is configured.
    /// </summary>
    public ValueTask<MarmotMessageReceived?> GetLastMessageAsync(
        MarmotConversation conversation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        EnsureNotDisposed();
        return _messageLog is null
            ? new ValueTask<MarmotMessageReceived?>((MarmotMessageReceived?)null)
            : _messageLog.GetLastAsync(conversation.NostrGroupId, cancellationToken);
    }

    private static async IAsyncEnumerable<MarmotMessageReceived> EmptyHistory(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        yield break;
    }

    /// <summary>
    /// Adds a peer to an existing conversation. Publishes the Welcome
    /// gift wrap to the new peer and the Commit GroupEvent to the
    /// conversation's relays. Surfaces a <see cref="MarmotGroupStateChanged"/>
    /// to the caller's own <see cref="SubscribeAsync"/> stream (same
    /// rationale as <see cref="SendAsync"/>'s own-send echo — MLS won't
    /// decrypt our own Commit on the relay round-trip, so we emit it
    /// directly). Returns the Commit kind-445 event so callers can
    /// correlate by event id.
    /// </summary>
    public async Task<NostrEvent> AddPeerAsync(
        MarmotConversation conversation,
        NostrEvent peerKeyPackageEvent,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(peerKeyPackageEvent);
        EnsureNotDisposed();

        var result = await MarmotChat.AddPeerAsync(
            _provider, _identityKey, conversation, peerKeyPackageEvent,
            _advertisedRelays, ct).ConfigureAwait(false);

        await _relay.PublishAsync(result.WelcomeGiftWrap, ct).ConfigureAwait(false);
        await _relay.PublishAsync(result.CommitGroupEvent, ct).ConfigureAwait(false);

        await EmitOwnGroupStateChangeAsync(conversation, ct).ConfigureAwait(false);
        return result.CommitGroupEvent;
    }

    /// <summary>
    /// Removes peers from an existing conversation. Publishes the
    /// Commit GroupEvent so existing members process the removal; the
    /// removed peers lose decrypt access from the new epoch onward.
    /// Surfaces a <see cref="MarmotGroupStateChanged"/> to the caller's
    /// own <see cref="SubscribeAsync"/> stream. Returns the Commit
    /// kind-445 event.
    /// </summary>
    public async Task<NostrEvent> RemovePeersAsync(
        MarmotConversation conversation,
        IReadOnlyList<PublicKey> peersToRemove,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(peersToRemove);
        EnsureNotDisposed();

        var result = await MarmotChat.RemovePeerAsync(
            _provider, conversation, peersToRemove, ct).ConfigureAwait(false);
        await _relay.PublishAsync(result.CommitGroupEvent, ct).ConfigureAwait(false);

        await EmitOwnGroupStateChangeAsync(conversation, ct).ConfigureAwait(false);
        return result.CommitGroupEvent;
    }

    /// <summary>
    /// Rotates the local member's leaf keys (MLS self-update) and
    /// publishes the resulting Commit so existing members advance.
    /// Surfaces a <see cref="MarmotGroupStateChanged"/> to the caller's
    /// own <see cref="SubscribeAsync"/> stream. Returns the Commit
    /// kind-445 event.
    /// </summary>
    public async Task<NostrEvent> RotateKeysAsync(
        MarmotConversation conversation,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        EnsureNotDisposed();

        var result = await MarmotChat.RotateKeysAsync(_provider, conversation, ct).ConfigureAwait(false);
        await _relay.PublishAsync(result.CommitGroupEvent, ct).ConfigureAwait(false);

        await EmitOwnGroupStateChangeAsync(conversation, ct).ConfigureAwait(false);
        return result.CommitGroupEvent;
    }

    /// <summary>
    /// Sends a UTF-8 text message in <paramref name="conversation"/>.
    /// Encrypts via the MLS application ratchet, wraps in a kind-445
    /// GroupEvent, publishes, and surfaces the own send through the
    /// same channels (<see cref="SubscribeAsync"/> + the configured
    /// <see cref="IMarmotMessageLog"/>) that inbound messages flow
    /// through. Returns the published kind-445 event so callers can
    /// correlate by event id.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Apps render their own messages and peer messages through the
    /// same <see cref="MarmotMessageReceived"/> code path —
    /// <c>msg.Sender.Equals(client.Identity)</c> is the "from me" flag.
    /// No app-side echo or synthetic-id plumbing required.
    /// </para>
    /// <para>
    /// Why this is necessary at the library layer: when our own
    /// kind-445 is broadcast back to us by the relay, the receive
    /// pump can't decrypt it. MLS application-message encryption uses
    /// a per-leaf outbound ratchet; the sender's provider has already
    /// advanced past the generation the receiver-side decrypt would
    /// need, and there's no inverse "decrypt my own ciphertext"
    /// operation. So apps either get a one-direction render path
    /// (peer messages only — broken) or have to fabricate their own
    /// echo with synthetic ids that don't match real relay-delivered
    /// ids. Library-side emission closes that asymmetry cleanly.
    /// </para>
    /// </remarks>
    public async Task<NostrEvent> SendAsync(
        MarmotConversation conversation,
        string text,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(text);
        EnsureNotDisposed();

        // Build the rumor explicitly so we can echo the same RumorId on
        // the synthetic own-send. The receive-side ratchet can't decrypt
        // our own ciphertext, so without echoing the rumor id apps would
        // see a different stable id for the message they themselves sent
        // versus what peers see.
        var rumor = new UnsignedEvent
        {
            PubKey = _identityKey.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = MarmotChat.ChatMessageRumorKind,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = text,
        };
        EventId rumorId = rumor.ComputeId();

        var ev = await MarmotChat.EncryptRumorAsync(_provider, conversation, rumor, ct).ConfigureAwait(false);
        await _relay.PublishAsync(ev, ct).ConfigureAwait(false);

        var own = new MarmotMessageReceived(
            Conversation: conversation,
            EventId: ev.Id,
            RumorId: rumorId,
            RumorKind: rumor.Kind,
            RumorTags: rumor.Tags,
            Sender: _identityKey.PublicKey,
            Plaintext: text,
            ServerTimestamp: DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt));

        await EmitOwnApplicationMessageAsync(own, ct).ConfigureAwait(false);
        return ev;
    }

    /// <summary>
    /// Sends a NIP-25 reaction in <paramref name="conversation"/> targeting
    /// the inner rumor <paramref name="targetRumorId"/>. Surfaces the
    /// own-send via <see cref="SubscribeAsync"/> + <see cref="IMarmotMessageLog"/>
    /// the same way <see cref="SendAsync"/> does (the MLS ratchet
    /// asymmetry — sender can't decrypt own ciphertext — applies to
    /// every application message kind, not just chat).
    /// </summary>
    /// <param name="conversation">The conversation to react in.</param>
    /// <param name="targetRumorId">
    /// The inner Marmot rumor id being reacted to. Use
    /// <see cref="MarmotMessageReceived.RumorId"/>, NOT the outer
    /// <see cref="MarmotMessageReceived.EventId"/>.
    /// </param>
    /// <param name="reaction">Reaction text — emoji, <c>+</c>, <c>-</c>, or NIP-25 <c>:shortcode:</c>.</param>
    /// <param name="additionalTags">Optional extra tags (e.g. NIP-25 custom-emoji declaration).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The published kind-445 event so callers can correlate by event id.</returns>
    public async Task<NostrEvent> SendReactionAsync(
        MarmotConversation conversation,
        EventId targetRumorId,
        string reaction,
        IReadOnlyList<IReadOnlyList<string>>? additionalTags = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(targetRumorId);
        ArgumentNullException.ThrowIfNull(reaction);
        EnsureNotDisposed();

        var rumor = MarmotChat.BuildReactionRumor(
            targetRumorId, reaction, _identityKey.PublicKey, additionalTags);
        EventId rumorId = rumor.ComputeId();

        var ev = await MarmotChat.EncryptRumorAsync(_provider, conversation, rumor, ct).ConfigureAwait(false);
        await _relay.PublishAsync(ev, ct).ConfigureAwait(false);

        var own = new MarmotMessageReceived(
            Conversation: conversation,
            EventId: ev.Id,
            RumorId: rumorId,
            RumorKind: rumor.Kind,
            RumorTags: rumor.Tags,
            Sender: _identityKey.PublicKey,
            Plaintext: reaction,
            ServerTimestamp: DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt));

        await EmitOwnApplicationMessageAsync(own, ct).ConfigureAwait(false);
        return ev;
    }

    /// <summary>
    /// Sends a NIP-09 deletion request in <paramref name="conversation"/>
    /// targeting the inner rumor <paramref name="targetRumorId"/>.
    /// Surfaces the own-send via <see cref="SubscribeAsync"/> + the
    /// configured <see cref="IMarmotMessageLog"/>.
    /// </summary>
    /// <param name="conversation">The conversation containing the rumor being deleted.</param>
    /// <param name="targetRumorId">
    /// The inner Marmot rumor id being deleted. Use
    /// <see cref="MarmotMessageReceived.RumorId"/>, NOT the outer
    /// <see cref="MarmotMessageReceived.EventId"/>.
    /// </param>
    /// <param name="targetKind">
    /// The kind of the rumor being deleted — typically
    /// <see cref="MarmotChat.ChatMessageRumorKind"/> (9) or
    /// <see cref="MarmotChat.ReactionRumorKind"/> (7).
    /// </param>
    /// <param name="reason">Optional NIP-09 reason string; empty content when null.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <remarks>
    /// NIP-09 is advisory — receiving apps only honor the deletion when
    /// the sender (<see cref="MarmotMessageReceived.Sender"/>) matches
    /// the author of the targeted rumor. The library cannot enforce
    /// that check because the original event isn't in scope at receive
    /// time; consumers compare against their local message log.
    /// </remarks>
    public async Task<NostrEvent> SendDeletionAsync(
        MarmotConversation conversation,
        EventId targetRumorId,
        int targetKind,
        string? reason = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(targetRumorId);
        EnsureNotDisposed();

        var rumor = MarmotChat.BuildDeletionRumor(
            targetRumorId, targetKind, _identityKey.PublicKey, reason);
        EventId rumorId = rumor.ComputeId();

        var ev = await MarmotChat.EncryptRumorAsync(_provider, conversation, rumor, ct).ConfigureAwait(false);
        await _relay.PublishAsync(ev, ct).ConfigureAwait(false);

        var own = new MarmotMessageReceived(
            Conversation: conversation,
            EventId: ev.Id,
            RumorId: rumorId,
            RumorKind: rumor.Kind,
            RumorTags: rumor.Tags,
            Sender: _identityKey.PublicKey,
            Plaintext: reason ?? string.Empty,
            ServerTimestamp: DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt));

        await EmitOwnApplicationMessageAsync(own, ct).ConfigureAwait(false);
        return ev;
    }

    /// <summary>
    /// Shared own-send emission path: log the synthetic
    /// <see cref="MarmotMessageReceived"/>, then write it to the inbound
    /// channel. Both steps are fail-soft.
    /// </summary>
    private async Task EmitOwnApplicationMessageAsync(
        MarmotMessageReceived own,
        CancellationToken ct)
    {
        if (_messageLog is not null)
        {
            try
            {
                await _messageLog.AppendAsync(own, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
            }
        }

        if (_inboundChannel is not null)
        {
            try
            {
                await _inboundChannel.Writer.WriteAsync(own, ct).ConfigureAwait(false);
            }
            catch (System.Threading.Channels.ChannelClosedException)
            {
                // Disposal raced; nothing to do.
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Disposal.
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Releases resources owned by the client: cancels any
    /// SubscribeAsync pumps, disposes the underlying NostrClient if
    /// the builder created it, and disposes the MLS provider if it's
    /// disposable.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await DisposeSubscriptionsAsync().ConfigureAwait(false);

        if (_ownedClient is not null)
        {
            await _ownedClient.DisposeAsync().ConfigureAwait(false);
        }

        if (_provider is IDisposable d)
        {
            d.Dispose();
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(NostrMarmotClient));
        }
    }
}

/// <summary>Fluent builder for <see cref="NostrMarmotClient"/>.</summary>
public sealed class NostrMarmotClientBuilder
{
    private readonly PrivateKey _identityKey;
    private readonly IMarmotMlsProvider _provider;
    private readonly List<string> _relays = new();
    private IMarmotRelay? _relayBridge;
    private IMarmotMessageLog? _messageLog;
    private bool _autoAuth = true;
    private bool _autoReconnect = true;
    private bool _autoResubscribe = true;
    private bool _autoPublishKeyPackage = true;
    private bool _rotateAfterAccept = true;

    internal NostrMarmotClientBuilder(PrivateKey identityKey, IMarmotMlsProvider provider)
    {
        _identityKey = identityKey;
        _provider = provider;
    }

    /// <summary>Registers relay URIs to connect to.</summary>
    public NostrMarmotClientBuilder UseRelays(params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);
        _relays.AddRange(uris);
        return this;
    }

    /// <summary>Disables NIP-42 auto-AUTH for the underlying NostrClient. Default: enabled.</summary>
    public NostrMarmotClientBuilder WithAutoAuth(bool enabled)
    {
        _autoAuth = enabled;
        return this;
    }

    /// <summary>
    /// Disables automatic transport reconnect (with exponential backoff) on
    /// the underlying <see cref="NostrClient"/>. Default: enabled.
    /// </summary>
    /// <remarks>
    /// Has no effect when <see cref="UseRelayBridge"/> is used — the custom
    /// <see cref="IMarmotRelay"/> owns its own transport policy.
    /// </remarks>
    public NostrMarmotClientBuilder WithAutoReconnect(bool enabled)
    {
        _autoReconnect = enabled;
        return this;
    }

    /// <summary>
    /// Disables transparent subscription resume across reconnects on the
    /// underlying <see cref="NostrClient"/>. Default: enabled — the inbox
    /// pump (kind-1059 invites) and per-conversation pumps (kind-445
    /// group events) survive transient transport drops without surfacing
    /// the disconnect to the app.
    /// </summary>
    /// <remarks>
    /// Has no effect when <see cref="UseRelayBridge"/> is used. Most chat
    /// apps want this on — disabling it means an invite that arrives
    /// during a brief WebSocket reset is missed.
    /// </remarks>
    public NostrMarmotClientBuilder WithAutoResubscribe(bool enabled)
    {
        _autoResubscribe = enabled;
        return this;
    }

    /// <summary>
    /// Controls whether <see cref="ConnectAsync"/> publishes a fresh
    /// KeyPackage to the configured relays immediately after the
    /// underlying <see cref="NostrClient"/> connects. Default: <c>true</c>.
    /// MIP-00 says clients SHOULD rotate KeyPackages periodically; an
    /// app-launch publish is the simplest spec-conforming cadence and
    /// avoids the timer machinery a true scheduler would need. Failures
    /// are swallowed and surfaced via
    /// <see cref="NostrMarmotClient.LastAutoPublishError"/>.
    /// </summary>
    public NostrMarmotClientBuilder AutoPublishKeyPackage(bool enabled)
    {
        _autoPublishKeyPackage = enabled;
        return this;
    }

    /// <summary>
    /// Controls whether <see cref="NostrMarmotClient.AcceptInviteAsync"/>
    /// publishes a replacement KeyPackage after a successful join.
    /// Default: <c>true</c>. The KeyPackage that addressed the
    /// Welcome we just consumed should not be served to anyone else;
    /// the deterministic slot id (<see cref="MarmotChat.BuildKeyPackageEventAsync"/>)
    /// means the new publish replaces the old event under
    /// <c>(kind, pubkey, d)</c> on every cooperating relay.
    /// </summary>
    public NostrMarmotClientBuilder RotateKeyPackageAfterAccept(bool enabled)
    {
        _rotateAfterAccept = enabled;
        return this;
    }

    /// <summary>
    /// Supplies a custom <see cref="IMarmotRelay"/> instead of letting
    /// the builder construct a <see cref="NostrClient"/>. Mainly for
    /// tests; production code should use <see cref="UseRelays"/>.
    /// </summary>
    public NostrMarmotClientBuilder UseRelayBridge(IMarmotRelay relay)
    {
        ArgumentNullException.ThrowIfNull(relay);
        _relayBridge = relay;
        return this;
    }

    /// <summary>
    /// Attaches an <see cref="IMarmotMessageLog"/> for plaintext-message
    /// persistence. Every successfully-decrypted kind-445 application
    /// message will be appended automatically. Without a log, cold-start
    /// chat history is unavailable — MLS forward secrecy destroys old
    /// exporters as the epoch advances, so kind-445 ciphertext on relays
    /// can't be re-decrypted on a future session.
    /// </summary>
    public NostrMarmotClientBuilder WithMessageLog(IMarmotMessageLog log)
    {
        ArgumentNullException.ThrowIfNull(log);
        _messageLog = log;
        return this;
    }

    /// <summary>
    /// Builds the <see cref="NostrMarmotClient"/>. When
    /// <see cref="UseRelayBridge"/> hasn't been called, connects a
    /// fresh <see cref="NostrClient"/> to the configured relays and
    /// wraps it.
    /// </summary>
    public async Task<NostrMarmotClient> ConnectAsync(CancellationToken ct = default)
    {
        NostrMarmotClient marmot;
        if (_relayBridge is not null)
        {
            marmot = new NostrMarmotClient(_relayBridge, _provider, _identityKey, _relays, ownedClient: null, _rotateAfterAccept, _messageLog);
        }
        else
        {
            if (_relays.Count == 0)
            {
                throw new InvalidOperationException(
                    "Provide at least one relay via UseRelays(...) or supply a custom IMarmotRelay via UseRelayBridge(...).");
            }

            var clientBuilder = NostrClient.Builder(_identityKey)
                .UseRelays(_relays.ToArray())
                .WithAutoAuth(_autoAuth)
                .WithAutoReconnect(_autoReconnect)
                .WithAutoResubscribe(_autoResubscribe);

            var client = await clientBuilder.ConnectAsync(ct).ConfigureAwait(false);
            var bridge = new NostrClientMarmotRelay(client);
            marmot = new NostrMarmotClient(bridge, _provider, _identityKey, _relays, ownedClient: client, _rotateAfterAccept, _messageLog);
        }

        if (_autoPublishKeyPackage)
        {
            // Best-effort: a relay hiccup at startup shouldn't block
            // the whole app, but the error is surfaced via
            // LastAutoPublishError so curious callers can check.
            try
            {
                await marmot.PublishKeyPackageAsync(ct: ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                marmot.SetAutoPublishError(ex);
            }
        }

        return marmot;
    }
}
