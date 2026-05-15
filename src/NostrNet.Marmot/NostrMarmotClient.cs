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

    internal NostrMarmotClient(
        IMarmotRelay relay,
        IMarmotMlsProvider provider,
        PrivateKey identityKey,
        IReadOnlyList<string> advertisedRelays,
        NostrClient? ownedClient,
        bool rotateAfterAccept)
    {
        _relay = relay ?? throw new ArgumentNullException(nameof(relay));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _identityKey = identityKey ?? throw new ArgumentNullException(nameof(identityKey));
        _advertisedRelays = advertisedRelays ?? Array.Empty<string>();
        _ownedClient = ownedClient;
        _rotateAfterAccept = rotateAfterAccept;
    }

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
    /// MLS store and start subscribing to each one's kind-445 traffic.
    /// Intended for app startup — calling it lets the app restore the
    /// conversations from a previous session without each having to be
    /// re-accepted from a Welcome.
    /// </summary>
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

            var convo = new MarmotConversation(g.NostrGroupId, peer);
            TrackConversation(convo);
            conversations.Add(convo);
        }

        return conversations;
    }

    /// <summary>
    /// Adds a peer to an existing conversation. Publishes the Welcome
    /// gift wrap to the new peer and the Commit GroupEvent to the
    /// conversation's relays.
    /// </summary>
    public async Task AddPeerAsync(
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
    }

    /// <summary>
    /// Removes peers from an existing conversation. Publishes the
    /// Commit GroupEvent so existing members (and the about-to-be-
    /// removed peers) process the removal.
    /// </summary>
    public async Task RemovePeersAsync(
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
    }

    /// <summary>
    /// Rotates the local member's leaf keys (MLS self-update) and
    /// publishes the resulting Commit so existing members advance.
    /// </summary>
    public async Task RotateKeysAsync(
        MarmotConversation conversation,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        EnsureNotDisposed();

        var result = await MarmotChat.RotateKeysAsync(_provider, conversation, ct).ConfigureAwait(false);
        await _relay.PublishAsync(result.CommitGroupEvent, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a UTF-8 text message in <paramref name="conversation"/>.
    /// Encrypts via the MLS application ratchet, wraps in a kind-445
    /// GroupEvent, and publishes.
    /// </summary>
    public async Task SendAsync(
        MarmotConversation conversation,
        string text,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(text);
        EnsureNotDisposed();

        var ev = await MarmotChat.EncryptMessageAsync(_provider, conversation, _identityKey, text, ct).ConfigureAwait(false);
        await _relay.PublishAsync(ev, ct).ConfigureAwait(false);
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
    private bool _autoAuth = true;
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
            marmot = new NostrMarmotClient(_relayBridge, _provider, _identityKey, _relays, ownedClient: null, _rotateAfterAccept);
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
                .WithAutoAuth(_autoAuth);

            var client = await clientBuilder.ConnectAsync(ct).ConfigureAwait(false);
            var bridge = new NostrClientMarmotRelay(client);
            marmot = new NostrMarmotClient(bridge, _provider, _identityKey, _relays, ownedClient: client, _rotateAfterAccept);
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
