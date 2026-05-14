// SPDX-License-Identifier: MIT
//
// End-to-end exercises of NostrMarmotClient against a fake IMarmotRelay.
// The fake is an in-memory broadcast relay: events Publish'd by any
// client are stored and re-delivered to every active SubscribeAsync
// stream whose Filter matches. This lets us drive the full Marmot
// conversation flow — invite, accept, send/receive, add/remove — with
// no WebSocket dependency.

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Relay;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class NostrMarmotClientTests
{
    private const string FakeRelayUri = "wss://fake.example";

    [Fact]
    public async Task FullOneToOneFlow_OverFakeRelay()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        // Bob's inbound stream must be tapped before publish so the
        // inbox pump is actually subscribed when the invite arrives.
        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        var bobKp = await bob.PublishKeyPackageAsync();
        var fetched = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        Assert.NotNull(fetched);
        Assert.Equal(bobKp.Id, fetched!.Id);

        var aliceConvo = await alice.StartConversationAsync(fetched, "Alice <> Bob");

        var invite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        Assert.Equal(aliceKey.PublicKey, invite.Sender);

        var bobConvo = await bob.AcceptInviteAsync(invite);
        Assert.Equal(aliceConvo.NostrGroupId, bobConvo.NostrGroupId);

        await alice.SendAsync(aliceConvo, "hello bob");

        var got = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
        Assert.Equal("hello bob", got.Plaintext);
        Assert.Equal(aliceKey.PublicKey, got.Sender);
    }

    [Fact]
    public async Task GroupAdd_SurfacesAsStateChange_ForExistingMembers()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var charlieKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);
        await using var charlie = await BuildAsync(charlieKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);
        var charlieInbound = charlie.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        await charlie.PublishKeyPackageAsync();

        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var charlieKp = await alice.TryGetKeyPackageAsync(charlieKey.PublicKey, TimeSpan.FromSeconds(2));
        Assert.NotNull(bobKp);
        Assert.NotNull(charlieKp);

        var aliceConvo = await alice.StartConversationAsync(bobKp!, "ABC");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        await alice.AddPeerAsync(aliceConvo, charlieKp!);

        var bobStateChange = await NextOfTypeAsync<MarmotGroupStateChanged>(bobInbound);
        Assert.Equal(aliceConvo.NostrGroupId, bobStateChange.Conversation.NostrGroupId);
        Assert.Equal(aliceKey.PublicKey, bobStateChange.Sender);

        var charlieInvite = await NextOfTypeAsync<MarmotInviteReceived>(charlieInbound);
        Assert.Equal(aliceKey.PublicKey, charlieInvite.Sender);
    }

    [Fact]
    public async Task RemovePeer_SurfacesAsStateChange_AndStopsDeliveryToRemovedMember()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var charlieKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);
        await using var charlie = await BuildAsync(charlieKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);
        var charlieInbound = charlie.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        await charlie.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var charlieKp = await alice.TryGetKeyPackageAsync(charlieKey.PublicKey, TimeSpan.FromSeconds(2));

        var aliceConvo = await alice.StartConversationAsync(bobKp!, "Trio");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(bobInvite);

        await alice.AddPeerAsync(aliceConvo, charlieKp!);
        // Bob processes the add commit; ignore it for this test.
        _ = await NextOfTypeAsync<MarmotGroupStateChanged>(bobInbound);
        var charlieInvite = await NextOfTypeAsync<MarmotInviteReceived>(charlieInbound);
        var charlieConvo = await charlie.AcceptInviteAsync(charlieInvite);

        // Alice removes Charlie. Bob sees a state change for the Commit
        // (the merged staged state advances past the removal).
        await alice.RemovePeersAsync(aliceConvo, new[] { charlieKey.PublicKey });

        var stateChange = await NextOfTypeAsync<MarmotGroupStateChanged>(bobInbound);
        Assert.Equal(aliceKey.PublicKey, stateChange.Sender);
        Assert.Equal(aliceConvo.NostrGroupId, stateChange.Conversation.NostrGroupId);

        // Alice and Bob can keep chatting after the remove.
        await alice.SendAsync(aliceConvo, "after-remove");
        var got = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
        Assert.Equal("after-remove", got.Plaintext);

        // The fake relay still hands Charlie a copy of the kind-445, but
        // his stream surfaces nothing — TryProcessMessage drops it
        // because Charlie's MLS state can no longer decrypt this group.
        using var charlieIdle = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var leak = await TryNextAsync(charlieInbound, charlieIdle.Token);
        Assert.Null(leak);
    }

    [Fact]
    public async Task RotateKeys_SurfacesAsStateChange_AndMessagesStillFlow()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "rot");
        var invite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(invite);

        await alice.RotateKeysAsync(aliceConvo);

        var rotated = await NextOfTypeAsync<MarmotGroupStateChanged>(bobInbound);
        Assert.Equal(aliceKey.PublicKey, rotated.Sender);

        await alice.SendAsync(aliceConvo, "post-rotation");
        var got = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
        Assert.Equal("post-rotation", got.Plaintext);
        Assert.Equal(aliceKey.PublicKey, got.Sender);
    }

    [Fact]
    public async Task MultipleMessages_DeliveredInPublishOrder()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "ordered");
        var invite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        _ = await bob.AcceptInviteAsync(invite);

        string[] sent = { "one", "two", "three", "four", "five" };
        foreach (var s in sent)
        {
            await alice.SendAsync(aliceConvo, s);
        }

        var received = new List<string>();
        for (int i = 0; i < sent.Length; i++)
        {
            var m = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
            received.Add(m.Plaintext);
        }

        Assert.Equal(sent, received);
    }

    [Fact]
    public async Task UnrelatedConversation_DoesNotLeakIntoSubscriber()
    {
        // Three parties: Alice <-> Bob in one conversation, and a parallel
        // Dave <-> Eve in another. Bob's stream must surface Alice-Bob
        // traffic only — even though both conversations land on the same
        // fake relay, the per-group h-tag filter keeps them separate.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var daveKey = PrivateKey.Generate();
        using var eveKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);
        await using var dave = await BuildAsync(daveKey, relay);
        await using var eve = await BuildAsync(eveKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);
        var eveInbound = eve.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        await eve.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var eveKp = await dave.TryGetKeyPackageAsync(eveKey.PublicKey, TimeSpan.FromSeconds(2));

        var aliceConvo = await alice.StartConversationAsync(bobKp!, "AB");
        var daveConvo = await dave.StartConversationAsync(eveKp!, "DE");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        _ = await bob.AcceptInviteAsync(bobInvite);
        var eveInvite = await NextOfTypeAsync<MarmotInviteReceived>(eveInbound);
        _ = await eve.AcceptInviteAsync(eveInvite);

        await alice.SendAsync(aliceConvo, "for-bob");
        await dave.SendAsync(daveConvo, "for-eve");

        var bobGot = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
        Assert.Equal("for-bob", bobGot.Plaintext);
        var eveGot = await NextOfTypeAsync<MarmotMessageReceived>(eveInbound);
        Assert.Equal("for-eve", eveGot.Plaintext);

        // Neither side ever sees the other group's plaintext.
        using var idle = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        var bobLeak = await TryNextOfTypeAsync<MarmotMessageReceived>(bobInbound, idle.Token);
        Assert.Null(bobLeak);
    }

    [Fact]
    public async Task DisposeAsync_CompletesActiveSubscribers()
    {
        using var aliceKey = PrivateKey.Generate();
        var relay = new FakeRelay();
        var alice = await BuildAsync(aliceKey, relay);

        await using var enumerator = alice.SubscribeAsync(default).GetAsyncEnumerator();
        // Give the inbox pump a tick to actually register with the fake relay.
        await Task.Delay(50);

        await alice.DisposeAsync();

        bool more = await enumerator.MoveNextAsync();
        Assert.False(more);
    }

    private static Task<NostrMarmotClient> BuildAsync(PrivateKey identityKey, FakeRelay relay) =>
        NostrMarmotClient.Builder(identityKey, new OpenMlsProvider())
            .UseRelays(FakeRelayUri)
            .UseRelayBridge(relay)
            .ConnectAsync();

    private static async Task<T> NextOfTypeAsync<T>(IAsyncEnumerable<MarmotInboundEvent> source)
        where T : MarmotInboundEvent
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await foreach (var ev in source.WithCancellation(cts.Token))
        {
            if (ev is T t)
            {
                return t;
            }
        }

        throw new TimeoutException($"Timed out waiting for {typeof(T).Name}.");
    }

    /// <summary>
    /// Like <see cref="NextOfTypeAsync"/> but returns <c>null</c> on
    /// timeout instead of throwing. Useful for asserting silence.
    /// </summary>
    private static async Task<T?> TryNextOfTypeAsync<T>(
        IAsyncEnumerable<MarmotInboundEvent> source,
        CancellationToken ct)
        where T : MarmotInboundEvent
    {
        try
        {
            await foreach (var ev in source.WithCancellation(ct))
            {
                if (ev is T t)
                {
                    return t;
                }
            }
        }
        catch (OperationCanceledException)
        {
        }

        return null;
    }

    /// <summary>Pulls the next event of any type, or null on timeout.</summary>
    private static async Task<MarmotInboundEvent?> TryNextAsync(
        IAsyncEnumerable<MarmotInboundEvent> source,
        CancellationToken ct)
    {
        try
        {
            await foreach (var ev in source.WithCancellation(ct))
            {
                return ev;
            }
        }
        catch (OperationCanceledException)
        {
        }

        return null;
    }

    /// <summary>
    /// Single-process broadcast relay. Stores every Publish; every active
    /// SubscribeAsync gets the stored backlog matching its filter, then
    /// every subsequent Publish that matches.
    /// </summary>
    private sealed class FakeRelay : IMarmotRelay
    {
        private readonly object _lock = new();
        private readonly List<NostrEvent> _stored = new();
        private readonly ConcurrentDictionary<Subscriber, byte> _subscribers = new();

        public Task PublishAsync(NostrEvent ev, CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(ev);
            lock (_lock)
            {
                _stored.Add(ev);
            }

            foreach (var sub in _subscribers.Keys)
            {
                if (sub.Matches(ev))
                {
                    sub.Writer.TryWrite(ev);
                }
            }

            return Task.CompletedTask;
        }

        public async IAsyncEnumerable<NostrEvent> SubscribeAsync(
            IReadOnlyList<Filter> filters,
            [EnumeratorCancellation] CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(filters);
            var sub = new Subscriber(filters);

            NostrEvent[] snapshot;
            lock (_lock)
            {
                snapshot = _stored.ToArray();
                _subscribers.TryAdd(sub, 0);
            }

            try
            {
                foreach (var ev in snapshot)
                {
                    if (sub.Matches(ev))
                    {
                        yield return ev;
                    }
                }

                while (await sub.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
                {
                    while (sub.Reader.TryRead(out var ev))
                    {
                        yield return ev;
                    }
                }
            }
            finally
            {
                _subscribers.TryRemove(sub, out _);
                sub.Writer.TryComplete();
            }
        }

        private sealed class Subscriber
        {
            private readonly IReadOnlyList<Filter> _filters;
            private readonly Channel<NostrEvent> _ch =
                Channel.CreateUnbounded<NostrEvent>(new UnboundedChannelOptions { SingleReader = true });

            public Subscriber(IReadOnlyList<Filter> filters) => _filters = filters;
            public ChannelWriter<NostrEvent> Writer => _ch.Writer;
            public ChannelReader<NostrEvent> Reader => _ch.Reader;

            public bool Matches(NostrEvent ev)
            {
                foreach (var f in _filters)
                {
                    if (MatchesFilter(ev, f))
                    {
                        return true;
                    }
                }

                return false;
            }

            private static bool MatchesFilter(NostrEvent ev, Filter f)
            {
                if (f.Kinds is { Count: > 0 } kinds && !kinds.Contains(ev.Kind))
                {
                    return false;
                }

                if (f.Authors is { Count: > 0 } authors)
                {
                    string evAuthor = ev.PubKey.ToHex();
                    bool any = false;
                    foreach (var a in authors)
                    {
                        if (string.Equals(a, evAuthor, StringComparison.OrdinalIgnoreCase))
                        {
                            any = true;
                            break;
                        }
                    }

                    if (!any)
                    {
                        return false;
                    }
                }

                if (f.TagFilters is { Count: > 0 } tagFilters)
                {
                    foreach (var kv in tagFilters)
                    {
                        bool any = false;
                        foreach (var tag in ev.Tags)
                        {
                            if (tag.Count >= 2 && string.Equals(tag[0], kv.Key, StringComparison.Ordinal))
                            {
                                foreach (var wanted in kv.Value)
                                {
                                    if (string.Equals(tag[1], wanted, StringComparison.OrdinalIgnoreCase))
                                    {
                                        any = true;
                                        break;
                                    }
                                }
                            }

                            if (any)
                            {
                                break;
                            }
                        }

                        if (!any)
                        {
                            return false;
                        }
                    }
                }

                return true;
            }
        }
    }
}
