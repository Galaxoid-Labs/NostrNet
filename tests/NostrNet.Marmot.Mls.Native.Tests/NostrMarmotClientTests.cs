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
        Assert.NotNull(bobConvo);
        Assert.Equal(aliceConvo.NostrGroupId, bobConvo!.NostrGroupId);

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

    [Fact]
    public async Task SubscribeAsync_DedupsWelcomesByEventId()
    {
        // Multi-relay setups deliver the same kind-1059 welcome event once
        // per relay carrying it. The pump must yield one MarmotInviteReceived
        // per unique outer event id, not N. Simulate by re-publishing the
        // same wire event a second time.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        await alice.StartConversationAsync(bobKp!, "dedup");

        // First invite is the legitimate delivery.
        var first = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);

        // Grab the just-published welcome wire event and re-publish it
        // (simulating a second relay delivering the same event id).
        var welcomeWire = relay.AllPublished.Single(e => e.Id.Equals(first.OriginalGiftWrap.Id));
        await relay.PublishAsync(welcomeWire);

        // Nothing more should arrive — the pump's dedup set drops the
        // second delivery before unwrap.
        using var idle = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var leak = await TryNextOfTypeAsync<MarmotInviteReceived>(bobInbound, idle.Token);
        Assert.Null(leak);
    }

    [Fact]
    public async Task SubscribeAsync_DedupsApplicationMessagesByEventId()
    {
        // Same fix applies to kind-445 application messages — N relay
        // copies of the same wire event must yield one MarmotMessageReceived.
        // (MLS itself replay-rejects the second-decrypt on its ratchet, but
        // we want the pump to skip it cleanly before reaching the MLS layer.)
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "dedup-msg");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "hello");
        var first = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        // Re-publish the same kind-445 wire event.
        var groupEvWire = relay.AllPublished.Single(e => e.Id.Equals(first.EventId));
        await relay.PublishAsync(groupEvWire);

        using var idle = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var leak = await TryNextOfTypeAsync<MarmotMessageReceived>(bobInbound, idle.Token);
        Assert.Null(leak);
    }

    [Fact]
    public async Task SubscribeAsync_DedupsCommitsByEventId()
    {
        // Commits (MarmotGroupStateChanged) ride on kind-445 too, and have
        // the same multi-relay duplicate-delivery shape. App handlers are
        // usually idempotent, but firing one state-change per Commit is the
        // correct contract.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var charlieKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);
        await using var charlie = await BuildAsync(charlieKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        await charlie.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var charlieKp = await alice.TryGetKeyPackageAsync(charlieKey.PublicKey, TimeSpan.FromSeconds(2));

        var aliceConvo = await alice.StartConversationAsync(bobKp!, "dedup-commit");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        // Adding charlie fires a Commit kind-445 that bob processes as a
        // state change.
        await alice.AddPeerAsync(aliceConvo, charlieKp!);
        var first = await NextOfTypeAsync<MarmotGroupStateChanged>(bobInbound);

        // Find the kind-445 Commit (the only one published so far for this
        // group) and re-publish it.
        var groupIdHex = Convert.ToHexStringLower(aliceConvo.NostrGroupId);
        var commitWire = relay.AllPublished
            .Where(e => e.Kind == MarmotKinds.GroupEvent)
            .Single(e => e.Tags.Any(t => t.Count >= 2 && t[0] == "h" && t[1] == groupIdHex));
        await relay.PublishAsync(commitWire);

        using var idle = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var leak = await TryNextOfTypeAsync<MarmotGroupStateChanged>(bobInbound, idle.Token);
        Assert.Null(leak);

        // Sanity check on first: it's the right state change.
        Assert.Equal(aliceKey.PublicKey, first.Sender);
    }

    // Tests opt out of auto-publish + rotate-after-accept so they can
    // assert deterministic KeyPackage IDs and inbound-event counts.
    // The auto-rotation behavior has its own dedicated test below.
    private static Task<NostrMarmotClient> BuildAsync(PrivateKey identityKey, FakeRelay relay) =>
        NostrMarmotClient.Builder(identityKey, new OpenMlsProvider())
            .UseRelays(FakeRelayUri)
            .UseRelayBridge(relay)
            .AutoPublishKeyPackage(false)
            .RotateKeyPackageAfterAccept(false)
            .ConnectAsync();

    [Fact]
    public async Task AutoPublishKeyPackage_True_PublishesOnConnect()
    {
        using var key = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var client = await NostrMarmotClient.Builder(key, new OpenMlsProvider())
            .UseRelays(FakeRelayUri)
            .UseRelayBridge(relay)
            // default: AutoPublishKeyPackage(true)
            .ConnectAsync();

        // The relay should have seen exactly one kind-30443 event from us.
        Assert.Contains(relay.AllPublished, ev =>
            ev.Kind == NostrNet.Marmot.MarmotKinds.KeyPackage && ev.PubKey.Equals(key.PublicKey));
        Assert.Null(client.LastAutoPublishError);
    }

    [Fact]
    public async Task AutoPublishKeyPackage_False_SkipsPublish()
    {
        using var key = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var client = await NostrMarmotClient.Builder(key, new OpenMlsProvider())
            .UseRelays(FakeRelayUri)
            .UseRelayBridge(relay)
            .AutoPublishKeyPackage(false)
            .ConnectAsync();

        Assert.DoesNotContain(relay.AllPublished, ev =>
            ev.Kind == NostrNet.Marmot.MarmotKinds.KeyPackage && ev.PubKey.Equals(key.PublicKey));
    }

    [Fact]
    public async Task ParkedAppMessage_DecryptsAfterEnablingCommit_OutOfOrderDelivery()
    {
        // Simulates the offline-catchup case: a relay delivers an
        // application message from a new epoch BEFORE the Commit that
        // advanced everyone into that epoch. The parked-message logic
        // in GroupPumpAsync should buffer the un-decryptable message,
        // process the Commit when it arrives, and then replay the
        // buffered message at the new epoch.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var aliceProv = new OpenMlsProvider();
        using var bobProv = new OpenMlsProvider();
        var relay = new FakeRelay();
        var advertise = new[] { FakeRelayUri };

        // Set up the conversation via the low-level helpers so we can
        // build the events we want WITHOUT them being delivered to
        // bob immediately by a live subscription.
        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(
            bobProv, bobKey, slot: null, advertise);
        var started = await MarmotChat.StartConversationAsync(
            aliceProv, aliceKey, bobKp, "park-test", advertise);
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(
            bobProv, bobKey, started.WelcomeGiftWrap);
        Assert.NotNull(bobConvo);

        // Alice rotates → Commit event + advance Alice to next epoch.
        var rotated = await MarmotChat.RotateKeysAsync(aliceProv, started.Conversation);
        // Alice sends one message ENCRYPTED AT THE NEW EPOCH.
        var newEpochMessage = await MarmotChat.EncryptMessageAsync(
            aliceProv, started.Conversation, aliceKey, "after the rotation");

        // Publish to the relay in causal order, but flip the delivery
        // flag so a new subscriber drains the backlog newest-first.
        await relay.PublishAsync(rotated.CommitGroupEvent);
        await relay.PublishAsync(newEpochMessage);
        relay.ReverseBacklogOrder = true;

        // Bob spins up his client now. AutoPublish + RotateAfterAccept
        // would inject extra events into the relay; turn them off so
        // the test's backlog matches our expectations.
        await using var bob = await NostrMarmotClient.Builder(bobKey, bobProv)
            .UseRelays(FakeRelayUri)
            .UseRelayBridge(relay)
            .AutoPublishKeyPackage(false)
            .RotateKeyPackageAfterAccept(false)
            .ConnectAsync();

        await bob.LoadExistingConversationsAsync();

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var inbound = bob.SubscribeAsync(streamCts.Token);

        bool sawState = false;
        bool sawMessage = false;
        await foreach (var ev in inbound.WithCancellation(streamCts.Token))
        {
            switch (ev)
            {
                case MarmotGroupStateChanged:
                    sawState = true;
                    break;
                case MarmotMessageReceived m when m.Plaintext == "after the rotation":
                    sawMessage = true;
                    break;
            }

            if (sawState && sawMessage) break;
        }

        Assert.True(sawState, "Commit (epoch advance) should be observed");
        Assert.True(sawMessage,
            "Parked new-epoch message should be replayed after the Commit advances Bob's epoch");
    }

    [Fact]
    public async Task RotateAfterAccept_RepublishesKeyPackage_AfterJoin()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        // Bob runs with rotate-after-accept enabled (default).
        await using var alice = await NostrMarmotClient.Builder(aliceKey, new OpenMlsProvider())
            .UseRelays(FakeRelayUri)
            .UseRelayBridge(relay)
            .AutoPublishKeyPackage(false)
            .RotateKeyPackageAfterAccept(false)
            .ConnectAsync();
        await using var bob = await NostrMarmotClient.Builder(bobKey, new OpenMlsProvider())
            .UseRelays(FakeRelayUri)
            .UseRelayBridge(relay)
            // defaults: both auto-rotations enabled
            .ConnectAsync();

        // Bob's connect-time auto-publish.
        int kpsAtConnect = relay.AllPublished
            .Count(ev => ev.Kind == NostrNet.Marmot.MarmotKinds.KeyPackage && ev.PubKey.Equals(bobKey.PublicKey));
        Assert.Equal(1, kpsAtConnect);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        // Alice fetches Bob's KP and starts a chat.
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        Assert.NotNull(bobKp);
        _ = await alice.StartConversationAsync(bobKp!, "rot-test");

        // Wait for Bob's auto-accept path to run, then for the
        // rotate-after-accept fire-and-forget task to flush.
        var invite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(invite);
        Assert.NotNull(bobConvo);

        // Poll for the rotated KP — the Task.Run scheduler may not
        // have flushed before the await unblocked.
        var deadline = DateTimeOffset.UtcNow.AddSeconds(2);
        int finalCount = kpsAtConnect;
        while (DateTimeOffset.UtcNow < deadline)
        {
            finalCount = relay.AllPublished
                .Count(ev => ev.Kind == NostrNet.Marmot.MarmotKinds.KeyPackage && ev.PubKey.Equals(bobKey.PublicKey));
            if (finalCount > kpsAtConnect) break;
            await Task.Delay(25);
        }

        Assert.True(finalCount > kpsAtConnect,
            $"Expected a rotated KP after AcceptInvite; saw {finalCount} (started at {kpsAtConnect}).");
    }

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

        /// <summary>
        /// Snapshot copy of every event the resolver has ever
        /// published. Reads are lock-free at the point of inspection
        /// because we copy under the lock.
        /// </summary>
        public IReadOnlyList<NostrEvent> AllPublished
        {
            get
            {
                lock (_lock) return _stored.ToArray();
            }
        }

        /// <summary>
        /// When true, new subscribers drain the historical backlog in
        /// reverse insertion order. Used by the park-and-retry test to
        /// simulate a misbehaving relay that delivers a new-epoch
        /// message before its enabling Commit.
        /// </summary>
        public bool ReverseBacklogOrder { get; set; }

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

            if (ReverseBacklogOrder)
            {
                Array.Reverse(snapshot);
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
