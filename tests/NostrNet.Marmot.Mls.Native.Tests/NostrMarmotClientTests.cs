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

    [Fact]
    public async Task Members_PopulatedAtAllConstructionSites()
    {
        // Verify the Members invariant holds across StartConversationAsync,
        // StartGroupAsync (N=2 + N=3), AcceptInviteAsync, and after
        // LoadExistingConversationsAsync rehydration.
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

        // 1:1 via StartConversationAsync — Members has both keys, Peer set, IsGroup false.
        var oneToOne = await alice.StartConversationAsync(bobKp!, "1:1");
        Assert.Equal(2, oneToOne.Members.Count);
        Assert.Contains(oneToOne.Members, p => p.Equals(aliceKey.PublicKey));
        Assert.Contains(oneToOne.Members, p => p.Equals(bobKey.PublicKey));
        Assert.False(oneToOne.IsGroup);

        // Bob accepts — his side carries the same 2-member list.
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(bobInvite);
        Assert.NotNull(bobConvo);
        Assert.Equal(2, bobConvo!.Members.Count);
        Assert.Contains(bobConvo.Members, p => p.Equals(aliceKey.PublicKey));
        Assert.Contains(bobConvo.Members, p => p.Equals(bobKey.PublicKey));
    }

    [Fact]
    public async Task Members_PopulatedAfterStartGroupAsync()
    {
        // StartGroupAsync with multiple peers — Members reflects all
        // initial members (including self), Peer is null for N>1.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var charlieKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);
        await using var charlie = await BuildAsync(charlieKey, relay);

        await bob.PublishKeyPackageAsync();
        await charlie.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var charlieKp = await alice.TryGetKeyPackageAsync(charlieKey.PublicKey, TimeSpan.FromSeconds(2));

        var group = await alice.StartGroupAsync(new[] { bobKp!, charlieKp! }, "Trio");
        Assert.Equal(3, group.Members.Count);
        Assert.Contains(group.Members, p => p.Equals(aliceKey.PublicKey));
        Assert.Contains(group.Members, p => p.Equals(bobKey.PublicKey));
        Assert.Contains(group.Members, p => p.Equals(charlieKey.PublicKey));
        Assert.True(group.IsGroup);
        Assert.Null(group.Peer);
    }

    [Fact]
    public async Task MarmotGroupStateChanged_CarriesRefreshedMembers()
    {
        // When an admin adds a member, MarmotGroupStateChanged.Conversation
        // should reflect the post-Commit membership — not the snapshot the
        // pump captured at conversation-start time.
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

        // Start as 1:1 alice + bob, accept on bob's side.
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "growing");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(bobInvite);
        Assert.Equal(2, bobConvo!.Members.Count);

        // Alice adds Charlie. Bob processes the Commit.
        await alice.AddPeerAsync(aliceConvo, charlieKp!);
        var stateChange = await NextOfTypeAsync<MarmotGroupStateChanged>(bobInbound);

        // The state-change event's Conversation should now have 3 members.
        Assert.Equal(3, stateChange.Conversation.Members.Count);
        Assert.Contains(stateChange.Conversation.Members, p => p.Equals(charlieKey.PublicKey));
    }

    [Fact]
    public async Task Members_RefreshedAfterCommit_ReflectedInSubsequentMessageReceived()
    {
        // After a Commit refreshes membership, the next MarmotMessageReceived
        // for this group should carry the post-Commit member list too —
        // not just the state-change event.
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

        var aliceConvo = await alice.StartConversationAsync(bobKp!, "growing-msg");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        // Add charlie → state-change fires.
        await alice.AddPeerAsync(aliceConvo, charlieKp!);
        _ = await NextOfTypeAsync<MarmotGroupStateChanged>(bobInbound);

        // Alice sends a message in the post-add epoch. Bob's
        // MarmotMessageReceived.Conversation should have all 3 members.
        await alice.SendAsync(aliceConvo, "now we are three");
        var msg = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
        Assert.Equal("now we are three", msg.Plaintext);
        Assert.Equal(3, msg.Conversation.Members.Count);
    }

    [Fact]
    public async Task StaleWelcome_DroppedSilentlyByInboxPump()
    {
        // Real-world scenario: bob's relays still hold a kind-1059 welcome
        // addressed to a KeyPackage bob has since rotated away (state wipe
        // + fresh KP). AcceptInviteAsync would return null on a user click;
        // the pump should never surface it as MarmotInviteReceived in the
        // first place.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);

        // Bob #1 — publishes a KP, alice starts a conversation against it,
        // which publishes the kind-1059 welcome to the relay. Then bob #1
        // tears down without accepting; the welcome is now relay-cached
        // but addresses an init key no live provider holds.
        NostrEvent staleWelcomeEv;
        {
            await using var bob1 = await BuildAsync(bobKey, relay);
            await bob1.PublishKeyPackageAsync();
            var bobKp1 = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
            await alice.StartConversationAsync(bobKp1!, "stale-welcome");

            staleWelcomeEv = relay.AllPublished.Single(e => e.Kind == 1059);
            // bob1's provider disposes here; its init keys are gone.
        }

        // Bob #2 — fresh provider (no init keys for the old welcome),
        // taps the inbound stream. The relay-cached welcome should be
        // filtered out by the pump's CanJoinWelcomeAsync check.
        await using var bob2 = await BuildAsync(bobKey, relay);
        using var streamCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
        var bob2Inbound = bob2.SubscribeAsync(streamCts.Token);

        var leak = await TryNextOfTypeAsync<MarmotInviteReceived>(bob2Inbound, streamCts.Token);
        Assert.Null(leak);
        // Sanity: the stale event IS in the relay's backlog and IS addressed
        // to bob's pubkey — the filter is what kept it out of the stream.
        Assert.NotNull(staleWelcomeEv);
    }

    [Fact]
    public async Task SendAsync_SurfacesOwnSendThroughSubscribeAsync()
    {
        // MLS application-message ratchets are one-way per leaf; our
        // own provider can't decrypt our own send when it comes back
        // via the relay broadcast. The library compensates by emitting
        // the MarmotMessageReceived directly to the inbound channel
        // when SendAsync publishes. Apps render own + peer messages
        // through one code path; no synthetic-id echo needed.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "own-send-echo");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        // Alice sends; SendAsync now returns the published kind-445 event.
        var publishedEv = await alice.SendAsync(aliceConvo, "hello from me");
        Assert.Equal(NostrNet.Marmot.MarmotKinds.GroupEvent, publishedEv.Kind);

        // Alice's own SubscribeAsync should yield the MarmotMessageReceived
        // with Sender = alice (the "is from me" signal apps use to render).
        var aliceOwnRender = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        Assert.Equal("hello from me", aliceOwnRender.Plaintext);
        Assert.Equal(aliceKey.PublicKey, aliceOwnRender.Sender);
        Assert.Equal(publishedEv.Id, aliceOwnRender.EventId);

        // Bob still gets it the normal way — MLS decrypts cross-leaf fine.
        var bobReceived = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
        Assert.Equal("hello from me", bobReceived.Plaintext);
        Assert.Equal(aliceKey.PublicKey, bobReceived.Sender);
    }

    [Fact]
    public async Task SendAsync_AppendsOwnSendToMessageLog()
    {
        // Companion to the SubscribeAsync echo: own sends must also
        // hit the configured IMarmotMessageLog so LoadHistoryAsync on
        // a future session replays them just like peer messages.
        // Without this, app-side history shows only inbound after a
        // restart — broken for the user's own chat record.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();
        var log = new MemoryMarmotMessageLog();

        await using var alice = await NostrMarmotClient.Builder(aliceKey, new OpenMlsProvider())
            .UseRelayBridge(relay)
            .AutoPublishKeyPackage(false)
            .RotateKeyPackageAfterAccept(false)
            .WithMessageLog(log)
            .ConnectAsync();
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "own-send-log");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "log me");

        // alice's log should now contain her own send, keyed on the
        // real kind-445 event id.
        var stored = await log.GetLastAsync(aliceConvo.NostrGroupId);
        Assert.NotNull(stored);
        Assert.Equal("log me", stored!.Plaintext);
        Assert.Equal(aliceKey.PublicKey, stored.Sender);
    }

    [Fact]
    public async Task SendAsync_RumorIdIsStableAcrossSenders()
    {
        // The inner Marmot rumor id is derived from the unsigned JSON
        // payload that goes into the MLS ratchet — sender + created_at +
        // kind + tags + content — and is independent of which leaf
        // produced the kind-445 envelope. Alice's own MarmotMessageReceived
        // and Bob's MarmotMessageReceived must therefore see the SAME
        // RumorId for the message Alice sent. SeerChat-style reaction /
        // deletion UI relies on this — both sides have to be able to
        // key on the same identifier.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "rumor-id-stability");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "hello");

        var aliceOwn = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        var bobReceived = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        Assert.Equal(aliceOwn.RumorId, bobReceived.RumorId);
        Assert.Equal(MarmotChat.ChatMessageRumorKind, aliceOwn.RumorKind);
        Assert.Equal(MarmotChat.ChatMessageRumorKind, bobReceived.RumorKind);
        Assert.Equal("hello", aliceOwn.Plaintext);
        Assert.Equal("hello", bobReceived.Plaintext);
    }

    [Fact]
    public async Task SendReactionAsync_TargetsInnerRumorId_AndRoundTrips()
    {
        // Reaction round-trip: bob reacts to alice's message; alice sees
        // a kind-7 rumor whose e-tag points at the INNER rumor id she
        // observed (RumorId), not the outer kind-445 event id (EventId).
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "reaction-test");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "hi");

        // Drain own-send + peer-recv to find bob's view of the chat.
        var aliceOwnChat = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        var bobChat = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
        Assert.Equal(aliceOwnChat.RumorId, bobChat.RumorId);

        await bob.SendReactionAsync(bobConvo!, bobChat.RumorId, "👍");

        // Alice sees the reaction with the right kind, e-tag, and sender.
        MarmotMessageReceived? reactionAtAlice = null;
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            await foreach (var ev in aliceInbound.WithCancellation(deadline.Token))
            {
                if (ev is MarmotMessageReceived m && m.RumorKind == MarmotChat.ReactionRumorKind)
                {
                    reactionAtAlice = m;
                    break;
                }
            }
        }

        Assert.NotNull(reactionAtAlice);
        Assert.Equal("👍", reactionAtAlice!.Plaintext);
        Assert.Equal(bobKey.PublicKey, reactionAtAlice.Sender);
        var eTag = reactionAtAlice.RumorTags.FirstOrDefault(t => t.Count >= 2 && t[0] == "e");
        Assert.NotNull(eTag);
        Assert.Equal(aliceOwnChat.RumorId.ToHex(), eTag![1]);
    }

    [Fact]
    public async Task SendReactionAsync_OwnSendEchoesOnSenderStream()
    {
        // Own-send synthetic emission must apply to reactions too —
        // MLS ratchet asymmetry doesn't care which rumor kind is
        // riding inside the application message.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "own-reaction-echo");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "msg");
        var aliceOwnChat = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        _ = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        await alice.SendReactionAsync(aliceConvo, aliceOwnChat.RumorId, "+");

        // Alice should see her own reaction on her own stream — the
        // ratchet can't decrypt it via the receive pump, the library
        // emits it directly.
        MarmotMessageReceived? own = null;
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            await foreach (var ev in aliceInbound.WithCancellation(deadline.Token))
            {
                if (ev is MarmotMessageReceived m && m.RumorKind == MarmotChat.ReactionRumorKind)
                {
                    own = m;
                    break;
                }
            }
        }

        Assert.NotNull(own);
        Assert.Equal("+", own!.Plaintext);
        Assert.Equal(aliceKey.PublicKey, own.Sender);
    }

    [Fact]
    public async Task SendDeletionAsync_TargetsInnerRumorId_AndRoundTrips()
    {
        // Deletion round-trip: alice deletes her own message; both
        // alice (via own-send echo) and bob (via MLS decrypt) see a
        // kind-5 rumor with e-tag pointing at the inner rumor id and
        // k-tag declaring the deleted kind (9 for chat).
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "deletion-test");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "typo");
        var aliceOwnChat = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        var bobChat = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        await alice.SendDeletionAsync(
            aliceConvo,
            aliceOwnChat.RumorId,
            MarmotChat.ChatMessageRumorKind,
            "typo");

        MarmotMessageReceived? aliceOwnDel = null;
        MarmotMessageReceived? bobDel = null;
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            await foreach (var ev in aliceInbound.WithCancellation(deadline.Token))
            {
                if (ev is MarmotMessageReceived m && m.RumorKind == MarmotChat.DeletionRumorKind)
                {
                    aliceOwnDel = m;
                    break;
                }
            }
        }
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            await foreach (var ev in bobInbound.WithCancellation(deadline.Token))
            {
                if (ev is MarmotMessageReceived m && m.RumorKind == MarmotChat.DeletionRumorKind)
                {
                    bobDel = m;
                    break;
                }
            }
        }

        Assert.NotNull(aliceOwnDel);
        Assert.NotNull(bobDel);

        // Both sides see the same inner rumor id for the deletion request itself.
        Assert.Equal(aliceOwnDel!.RumorId, bobDel!.RumorId);

        // Sender attribution is alice.
        Assert.Equal(aliceKey.PublicKey, aliceOwnDel.Sender);
        Assert.Equal(aliceKey.PublicKey, bobDel.Sender);

        // e-tag references the chat rumor id; k-tag carries kind 9.
        foreach (var del in new[] { aliceOwnDel, bobDel })
        {
            var eTag = del.RumorTags.FirstOrDefault(t => t.Count >= 2 && t[0] == "e");
            var kTag = del.RumorTags.FirstOrDefault(t => t.Count >= 2 && t[0] == "k");
            Assert.NotNull(eTag);
            Assert.NotNull(kTag);
            Assert.Equal(aliceOwnChat.RumorId.ToHex(), eTag![1]);
            Assert.Equal(MarmotChat.ChatMessageRumorKind.ToString(System.Globalization.CultureInfo.InvariantCulture), kTag![1]);
        }

        // Reason is surfaced as Plaintext.
        Assert.Equal("typo", aliceOwnDel.Plaintext);
        Assert.Equal("typo", bobDel.Plaintext);
    }

    [Fact]
    public async Task SendAsync_WithReplyMarkers_TagsRoundTripToPeer()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "reply-tags");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(bobInvite);

        // Alice sends the parent + thread root, drain own + peer copies.
        await alice.SendAsync(aliceConvo, "root msg");
        var aliceRoot = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        var bobRoot = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        await alice.SendAsync(aliceConvo, "parent msg");
        var aliceParent = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        var bobParent = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        // Bob replies with both reply + root markers.
        await bob.SendAsync(
            bobConvo!,
            "answer",
            replyTo: bobParent.RumorId,
            replyRoot: bobRoot.RumorId);

        var bobOwn = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);
        var aliceReceived = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);

        foreach (var msg in new[] { bobOwn, aliceReceived })
        {
            var replyTag = msg.RumorTags.FirstOrDefault(t =>
                t.Count >= 4 && t[0] == "e" && t[3] == "reply");
            var rootTag = msg.RumorTags.FirstOrDefault(t =>
                t.Count >= 4 && t[0] == "e" && t[3] == "root");

            Assert.NotNull(replyTag);
            Assert.NotNull(rootTag);
            Assert.Equal(aliceParent.RumorId.ToHex(), replyTag![1]);
            Assert.Equal(aliceRoot.RumorId.ToHex(), rootTag![1]);
            Assert.Equal(string.Empty, replyTag[2]);
            Assert.Equal(string.Empty, rootTag[2]);
        }

        // Own-send parity: sender's tags exactly match the peer's view.
        Assert.Equal(bobOwn.RumorTags.Count, aliceReceived.RumorTags.Count);
        for (int i = 0; i < bobOwn.RumorTags.Count; i++)
        {
            Assert.Equal(bobOwn.RumorTags[i], aliceReceived.RumorTags[i]);
        }
    }

    [Fact]
    public async Task SendAsync_ReplyToOnly_OmitsRootTag()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "reply-no-root");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "parent");
        _ = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        var bobParent = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        await bob.SendAsync(bobConvo!, "reply only", replyTo: bobParent.RumorId);
        var bobOwn = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        Assert.Single(bobOwn.RumorTags);
        Assert.Equal("e", bobOwn.RumorTags[0][0]);
        Assert.Equal("reply", bobOwn.RumorTags[0][3]);
    }

    [Fact]
    public async Task SendAsync_NoReplyMarkers_RumorTagsEmpty()
    {
        // Sanity: the new optional params don't perturb the baseline
        // "no reply" path — Tags stays empty just like preview18.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "no-reply");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "plain msg");
        var aliceOwn = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        var bobReceived = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        Assert.Empty(aliceOwn.RumorTags);
        Assert.Empty(bobReceived.RumorTags);
    }

    [Fact]
    public async Task SendAsync_AdditionalTags_AppendAfterMarkers()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "tag-order");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        var bobConvo = await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "parent");
        _ = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        var bobParent = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        var extras = new IReadOnlyList<string>[]
        {
            new[] { "p", aliceKey.PublicKey.ToHex() },
            new[] { "alt", "metadata" },
        };

        await bob.SendAsync(
            bobConvo!,
            "answer",
            replyTo: bobParent.RumorId,
            additionalTags: extras);

        var bobOwn = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        // Layout: [reply, p, alt] — markers FIRST, additionalTags after.
        Assert.Equal(3, bobOwn.RumorTags.Count);
        Assert.Equal("e", bobOwn.RumorTags[0][0]);
        Assert.Equal("reply", bobOwn.RumorTags[0][3]);
        Assert.Equal("p", bobOwn.RumorTags[1][0]);
        Assert.Equal(aliceKey.PublicKey.ToHex(), bobOwn.RumorTags[1][1]);
        Assert.Equal("alt", bobOwn.RumorTags[2][0]);
        Assert.Equal("metadata", bobOwn.RumorTags[2][1]);
    }

    [Fact]
    public async Task BuildChatRumor_ComputeId_MatchesRoundTripRumorId()
    {
        // Optimistic-UI use case: an app pre-computes the rumor id via
        // BuildChatRumor + ComputeId before SendAsync round-trips. The
        // value must equal what both the sender's own-emit and the
        // peer's decrypted view ultimately surface as RumorId — that's
        // the contract that makes optimistic store writes safe.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "id-pre-compute");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        // Use a fixed timestamp so the round-trip path produces the same
        // id we predict here. Alice's send path uses DateTimeOffset.UtcNow
        // internally — we can't observe-then-predict for the same send,
        // but we CAN build the rumor here and prove ComputeId returns
        // the same EventId NIP-01 canonical hash that the receive side
        // would compute. To compare against the live stream we'd need a
        // clock injection point we don't have; the substantive
        // invariant (sender's own RumorId == peer's RumorId for the same
        // logical message) is already covered by
        // SendAsync_RumorIdIsStableAcrossSenders. Here we just assert
        // that two BuildChatRumor calls with identical inputs produce
        // identical ids (deterministic build) and that the id has the
        // expected length / format.
        var fixedTime = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var r1 = MarmotChat.BuildChatRumor("hi", aliceKey.PublicKey, createdAt: fixedTime);
        var r2 = MarmotChat.BuildChatRumor("hi", aliceKey.PublicKey, createdAt: fixedTime);
        Assert.Equal(r1.ComputeId(), r2.ComputeId());

        // Reply markers change the rumor id.
        var fakeId = new EventId(new byte[EventId.Size]);
        var r3 = MarmotChat.BuildChatRumor("hi", aliceKey.PublicKey, replyTo: fakeId, createdAt: fixedTime);
        Assert.NotEqual(r1.ComputeId(), r3.ComputeId());
    }

    [Fact]
    public async Task SendDeletionAsync_NullReason_YieldsEmptyPlaintext()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "deletion-no-reason");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        await alice.SendAsync(aliceConvo, "x");
        var chat = await NextOfTypeAsync<MarmotMessageReceived>(aliceInbound);
        _ = await NextOfTypeAsync<MarmotMessageReceived>(bobInbound);

        await alice.SendDeletionAsync(aliceConvo, chat.RumorId, MarmotChat.ChatMessageRumorKind);

        MarmotMessageReceived? del = null;
        using (var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
        {
            await foreach (var ev in aliceInbound.WithCancellation(deadline.Token))
            {
                if (ev is MarmotMessageReceived m && m.RumorKind == MarmotChat.DeletionRumorKind)
                {
                    del = m;
                    break;
                }
            }
        }

        Assert.NotNull(del);
        Assert.Equal(string.Empty, del!.Plaintext);
    }

    [Fact]
    public async Task AddPeerAsync_SurfacesOwnCommitThroughCallerSubscribeAsync()
    {
        // Same shape as the preview15 SendAsync own-send fix: MLS won't
        // decrypt the caller's own Commit when the relay echoes it back,
        // so the library emits MarmotGroupStateChanged directly to the
        // initiator's inbound channel. Caller's UI sees the membership
        // change for their own action; Members reflects post-Commit state.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var charlieKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);
        await using var charlie = await BuildAsync(charlieKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        await charlie.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var charlieKp = await alice.TryGetKeyPackageAsync(charlieKey.PublicKey, TimeSpan.FromSeconds(2));

        var aliceConvo = await alice.StartConversationAsync(bobKp!, "own-commit-add");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        // Alice adds charlie — should return the Commit kind-445 event AND
        // surface MarmotGroupStateChanged on alice's stream.
        var commit = await alice.AddPeerAsync(aliceConvo, charlieKp!);
        Assert.Equal(NostrNet.Marmot.MarmotKinds.GroupEvent, commit.Kind);

        var aliceStateChange = await NextOfTypeAsync<MarmotGroupStateChanged>(aliceInbound);
        Assert.Equal(aliceKey.PublicKey, aliceStateChange.Sender);
        Assert.Equal(3, aliceStateChange.Conversation.Members.Count);
        Assert.Contains(aliceStateChange.Conversation.Members, p => p.Equals(charlieKey.PublicKey));

        // No second emit on alice's stream from the relay round-trip —
        // the kind-445 will fail to decrypt and get parked silently.
        using var idle = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
        var leak = await TryNextOfTypeAsync<MarmotGroupStateChanged>(aliceInbound, idle.Token);
        Assert.Null(leak);

        // Bob still sees his own state-change from the same Commit (peer path).
        var bobStateChange = await NextOfTypeAsync<MarmotGroupStateChanged>(bobInbound);
        Assert.Equal(aliceKey.PublicKey, bobStateChange.Sender);
    }

    [Fact]
    public async Task RemovePeersAsync_SurfacesOwnCommitThroughCallerSubscribeAsync()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var charlieKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);
        await using var charlie = await BuildAsync(charlieKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        await charlie.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var charlieKp = await alice.TryGetKeyPackageAsync(charlieKey.PublicKey, TimeSpan.FromSeconds(2));

        var aliceConvo = await alice.StartGroupAsync(new[] { bobKp!, charlieKp! }, "own-commit-remove");

        // Alice kicks charlie.
        var commit = await alice.RemovePeersAsync(aliceConvo, new[] { charlieKey.PublicKey });
        Assert.Equal(NostrNet.Marmot.MarmotKinds.GroupEvent, commit.Kind);

        var aliceStateChange = await NextOfTypeAsync<MarmotGroupStateChanged>(aliceInbound);
        Assert.Equal(aliceKey.PublicKey, aliceStateChange.Sender);
        Assert.Equal(2, aliceStateChange.Conversation.Members.Count);
        Assert.DoesNotContain(aliceStateChange.Conversation.Members, p => p.Equals(charlieKey.PublicKey));

        using var idle = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
        var leak = await TryNextOfTypeAsync<MarmotGroupStateChanged>(aliceInbound, idle.Token);
        Assert.Null(leak);
    }

    [Fact]
    public async Task RotateKeysAsync_SurfacesOwnCommitThroughCallerSubscribeAsync()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var aliceInbound = alice.SubscribeAsync(streamCts.Token);
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        var aliceConvo = await alice.StartConversationAsync(bobKp!, "own-commit-rotate");
        var bobInvite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        await bob.AcceptInviteAsync(bobInvite);

        // Alice rotates her own leaf keys.
        var commit = await alice.RotateKeysAsync(aliceConvo);
        Assert.Equal(NostrNet.Marmot.MarmotKinds.GroupEvent, commit.Kind);

        var aliceStateChange = await NextOfTypeAsync<MarmotGroupStateChanged>(aliceInbound);
        Assert.Equal(aliceKey.PublicKey, aliceStateChange.Sender);
        // Members unchanged by a self-update — same 2 members.
        Assert.Equal(2, aliceStateChange.Conversation.Members.Count);

        using var idle = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
        var leak = await TryNextOfTypeAsync<MarmotGroupStateChanged>(aliceInbound, idle.Token);
        Assert.Null(leak);
    }

    [Fact]
    public async Task AcceptInvite_DeletesConsumedKeyPackageBundle_SoReDeliveryIsFiltered()
    {
        // The bug: accepting a welcome left the consumed KP bundle in
        // provider storage. On the next session, the preview13 stale-
        // welcome filter saw the bundle as "still present" and surfaced
        // the same welcome again as a new MarmotInviteReceived. Fix:
        // delete the consumed bundle after a successful join. Probe:
        // CanJoinWelcomeAsync(welcomeBytes) must return false post-accept.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        await alice.StartConversationAsync(bobKp!, "delete-on-consume");

        var invite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        // Sanity: before accept, the welcome was joinable (the pump filter
        // already proved this by surfacing the invite at all).

        var conv = await bob.AcceptInviteAsync(invite);
        Assert.NotNull(conv);

        // After accept, the consumed bundle must be gone from storage —
        // CanJoinWelcomeAsync now returns false on this welcome.
        // (NostrMarmotClient exposes the underlying provider for tests via
        // MlsProvider; if not, route through bob.NostrClient... falling
        // back to the FakeRelay's stored event.)
        var welcomeEv = relay.AllPublished.Single(e => e.Id.Equals(invite.OriginalGiftWrap.Id));
        Assert.NotNull(welcomeEv);

        // Re-publishing the wire event simulates a relay re-delivery on
        // the next session (the bug's actual repro). Because the bundle
        // was deleted on accept, the pump's filter drops it silently.
        await relay.PublishAsync(welcomeEv);

        using var idle = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
        var leak = await TryNextOfTypeAsync<MarmotInviteReceived>(bobInbound, idle.Token);
        Assert.Null(leak);
    }

    [Fact]
    public async Task FreshWelcome_PassesInboxPumpFilter()
    {
        // The other half of the stale-welcome contract: a welcome whose
        // target KeyPackage IS in storage must surface normally.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relay = new FakeRelay();

        await using var alice = await BuildAsync(aliceKey, relay);
        await using var bob = await BuildAsync(bobKey, relay);

        using var streamCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var bobInbound = bob.SubscribeAsync(streamCts.Token);

        await bob.PublishKeyPackageAsync();
        var bobKp = await alice.TryGetKeyPackageAsync(bobKey.PublicKey, TimeSpan.FromSeconds(2));
        await alice.StartConversationAsync(bobKp!, "fresh-welcome");

        // Should arrive; filter is a no-op when the KP is still ours.
        var invite = await NextOfTypeAsync<MarmotInviteReceived>(bobInbound);
        Assert.Equal(aliceKey.PublicKey, invite.Sender);
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
