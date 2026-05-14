// SPDX-License-Identifier: MIT
//
// 3+ member group conversations end-to-end via OpenMLS:
//   - StartGroupAsync creates a group with multiple initial members
//   - All members can encrypt/decrypt to each other
//   - AddPeerAsync grows an existing group; existing members process
//     the inbound Commit to advance epoch and then can talk to the
//     new member

using NostrNet.Keys;
using NostrNet.Marmot;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class GroupChatTests
{
    private sealed record Member(PrivateKey Key, OpenMlsProvider Provider) : IDisposable
    {
        public void Dispose()
        {
            Provider.Dispose();
            Key.Dispose();
        }
    }

    private static Member Make()
    {
        return new Member(PrivateKey.Generate(), new OpenMlsProvider());
    }

    [Fact]
    public async Task ThreeMemberGroup_AllPairsCanCommunicate()
    {
        using var alice = Make();
        using var bob = Make();
        using var carol = Make();
        var relays = new[] { "wss://relay.example" };

        // Bob and Carol publish KeyPackages.
        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob.Provider, bob.Key, null, relays);
        var carolKp = await MarmotChat.BuildKeyPackageEventAsync(carol.Provider, carol.Key, null, relays);

        // Alice starts a group with both.
        var started = await MarmotChat.StartGroupAsync(
            alice.Provider, alice.Key,
            new[] { bobKp, carolKp },
            "Alice/Bob/Carol",
            relays);

        Assert.Equal(2, started.WelcomeGiftWraps.Count);

        // Bob and Carol each accept their own gift wrap.
        // (In practice an app filters kind-1059 by p-tag-targeted-at-me;
        // here we know which gift wrap is whose by index.)
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bob.Provider, bob.Key, started.WelcomeGiftWraps[0]);
        var carolConvo = await MarmotChat.TryAcceptInviteAsync(carol.Provider, carol.Key, started.WelcomeGiftWraps[1]);
        Assert.NotNull(bobConvo);
        Assert.NotNull(carolConvo);
        Assert.Equal(started.Conversation.NostrGroupId, bobConvo.NostrGroupId);
        Assert.Equal(started.Conversation.NostrGroupId, carolConvo.NostrGroupId);

        // Alice → group: Bob and Carol both decrypt.
        var aliceMsg = await MarmotChat.EncryptMessageAsync(alice.Provider, started.Conversation, alice.Key, "hello everyone");
        Assert.Equal("hello everyone", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, aliceMsg));
        Assert.Equal("hello everyone", await MarmotChat.TryDecryptMessageAsync(carol.Provider, carolConvo, aliceMsg));

        // Bob → group: Alice and Carol decrypt.
        var bobMsg = await MarmotChat.EncryptMessageAsync(bob.Provider, bobConvo, bob.Key, "bob's chiming in");
        Assert.Equal("bob's chiming in", await MarmotChat.TryDecryptMessageAsync(alice.Provider, started.Conversation, bobMsg));
        Assert.Equal("bob's chiming in", await MarmotChat.TryDecryptMessageAsync(carol.Provider, carolConvo, bobMsg));

        // Carol → group: Alice and Bob decrypt.
        var carolMsg = await MarmotChat.EncryptMessageAsync(carol.Provider, carolConvo, carol.Key, "carol here");
        Assert.Equal("carol here", await MarmotChat.TryDecryptMessageAsync(alice.Provider, started.Conversation, carolMsg));
        Assert.Equal("carol here", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, carolMsg));
    }

    [Fact]
    public async Task AddPeer_MidConversation_FourthMemberJoins()
    {
        using var alice = Make();
        using var bob = Make();
        using var carol = Make();
        using var dave = Make();
        var relays = new[] { "wss://relay.example" };

        // Start a 3-member group.
        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob.Provider, bob.Key, null, relays);
        var carolKp = await MarmotChat.BuildKeyPackageEventAsync(carol.Provider, carol.Key, null, relays);
        var started = await MarmotChat.StartGroupAsync(
            alice.Provider, alice.Key, new[] { bobKp, carolKp }, "group", relays);
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bob.Provider, bob.Key, started.WelcomeGiftWraps[0]);
        var carolConvo = await MarmotChat.TryAcceptInviteAsync(carol.Provider, carol.Key, started.WelcomeGiftWraps[1]);
        Assert.NotNull(bobConvo);
        Assert.NotNull(carolConvo);

        // A pre-add round so we know everyone's on epoch 1.
        var pre = await MarmotChat.EncryptMessageAsync(alice.Provider, started.Conversation, alice.Key, "hi");
        Assert.Equal("hi", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, pre));
        Assert.Equal("hi", await MarmotChat.TryDecryptMessageAsync(carol.Provider, carolConvo, pre));

        // Dave publishes a KeyPackage and Alice adds him.
        var daveKp = await MarmotChat.BuildKeyPackageEventAsync(dave.Provider, dave.Key, null, relays);
        var add = await MarmotChat.AddPeerAsync(alice.Provider, alice.Key, started.Conversation, daveKp, relays);

        // Dave joins via the Welcome gift wrap.
        var daveConvo = await MarmotChat.TryAcceptInviteAsync(dave.Provider, dave.Key, add.WelcomeGiftWrap);
        Assert.NotNull(daveConvo);
        Assert.Equal(started.Conversation.NostrGroupId, daveConvo.NostrGroupId);

        // Bob and Carol receive the Commit GroupEvent. TryProcessMessage
        // recognizes it as a Commit and silently advances their state.
        var bobProcessed = await MarmotChat.TryProcessMessageAsync(bob.Provider, bobConvo, add.CommitGroupEvent);
        var carolProcessed = await MarmotChat.TryProcessMessageAsync(carol.Provider, carolConvo, add.CommitGroupEvent);
        Assert.NotNull(bobProcessed);
        Assert.NotNull(carolProcessed);
        Assert.Equal(MarmotMessageKind.Commit, bobProcessed.Kind);
        Assert.Equal(MarmotMessageKind.Commit, carolProcessed.Kind);
        Assert.True(bobProcessed.EpochAdvanced);
        Assert.True(carolProcessed.EpochAdvanced);

        // Now all four can exchange messages on the new epoch.
        var fromAlice = await MarmotChat.EncryptMessageAsync(alice.Provider, started.Conversation, alice.Key, "welcome dave");
        Assert.Equal("welcome dave", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, fromAlice));
        Assert.Equal("welcome dave", await MarmotChat.TryDecryptMessageAsync(carol.Provider, carolConvo, fromAlice));
        Assert.Equal("welcome dave", await MarmotChat.TryDecryptMessageAsync(dave.Provider, daveConvo, fromAlice));

        var fromDave = await MarmotChat.EncryptMessageAsync(dave.Provider, daveConvo, dave.Key, "thanks!");
        Assert.Equal("thanks!", await MarmotChat.TryDecryptMessageAsync(alice.Provider, started.Conversation, fromDave));
        Assert.Equal("thanks!", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, fromDave));
        Assert.Equal("thanks!", await MarmotChat.TryDecryptMessageAsync(carol.Provider, carolConvo, fromDave));
    }

    [Fact]
    public async Task TryProcessMessage_OnApplication_PopulatesPlaintext()
    {
        using var alice = Make();
        using var bob = Make();
        var relays = new[] { "wss://relay.example" };

        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob.Provider, bob.Key, null, relays);
        var started = await MarmotChat.StartConversationAsync(alice.Provider, alice.Key, bobKp, "1:1", relays);
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bob.Provider, bob.Key, started.WelcomeGiftWrap);
        Assert.NotNull(bobConvo);

        var msg = await MarmotChat.EncryptMessageAsync(alice.Provider, started.Conversation, alice.Key, "hi");
        var processed = await MarmotChat.TryProcessMessageAsync(bob.Provider, bobConvo, msg);

        Assert.NotNull(processed);
        Assert.Equal(MarmotMessageKind.Application, processed.Kind);
        Assert.Equal("hi", processed.Plaintext);
        Assert.False(processed.EpochAdvanced);
        // Sender comes from the MLS layer (resolved via OpenMLS's
        // sender leaf index → BasicCredential identity), not from
        // the outer ephemeral kind-445 signature.
        Assert.Equal(alice.Key.PublicKey, processed.Sender);
    }

    [Fact]
    public async Task TryProcessMessage_OnCommit_IdentifiesCommitter()
    {
        // In a 3-member group, when Alice adds a 4th member, the
        // resulting Commit GroupEvent's Sender (as seen by Bob) should
        // be Alice — not the ephemeral kind-445 signer.
        using var alice = Make();
        using var bob = Make();
        using var carol = Make();
        using var dave = Make();
        var relays = new[] { "wss://relay.example" };

        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob.Provider, bob.Key, null, relays);
        var carolKp = await MarmotChat.BuildKeyPackageEventAsync(carol.Provider, carol.Key, null, relays);
        var started = await MarmotChat.StartGroupAsync(
            alice.Provider, alice.Key, new[] { bobKp, carolKp }, "g", relays);
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bob.Provider, bob.Key, started.WelcomeGiftWraps[0]);
        var carolConvo = await MarmotChat.TryAcceptInviteAsync(carol.Provider, carol.Key, started.WelcomeGiftWraps[1]);
        Assert.NotNull(bobConvo);
        Assert.NotNull(carolConvo);

        var daveKp = await MarmotChat.BuildKeyPackageEventAsync(dave.Provider, dave.Key, null, relays);
        var add = await MarmotChat.AddPeerAsync(alice.Provider, alice.Key, started.Conversation, daveKp, relays);

        var bobProc = await MarmotChat.TryProcessMessageAsync(bob.Provider, bobConvo, add.CommitGroupEvent);
        Assert.NotNull(bobProc);
        Assert.Equal(MarmotMessageKind.Commit, bobProc.Kind);
        Assert.True(bobProc.EpochAdvanced);
        // The committer that Bob sees IS Alice — surfaces correctly
        // through the MLS layer.
        Assert.Equal(alice.Key.PublicKey, bobProc.Sender);
    }
}
