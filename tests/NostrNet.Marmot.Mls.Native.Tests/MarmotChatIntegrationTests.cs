// SPDX-License-Identifier: MIT
//
// Integration: drives the MarmotChat high-level helper with the
// OpenMLS-backed provider. Verifies the full 1:1 flow — KeyPackage
// publish, conversation start, invite accept, bidirectional message
// exchange — works through the FFI.

using System.Security.Cryptography;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class MarmotChatIntegrationTests
{
    [Fact]
    public async Task FullOneToOneFlow_Bidirectional()
    {
        using var alice = new OpenMlsProvider();
        using var bob = new OpenMlsProvider();
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relays = new[] { "wss://relay.example" };

        // Bob publishes a KeyPackage.
        var bobKpEvent = await MarmotChat.BuildKeyPackageEventAsync(
            bob, bobKey, slot: "default", relays);
        Assert.True(bobKpEvent.Verify());

        // Alice starts a conversation by referencing it.
        var started = await MarmotChat.StartConversationAsync(
            alice, aliceKey, bobKpEvent, "Alice <> Bob", relays);
        Assert.Equal(1059, started.WelcomeGiftWrap.Kind);
        Assert.True(started.WelcomeGiftWrap.Verify());

        // Bob receives the gift wrap and accepts.
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bob, bobKey, started.WelcomeGiftWrap);
        Assert.NotNull(bobConvo);
        Assert.Equal(started.Conversation.NostrGroupId, bobConvo.NostrGroupId);
        Assert.Equal(aliceKey.PublicKey, bobConvo.Peer);

        // Alice → Bob.
        var msg1 = await MarmotChat.EncryptMessageAsync(alice, started.Conversation, "hello bob");
        string? got1 = await MarmotChat.TryDecryptMessageAsync(bob, bobConvo, msg1);
        Assert.Equal("hello bob", got1);

        // Bob → Alice.
        var msg2 = await MarmotChat.EncryptMessageAsync(bob, bobConvo, "hi alice");
        string? got2 = await MarmotChat.TryDecryptMessageAsync(alice, started.Conversation, msg2);
        Assert.Equal("hi alice", got2);

        // Several interleaved rounds.
        for (int i = 0; i < 3; i++)
        {
            string aT = $"alice #{i}";
            string bT = $"bob #{i}";
            var aSent = await MarmotChat.EncryptMessageAsync(alice, started.Conversation, aT);
            var bSent = await MarmotChat.EncryptMessageAsync(bob, bobConvo, bT);

            Assert.Equal(aT, await MarmotChat.TryDecryptMessageAsync(bob, bobConvo, aSent));
            Assert.Equal(bT, await MarmotChat.TryDecryptMessageAsync(alice, started.Conversation, bSent));
        }
    }

    [Fact]
    public async Task TryDecrypt_RejectsReplay()
    {
        using var alice = new OpenMlsProvider();
        using var bob = new OpenMlsProvider();
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var relays = new[] { "wss://relay.example" };

        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob, bobKey, "default", relays);
        var started = await MarmotChat.StartConversationAsync(alice, aliceKey, bobKp, "t", relays);
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bob, bobKey, started.WelcomeGiftWrap);
        Assert.NotNull(bobConvo);

        var msg = await MarmotChat.EncryptMessageAsync(alice, started.Conversation, "once");
        Assert.Equal("once", await MarmotChat.TryDecryptMessageAsync(bob, bobConvo, msg));

        // OpenMLS rejects replays internally; TryDecrypt swallows the failure.
        string? replayResult = await MarmotChat.TryDecryptMessageAsync(bob, bobConvo, msg);
        Assert.Null(replayResult);
    }
}
