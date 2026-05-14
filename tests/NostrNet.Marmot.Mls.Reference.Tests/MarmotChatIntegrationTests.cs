// SPDX-License-Identifier: MIT
//
// Integration: drives the MarmotChat high-level helper with the real
// reference MLS provider, demonstrating the API an app developer would
// actually use for 1:1 chat.

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot;

namespace NostrNet.Marmot.Mls.Reference.Tests;

public class MarmotChatIntegrationTests
{
    [Fact]
    public async Task FullOneToOneFlow_Bidirectional()
    {
        // Each side has its own provider — like two apps on two phones.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        var aliceProv = new ReferenceMarmotMlsProvider();
        var bobProv = new ReferenceMarmotMlsProvider();
        var relays = new[] { "wss://relay.example" };

        // Bob publishes his KeyPackage event.
        var bobKpEvent = await MarmotChat.BuildKeyPackageEventAsync(
            bobProv, bobKey, slot: "default", relays);

        Assert.Equal(MarmotKinds.KeyPackage, bobKpEvent.Kind);
        Assert.True(bobKpEvent.Verify());
        // Bob's app would publish this to his inbox relays.

        // Alice starts a conversation by referencing Bob's KeyPackage event.
        // (In a real app, Alice fetched bobKpEvent off a relay.)
        var started = await MarmotChat.StartConversationAsync(
            aliceProv, aliceKey, bobKpEvent, "Alice <> Bob", relays);

        Assert.Equal(1059, started.WelcomeGiftWrap.Kind);
        Assert.True(started.WelcomeGiftWrap.Verify());
        // Alice's app would publish the gift wrap to Bob's inbox relays.

        // Bob receives the gift wrap and accepts.
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(
            bobProv, bobKey, started.WelcomeGiftWrap);
        Assert.NotNull(bobConvo);
        Assert.Equal(started.Conversation.NostrGroupId, bobConvo.NostrGroupId);
        Assert.Equal(aliceKey.PublicKey, bobConvo.Peer);

        // Alice sends "hello bob".
        var msg1 = await MarmotChat.EncryptMessageAsync(
            aliceProv, started.Conversation, "hello bob");
        Assert.Equal(MarmotKinds.GroupEvent, msg1.Kind);
        Assert.True(msg1.Verify());
        Assert.True(MarmotChat.LooksLikeGroupEventFor(bobConvo, msg1));

        // Bob decrypts.
        string? got1 = await MarmotChat.TryDecryptMessageAsync(bobProv, bobConvo, msg1);
        Assert.Equal("hello bob", got1);

        // Bob replies.
        var msg2 = await MarmotChat.EncryptMessageAsync(
            bobProv, bobConvo, "hi alice");
        string? got2 = await MarmotChat.TryDecryptMessageAsync(
            aliceProv, started.Conversation, msg2);
        Assert.Equal("hi alice", got2);

        // Several interleaved rounds.
        for (int i = 0; i < 5; i++)
        {
            string aT = $"alice msg #{i}";
            string bT = $"bob msg #{i}";
            var aSent = await MarmotChat.EncryptMessageAsync(aliceProv, started.Conversation, aT);
            var bSent = await MarmotChat.EncryptMessageAsync(bobProv, bobConvo, bT);

            Assert.Equal(aT, await MarmotChat.TryDecryptMessageAsync(bobProv, bobConvo, aSent));
            Assert.Equal(bT, await MarmotChat.TryDecryptMessageAsync(aliceProv, started.Conversation, bSent));
        }
    }

    [Fact]
    public async Task TryDecrypt_RejectsReplay()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var aliceProv = new ReferenceMarmotMlsProvider();
        var bobProv = new ReferenceMarmotMlsProvider();
        var relays = new[] { "wss://relay.example" };

        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bobProv, bob, "default", relays);
        var started = await MarmotChat.StartConversationAsync(aliceProv, alice, bobKp, "test", relays);
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bobProv, bob, started.WelcomeGiftWrap);
        Assert.NotNull(bobConvo);

        var msg = await MarmotChat.EncryptMessageAsync(aliceProv, started.Conversation, "once");
        string? first = await MarmotChat.TryDecryptMessageAsync(bobProv, bobConvo, msg);
        Assert.Equal("once", first);

        // Replay → null (silently dropped, not throwing).
        string? second = await MarmotChat.TryDecryptMessageAsync(bobProv, bobConvo, msg);
        Assert.Null(second);
    }
}
