// SPDX-License-Identifier: MIT
//
// Member removal and key rotation through the OpenMLS FFI.

using NostrNet.Keys;
using NostrNet.Marmot;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class MembershipChangeTests
{
    private sealed record Member(PrivateKey Key, OpenMlsProvider Provider) : IDisposable
    {
        public void Dispose()
        {
            Provider.Dispose();
            Key.Dispose();
        }
    }

    private static Member Make() => new(PrivateKey.Generate(), new OpenMlsProvider());

    [Fact]
    public async Task RemovePeer_RemovedMemberLosesAccess()
    {
        using var alice = Make();
        using var bob = Make();
        using var carol = Make();
        var relays = new[] { "wss://relay.example" };

        // 3-member group with Alice as founder.
        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob.Provider, bob.Key, null, relays);
        var carolKp = await MarmotChat.BuildKeyPackageEventAsync(carol.Provider, carol.Key, null, relays);
        var started = await MarmotChat.StartGroupAsync(
            alice.Provider, alice.Key, new[] { bobKp, carolKp }, "test", relays);
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bob.Provider, bob.Key, started.WelcomeGiftWraps[0]);
        var carolConvo = await MarmotChat.TryAcceptInviteAsync(carol.Provider, carol.Key, started.WelcomeGiftWraps[1]);
        Assert.NotNull(bobConvo);
        Assert.NotNull(carolConvo);

        // Pre-removal sanity round.
        var preMsg = await MarmotChat.EncryptMessageAsync(alice.Provider, started.Conversation, alice.Key, "hi all");
        Assert.Equal("hi all", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, preMsg));
        Assert.Equal("hi all", await MarmotChat.TryDecryptMessageAsync(carol.Provider, carolConvo, preMsg));

        // Alice removes Carol.
        var removed = await MarmotChat.RemovePeerAsync(
            alice.Provider, started.Conversation, new[] { carol.Key.PublicKey });

        // Bob processes the Commit and advances his epoch.
        var bobProcessed = await MarmotChat.TryProcessMessageAsync(bob.Provider, bobConvo, removed.CommitGroupEvent);
        Assert.NotNull(bobProcessed);
        Assert.Equal(MarmotMessageKind.Commit, bobProcessed.Kind);
        Assert.True(bobProcessed.EpochAdvanced);

        // Carol receives the same Commit. OpenMLS lets her process it
        // (she sees that she was removed) — TryProcessMessage may
        // succeed and report a Commit, but she should be unable to
        // decrypt future application messages.
        _ = await MarmotChat.TryProcessMessageAsync(carol.Provider, carolConvo, removed.CommitGroupEvent);

        // Post-removal: Alice + Bob can still talk, Carol cannot decrypt.
        var postMsg = await MarmotChat.EncryptMessageAsync(alice.Provider, started.Conversation, alice.Key, "after removal");
        Assert.Equal("after removal", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, postMsg));

        string? carolGot = await MarmotChat.TryDecryptMessageAsync(carol.Provider, carolConvo, postMsg);
        Assert.Null(carolGot);  // forward secrecy: Carol can't decrypt anymore
    }

    [Fact]
    public async Task RotateKeys_MessagesStillFlow()
    {
        using var alice = Make();
        using var bob = Make();
        var relays = new[] { "wss://relay.example" };

        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob.Provider, bob.Key, null, relays);
        var started = await MarmotChat.StartConversationAsync(
            alice.Provider, alice.Key, bobKp, "1:1", relays);
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bob.Provider, bob.Key, started.WelcomeGiftWrap);
        Assert.NotNull(bobConvo);

        // Pre-rotation message.
        var m1 = await MarmotChat.EncryptMessageAsync(alice.Provider, started.Conversation, alice.Key, "before");
        Assert.Equal("before", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, m1));

        // Capture current exporter so we can verify it changes after rotation.
        byte[] expBefore = await alice.Provider.CurrentExporterSecretAsync(started.Conversation.NostrGroupId);

        // Alice rotates her keys.
        var rotated = await MarmotChat.RotateKeysAsync(alice.Provider, started.Conversation);

        // Bob processes the self-update Commit.
        var processed = await MarmotChat.TryProcessMessageAsync(bob.Provider, bobConvo, rotated.CommitGroupEvent);
        Assert.NotNull(processed);
        Assert.Equal(MarmotMessageKind.Commit, processed.Kind);
        Assert.True(processed.EpochAdvanced);

        // Exporter changed.
        byte[] expAfter = await alice.Provider.CurrentExporterSecretAsync(started.Conversation.NostrGroupId);
        Assert.NotEqual(Convert.ToHexString(expBefore), Convert.ToHexString(expAfter));

        // Both sides can still talk on the new epoch.
        var m2 = await MarmotChat.EncryptMessageAsync(alice.Provider, started.Conversation, alice.Key, "after");
        Assert.Equal("after", await MarmotChat.TryDecryptMessageAsync(bob.Provider, bobConvo, m2));

        var m3 = await MarmotChat.EncryptMessageAsync(bob.Provider, bobConvo, bob.Key, "bob replies");
        Assert.Equal("bob replies", await MarmotChat.TryDecryptMessageAsync(alice.Provider, started.Conversation, m3));
    }
}
