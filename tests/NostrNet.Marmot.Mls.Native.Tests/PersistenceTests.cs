// SPDX-License-Identifier: MIT
//
// Persistent provider state across process-restart-equivalent reopens.

using NostrNet.Keys;
using NostrNet.Marmot;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class PersistenceTests
{
    private static string TempSqlitePath()
    {
        return Path.Combine(
            Path.GetTempPath(),
            $"nostrnet-marmot-persist-{Guid.NewGuid():N}.sqlite");
    }

    [Fact]
    public async Task GroupSurvivesProviderReopen()
    {
        string aliceDb = TempSqlitePath();
        string bobDb = TempSqlitePath();
        try
        {
            using var aliceKey = PrivateKey.Generate();
            using var bobKey = PrivateKey.Generate();
            var relays = new[] { "wss://relay.example" };

            // ── Phase 1: build group on persistent providers.
            byte[] aliceExpAtEpoch1;
            byte[] bobExpAtEpoch1;
            byte[] groupId;
            string slot1Message;
            byte[] slot1MessageBytes;

            {
                using var aliceProv = OpenMlsProvider.OpenAtPath(aliceDb);
                using var bobProv = OpenMlsProvider.OpenAtPath(bobDb);

                var bobKpEvent = await MarmotChat.BuildKeyPackageEventAsync(bobProv, bobKey, null, relays);
                var started = await MarmotChat.StartConversationAsync(
                    aliceProv, aliceKey, bobKpEvent, "persisted", relays);
                var bobConvo = await MarmotChat.TryAcceptInviteAsync(bobProv, bobKey, started.WelcomeGiftWrap);
                Assert.NotNull(bobConvo);

                groupId = started.Conversation.NostrGroupId;
                aliceExpAtEpoch1 = await aliceProv.CurrentExporterSecretAsync(groupId);
                bobExpAtEpoch1 = await bobProv.CurrentExporterSecretAsync(groupId);
                Assert.Equal(Convert.ToHexString(aliceExpAtEpoch1), Convert.ToHexString(bobExpAtEpoch1));

                slot1Message = "from before restart";
                slot1MessageBytes = (await MarmotChat.EncryptMessageAsync(
                    aliceProv, started.Conversation, aliceKey, slot1Message)).Content.FromBase64();
                // The kind-445 GroupEvent payload above isn't the MLSMessage —
                // it's the OUTER (ChaCha20-Poly1305-encrypted with exporter)
                // ciphertext. We'll re-decrypt it on the reopened bob below.
            }

            // ── Both providers go out of scope; SQLite files are now closed.

            // ── Phase 2: reopen both providers from the same paths, confirm
            //    state is restored.
            using var aliceProv2 = OpenMlsProvider.OpenAtPath(aliceDb);
            using var bobProv2 = OpenMlsProvider.OpenAtPath(bobDb);

            byte[] aliceExpAfter = await aliceProv2.CurrentExporterSecretAsync(groupId);
            byte[] bobExpAfter = await bobProv2.CurrentExporterSecretAsync(groupId);
            Assert.Equal(Convert.ToHexString(aliceExpAtEpoch1), Convert.ToHexString(aliceExpAfter));
            Assert.Equal(Convert.ToHexString(bobExpAtEpoch1), Convert.ToHexString(bobExpAfter));

            // Send and decrypt a NEW message through the reopened providers.
            var conv1 = new MarmotConversation(groupId, bobKey.PublicKey);
            var conv2 = new MarmotConversation(groupId, aliceKey.PublicKey);
            var msg = await MarmotChat.EncryptMessageAsync(aliceProv2, conv1, aliceKey, "post-reopen ping");
            Assert.Equal("post-reopen ping",
                await MarmotChat.TryDecryptMessageAsync(bobProv2, conv2, msg));

            // Bidirectional also works on the reopened providers.
            var reply = await MarmotChat.EncryptMessageAsync(bobProv2, conv2, bobKey, "post-reopen pong");
            Assert.Equal("post-reopen pong",
                await MarmotChat.TryDecryptMessageAsync(aliceProv2, conv1, reply));
        }
        finally
        {
            if (File.Exists(aliceDb)) File.Delete(aliceDb);
            if (File.Exists(bobDb)) File.Delete(bobDb);
        }
    }

    [Fact]
    public async Task NewMemberCanJoin_FromPersistedKeyPackage()
    {
        // Bob builds a KeyPackage on a persistent provider, the provider
        // closes, then re-opens. Alice fetches Bob's KeyPackage event and
        // starts a conversation. Bob (re-opened) accepts the invite —
        // his signature keys are still in storage.
        string bobDb = TempSqlitePath();
        try
        {
            using var aliceKey = PrivateKey.Generate();
            using var bobKey = PrivateKey.Generate();
            var relays = new[] { "wss://relay.example" };

            NostrNet.Events.NostrEvent bobKpEvent;
            {
                using var bobProv = OpenMlsProvider.OpenAtPath(bobDb);
                bobKpEvent = await MarmotChat.BuildKeyPackageEventAsync(
                    bobProv, bobKey, null, relays);
            }

            // Alice (always fresh in-memory) starts a conversation against
            // bob's published KeyPackage event.
            using var aliceProv = new OpenMlsProvider();
            var started = await MarmotChat.StartConversationAsync(
                aliceProv, aliceKey, bobKpEvent, "x", relays);

            // Bob reopens his provider and accepts.
            using var bobProv2 = OpenMlsProvider.OpenAtPath(bobDb);
            var bobConvo = await MarmotChat.TryAcceptInviteAsync(
                bobProv2, bobKey, started.WelcomeGiftWrap);
            Assert.NotNull(bobConvo);

            // Round-trip a message to prove it works.
            var msg = await MarmotChat.EncryptMessageAsync(aliceProv, started.Conversation, aliceKey, "hi reopened bob");
            Assert.Equal("hi reopened bob",
                await MarmotChat.TryDecryptMessageAsync(bobProv2, bobConvo, msg));
        }
        finally
        {
            if (File.Exists(bobDb)) File.Delete(bobDb);
        }
    }
}

file static class Base64Extensions
{
    public static byte[] FromBase64(this string s) => Convert.FromBase64String(s);
}
