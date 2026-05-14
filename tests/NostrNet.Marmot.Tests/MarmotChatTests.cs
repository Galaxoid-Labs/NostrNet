// SPDX-License-Identifier: MIT
//
// End-to-end test for the high-level MarmotChat 1:1 helper. This is the
// "what an app developer sees" API surface — if these tests work, the
// app developer experience for one-to-one Marmot is sound.

using NostrNet.Keys;
using NostrNet.Marmot.Events;

namespace NostrNet.Marmot.Tests;

public class MarmotChatTests
{
    // A minimal in-memory IMarmotMlsProvider stand-in so the
    // NostrNet.Marmot test project can exercise MarmotChat without
    // pulling NostrNet.Marmot.Mls.Native (and its Rust toolchain
    // dependency) into its dependency graph.
    // It tracks the symmetric "exporter secret" both sides need to
    // match for kind-445 to round-trip, plus a per-leaf generation
    // counter so we still demonstrate forward-direction tracking.
    //
    // Crypto is intentionally fake — this is for testing the high-level
    // glue, not for vetting MLS. The real reference provider has its own
    // exhaustive tests.
    private sealed class FakeProvider : IMarmotMlsProvider
    {
        public Dictionary<string, byte[]> _byGroup = new(StringComparer.Ordinal);
        public Dictionary<string, byte[]> _kpRefToInitSk = new(StringComparer.Ordinal);
        public Dictionary<string, byte[]> _kpRefToSecret = new(StringComparer.Ordinal);

        public Task<KeyPackageBundle> BuildKeyPackageAsync(
            PublicKey identityPubkey, ushort ciphersuite,
            IReadOnlyList<ushort> extensions, IReadOnlyList<ushort> proposals,
            CancellationToken ct = default)
        {
            byte[] secret = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(secret);
            byte[] kpRef = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(kpRef);
            string kpRefHex = Convert.ToHexStringLower(kpRef);

            byte[] bundle = new byte[64];
            secret.CopyTo(bundle, 0);
            kpRef.CopyTo(bundle, 32);

            _kpRefToInitSk[kpRefHex] = secret;
            _kpRefToSecret[kpRefHex] = secret;
            return Task.FromResult(new KeyPackageBundle(bundle, ciphersuite, "1.0", kpRefHex));
        }

        public Task<KeyPackageInfo> ParseKeyPackageAsync(
            ReadOnlyMemory<byte> kp, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<CreateGroupResult> CreateGroupAsync(
            PublicKey creator, NostrNet.Marmot.GroupData.MarmotGroupDataExtension data,
            ushort ciphersuite, CancellationToken ct = default)
        {
            byte[] expBase = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(expBase);
            _byGroup[Convert.ToHexStringLower(data.NostrGroupId)] = expBase;
            return Task.FromResult(new CreateGroupResult((byte[])data.NostrGroupId.Clone(), expBase));
        }

        public Task<AddMembersResult> AddMembersAsync(
            ReadOnlyMemory<byte> groupId, IReadOnlyList<ReadOnlyMemory<byte>> kps,
            CancellationToken ct = default)
        {
            // The Welcome carries the symmetric group-exporter so both sides match.
            string gh = Convert.ToHexStringLower(groupId.Span);
            byte[] secret = _byGroup[gh];

            // The recipient identity is encoded in the bundle layout we created.
            byte[] kpRef = kps[0].Slice(32, 32).ToArray();
            string kpRefHex = Convert.ToHexStringLower(kpRef);

            // Welcome bytes layout (fake): [32:secret][32:groupId][32:kpRef]
            byte[] welcome = new byte[96];
            secret.CopyTo(welcome, 0);
            groupId.Span.CopyTo(welcome.AsSpan(32));
            kpRef.CopyTo(welcome, 64);

            var recipientPubkey = new PublicKey(new byte[32]); // placeholder — caller uses peerKp.Author elsewhere
            return Task.FromResult(new AddMembersResult(
                CommitMlsMessageBytes: Array.Empty<byte>(),
                Welcomes: new[] { new WelcomeToSend(recipientPubkey, welcome) },
                NewExporterSecret: secret));
        }

        public Task<JoinedGroupResult> JoinGroupFromWelcomeAsync(
            ReadOnlyMemory<byte> welcomeBytes, CancellationToken ct = default)
        {
            byte[] secret = welcomeBytes.Slice(0, 32).ToArray();
            byte[] groupId = welcomeBytes.Slice(32, 32).ToArray();
            byte[] kpRef = welcomeBytes.Slice(64, 32).ToArray();
            string kpRefHex = Convert.ToHexStringLower(kpRef);

            if (!_kpRefToSecret.ContainsKey(kpRefHex))
            {
                throw new System.Security.Cryptography.CryptographicException("No matching KeyPackage.");
            }

            _byGroup[Convert.ToHexStringLower(groupId)] = secret;
            return Task.FromResult(new JoinedGroupResult(
                NostrGroupId: groupId,
                GroupData: new NostrNet.Marmot.GroupData.MarmotGroupDataExtension
                {
                    NostrGroupId = groupId,
                    AdminPubkeys = Array.Empty<PublicKey>(),
                    Relays = Array.Empty<string>(),
                },
                CurrentExporterSecret: secret));
        }

        public Task<RemoveMembersResult> RemoveMembersAsync(
            ReadOnlyMemory<byte> groupId, IReadOnlyList<PublicKey> peers, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<SelfUpdateResult> SelfUpdateAsync(
            ReadOnlyMemory<byte> groupId, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<byte[]> BuildSelfRemoveProposalAsync(
            ReadOnlyMemory<byte> groupId, CancellationToken ct = default)
            => throw new NotImplementedException();

        public Task<byte[]> EncryptApplicationMessageAsync(
            ReadOnlyMemory<byte> groupId, ReadOnlyMemory<byte> plaintext,
            CancellationToken ct = default)
        {
            // Fake "MLS message" = plaintext (no ratchet). Round-tripping is
            // still exercised at the kind-445 layer via the real exporter.
            return Task.FromResult(plaintext.ToArray());
        }

        public Task<ProcessedMlsMessage> ProcessIncomingMlsMessageAsync(
            ReadOnlyMemory<byte> groupId, ReadOnlyMemory<byte> mlsBytes,
            CancellationToken ct = default)
        {
            return Task.FromResult(new ProcessedMlsMessage(
                Kind: MlsMessageKind.Application,
                ApplicationPayload: mlsBytes.ToArray(),
                EpochAdvanced: false,
                NewExporterSecret: null));
        }

        public Task<byte[]> CurrentExporterSecretAsync(
            ReadOnlyMemory<byte> groupId, CancellationToken ct = default)
        {
            return Task.FromResult(_byGroup[Convert.ToHexStringLower(groupId.Span)]);
        }

        public Task<IReadOnlyList<MarmotStoredGroup>> ListGroupsAsync(CancellationToken ct = default)
        {
            return Task.FromResult<IReadOnlyList<MarmotStoredGroup>>(Array.Empty<MarmotStoredGroup>());
        }

        public Task DeleteGroupAsync(ReadOnlyMemory<byte> nostrGroupId, CancellationToken ct = default)
        {
            _byGroup.Remove(Convert.ToHexStringLower(nostrGroupId.Span));
            return Task.CompletedTask;
        }

        public Task VacuumAsync(CancellationToken ct = default) => Task.CompletedTask;
    }

    [Fact]
    public async Task FullOneToOneFlow_WithFakeProvider()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();

        var aliceProv = new FakeProvider();
        var bobProv = new FakeProvider();
        var relays = new[] { "wss://relay.example" };

        // 1. Bob publishes a KeyPackage event.
        var bobKpEvent = await MarmotChat.BuildKeyPackageEventAsync(
            bobProv, bobKey, slot: null, relays);
        Assert.Equal(MarmotKinds.KeyPackage, bobKpEvent.Kind);
        Assert.True(bobKpEvent.Verify());

        // 2. Alice starts a conversation by referencing Bob's KeyPackage event.
        var started = await MarmotChat.StartConversationAsync(
            aliceProv, aliceKey, bobKpEvent, "alice + bob", relays);
        Assert.NotNull(started.WelcomeGiftWrap);
        Assert.Equal(1059, started.WelcomeGiftWrap.Kind);
        Assert.Equal(bobKey.PublicKey, started.Conversation.Peer);

        // 3. Bob receives the gift wrap and accepts the invite.
        var bobConvo = await MarmotChat.TryAcceptInviteAsync(bobProv, bobKey, started.WelcomeGiftWrap);
        Assert.NotNull(bobConvo);
        Assert.Equal(started.Conversation.NostrGroupId, bobConvo.NostrGroupId);
        Assert.Equal(aliceKey.PublicKey, bobConvo.Peer);

        // 4. Alice sends a message.
        var aliceMsg = await MarmotChat.EncryptMessageAsync(
            aliceProv, started.Conversation, aliceKey, "hello bob");
        Assert.Equal(MarmotKinds.GroupEvent, aliceMsg.Kind);
        Assert.True(MarmotChat.LooksLikeGroupEventFor(bobConvo, aliceMsg));

        // 5. Bob decrypts it.
        string? gotAlice = await MarmotChat.TryDecryptMessageAsync(bobProv, bobConvo, aliceMsg);
        Assert.Equal("hello bob", gotAlice);

        // 6. Bob replies.
        var bobMsg = await MarmotChat.EncryptMessageAsync(
            bobProv, bobConvo, bobKey, "hi alice");
        string? gotBob = await MarmotChat.TryDecryptMessageAsync(aliceProv, started.Conversation, bobMsg);
        Assert.Equal("hi alice", gotBob);
    }

    [Fact]
    public async Task TryAcceptInvite_ReturnsNullForNonMarmotGiftWrap()
    {
        // A NIP-17 DM gift-wrap isn't a Marmot Welcome — accept must
        // gracefully return null instead of throwing.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var dmGiftWrap = NostrNet.Crypto.Nip17.CreateDirectMessage(
            "regular nip-17 dm",
            senderPrivateKey: alice,
            recipientPublicKey: bob.PublicKey);

        var prov = new FakeProvider();
        var result = await MarmotChat.TryAcceptInviteAsync(prov, bob, dmGiftWrap);
        Assert.Null(result);
    }

    [Fact]
    public async Task TryDecryptMessage_ReturnsNullForUnrelatedKind445()
    {
        // A kind-445 event with the wrong h-tag / wrong exporter shouldn't
        // throw — TryDecrypt returns null.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var aliceProv = new FakeProvider();

        var relays = new[] { "wss://relay.example" };
        var bobKpEvent = await MarmotChat.BuildKeyPackageEventAsync(
            aliceProv, bob, null, relays);

        var started = await MarmotChat.StartConversationAsync(
            aliceProv, alice, bobKpEvent, null, relays);

        // Build a stray kind-445 with a random group id that doesn't match.
        byte[] otherGroupId = new byte[32];
        new Random(99).NextBytes(otherGroupId);
        byte[] otherSecret = new byte[32];
        new Random(98).NextBytes(otherSecret);
        var stray = GroupEvent.Build(
            mlsMessageBytes: new byte[] { 1, 2, 3 },
            exporterSecret: otherSecret,
            nostrGroupId: otherGroupId);

        // h-tag check + wrong-exporter both lead to null instead of throwing.
        Assert.False(MarmotChat.LooksLikeGroupEventFor(started.Conversation, stray));
        string? text = await MarmotChat.TryDecryptMessageAsync(aliceProv, started.Conversation, stray);
        Assert.Null(text);
    }
}
