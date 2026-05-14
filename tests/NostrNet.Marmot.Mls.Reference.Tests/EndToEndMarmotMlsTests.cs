// SPDX-License-Identifier: MIT
//
// Full Marmot + reference-MLS integration test. Walks through the
// happy path two real Marmot users would take:
//
//   1. Both Alice and Bob create Marmot identities (Nostr private keys).
//   2. Bob's provider builds a KeyPackage for him.
//   3. Bob publishes his KeyPackage as a kind-30443 KeyPackageEvent.
//   4. Alice's provider creates a Marmot group (with a MarmotGroupDataExtension).
//   5. Alice's provider runs AddMembersAsync on Bob's KeyPackage and gets
//      a Welcome blob.
//   6. Alice wraps that Welcome in a NIP-59 kind-1059 gift wrap via
//      NostrNet.Marmot.Events.WelcomeEvent.
//   7. Bob unwraps the gift wrap, hands the inner MLS Welcome bytes to
//      his provider, and joins the group.
//   8. Both sides ask their provider for CurrentExporterSecretAsync. They match.
//   9. Alice encrypts a payload as a kind-445 Marmot GroupEvent using the
//      exporter secret; Bob decrypts it. Identical plaintext.

using NostrNet.Keys;
using NostrNet.Marmot.Events;
using NostrNet.Marmot.GroupData;
using NostrNet.Marmot.Mls.Reference;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference.Tests;

public class EndToEndMarmotMlsTests
{
    [Fact]
    public async Task TwoMember_MarmotPlusReferenceMls_FullRoundTrip()
    {
        // ── 1. Nostr identities for Alice and Bob.
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();

        // ── 2. Bob's provider produces a KeyPackage for him.
        var bobProvider = new ReferenceMarmotMlsProvider();
        var bobBundle = await bobProvider.BuildKeyPackageAsync(
            identityPubkey: bobKey.PublicKey,
            ciphersuite: 0x0001,
            extensions: new ushort[] { 0xF2EE },
            proposals: Array.Empty<ushort>());

        // ── 3. Bob publishes his KeyPackage as a kind-30443 event.
        var bobKpEvent = KeyPackageEvent.Create("bob-mls-slot-1")
            .WithBundleBytes(bobBundle.BundleBytes)
            .WithCiphersuite(bobBundle.Ciphersuite)
            .WithExtension(0xF2EE)
            .WithKeyPackageRef(bobBundle.KeyPackageRef ?? throw new InvalidOperationException("missing kp ref"))
            .WithRelay("wss://relay.example.com")
            .Sign(bobKey);

        Assert.True(bobKpEvent.Verify());
        var parsedBobKp = KeyPackageEvent.FromEvent(bobKpEvent);
        Assert.Equal(bobBundle.BundleBytes, parsedBobKp.KeyPackageBundleBytes);

        // ── 4. Alice creates a Marmot group.
        var aliceProvider = new ReferenceMarmotMlsProvider();
        byte[] nostrGroupId = new byte[32];
        new Random(42).NextBytes(nostrGroupId);

        var groupData = new MarmotGroupDataExtension
        {
            NostrGroupId = nostrGroupId,
            Name = "Alice + Bob",
            AdminPubkeys = new[] { aliceKey.PublicKey },
            Relays = new[] { "wss://relay.example.com" },
        };

        var createResult = await aliceProvider.CreateGroupAsync(
            creatorPubkey: aliceKey.PublicKey,
            groupData: groupData,
            ciphersuite: 0x0001);

        Assert.Equal(nostrGroupId, createResult.NostrGroupId);

        // ── 5. Alice adds Bob via the Marmot provider, getting a Welcome blob.
        var addResult = await aliceProvider.AddMembersAsync(
            nostrGroupId: nostrGroupId,
            keyPackageBundles: new ReadOnlyMemory<byte>[] { parsedBobKp.KeyPackageBundleBytes });

        Assert.Single(addResult.Welcomes);
        Assert.Equal(bobKey.PublicKey, addResult.Welcomes[0].RecipientPubkey);

        // ── 6. Alice wraps the Welcome in a NIP-59 gift wrap (kind 1059).
        var giftWrap = WelcomeEvent.Build(
            mlsWelcomeBytes: addResult.Welcomes[0].WelcomeMlsMessageBytes,
            keyPackageEventId: bobKpEvent.Id.ToHex(),
            senderKey: aliceKey,
            recipientPubkey: bobKey.PublicKey,
            recommendedRelays: groupData.Relays.ToList());

        Assert.Equal(1059, giftWrap.Kind);
        Assert.True(giftWrap.Verify());

        // ── 7. Bob unwraps the gift wrap and joins the group via his provider.
        var unwrapped = WelcomeEvent.Unwrap(giftWrap, bobKey);
        Assert.Equal(aliceKey.PublicKey, unwrapped.Sender);
        Assert.Equal(bobKpEvent.Id.ToHex(), unwrapped.KeyPackageEventId);

        var joined = await bobProvider.JoinGroupFromWelcomeAsync(unwrapped.MlsWelcomeBytes);
        Assert.Equal(nostrGroupId, joined.NostrGroupId);

        // ── 8. Both sides agree on the exporter secret.
        byte[] aliceExp = await aliceProvider.CurrentExporterSecretAsync(nostrGroupId);
        byte[] bobExp = await bobProvider.CurrentExporterSecretAsync(nostrGroupId);
        Assert.Equal(32, aliceExp.Length);
        Assert.Equal(Convert.ToHexString(aliceExp), Convert.ToHexString(bobExp));

        // ── 9. Alice encrypts a kind-445 GroupEvent; Bob decrypts it.
        byte[] mlsAppPayload = SysEncoding.UTF8.GetBytes("hello over MLS exporter");
        var groupEvent = GroupEvent.Build(
            mlsMessageBytes: mlsAppPayload,
            exporterSecret: aliceExp,
            nostrGroupId: nostrGroupId);

        Assert.Equal(445, groupEvent.Kind);
        Assert.True(groupEvent.Verify());

        var decrypted = GroupEvent.Decrypt(groupEvent, bobExp);
        Assert.Equal(mlsAppPayload, decrypted.MlsMessageBytes);
        Assert.Equal(nostrGroupId, decrypted.NostrGroupId);
    }
}
