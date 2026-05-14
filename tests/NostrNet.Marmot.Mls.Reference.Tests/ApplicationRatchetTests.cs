// SPDX-License-Identifier: MIT
//
// Tests for the per-leaf application-message ratchet wired through the
// IMarmotMlsProvider.

using System.Security.Cryptography;
using NostrNet.Keys;
using NostrNet.Marmot.Events;
using NostrNet.Marmot.GroupData;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference.Tests;

public class ApplicationRatchetTests
{
    private record TestGroup(
        byte[] GroupId,
        ReferenceMarmotMlsProvider AliceProvider,
        ReferenceMarmotMlsProvider BobProvider);

    private static async Task<TestGroup> BuildTwoMemberGroupAsync()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();

        var alice = new ReferenceMarmotMlsProvider();
        var bob = new ReferenceMarmotMlsProvider();

        var bobKp = await bob.BuildKeyPackageAsync(
            bobKey.PublicKey, ciphersuite: 0x0001,
            extensions: new ushort[] { 0xF2EE }, proposals: Array.Empty<ushort>());

        byte[] groupId = new byte[32];
        new Random(7).NextBytes(groupId);

        await alice.CreateGroupAsync(
            aliceKey.PublicKey,
            new MarmotGroupDataExtension
            {
                NostrGroupId = groupId,
                AdminPubkeys = new[] { aliceKey.PublicKey },
                Relays = Array.Empty<string>(),
            },
            ciphersuite: 0x0001);

        var add = await alice.AddMembersAsync(
            groupId,
            new ReadOnlyMemory<byte>[] { bobKp.BundleBytes });

        await bob.JoinGroupFromWelcomeAsync(add.Welcomes[0].WelcomeMlsMessageBytes);
        return new TestGroup(groupId, alice, bob);
    }

    [Fact]
    public async Task EncryptDecrypt_RoundTrip()
    {
        var g = await BuildTwoMemberGroupAsync();

        byte[] plaintext = SysEncoding.UTF8.GetBytes("hello bob via mls ratchet");

        byte[] mlsBytes = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, plaintext);
        Assert.NotEmpty(mlsBytes);
        Assert.NotEqual(plaintext, mlsBytes);

        var processed = await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, mlsBytes);
        Assert.Equal(MlsMessageKind.Application, processed.Kind);
        Assert.Equal(plaintext, processed.ApplicationPayload);
        Assert.False(processed.EpochAdvanced);
        Assert.Null(processed.NewExporterSecret);
    }

    [Fact]
    public async Task ForwardSecrecy_KeysDifferPerMessage()
    {
        var g = await BuildTwoMemberGroupAsync();
        byte[] same = SysEncoding.UTF8.GetBytes("same text");

        byte[] m1 = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, same);
        byte[] m2 = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, same);

        // Same plaintext but different ciphertexts: the ratchet keys differ.
        Assert.NotEqual(m1, m2);

        var p1 = await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, m1);
        var p2 = await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, m2);
        Assert.Equal(same, p1.ApplicationPayload);
        Assert.Equal(same, p2.ApplicationPayload);
    }

    [Fact]
    public async Task Replay_IsRejected()
    {
        var g = await BuildTwoMemberGroupAsync();
        byte[] payload = SysEncoding.UTF8.GetBytes("first message");

        byte[] msg = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, payload);
        var firstProcessed = await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, msg);
        Assert.Equal(payload, firstProcessed.ApplicationPayload);

        // Replay attempt: same MLSMessage bytes, second time.
        await Assert.ThrowsAnyAsync<CryptographicException>(
            async () => await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, msg));
    }

    [Fact]
    public async Task TamperedHeader_FailsAuthentication()
    {
        var g = await BuildTwoMemberGroupAsync();
        byte[] payload = SysEncoding.UTF8.GetBytes("hi");
        byte[] msg = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, payload);

        // Flip a header byte (after the wire-format prefix). The header is
        // bound in as AEAD AAD, so any change fails the tag check.
        byte[] tampered = (byte[])msg.Clone();
        tampered[3] ^= 0x01;

        await Assert.ThrowsAnyAsync<CryptographicException>(
            async () => await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, tampered));
    }

    [Fact]
    public async Task EncryptDecrypt_AcrossManyMessages()
    {
        // Forward-only ratchet should run cleanly across many sequential messages.
        var g = await BuildTwoMemberGroupAsync();
        const int N = 32;
        for (int i = 0; i < N; i++)
        {
            byte[] p = SysEncoding.UTF8.GetBytes($"message {i}");
            byte[] mls = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, p);
            var decoded = await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, mls);
            Assert.Equal(p, decoded.ApplicationPayload);
        }
    }

    [Fact]
    public async Task Bidirectional_AliceAndBob_BothDirections()
    {
        // 1:1 messaging means BOTH sides talk. Each side runs its own
        // outbound ratchet (leaf 0 for Alice, leaf 1 for Bob) and tracks
        // the peer's inbound ratchet independently.
        var g = await BuildTwoMemberGroupAsync();

        // Alice → Bob
        byte[] aliceMsg = SysEncoding.UTF8.GetBytes("hello from alice");
        byte[] aliceCipher = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, aliceMsg);
        var bobGot = await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, aliceCipher);
        Assert.Equal(aliceMsg, bobGot.ApplicationPayload);

        // Bob → Alice
        byte[] bobMsg = SysEncoding.UTF8.GetBytes("hi alice, this is bob");
        byte[] bobCipher = await g.BobProvider.EncryptApplicationMessageAsync(g.GroupId, bobMsg);
        var aliceGot = await g.AliceProvider.ProcessIncomingMlsMessageAsync(g.GroupId, bobCipher);
        Assert.Equal(bobMsg, aliceGot.ApplicationPayload);

        // Several more rounds, interleaved, to be sure neither side's
        // ratchets cross-pollute.
        for (int i = 0; i < 5; i++)
        {
            byte[] a = SysEncoding.UTF8.GetBytes($"A{i}");
            byte[] b = SysEncoding.UTF8.GetBytes($"B{i}");

            byte[] aCt = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, a);
            byte[] bCt = await g.BobProvider.EncryptApplicationMessageAsync(g.GroupId, b);

            var aGotB = await g.AliceProvider.ProcessIncomingMlsMessageAsync(g.GroupId, bCt);
            var bGotA = await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, aCt);

            Assert.Equal(b, aGotB.ApplicationPayload);
            Assert.Equal(a, bGotA.ApplicationPayload);
        }
    }

    [Fact]
    public async Task Bidirectional_SenderCantDecryptOwnMessages()
    {
        // The MLS ratchet binds messages to a SENDER leaf. Alice
        // encrypting with her outbound ratchet (leaf 0) cannot be
        // decrypted by Alice's inbound ratchet (which is keyed for
        // leaf 1's outbound). Self-decrypt MUST fail.
        var g = await BuildTwoMemberGroupAsync();

        byte[] msg = SysEncoding.UTF8.GetBytes("alice's own message");
        byte[] ciphertext = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, msg);

        await Assert.ThrowsAnyAsync<CryptographicException>(
            async () => await g.AliceProvider.ProcessIncomingMlsMessageAsync(g.GroupId, ciphertext));
    }

    [Fact]
    public async Task GroupEvent_WrapsRatchetedMessage_EndToEnd()
    {
        // The fully Marmot-compliant path: MLS app message INSIDE a kind-445
        // GroupEvent that's separately encrypted with the exporter secret.
        var g = await BuildTwoMemberGroupAsync();
        byte[] plaintext = SysEncoding.UTF8.GetBytes("layered encryption");

        // 1. Alice MLS-encrypts the app message.
        byte[] mlsBytes = await g.AliceProvider.EncryptApplicationMessageAsync(g.GroupId, plaintext);

        // 2. Alice wraps it in a kind-445 GroupEvent keyed by the exporter.
        byte[] aliceExp = await g.AliceProvider.CurrentExporterSecretAsync(g.GroupId);
        var ev = GroupEvent.Build(mlsBytes, aliceExp, g.GroupId);
        Assert.True(ev.Verify());

        // 3. Bob unwraps the GroupEvent.
        byte[] bobExp = await g.BobProvider.CurrentExporterSecretAsync(g.GroupId);
        var decrypted = GroupEvent.Decrypt(ev, bobExp);

        // 4. Bob processes the MLSMessage to recover plaintext.
        var processed = await g.BobProvider.ProcessIncomingMlsMessageAsync(g.GroupId, decrypted.MlsMessageBytes);
        Assert.Equal(plaintext, processed.ApplicationPayload);
    }
}
