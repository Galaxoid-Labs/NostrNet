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
