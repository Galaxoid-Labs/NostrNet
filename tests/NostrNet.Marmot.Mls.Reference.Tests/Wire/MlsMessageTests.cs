// SPDX-License-Identifier: MIT
//
// Tests for the MLSMessage envelope wrapping (RFC 9420 §6.1).

using System.IO;
using NostrNet.Marmot.Mls.Reference.Crypto;
using NostrNet.Marmot.Mls.Reference.Wire;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference.Tests.Wire;

public class MlsMessageTests
{
    private static KeyPackage SampleKeyPackage()
    {
        Ed25519.GenerateKeyPair(out byte[] sigSk, out byte[] sigPk);
        X25519.GenerateKeyPair(out _, out byte[] encPk);
        X25519.GenerateKeyPair(out _, out byte[] initPk);

        var leaf = LeafNode.Sign(
            encryptionKey: encPk,
            signatureKey: sigPk,
            signaturePrivateKey: sigSk,
            credential: new BasicCredential(SysEncoding.UTF8.GetBytes("alice")),
            capabilities: ReferenceMlsGroup.DefaultCapabilities(),
            lifetime: new Lifetime(0UL, ulong.MaxValue),
            extensions: Array.Empty<Extension>());

        return KeyPackage.Sign(
            version: ProtocolVersion.Mls10,
            suite: Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519,
            initKey: initPk,
            leaf: leaf,
            signaturePrivateKey: sigSk);
    }

    [Fact]
    public void KeyPackage_EnvelopeRoundTrip()
    {
        var kp = SampleKeyPackage();
        byte[] mls = MlsMessage.EncodeKeyPackage(kp);

        // Envelope: uint16(version=0x0001) || uint16(wire_format=0x0005) || body.
        Assert.True(mls.Length > 4);
        Assert.Equal(0x00, mls[0]);
        Assert.Equal(0x01, mls[1]);
        Assert.Equal(0x00, mls[2]);
        Assert.Equal(0x05, mls[3]); // mls_key_package

        var decoded = MlsMessage.DecodeKeyPackage(mls);
        Assert.True(decoded.Verify());
        Assert.Equal(kp.Signature, decoded.Signature);
    }

    [Fact]
    public void PeekWireFormat_ReadsTheDiscriminator()
    {
        var kp = SampleKeyPackage();
        byte[] mls = MlsMessage.EncodeKeyPackage(kp);
        Assert.Equal(WireFormat.KeyPackage, MlsMessage.PeekWireFormat(mls));
    }

    [Fact]
    public void DecodeKeyPackage_RejectsWrongWireFormat()
    {
        // Build an envelope claiming mls_welcome (0x0003) but with key-package bytes inside.
        var kp = SampleKeyPackage();
        byte[] body = kp.Encode();
        byte[] mls = new byte[4 + body.Length];
        mls[0] = 0x00; mls[1] = 0x01;                    // version
        mls[2] = 0x00; mls[3] = (byte)WireFormat.Welcome; // wrong format
        body.CopyTo(mls, 4);

        Assert.Throws<InvalidDataException>(() => MlsMessage.DecodeKeyPackage(mls));
    }

    [Fact]
    public void DecodeKeyPackage_RejectsUnknownProtocolVersion()
    {
        var kp = SampleKeyPackage();
        byte[] body = kp.Encode();
        byte[] mls = new byte[4 + body.Length];
        mls[0] = 0x00; mls[1] = 0x02;                       // bogus version
        mls[2] = 0x00; mls[3] = (byte)WireFormat.KeyPackage;
        body.CopyTo(mls, 4);

        Assert.Throws<InvalidDataException>(() => MlsMessage.DecodeKeyPackage(mls));
    }

    [Fact]
    public async Task Welcome_EnvelopeIsRoutableViaPeekWireFormat()
    {
        // Build a complete two-member group flow so we have a real Welcome.
        using var alice = NostrNet.Keys.PrivateKey.Generate();
        using var bob = NostrNet.Keys.PrivateKey.Generate();

        var aliceProv = new ReferenceMarmotMlsProvider();
        var bobProv = new ReferenceMarmotMlsProvider();

        var bobBundle = await bobProv.BuildKeyPackageAsync(
            bob.PublicKey, 0x0001, new ushort[] { 0xF2EE }, Array.Empty<ushort>());

        byte[] groupId = new byte[32];
        new Random(1).NextBytes(groupId);
        await aliceProv.CreateGroupAsync(
            alice.PublicKey,
            new NostrNet.Marmot.GroupData.MarmotGroupDataExtension
            {
                NostrGroupId = groupId,
                AdminPubkeys = new[] { alice.PublicKey },
                Relays = Array.Empty<string>(),
            },
            0x0001);

        var add = await aliceProv.AddMembersAsync(
            groupId,
            new ReadOnlyMemory<byte>[] { bobBundle.BundleBytes });

        byte[] welcomeWire = add.Welcomes[0].WelcomeMlsMessageBytes;

        // The wire bytes peek as mls_welcome.
        Assert.Equal(WireFormat.Welcome, MlsMessage.PeekWireFormat(welcomeWire));

        // And the key-package wire bytes peek as mls_key_package.
        Assert.Equal(WireFormat.KeyPackage, MlsMessage.PeekWireFormat(bobBundle.BundleBytes));
    }
}
