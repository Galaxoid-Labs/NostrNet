// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using NostrNet.Marmot.Mls.Reference.Crypto;
using NostrNet.Marmot.Mls.Reference.Wire;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference.Tests.Wire;

public class KeyPackageTests
{
    private static (LeafNode Leaf, byte[] InitKey, byte[] SigSk) BuildLeaf(string identity)
    {
        Ed25519.GenerateKeyPair(out byte[] sigSk, out byte[] sigPk);
        X25519.GenerateKeyPair(out _, out byte[] encPk);
        X25519.GenerateKeyPair(out _, out byte[] initPk);

        var leaf = LeafNode.Sign(
            encryptionKey: encPk,
            signatureKey: sigPk,
            signaturePrivateKey: sigSk,
            credential: new BasicCredential(SysEncoding.UTF8.GetBytes(identity)),
            capabilities: new Capabilities(
                Versions: new ushort[] { (ushort)ProtocolVersion.Mls10 },
                CipherSuites: new ushort[] { (ushort)CiphersuiteInfo.Supported },
                ExtensionTypes: Array.Empty<ushort>(),
                ProposalTypes: Array.Empty<ushort>(),
                CredentialTypes: new ushort[] { (ushort)CredentialType.Basic }),
            lifetime: new Lifetime(0UL, ulong.MaxValue),
            extensions: Array.Empty<Extension>());

        return (leaf, initPk, sigSk);
    }

    [Fact]
    public void LeafNode_Sign_AndVerify_RoundTrip()
    {
        var (leaf, _, _) = BuildLeaf("alice");
        Assert.True(leaf.VerifySignature());

        // Encoded and re-decoded leaf still verifies.
        byte[] encoded = leaf.Encode();
        var decoded = LeafNode.Decode(encoded);
        Assert.True(decoded.VerifySignature());
        Assert.Equal(leaf.Signature, decoded.Signature);
    }

    [Fact]
    public void LeafNode_TamperedSignatureFailsVerification()
    {
        var (leaf, _, _) = BuildLeaf("alice");
        byte[] badSig = (byte[])leaf.Signature.Clone();
        badSig[0] ^= 0x01;
        var tampered = leaf with { Signature = badSig };
        Assert.False(tampered.VerifySignature());
    }

    [Fact]
    public void KeyPackage_Sign_AndVerify_RoundTrip()
    {
        var (leaf, initKey, sigSk) = BuildLeaf("alice");
        var kp = KeyPackage.Sign(
            version: ProtocolVersion.Mls10,
            suite: Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519,
            initKey: initKey,
            leaf: leaf,
            signaturePrivateKey: sigSk);

        Assert.True(kp.Verify());

        byte[] encoded = kp.Encode();
        var decoded = KeyPackage.Decode(encoded);
        Assert.True(decoded.Verify());
        Assert.Equal(kp.Signature, decoded.Signature);
        Assert.Equal(leaf.Signature, decoded.Leaf.Signature);
    }

    [Fact]
    public void KeyPackage_TamperedLeafFailsVerification()
    {
        var (leaf, initKey, sigSk) = BuildLeaf("alice");
        var kp = KeyPackage.Sign(
            ProtocolVersion.Mls10,
            Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519,
            initKey,
            leaf,
            sigSk);

        byte[] badLeafSig = (byte[])kp.Leaf.Signature.Clone();
        badLeafSig[0] ^= 0x01;
        var tampered = kp with { Leaf = kp.Leaf with { Signature = badLeafSig } };
        Assert.False(tampered.Verify());
    }

    [Fact]
    public void KeyPackage_Reference_IsDeterministic()
    {
        var (leaf, initKey, sigSk) = BuildLeaf("alice");
        var kp = KeyPackage.Sign(
            ProtocolVersion.Mls10,
            Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519,
            initKey,
            leaf,
            sigSk);

        byte[] r1 = kp.ComputeReference();
        byte[] r2 = kp.ComputeReference();
        Assert.Equal(32, r1.Length);
        Assert.Equal(r1, r2);
    }

    [Fact]
    public void KeyPackage_DifferentBuilds_ProduceDifferentReferences()
    {
        var (leafA, initKeyA, sigSkA) = BuildLeaf("alice");
        var (leafB, initKeyB, sigSkB) = BuildLeaf("bob");

        var kpA = KeyPackage.Sign(ProtocolVersion.Mls10, Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519, initKeyA, leafA, sigSkA);
        var kpB = KeyPackage.Sign(ProtocolVersion.Mls10, Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519, initKeyB, leafB, sigSkB);

        Assert.NotEqual(Convert.ToHexString(kpA.ComputeReference()), Convert.ToHexString(kpB.ComputeReference()));
    }
}
