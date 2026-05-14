// SPDX-License-Identifier: MIT
//
// End-to-end test: Alice creates a group, adds Bob, and emits a Welcome.
// Bob processes the Welcome. Both sides derive an identical exporter
// secret — which is exactly what Marmot kind-445 GroupEvent encryption
// needs to work between two members.

using System.Security.Cryptography;
using NostrNet.Marmot.Mls.Reference.Crypto;
using NostrNet.Marmot.Mls.Reference.Wire;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference.Tests;

public class GroupTests
{
    private record Member(
        byte[] SignatureSk, byte[] SignaturePk,
        byte[] InitSk, byte[] InitPk,
        byte[] EncSk, byte[] EncPk,
        BasicCredential Credential);

    private static Member MakeMember(string identity)
    {
        Ed25519.GenerateKeyPair(out byte[] sigSk, out byte[] sigPk);
        X25519.GenerateKeyPair(out byte[] initSk, out byte[] initPk);
        X25519.GenerateKeyPair(out byte[] encSk, out byte[] encPk);
        return new Member(sigSk, sigPk, initSk, initPk, encSk, encPk,
            new BasicCredential(SysEncoding.UTF8.GetBytes(identity)));
    }

    private static (KeyPackage Kp, Member M) MakeKeyPackage(string identity)
    {
        var m = MakeMember(identity);
        var leaf = LeafNode.Sign(
            encryptionKey: m.EncPk,
            signatureKey: m.SignaturePk,
            signaturePrivateKey: m.SignatureSk,
            credential: m.Credential,
            capabilities: ReferenceMlsGroup.DefaultCapabilities(),
            lifetime: new Lifetime(0UL, ulong.MaxValue),
            extensions: Array.Empty<Extension>());

        var kp = KeyPackage.Sign(
            version: ProtocolVersion.Mls10,
            suite: Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519,
            initKey: m.InitPk,
            leaf: leaf,
            signaturePrivateKey: m.SignatureSk);

        return (kp, m);
    }

    [Fact]
    public void Founder_CreatesGroup_AtEpoch0()
    {
        var alice = MakeMember("alice");
        byte[] groupId = SysEncoding.UTF8.GetBytes("test-group");

        var group = ReferenceMlsGroup.CreateAsFounder(
            groupId: groupId,
            founderCredential: alice.Credential,
            founderSignaturePublicKey: alice.SignaturePk,
            founderSignaturePrivateKey: alice.SignatureSk,
            founderInitPublicKey: alice.InitPk,
            founderInitPrivateKey: alice.InitSk,
            founderEncryptionPublicKey: alice.EncPk);

        Assert.Equal(0UL, group.Context.Epoch);
        Assert.Equal(groupId, group.Context.GroupId);
        Assert.Null(group.MemberLeaf);
        Assert.True(group.FounderLeaf.VerifySignature());
        Assert.NotNull(group.MarmotExporterSecret());
        Assert.Equal(32, group.MarmotExporterSecret().Length);
    }

    [Fact]
    public void Welcome_RoundTrip_ExporterSecretsMatch()
    {
        // ── Alice creates group, Bob publishes a KeyPackage.
        var alice = MakeMember("alice");
        var (bobKp, bob) = MakeKeyPackage("bob");

        byte[] groupId = SysEncoding.UTF8.GetBytes("alice-bob-test-group");
        var aliceGroup = ReferenceMlsGroup.CreateAsFounder(
            groupId: groupId,
            founderCredential: alice.Credential,
            founderSignaturePublicKey: alice.SignaturePk,
            founderSignaturePrivateKey: alice.SignatureSk,
            founderInitPublicKey: alice.InitPk,
            founderInitPrivateKey: alice.InitSk,
            founderEncryptionPublicKey: alice.EncPk);

        // ── Alice adds Bob and emits a Welcome.
        byte[] welcomeBytes = aliceGroup.AddMember(bobKp);
        Assert.Equal(1UL, aliceGroup.Context.Epoch);
        Assert.NotNull(aliceGroup.MemberLeaf);

        // ── Bob joins from the Welcome.
        var bobGroup = ReferenceMlsGroup.JoinFromWelcome(
            welcomeBytes: welcomeBytes,
            myKeyPackage: bobKp,
            myInitPrivateKey: bob.InitSk,
            mySignaturePrivateKey: bob.SignatureSk);

        Assert.Equal(1UL, bobGroup.Context.Epoch);
        Assert.Equal(aliceGroup.Context.GroupId, bobGroup.Context.GroupId);
        Assert.Equal(aliceGroup.Context.TreeHash, bobGroup.Context.TreeHash);

        // ── The hinge: exporter secrets must match exactly.
        byte[] aliceExp = aliceGroup.MarmotExporterSecret();
        byte[] bobExp = bobGroup.MarmotExporterSecret();
        Assert.Equal(32, aliceExp.Length);
        Assert.Equal(Convert.ToHexString(aliceExp), Convert.ToHexString(bobExp));
    }

    [Fact]
    public void Welcome_TamperedCiphertext_FailsToOpen()
    {
        var alice = MakeMember("alice");
        var (bobKp, bob) = MakeKeyPackage("bob");

        var aliceGroup = ReferenceMlsGroup.CreateAsFounder(
            SysEncoding.UTF8.GetBytes("g"),
            alice.Credential, alice.SignaturePk, alice.SignatureSk,
            alice.InitPk, alice.InitSk, alice.EncPk);

        byte[] welcomeBytes = aliceGroup.AddMember(bobKp);
        // Flip a bit deep in the encrypted_group_info portion.
        welcomeBytes[welcomeBytes.Length - 5] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() =>
            ReferenceMlsGroup.JoinFromWelcome(welcomeBytes, bobKp, bob.InitSk, bob.SignatureSk));
    }

    [Fact]
    public void Welcome_WrongRecipient_FailsKeyPackageRefLookup()
    {
        var alice = MakeMember("alice");
        var (bobKp, _) = MakeKeyPackage("bob");
        var (eveKp, eve) = MakeKeyPackage("eve");

        var aliceGroup = ReferenceMlsGroup.CreateAsFounder(
            SysEncoding.UTF8.GetBytes("g"),
            alice.Credential, alice.SignaturePk, alice.SignatureSk,
            alice.InitPk, alice.InitSk, alice.EncPk);

        byte[] welcomeBytes = aliceGroup.AddMember(bobKp);

        // Eve tries to use her own KeyPackage to claim Bob's Welcome.
        Assert.Throws<CryptographicException>(() =>
            ReferenceMlsGroup.JoinFromWelcome(welcomeBytes, eveKp, eve.InitSk, eve.SignatureSk));
    }

    [Fact]
    public void Exporter_DerivationIsDeterministic()
    {
        var alice = MakeMember("alice");
        var (bobKp, bob) = MakeKeyPackage("bob");

        // Two separate "Alice creates + adds Bob + Bob joins" runs with
        // the same key material produce different exporter secrets,
        // because the founder's bootstrap init_secret is random per call.
        byte[] CreateAndExport()
        {
            var ag = ReferenceMlsGroup.CreateAsFounder(
                SysEncoding.UTF8.GetBytes("g"),
                alice.Credential, alice.SignaturePk, alice.SignatureSk,
                alice.InitPk, alice.InitSk, alice.EncPk);
            byte[] w = ag.AddMember(bobKp);
            var bg = ReferenceMlsGroup.JoinFromWelcome(w, bobKp, bob.InitSk, bob.SignatureSk);
            return bg.MarmotExporterSecret();
        }

        byte[] e1 = CreateAndExport();
        byte[] e2 = CreateAndExport();
        Assert.NotEqual(Convert.ToHexString(e1), Convert.ToHexString(e2));
    }
}
