// SPDX-License-Identifier: MIT
//
// The critical test for the OpenMLS FFI: Alice and Bob run independent
// providers, exchange a real MLS Welcome, and both sides derive an
// identical Marmot exporter secret.

using NostrNet.Keys;
using NostrNet.Marmot.GroupData;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class GroupLifecycleTests
{
    private static byte[] RandomGroupId(int seed)
    {
        byte[] g = new byte[32];
        new Random(seed).NextBytes(g);
        return g;
    }

    [Fact]
    public async Task CreateGroup_AndExporter_Available()
    {
        using var alice = new OpenMlsProvider();
        using var aliceKey = PrivateKey.Generate();
        byte[] gid = RandomGroupId(1);

        var result = await alice.CreateGroupAsync(
            aliceKey.PublicKey,
            new MarmotGroupDataExtension
            {
                NostrGroupId = gid,
                AdminPubkeys = new[] { aliceKey.PublicKey },
                Relays = Array.Empty<string>(),
            },
            ciphersuite: 0x0001);

        Assert.Equal(gid, result.NostrGroupId);
        Assert.Equal(32, result.InitialExporterSecret.Length);

        // CurrentExporterSecretAsync should match the creator's exporter.
        byte[] current = await alice.CurrentExporterSecretAsync(gid);
        Assert.Equal(result.InitialExporterSecret, current);
    }

    [Fact]
    public async Task TwoMember_AliceAndBob_DeriveMatchingExporter()
    {
        using var alice = new OpenMlsProvider();
        using var bob = new OpenMlsProvider();
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        byte[] gid = RandomGroupId(7);

        // Bob publishes a KeyPackage.
        var bobKp = await bob.BuildKeyPackageAsync(
            bobKey.PublicKey, 0x0001,
            new ushort[] { 0xF2EE }, Array.Empty<ushort>());

        // Alice creates a group.
        await alice.CreateGroupAsync(
            aliceKey.PublicKey,
            new MarmotGroupDataExtension
            {
                NostrGroupId = gid,
                AdminPubkeys = new[] { aliceKey.PublicKey },
                Relays = Array.Empty<string>(),
            },
            ciphersuite: 0x0001);

        // Alice adds Bob.
        var add = await alice.AddMembersAsync(
            gid,
            new ReadOnlyMemory<byte>[] { bobKp.BundleBytes });

        Assert.Single(add.Welcomes);
        Assert.Equal(bobKey.PublicKey, add.Welcomes[0].RecipientPubkey);
        Assert.NotEmpty(add.NewExporterSecret);

        // Bob joins from the Welcome.
        var joined = await bob.JoinGroupFromWelcomeAsync(
            add.Welcomes[0].WelcomeMlsMessageBytes);

        Assert.Equal(gid, joined.NostrGroupId);
        Assert.NotEmpty(joined.CurrentExporterSecret);

        // The hinge: both sides agree on the exporter for the new epoch.
        Assert.Equal(
            Convert.ToHexString(add.NewExporterSecret),
            Convert.ToHexString(joined.CurrentExporterSecret));

        // CurrentExporterSecretAsync confirms both sides' state matches too.
        byte[] aliceExp = await alice.CurrentExporterSecretAsync(gid);
        byte[] bobExp = await bob.CurrentExporterSecretAsync(gid);
        Assert.Equal(Convert.ToHexString(aliceExp), Convert.ToHexString(bobExp));
    }

    [Fact]
    public async Task CurrentExporter_RejectsUnknownGroupId()
    {
        using var provider = new OpenMlsProvider();
        await Assert.ThrowsAnyAsync<InvalidOperationException>(
            async () => await provider.CurrentExporterSecretAsync(RandomGroupId(42)));
    }
}
