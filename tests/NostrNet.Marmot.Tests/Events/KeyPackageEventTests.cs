// SPDX-License-Identifier: MIT

using NostrNet.Keys;
using NostrNet.Marmot;
using NostrNet.Marmot.Events;

namespace NostrNet.Marmot.Tests.Events;

public class KeyPackageEventTests
{
    private static byte[] FakeBundleBytes(int seed = 1)
    {
        var rng = new Random(seed);
        byte[] b = new byte[256];
        rng.NextBytes(b);
        return b;
    }

    [Fact]
    public void Build_AndParse_RoundTrip()
    {
        using var key = PrivateKey.Generate();
        byte[] bundle = FakeBundleBytes();

        var ev = KeyPackageEvent.Create("slot-12345")
            .WithBundleBytes(bundle)
            .WithCiphersuite((ushort)0x0001)
            .WithExtension(MarmotMlsExtensions.MarmotGroupData)
            .WithExtension(MarmotMlsExtensions.LastResort)
            .WithProposal(MarmotMlsProposalTypes.SelfRemove)
            .WithKeyPackageRef("a1b2c3d4e5f6")
            .WithRelays("wss://relay.example.com", "wss://nos.lol")
            .WithClient("MyMLSClient")
            .Sign(key);

        Assert.Equal(MarmotKinds.KeyPackage, ev.Kind);
        Assert.True(ev.Verify());

        var kp = KeyPackageEvent.FromEvent(ev);
        Assert.Equal("slot-12345", kp.Identifier);
        Assert.Equal(key.PublicKey, kp.Author);
        Assert.Equal(bundle, kp.KeyPackageBundleBytes);
        Assert.Equal("1.0", kp.MlsProtocolVersion);
        Assert.Equal("0x0001", kp.MlsCiphersuite);
        Assert.Equal(new[] { "0xf2ee", "0x000a" }, kp.MlsExtensions);
        Assert.Equal(new[] { "0x000a" }, kp.MlsProposals);
        Assert.Equal("a1b2c3d4e5f6", kp.KeyPackageRef);
        Assert.Equal(new[] { "wss://relay.example.com", "wss://nos.lol" }, kp.Relays);
        Assert.Equal("MyMLSClient", kp.Client);
    }

    [Fact]
    public void Sign_RejectsMissingBundle()
    {
        using var key = PrivateKey.Generate();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            KeyPackageEvent.Create("slot-1")
                .WithCiphersuite((ushort)0x0001)
                .WithRelay("wss://relay.example.com")
                .Sign(key));
        Assert.Contains("bundle bytes", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Sign_RejectsMissingCiphersuite()
    {
        using var key = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            KeyPackageEvent.Create("slot-1")
                .WithBundleBytes(FakeBundleBytes())
                .WithRelay("wss://relay.example.com")
                .Sign(key));
    }

    [Fact]
    public void Sign_RejectsMissingRelays()
    {
        using var key = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            KeyPackageEvent.Create("slot-1")
                .WithBundleBytes(FakeBundleBytes())
                .WithCiphersuite((ushort)0x0001)
                .Sign(key));
    }

    [Fact]
    public void FromEvent_RejectsWrongKind()
    {
        using var key = PrivateKey.Generate();
        var note = new NostrNet.Events.UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "not a key package",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => KeyPackageEvent.FromEvent(note));
    }

    [Fact]
    public void FromEvent_RejectsNonBase64Encoding()
    {
        using var key = PrivateKey.Generate();
        var ev = new NostrNet.Events.UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = MarmotKinds.KeyPackage,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "d", "slot" },
                new[] { "mls_protocol_version", "1.0" },
                new[] { "mls_ciphersuite", "0x0001" },
                new[] { "encoding", "hex" },   // not allowed
                new[] { "relays", "wss://relay.example.com" },
            },
            Content = "deadbeef",
        }.Sign(key);

        var ex = Assert.Throws<FormatException>(() => KeyPackageEvent.FromEvent(ev));
        Assert.Contains("base64", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ToNaddr_UsesIdentifierAndKind()
    {
        using var key = PrivateKey.Generate();
        var ev = KeyPackageEvent.Create("my-slot")
            .WithBundleBytes(FakeBundleBytes())
            .WithCiphersuite((ushort)0x0001)
            .WithRelay("wss://relay.example.com")
            .Sign(key);

        var naddr = KeyPackageEvent.FromEvent(ev).ToNaddr();
        Assert.Equal(MarmotKinds.KeyPackage, naddr.Kind);
        Assert.Equal("my-slot", naddr.Identifier);
        Assert.Equal(key.PublicKey, naddr.PubKey);
    }

    [Fact]
    public void TryFromEvent_FailsGracefully()
    {
        Assert.False(KeyPackageEvent.TryFromEvent(null, out var kp));
        Assert.Null(kp);

        using var key = PrivateKey.Generate();
        var note = new NostrNet.Events.UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "",
        }.Sign(key);

        Assert.False(KeyPackageEvent.TryFromEvent(note, out kp));
    }
}
