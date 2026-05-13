// SPDX-License-Identifier: MIT
//
// Tests for NIP-65 relay list metadata round-trips.

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.RelayList;

namespace NostrNet.Tests.RelayList;

public class RelayListMetadataTests
{
    [Fact]
    public void Build_AndParse_PreservesAllEntries()
    {
        using var key = PrivateKey.Generate();

        var ev = RelayListMetadata.Create()
            .AddRelay("wss://both.example.com")                 // read+write
            .AddReadRelay("wss://read.example.com")
            .AddWriteRelay("wss://write.example.com")
            .Sign(key);

        Assert.Equal(Nip65Kinds.RelayListMetadata, ev.Kind);
        Assert.Equal(string.Empty, ev.Content);
        Assert.True(ev.Verify());

        var list = RelayListMetadata.FromEvent(ev);

        Assert.Equal(key.PublicKey, list.Owner);
        Assert.Equal(3, list.Relays.Count);
        Assert.Equal(new RelayEntry("wss://both.example.com", RelayUsage.ReadAndWrite), list.Relays[0]);
        Assert.Equal(new RelayEntry("wss://read.example.com", RelayUsage.ReadOnly), list.Relays[1]);
        Assert.Equal(new RelayEntry("wss://write.example.com", RelayUsage.WriteOnly), list.Relays[2]);
    }

    [Fact]
    public void ReadRelays_IncludesReadOnlyAndReadWrite()
    {
        using var key = PrivateKey.Generate();
        var ev = RelayListMetadata.Create()
            .AddRelay("wss://both")
            .AddReadRelay("wss://reader")
            .AddWriteRelay("wss://writer")
            .Sign(key);

        var list = RelayListMetadata.FromEvent(ev);
        Assert.Equal(new[] { "wss://both", "wss://reader" }, list.ReadRelays);
    }

    [Fact]
    public void WriteRelays_IncludesWriteOnlyAndReadWrite()
    {
        using var key = PrivateKey.Generate();
        var ev = RelayListMetadata.Create()
            .AddRelay("wss://both")
            .AddReadRelay("wss://reader")
            .AddWriteRelay("wss://writer")
            .Sign(key);

        var list = RelayListMetadata.FromEvent(ev);
        Assert.Equal(new[] { "wss://both", "wss://writer" }, list.WriteRelays);
    }

    [Fact]
    public void Build_EmptyList_IsLegal()
    {
        using var key = PrivateKey.Generate();
        var ev = RelayListMetadata.Create().Sign(key);
        var list = RelayListMetadata.FromEvent(ev);

        Assert.Empty(list.Relays);
        Assert.Empty(list.ReadRelays);
        Assert.Empty(list.WriteRelays);
    }

    [Fact]
    public void FromEvent_TagsWithExtraColumns_PreserveBaseMeaning()
    {
        // Some clients add a 4th element to "r" tags (e.g. comments / notes).
        // We should still parse the URL + usage correctly.
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip65Kinds.RelayListMetadata,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "r", "wss://a", "read", "extra-info" },
                new[] { "r", "wss://b", "write", "more" },
            },
            Content = string.Empty,
        }.Sign(key);

        var list = RelayListMetadata.FromEvent(ev);
        Assert.Equal(2, list.Relays.Count);
        Assert.Equal(RelayUsage.ReadOnly, list.Relays[0].Usage);
        Assert.Equal(RelayUsage.WriteOnly, list.Relays[1].Usage);
    }

    [Fact]
    public void FromEvent_TagWithUnknownMarker_TreatedAsReadAndWrite()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip65Kinds.RelayListMetadata,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "r", "wss://a", "weird-marker" },
            },
            Content = string.Empty,
        }.Sign(key);

        var list = RelayListMetadata.FromEvent(ev);
        Assert.Single(list.Relays);
        Assert.Equal(RelayUsage.ReadAndWrite, list.Relays[0].Usage);
    }

    [Fact]
    public void FromEvent_MalformedRTag_Skipped()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip65Kinds.RelayListMetadata,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "r" },                          // no URL — skipped
                new[] { "r", "" },                      // empty URL — skipped
                new[] { "r", "wss://good.example.com" }, // kept
                new[] { "t", "hashtag" },               // wrong tag — ignored
            },
            Content = string.Empty,
        }.Sign(key);

        var list = RelayListMetadata.FromEvent(ev);
        Assert.Single(list.Relays);
        Assert.Equal("wss://good.example.com", list.Relays[0].Url);
    }

    [Fact]
    public void FromEvent_RejectsWrongKind()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = string.Empty,
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => RelayListMetadata.FromEvent(ev));
    }

    [Fact]
    public void TryFromEvent_FailsOnWrongKindOrNull()
    {
        Assert.False(RelayListMetadata.TryFromEvent(null, out var meta));
        Assert.Null(meta);

        using var key = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "not a relay list",
        }.Sign(key);

        Assert.False(RelayListMetadata.TryFromEvent(note, out meta));
        Assert.Null(meta);
    }

    [Fact]
    public void Builder_RejectsEmptyUrl()
    {
        var builder = RelayListMetadata.Create();
        Assert.Throws<ArgumentException>(() => builder.AddRelay(""));
        Assert.Throws<ArgumentException>(() => builder.AddReadRelay(""));
        Assert.Throws<ArgumentException>(() => builder.AddWriteRelay(""));
    }
}
