// SPDX-License-Identifier: MIT
//
// Tests for the Tag factory helpers and tag query extensions.

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Events;

public class TagTests
{
    private static readonly PublicKey AlicePub =
        PublicKey.FromHex("4b7fef1400aae7011f3121c1cbf63e72ae30ef250e0da169e0fd48427f3fb794");
    private static readonly PublicKey BobPub =
        PublicKey.FromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    private static readonly EventId KnownId =
        EventId.FromHex("f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb");

    [Fact]
    public void Tag_P_BuildsPubkeyTag()
    {
        var tag = Tag.P(AlicePub);
        Assert.Equal(new[] { "p", AlicePub.ToHex() }, tag);
    }

    [Fact]
    public void Tag_P_WithRelay_IncludesUrl()
    {
        var tag = Tag.P(AlicePub, "wss://relay.example.com");
        Assert.Equal(new[] { "p", AlicePub.ToHex(), "wss://relay.example.com" }, tag);
    }

    [Fact]
    public void Tag_E_WithMarker_IncludesAll()
    {
        var tag = Tag.E(KnownId, "wss://relay.example.com", "reply");
        Assert.Equal(4, tag.Count);
        Assert.Equal("reply", tag[3]);
    }

    [Fact]
    public void Tag_A_FormatsCoordinate()
    {
        var tag = Tag.A(30023, AlicePub, "my-slug");
        Assert.Equal("a", tag[0]);
        Assert.Equal($"30023:{AlicePub.ToHex()}:my-slug", tag[1]);
    }

    [Fact]
    public void TagExtensions_Named_FiltersByName()
    {
        var tags = new IReadOnlyList<string>[]
        {
            Tag.P(AlicePub),
            Tag.P(BobPub),
            Tag.T("nostr"),
            Tag.E(KnownId),
        };

        Assert.Equal(2, tags.Named("p").Count());
        Assert.Single(tags.Named("t"));
        Assert.Single(tags.Named("e"));
        Assert.Empty(tags.Named("q"));
    }

    [Fact]
    public void TagExtensions_Has_DetectsPresence()
    {
        var tags = new IReadOnlyList<string>[] { Tag.D("article-slug"), Tag.T("nostr") };
        Assert.True(tags.Has("d"));
        Assert.True(tags.Has("t"));
        Assert.False(tags.Has("e"));
    }

    [Fact]
    public void TagExtensions_FirstValue_GetsSecondElement()
    {
        var tags = new IReadOnlyList<string>[]
        {
            Tag.D("my-slug"),
            Tag.Title("My Article"),
            Tag.P(AlicePub),
        };

        Assert.Equal("my-slug", tags.FirstValue("d"));
        Assert.Equal("My Article", tags.FirstValue("title"));
        Assert.Equal(AlicePub.ToHex(), tags.FirstValue("p"));
        Assert.Null(tags.FirstValue("missing"));
    }

    [Fact]
    public void TagExtensions_AllValues_ReturnsEachSecondElement()
    {
        var tags = new IReadOnlyList<string>[]
        {
            Tag.P(AlicePub),
            Tag.P(BobPub),
            Tag.T("nostr"),
            Tag.T("bitcoin"),
        };

        Assert.Equal(new[] { AlicePub.ToHex(), BobPub.ToHex() }, tags.AllValues("p"));
        Assert.Equal(new[] { "nostr", "bitcoin" }, tags.AllValues("t"));
    }

    [Fact]
    public void TagExtensions_Pubkeys_ParsesValid_SkipsInvalid()
    {
        var tags = new IReadOnlyList<string>[]
        {
            Tag.P(AlicePub),
            new[] { "p", "not-a-pubkey" },     // skipped
            Tag.P(BobPub),
            new[] { "p" },                       // skipped — no value
        };

        var pubs = tags.Pubkeys().ToList();
        Assert.Equal(2, pubs.Count);
        Assert.Contains(AlicePub, pubs);
        Assert.Contains(BobPub, pubs);
    }

    [Fact]
    public void TagExtensions_EventIds_ParsesValidIds()
    {
        var tags = new IReadOnlyList<string>[]
        {
            Tag.E(KnownId),
            new[] { "e", "garbage" },             // skipped
        };

        var ids = tags.EventIds().ToList();
        Assert.Single(ids);
        Assert.Equal(KnownId, ids[0]);
    }

    [Fact]
    public void TagExtensions_Identifier_ReturnsDTagValue()
    {
        var tags = new IReadOnlyList<string>[] { Tag.D("slug-123"), Tag.T("nostr") };
        Assert.Equal("slug-123", tags.Identifier());

        var noD = new IReadOnlyList<string>[] { Tag.T("nostr") };
        Assert.Null(noD.Identifier());
    }
}
