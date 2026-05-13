// SPDX-License-Identifier: MIT
//
// Tests for NIP-B0 web bookmark round-trips.

using NostrNet.Bookmarks;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Nip19;

namespace NostrNet.Tests.Bookmarks;

public class WebBookmarkTests
{
    [Fact]
    public void Build_AndParse_FullBookmark()
    {
        using var key = PrivateKey.Generate();
        var publishedAt = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        var ev = WebBookmark.Create("https://alice.blog/post-1")
            .WithTitle("Alice's marvelous post")
            .WithDescription("a marvelous insight by Alice")
            .WithPublishedAt(publishedAt)
            .WithHashtags("nostr", "bookmark")
            .Sign(key);

        Assert.Equal(NipB0Kinds.WebBookmark, ev.Kind);
        Assert.True(ev.Verify());

        var bm = WebBookmark.FromEvent(ev);
        Assert.Equal(key.PublicKey, bm.Author);
        Assert.Equal("alice.blog/post-1", bm.Url);            // scheme stripped
        Assert.Equal("a marvelous insight by Alice", bm.Description);
        Assert.Equal("Alice's marvelous post", bm.Title);
        Assert.Equal(publishedAt, bm.PublishedAt);
        Assert.Equal(new[] { "nostr", "bookmark" }, bm.Hashtags);
    }

    [Theory]
    [InlineData("https://example.com/page", "example.com/page")]
    [InlineData("http://example.com/page", "example.com/page")]
    [InlineData("HTTPS://Example.com/PAGE", "Example.com/PAGE")]   // scheme stripped, case preserved
    [InlineData("//example.com/page", "example.com/page")]
    [InlineData("example.com/page", "example.com/page")]
    [InlineData("alice.blog/post?id=1#section", "alice.blog/post?id=1#section")]
    public void NormalizeUrl_StripsCommonSchemePrefixes(string input, string expected)
    {
        using var key = PrivateKey.Generate();
        var ev = WebBookmark.Create(input).Sign(key);
        var bm = WebBookmark.FromEvent(ev);
        Assert.Equal(expected, bm.Url);
    }

    [Fact]
    public void ToUrl_AddsBackTheScheme()
    {
        using var key = PrivateKey.Generate();
        var ev = WebBookmark.Create("alice.blog/post").Sign(key);
        var bm = WebBookmark.FromEvent(ev);

        Assert.Equal("https://alice.blog/post", bm.ToUrl());
        Assert.Equal("http://alice.blog/post", bm.ToUrl("http"));
    }

    [Fact]
    public void MinimalBookmark_OnlyUrlNeeded()
    {
        using var key = PrivateKey.Generate();
        var ev = WebBookmark.Create("alice.blog/post").Sign(key);

        var bm = WebBookmark.FromEvent(ev);
        Assert.Equal("alice.blog/post", bm.Url);
        Assert.Equal(string.Empty, bm.Description);
        Assert.Null(bm.Title);
        Assert.Null(bm.PublishedAt);
        Assert.Empty(bm.Hashtags);
    }

    [Fact]
    public void ToNaddr_ProducesCorrectCoordinate()
    {
        using var key = PrivateKey.Generate();
        var ev = WebBookmark.Create("https://alice.blog/post").WithTitle("Alice").Sign(key);
        var bm = WebBookmark.FromEvent(ev);

        var naddr = bm.ToNaddr(new[] { "wss://relay.example.com" });
        Assert.Equal(NipB0Kinds.WebBookmark, naddr.Kind);
        Assert.Equal("alice.blog/post", naddr.Identifier);
        Assert.Equal(key.PublicKey, naddr.PubKey);

        // Round-trip through bech32.
        var decoded = (NaddrEntity)global::NostrNet.Nip19.Nip19.Parse(naddr.Encode());
        Assert.Equal("alice.blog/post", decoded.Identifier);
        Assert.Equal(NipB0Kinds.WebBookmark, decoded.Kind);
    }

    [Fact]
    public void FromEvent_RejectsWrongKind()
    {
        using var key = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = new[] { Tag.D("alice.blog/post") },
            Content = "not a bookmark",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => WebBookmark.FromEvent(note));
    }

    [Fact]
    public void FromEvent_RejectsMissingDTag()
    {
        using var key = PrivateKey.Generate();
        var bad = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = NipB0Kinds.WebBookmark,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "no d tag",
        }.Sign(key);

        Assert.Throws<FormatException>(() => WebBookmark.FromEvent(bad));
    }

    [Fact]
    public void TryFromEvent_FailsGracefully()
    {
        Assert.False(WebBookmark.TryFromEvent(null, out var bm));
        Assert.Null(bm);

        using var key = PrivateKey.Generate();
        var wrongKind = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "",
        }.Sign(key);

        Assert.False(WebBookmark.TryFromEvent(wrongKind, out bm));
        Assert.Null(bm);
    }

    [Fact]
    public void Builder_RejectsEmptyUrl()
    {
        Assert.Throws<ArgumentException>(() => WebBookmark.Create(""));
    }

    [Fact]
    public void Revision_SameUrlReplaces()
    {
        // NIP-33: two events with same (kind, author, d-tag) replace each other.
        using var key = PrivateKey.Generate();
        var v1 = WebBookmark.Create("https://alice.blog/post")
            .WithTitle("v1")
            .Sign(key);

        Thread.Sleep(10);

        var v2 = WebBookmark.Create("alice.blog/post")     // no scheme — same after normalize
            .WithTitle("v2 revised")
            .Sign(key);

        Assert.Equal("alice.blog/post", WebBookmark.FromEvent(v1).Url);
        Assert.Equal("alice.blog/post", WebBookmark.FromEvent(v2).Url);
        Assert.NotEqual(v1.Id, v2.Id);
    }
}
