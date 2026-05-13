// SPDX-License-Identifier: MIT
//
// Tests for NIP-23 long-form articles.

using NostrNet.Articles;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Nip19;

namespace NostrNet.Tests.Articles;

public class ArticleTests
{
    [Fact]
    public void Build_AndParse_FullArticle()
    {
        using var author = PrivateKey.Generate();
        var publishedAt = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);

        var ev = Article.Create("my-first-article", "# Hello\n\nSome **markdown** here.")
            .WithTitle("My First Article")
            .WithSummary("An introduction to my new blog")
            .WithImage("https://example.com/cover.png")
            .WithPublishedAt(publishedAt)
            .WithHashtags("intro", "blogging")
            .Sign(author);

        Assert.Equal(Nip23Kinds.LongFormArticle, ev.Kind);
        Assert.True(ev.Verify());

        var article = Article.FromEvent(ev);
        Assert.Equal(author.PublicKey, article.Author);
        Assert.Equal("my-first-article", article.Identifier);
        Assert.Equal("# Hello\n\nSome **markdown** here.", article.Markdown);
        Assert.Equal("My First Article", article.Title);
        Assert.Equal("An introduction to my new blog", article.Summary);
        Assert.Equal("https://example.com/cover.png", article.Image);
        Assert.Equal(publishedAt, article.PublishedAt);
        Assert.Equal(new[] { "intro", "blogging" }, article.Hashtags);
        Assert.False(article.IsDraft);
    }

    [Fact]
    public void Build_Draft_UsesKind30024()
    {
        using var author = PrivateKey.Generate();
        var ev = Article.Create("wip", "draft body").AsDraft().Sign(author);

        Assert.Equal(Nip23Kinds.LongFormDraft, ev.Kind);
        var article = Article.FromEvent(ev);
        Assert.True(article.IsDraft);
    }

    [Fact]
    public void Build_MinimalArticle_OnlyDTagAndMarkdown()
    {
        using var author = PrivateKey.Generate();
        var ev = Article.Create("bare", "just text").Sign(author);

        var article = Article.FromEvent(ev);
        Assert.Equal("bare", article.Identifier);
        Assert.Equal("just text", article.Markdown);
        Assert.Null(article.Title);
        Assert.Null(article.Summary);
        Assert.Null(article.Image);
        Assert.Null(article.PublishedAt);
        Assert.Empty(article.Hashtags);
    }

    [Fact]
    public void ToNaddr_ProducesCorrectCoordinate()
    {
        using var author = PrivateKey.Generate();
        var ev = Article.Create("my-slug", "body")
            .WithTitle("T")
            .Sign(author);

        var article = Article.FromEvent(ev);
        var naddr = article.ToNaddr(new[] { "wss://relay.example.com" });

        Assert.Equal(Nip23Kinds.LongFormArticle, naddr.Kind);
        Assert.Equal("my-slug", naddr.Identifier);
        Assert.Equal(author.PublicKey, naddr.PubKey);
        Assert.Single(naddr.Relays);

        // Round-trip through bech32.
        string encoded = naddr.Encode();
        var decoded = (NaddrEntity)global::NostrNet.Nip19.Nip19.Parse(encoded);
        Assert.Equal("my-slug", decoded.Identifier);
        Assert.Equal(author.PublicKey, decoded.PubKey);
        Assert.Equal(Nip23Kinds.LongFormArticle, decoded.Kind);
    }

    [Fact]
    public void ToNaddr_FromDraft_UsesDraftKind()
    {
        using var author = PrivateKey.Generate();
        var article = Article.FromEvent(Article.Create("wip", "x").AsDraft().Sign(author));
        Assert.Equal(Nip23Kinds.LongFormDraft, article.ToNaddr().Kind);
    }

    [Fact]
    public void FromEvent_RejectsWrongKind()
    {
        using var author = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = author.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = new[] { Tag.D("slug") },
            Content = "not an article",
        }.Sign(author);

        Assert.Throws<ArgumentException>(() => Article.FromEvent(note));
    }

    [Fact]
    public void FromEvent_RejectsMissingDTag()
    {
        using var author = PrivateKey.Generate();
        var bad = new UnsignedEvent
        {
            PubKey = author.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip23Kinds.LongFormArticle,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "no d tag",
        }.Sign(author);

        Assert.Throws<FormatException>(() => Article.FromEvent(bad));
    }

    [Fact]
    public void TryFromEvent_FailsGracefully()
    {
        Assert.False(Article.TryFromEvent(null, out var a));
        Assert.Null(a);

        using var author = PrivateKey.Generate();
        var wrongKind = new UnsignedEvent
        {
            PubKey = author.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "",
        }.Sign(author);

        Assert.False(Article.TryFromEvent(wrongKind, out a));
        Assert.Null(a);
    }

    [Fact]
    public void Builder_RejectsEmptyIdentifier()
    {
        Assert.Throws<ArgumentException>(() => Article.Create("", "body"));
    }

    [Fact]
    public void PublishedAt_FallsBackToNull_WhenTagMissing()
    {
        using var author = PrivateKey.Generate();
        var ev = Article.Create("slug", "body").Sign(author);
        var article = Article.FromEvent(ev);

        Assert.Null(article.PublishedAt);
        // Caller decides: typically fall back to CreatedAt.
        Assert.True(article.CreatedAt > DateTimeOffset.UnixEpoch);
    }

    [Fact]
    public void Revision_SameIdentifier_ReplacesPreviousEvent()
    {
        // Demonstrates the NIP-33 contract: two events with the same (kind,
        // author, d-tag) replace each other. The library doesn't enforce this
        // — relays do — but we verify the events have matching identifiers.
        using var author = PrivateKey.Generate();
        var v1 = Article.Create("evergreen", "version 1").WithTitle("Title").Sign(author);
        Thread.Sleep(10);
        var v2 = Article.Create("evergreen", "version 2").WithTitle("Title (revised)").Sign(author);

        Assert.Equal("evergreen", Article.FromEvent(v1).Identifier);
        Assert.Equal("evergreen", Article.FromEvent(v2).Identifier);
        Assert.NotEqual(v1.Id, v2.Id);   // different event ids (timestamps differ)
    }
}
