// SPDX-License-Identifier: MIT
//
// Round-trip tests for NIP-22 comments.

using NostrNet.Comments;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Comments;

public class CommentTests
{
    [Fact]
    public void TopLevelOnEvent_BuildAndParse()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        // Alice publishes an article (kind 30023).
        var article = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 30023,
            Tags = new[] { Tag.D("slug") },
            Content = "post body",
        }.Sign(alice);

        // Bob comments on it.
        var comment = Comment.ReplyTo(article)
            .WithContent("nice post!")
            .Sign(bob);

        Assert.Equal(Nip22Kinds.Comment, comment.Kind);
        Assert.True(comment.Verify());

        var parsed = Comment.FromEvent(comment);
        Assert.Equal(bob.PublicKey, parsed.Author);
        Assert.Equal("nice post!", parsed.Content);
        Assert.True(parsed.IsTopLevel);

        // For a top-level comment, root == parent.
        var rootEvent = Assert.IsType<EventCommentTarget>(parsed.Root);
        Assert.Equal(article.Id, rootEvent.Id);
        Assert.Equal(30023, rootEvent.Kind);
        Assert.Equal(alice.PublicKey, rootEvent.Author);
        Assert.Equal(parsed.Root, parsed.Parent);
    }

    [Fact]
    public void NestedReply_InheritsRootFromParentComment()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var carol = PrivateKey.Generate();

        // Alice posts an article.
        var article = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 30023,
            Tags = new[] { Tag.D("slug") },
            Content = "post body",
        }.Sign(alice);

        // Bob comments (top-level).
        var bobComment = Comment.ReplyTo(article).WithContent("first!").Sign(bob);

        // Carol replies to Bob's comment.
        var carolReply = Comment.ReplyTo(bobComment).WithContent("agreed").Sign(carol);

        var parsed = Comment.FromEvent(carolReply);
        Assert.False(parsed.IsTopLevel);

        // Root points back to Alice's article.
        var root = Assert.IsType<EventCommentTarget>(parsed.Root);
        Assert.Equal(article.Id, root.Id);
        Assert.Equal(alice.PublicKey, root.Author);

        // Parent points to Bob's comment.
        var parent = Assert.IsType<EventCommentTarget>(parsed.Parent);
        Assert.Equal(bobComment.Id, parent.Id);
        Assert.Equal(bob.PublicKey, parent.Author);
        Assert.Equal(Nip22Kinds.Comment, parent.Kind);
    }

    [Fact]
    public void TopLevelOnAddressable_RoundTrips()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var comment = Comment.Create()
            .OnAddressable(kind: 30023, author: alice.PublicKey, identifier: "my-article")
            .WithContent("great article")
            .Sign(bob);

        var parsed = Comment.FromEvent(comment);
        Assert.True(parsed.IsTopLevel);

        var root = Assert.IsType<AddressableCommentTarget>(parsed.Root);
        Assert.Equal(30023, root.Kind);
        Assert.Equal(alice.PublicKey, root.Author);
        Assert.Equal("my-article", root.Identifier);
        Assert.Equal($"30023:{alice.PublicKey.ToHex()}:my-article", root.ToCoordinate());
    }

    [Fact]
    public void TopLevelOnExternal_RoundTrips()
    {
        using var bob = PrivateKey.Generate();

        var comment = Comment.Create()
            .OnExternal("https://example.com/article", kind: "url")
            .WithContent("commenting on a URL")
            .Sign(bob);

        var parsed = Comment.FromEvent(comment);
        Assert.True(parsed.IsTopLevel);

        var root = Assert.IsType<ExternalCommentTarget>(parsed.Root);
        Assert.Equal("https://example.com/article", root.Identifier);
        Assert.Equal("url", root.Kind);
    }

    [Fact]
    public void MentionsAndQuotes_RoundTrip()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var carol = PrivateKey.Generate();
        using var dave = PrivateKey.Generate();

        var article = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 30023,
            Tags = new[] { Tag.D("slug") },
            Content = "body",
        }.Sign(alice);

        var someEventId = EventId.FromHex("f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb");

        var comment = Comment.ReplyTo(article)
            .WithContent("hey @carol see this")
            .Mention(carol.PublicKey)
            .Mention(dave.PublicKey)
            .Quote(someEventId)
            .Sign(bob);

        var parsed = Comment.FromEvent(comment);

        // Parent author (alice) should NOT be in Mentions
        Assert.DoesNotContain(alice.PublicKey, parsed.Mentions);

        // Carol and Dave should be
        Assert.Contains(carol.PublicKey, parsed.Mentions);
        Assert.Contains(dave.PublicKey, parsed.Mentions);

        Assert.Single(parsed.Quotes);
        Assert.Equal(someEventId, parsed.Quotes[0]);
    }

    [Fact]
    public void ReplyTo_RejectsKind1Notes()
    {
        using var alice = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "a regular note",
        }.Sign(alice);

        Assert.Throws<ArgumentException>(() => Comment.ReplyTo(note));
    }

    [Fact]
    public void FromEvent_RejectsWrongKind()
    {
        using var alice = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "not a comment",
        }.Sign(alice);

        Assert.Throws<ArgumentException>(() => Comment.FromEvent(note));
    }

    [Fact]
    public void FromEvent_RejectsMissingRootTags()
    {
        using var alice = PrivateKey.Generate();
        var bad = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip22Kinds.Comment,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "no root tags",
        }.Sign(alice);

        Assert.Throws<FormatException>(() => Comment.FromEvent(bad));
    }

    [Fact]
    public void TryFromEvent_FailsGracefully()
    {
        Assert.False(Comment.TryFromEvent(null, out var c));
        Assert.Null(c);

        using var alice = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "",
        }.Sign(alice);

        Assert.False(Comment.TryFromEvent(note, out c));
        Assert.Null(c);
    }

    [Fact]
    public void Sign_BeforeSettingTarget_Throws()
    {
        using var alice = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            Comment.Create().WithContent("orphan").Sign(alice));
    }

    [Fact]
    public void WireShape_UsesUppercaseAndLowercaseTags()
    {
        // Lower-level check: confirm we emit both tag-case variants per spec.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var carol = PrivateKey.Generate();

        var article = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 30023,
            Tags = new[] { Tag.D("slug") },
            Content = "body",
        }.Sign(alice);

        var bobComment = Comment.ReplyTo(article).WithContent("top").Sign(bob);
        var carolReply = Comment.ReplyTo(bobComment).WithContent("nested").Sign(carol);

        // Root scope uses uppercase E/K/P pointing at alice's article.
        Assert.Equal(article.Id.ToHex(), carolReply.Tags.FirstValue("E"));
        Assert.Equal("30023", carolReply.Tags.FirstValue("K"));
        Assert.Equal(alice.PublicKey.ToHex(), carolReply.Tags.FirstValue("P"));

        // Parent scope uses lowercase e/k/p pointing at bob's comment.
        Assert.Equal(bobComment.Id.ToHex(), carolReply.Tags.FirstValue("e"));
        Assert.Equal("1111", carolReply.Tags.FirstValue("k"));
        Assert.Equal(bob.PublicKey.ToHex(), carolReply.Tags.FirstValue("p"));
    }
}
