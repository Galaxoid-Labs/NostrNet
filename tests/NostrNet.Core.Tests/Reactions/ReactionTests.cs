// SPDX-License-Identifier: MIT
//
// Tests for NIP-25 reaction round-trips and content classification.

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Reactions;

namespace NostrNet.Tests.Reactions;

public class ReactionTests
{
    private static NostrEvent NoteFrom(PrivateKey author, int kind = 1, string? dTag = null)
    {
        IReadOnlyList<string>[] tags = dTag is null
            ? Array.Empty<IReadOnlyList<string>>()
            : new IReadOnlyList<string>[] { new[] { "d", dTag } };

        return new UnsignedEvent
        {
            PubKey = author.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = kind,
            Tags = tags,
            Content = "hi",
        }.Sign(author);
    }

    [Fact]
    public void Like_RoundTrip_DefaultsToPlus()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var target = NoteFrom(alice);

        var ev = Reaction.Create().To(target).AsLike().Sign(bob);
        Assert.Equal(Nip25Kinds.Reaction, ev.Kind);
        Assert.True(ev.Verify());
        Assert.Equal("+", ev.Content);

        var r = Reaction.FromEvent(ev);
        Assert.Equal(ReactionKind.Like, r.Kind);
        Assert.Equal(target.Id, r.TargetId);
        Assert.Equal(alice.PublicKey, r.TargetAuthor);
        Assert.Equal(1, r.TargetKind);
    }

    [Fact]
    public void Dislike_ParsesCorrectly()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var ev = Reaction.Create().To(NoteFrom(alice)).AsDislike().Sign(bob);
        var r = Reaction.FromEvent(ev);
        Assert.Equal(ReactionKind.Dislike, r.Kind);
        Assert.Equal("-", r.Content);
    }

    [Fact]
    public void EmptyContent_IsLike()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var target = NoteFrom(alice);
        var ev = Reaction.Create().To(target).WithContent("").Sign(bob);
        Assert.Equal(ReactionKind.Like, Reaction.FromEvent(ev).Kind);
    }

    [Fact]
    public void UnicodeEmoji_IsEmojiKind()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var ev = Reaction.Create().To(NoteFrom(alice)).WithEmoji("🤙").Sign(bob);
        var r = Reaction.FromEvent(ev);
        Assert.Equal(ReactionKind.Emoji, r.Kind);
        Assert.Equal("🤙", r.Content);
        Assert.Null(r.CustomEmoji);
    }

    [Fact]
    public void CustomEmoji_RequiresMatchingEmojiTag()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var ev = Reaction.Create()
            .To(NoteFrom(alice))
            .WithCustomEmoji("partyparrot", "https://emoji.example/partyparrot.gif")
            .Sign(bob);

        Assert.Equal(":partyparrot:", ev.Content);
        var r = Reaction.FromEvent(ev);
        Assert.Equal(ReactionKind.CustomEmoji, r.Kind);
        Assert.NotNull(r.CustomEmoji);
        Assert.Equal("partyparrot", r.CustomEmoji.Shortcode);
        Assert.Equal("https://emoji.example/partyparrot.gif", r.CustomEmoji.ImageUrl);
    }

    [Fact]
    public void CustomEmoji_WithoutMatchingTag_FallsThroughToEmojiKind()
    {
        // Forge a reaction with `:foo:` content but no matching emoji tag.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var target = NoteFrom(alice);

        var ev = new UnsignedEvent
        {
            PubKey = bob.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip25Kinds.Reaction,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "e", target.Id.ToHex() },
                new[] { "p", alice.PublicKey.ToHex() },
            },
            Content = ":foo:",
        }.Sign(bob);

        var r = Reaction.FromEvent(ev);
        Assert.Equal(ReactionKind.Emoji, r.Kind);
    }

    [Fact]
    public void LastETag_AndPTag_AreUsedAsTarget()
    {
        // NIP-25 spec: the LAST e- and p- tags are the target. Earlier
        // tags can carry the thread context.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var carol = PrivateKey.Generate();
        var thread = NoteFrom(alice);
        var direct = NoteFrom(carol);

        var ev = new UnsignedEvent
        {
            PubKey = bob.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip25Kinds.Reaction,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "e", thread.Id.ToHex(), "", "root" },     // thread context
                new[] { "p", alice.PublicKey.ToHex() },             // thread author
                new[] { "e", direct.Id.ToHex() },                   // actual target
                new[] { "p", carol.PublicKey.ToHex() },             // actual target author
            },
            Content = "+",
        }.Sign(bob);

        var r = Reaction.FromEvent(ev);
        Assert.Equal(direct.Id, r.TargetId);
        Assert.Equal(carol.PublicKey, r.TargetAuthor);
    }

    [Fact]
    public void AddressableTarget_RoundTrips()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var article = NoteFrom(alice, kind: 30023, dTag: "my-article");

        var ev = Reaction.Create()
            .To(article)
            .ToAddressable(30023, alice.PublicKey, "my-article")
            .AsLike()
            .Sign(bob);

        var r = Reaction.FromEvent(ev);
        Assert.NotNull(r.AddressableTarget);
        Assert.Equal(30023, r.AddressableTarget.Kind);
        Assert.Equal(alice.PublicKey, r.AddressableTarget.Author);
        Assert.Equal("my-article", r.AddressableTarget.Identifier);
    }

    [Fact]
    public void Sign_RejectsMissingTarget()
    {
        using var bob = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() => Reaction.Create().AsLike().Sign(bob));
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
            Content = "+",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => Reaction.FromEvent(ev));
        Assert.False(Reaction.TryFromEvent(ev, out _));
    }

    [Fact]
    public void FromEvent_RejectsMissingETag()
    {
        // Crafted as kind 7 but with no e-tag.
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip25Kinds.Reaction,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "p", key.PublicKey.ToHex() },
            },
            Content = "+",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => Reaction.FromEvent(ev));
        Assert.False(Reaction.TryFromEvent(ev, out _));
    }
}
