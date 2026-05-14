// SPDX-License-Identifier: MIT

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Reposts;

namespace NostrNet.Core.Tests.Reposts;

public class RepostEventTests
{
    [Fact]
    public void Builder_PicksKind6_ForKind1Original()
    {
        using var orig = PrivateKey.Generate();
        using var repostKey = PrivateKey.Generate();

        var original = BuildNote(orig, "hello, nostr");
        var repost = RepostEvent.Create(original)
            .WithRelayHint("wss://relay.example")
            .BuildAndSign(repostKey);

        Assert.True(repost.Verify());
        Assert.Equal(Nip18Kinds.Repost, repost.Kind);

        var parsed = RepostEvent.FromEvent(repost);
        Assert.Equal(Nip18Kinds.Repost, parsed.Kind);
        Assert.False(parsed.IsGeneric);
        Assert.Equal(original.Id, parsed.RepostedEventId);
        Assert.Equal("wss://relay.example", parsed.RepostedRelayUrl);
        Assert.Equal(orig.PublicKey, parsed.RepostedAuthor);
        Assert.Null(parsed.RepostedKind);
        Assert.NotNull(parsed.RepostedEvent);
        Assert.Equal(original.Id, parsed.RepostedEvent!.Id);
        Assert.Equal("hello, nostr", parsed.RepostedEvent.Content);
    }

    [Fact]
    public void Builder_PicksKind16_ForNonKind1_AndEmitsKtag()
    {
        using var orig = PrivateKey.Generate();
        using var repostKey = PrivateKey.Generate();

        // Build a custom kind 30023 (long-form article) as the "original".
        var original = new UnsignedEvent
        {
            PubKey = orig.PublicKey,
            CreatedAt = 1_700_000_000,
            Kind = 30023,
            Tags = new IReadOnlyList<string>[] { new[] { "d", "my-article" } },
            Content = "# Heading\n\nbody",
        }.Sign(orig);

        var repost = RepostEvent.Create(original)
            .WithRelayHint("wss://relay.example")
            .BuildAndSign(repostKey);

        Assert.True(repost.Verify());
        Assert.Equal(Nip18Kinds.GenericRepost, repost.Kind);

        var parsed = RepostEvent.FromEvent(repost);
        Assert.True(parsed.IsGeneric);
        Assert.Equal(30023, parsed.RepostedKind);
        Assert.Equal(orig.PublicKey, parsed.RepostedAuthor);
        Assert.NotNull(parsed.RepostedEvent);
    }

    [Fact]
    public void Builder_OmitsContent_WhenEmbedOriginalIsFalse()
    {
        using var orig = PrivateKey.Generate();
        using var repostKey = PrivateKey.Generate();

        var original = BuildNote(orig, "private payload");
        var repost = RepostEvent.Create(original)
            .EmbedOriginal(false)
            .BuildAndSign(repostKey);

        Assert.Empty(repost.Content);
        var parsed = RepostEvent.FromEvent(repost);
        Assert.Null(parsed.RepostedEvent);
        Assert.Equal(original.Id, parsed.RepostedEventId);
    }

    [Fact]
    public void FromEvent_ThrowsForNonRepostKind()
    {
        using var key = PrivateKey.Generate();
        var note = BuildNote(key, "x");
        Assert.Throws<ArgumentException>(() => RepostEvent.FromEvent(note));
    }

    [Fact]
    public void FromEvent_ThrowsWhenETagIsMissing()
    {
        using var key = PrivateKey.Generate();
        var bad = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip18Kinds.Repost,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "{}",
        }.Sign(key);
        Assert.Throws<FormatException>(() => RepostEvent.FromEvent(bad));
    }

    [Fact]
    public void TryFromEvent_ReturnsFalse_ForWrongKindOrMalformed()
    {
        using var key = PrivateKey.Generate();
        var note = BuildNote(key, "x");
        Assert.False(RepostEvent.TryFromEvent(note, out var r1));
        Assert.Null(r1);

        var bad = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip18Kinds.Repost,
            Tags = new IReadOnlyList<string>[] { new[] { "p", key.PublicKey.ToHex() } }, // no e
            Content = "{}",
        }.Sign(key);
        Assert.False(RepostEvent.TryFromEvent(bad, out var r2));
        Assert.Null(r2);
    }

    [Fact]
    public void RepostedEvent_IsNull_WhenContentIsNotEventJson()
    {
        using var key = PrivateKey.Generate();
        using var orig = PrivateKey.Generate();
        var original = BuildNote(orig, "x");

        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip18Kinds.Repost,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "e", original.Id.ToHex(), "wss://relay.example" },
                new[] { "p", orig.PublicKey.ToHex() },
            },
            Content = "not valid json{}}}",
        }.Sign(key);

        var parsed = RepostEvent.FromEvent(ev);
        Assert.Equal(original.Id, parsed.RepostedEventId);
        Assert.Null(parsed.RepostedEvent);
    }

    [Fact]
    public void QuoteTag_AllShapes()
    {
        using var author = PrivateKey.Generate();
        var id = EventId.FromHex(new string('a', 64));

        Assert.Equal(new[] { "q", id.ToHex() }, Repost.QuoteTag(id));
        Assert.Equal(
            new[] { "q", id.ToHex(), "wss://r.example" },
            Repost.QuoteTag(id, "wss://r.example"));
        Assert.Equal(
            new[] { "q", id.ToHex(), "wss://r.example", author.PublicKey.ToHex() },
            Repost.QuoteTag(id, "wss://r.example", author.PublicKey));
        Assert.Equal(
            new[] { "q", id.ToHex(), string.Empty, author.PublicKey.ToHex() },
            Repost.QuoteTag(id, relayUrl: null, author.PublicKey));
    }

    private static NostrEvent BuildNote(PrivateKey key, string content) =>
        new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = content,
        }.Sign(key);
}
