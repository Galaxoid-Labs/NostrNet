// SPDX-License-Identifier: MIT
//
// Tests for NIP-10 thread/reply tagging helpers.

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Threading;

namespace NostrNet.Tests.Threading;

public class ThreadingTagsTests
{
    private static EventId RandomId(int seed)
    {
        byte[] b = new byte[32];
        new Random(seed).NextBytes(b);
        return new EventId(b);
    }

    [Fact]
    public void Parse_MarkerForm_PopulatesRootReplyMention()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var rootId = RandomId(1);
        var replyId = RandomId(2);
        var mentionId = RandomId(3);

        var tags = new IReadOnlyList<string>[]
        {
            new[] { "e", rootId.ToHex(), "", "root" },
            new[] { "e", replyId.ToHex(), "wss://relay", "reply" },
            new[] { "e", mentionId.ToHex(), "", "mention" },
            new[] { "p", alice.PublicKey.ToHex() },
            new[] { "p", bob.PublicKey.ToHex() },
        };

        var info = ThreadingTags.Parse(tags);
        Assert.Equal(rootId, info.Root);
        Assert.Equal(replyId, info.Reply);
        Assert.Single(info.Mentions);
        Assert.Equal(mentionId, info.Mentions[0]);
        Assert.Equal(2, info.Participants.Count);
    }

    [Fact]
    public void Parse_MarkerForm_LonelyReplyIsPromotedToRoot()
    {
        // NIP-10: when only "reply" exists with no "root", treat as a
        // one-level thread (the reply IS the root).
        var only = RandomId(1);
        var tags = new IReadOnlyList<string>[]
        {
            new[] { "e", only.ToHex(), "", "reply" },
        };

        var info = ThreadingTags.Parse(tags);
        Assert.Equal(only, info.Root);
        Assert.Null(info.Reply);
    }

    [Fact]
    public void Parse_PositionalForm_SingleETagIsRoot()
    {
        var rootId = RandomId(1);
        var tags = new IReadOnlyList<string>[]
        {
            new[] { "e", rootId.ToHex() },
        };

        var info = ThreadingTags.Parse(tags);
        Assert.Equal(rootId, info.Root);
        Assert.Null(info.Reply);
        Assert.Empty(info.Mentions);
    }

    [Fact]
    public void Parse_PositionalForm_FirstIsRoot_LastIsReply_MiddleIsMention()
    {
        var rootId = RandomId(1);
        var mention1 = RandomId(2);
        var mention2 = RandomId(3);
        var replyId = RandomId(4);

        var tags = new IReadOnlyList<string>[]
        {
            new[] { "e", rootId.ToHex(), "" },
            new[] { "e", mention1.ToHex(), "" },
            new[] { "e", mention2.ToHex(), "" },
            new[] { "e", replyId.ToHex(), "" },
        };

        var info = ThreadingTags.Parse(tags);
        Assert.Equal(rootId, info.Root);
        Assert.Equal(replyId, info.Reply);
        Assert.Equal(new[] { mention1, mention2 }, info.Mentions);
    }

    [Fact]
    public void BuildReplyTags_ToTopLevelPost_EmitsRootMarkerOnly()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var parent = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "top-level post",
        }.Sign(alice);

        var tags = ThreadingTags.BuildReplyTags(parent, parentRelay: "wss://r.example",
            extraParticipants: new[] { bob.PublicKey });

        // root tag points at parent (since parent has no root of its own);
        // no separate "reply" tag because parent IS root.
        var eTags = tags.Where(t => t[0] == "e").ToArray();
        Assert.Single(eTags);
        Assert.Equal(parent.Id.ToHex(), eTags[0][1]);
        Assert.Equal("root", eTags[0][3]);

        // p-tags: parent author + extra. No duplicates.
        var pTagPubkeys = tags.Where(t => t[0] == "p").Select(t => t[1]).ToArray();
        Assert.Contains(alice.PublicKey.ToHex(), pTagPubkeys);
        Assert.Contains(bob.PublicKey.ToHex(), pTagPubkeys);
        Assert.Equal(2, pTagPubkeys.Length);
    }

    [Fact]
    public void BuildReplyTags_ToReplyInThread_PreservesRootAndMarksParentAsReply()
    {
        // alice posts root; bob replies; carol replies to bob.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var carol = PrivateKey.Generate();

        var root = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "alice's root",
        }.Sign(alice);

        var bobsReplyTags = ThreadingTags.BuildReplyTags(root);
        var bobsReply = new UnsignedEvent
        {
            PubKey = bob.PublicKey,
            CreatedAt = 1_700_000_001L,
            Kind = 1,
            Tags = bobsReplyTags,
            Content = "bob's reply",
        }.Sign(bob);

        // Now carol replies to bob.
        var carolReplyTags = ThreadingTags.BuildReplyTags(bobsReply);

        var rootTag = carolReplyTags.Single(t => t.Count >= 4 && t[0] == "e" && t[3] == "root");
        var replyTag = carolReplyTags.Single(t => t.Count >= 4 && t[0] == "e" && t[3] == "reply");
        Assert.Equal(root.Id.ToHex(), rootTag[1]);
        Assert.Equal(bobsReply.Id.ToHex(), replyTag[1]);

        // Participants must include alice (transitive root author) AND bob
        // (immediate parent), but not carol (the new poster).
        var pubkeys = carolReplyTags.Where(t => t[0] == "p").Select(t => t[1]).ToArray();
        Assert.Contains(alice.PublicKey.ToHex(), pubkeys);
        Assert.Contains(bob.PublicKey.ToHex(), pubkeys);
        Assert.DoesNotContain(carol.PublicKey.ToHex(), pubkeys);
    }

    [Fact]
    public void Parse_IgnoresMalformedTags()
    {
        var goodId = RandomId(1);
        var tags = new IReadOnlyList<string>[]
        {
            new[] { "e" },                                 // no value
            new[] { "e", "" },                              // empty
            new[] { "e", "not-hex" },                       // bad hex
            new[] { "p", "bad" },                           // bad pubkey
            new[] { "e", goodId.ToHex(), "", "root" },      // good
        };

        var info = ThreadingTags.Parse(tags);
        Assert.Equal(goodId, info.Root);
        Assert.Empty(info.Participants);
    }
}
