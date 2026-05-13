// SPDX-License-Identifier: MIT
//
// Round-trip tests for NIP-51 list events.

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Lists;

namespace NostrNet.Tests.Lists;

public class NostrListTests
{
    [Fact]
    public void MuteList_RoundTrip_PublicItems()
    {
        using var owner = PrivateKey.Generate();
        var spammer = PrivateKey.Generate().PublicKey;
        var droppedEvent = EventId.FromHex("f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb");

        var ev = NostrList.Create(Nip51Kinds.MuteList)
            .AddPubkey(spammer)
            .AddHashtag("spam")
            .AddWord("scam")
            .AddEvent(droppedEvent)
            .Sign(owner);

        Assert.Equal(Nip51Kinds.MuteList, ev.Kind);
        Assert.True(ev.Verify());

        // Parse back without owner key — public items still visible.
        var list = NostrList.FromEvent(ev);
        Assert.Equal(owner.PublicKey, list.Owner);
        Assert.Contains(spammer, list.Pubkeys);
        Assert.Contains("spam", list.Hashtags);
        Assert.Contains("scam", list.Words);
        Assert.Contains(droppedEvent, list.EventIds);
        Assert.False(list.HasEncryptedContent);
    }

    [Fact]
    public void MuteList_RoundTrip_PrivateItemsEncryptedAndDecryptable()
    {
        using var owner = PrivateKey.Generate();
        var publicTarget = PrivateKey.Generate().PublicKey;
        var privateTarget = PrivateKey.Generate().PublicKey;

        var ev = NostrList.Create(Nip51Kinds.MuteList)
            .AddPubkey(publicTarget)
            .AddPrivatePubkey(privateTarget)
            .AddPrivateWord("secret-keyword")
            .Sign(owner);

        // Content field carries encrypted JSON.
        Assert.NotEqual(string.Empty, ev.Content);

        // Without owner key: public visible, private inaccessible.
        var anonymous = NostrList.FromEvent(ev);
        Assert.True(anonymous.HasEncryptedContent);
        Assert.Contains(publicTarget, anonymous.Pubkeys);
        Assert.DoesNotContain(privateTarget, anonymous.Pubkeys);
        Assert.Empty(anonymous.PrivateItems);

        // With owner key: both halves visible.
        var owned = NostrList.FromEvent(ev, owner);
        Assert.Contains(publicTarget, owned.Pubkeys);
        Assert.Contains(privateTarget, owned.Pubkeys);
        Assert.Contains("secret-keyword", owned.Words);
        Assert.Equal(2, owned.PrivateItems.Count);
    }

    [Fact]
    public void FollowSet_RequiresIdentifier_AndPreservesMetadata()
    {
        using var owner = PrivateKey.Generate();
        var friend = PrivateKey.Generate().PublicKey;

        // Missing identifier is rejected for parameterized-set kinds.
        Assert.Throws<ArgumentException>(() => NostrList.Create(Nip51Kinds.FollowSets));

        var ev = NostrList.Create(Nip51Kinds.FollowSets, identifier: "close-friends")
            .WithTitle("Close Friends")
            .WithDescription("people I actually talk to")
            .WithImage("https://example.com/friends.png")
            .AddPubkey(friend)
            .Sign(owner);

        var list = NostrList.FromEvent(ev);
        Assert.Equal("close-friends", list.Identifier);
        Assert.Equal("Close Friends", list.Title);
        Assert.Equal("people I actually talk to", list.Description);
        Assert.Equal("https://example.com/friends.png", list.Image);
        Assert.Contains(friend, list.Pubkeys);
    }

    [Fact]
    public void Bookmarks_StoresEventAndAddressableReferences()
    {
        using var owner = PrivateKey.Generate();
        var noteId = EventId.FromHex("f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb");
        var articleAuthor = PrivateKey.Generate().PublicKey;

        var ev = NostrList.Create(Nip51Kinds.Bookmarks)
            .AddEvent(noteId)
            .AddAddress(30023, articleAuthor, "my-article")
            .Sign(owner);

        var list = NostrList.FromEvent(ev);
        Assert.Contains(noteId, list.EventIds);
        Assert.Contains($"30023:{articleAuthor.ToHex()}:my-article", list.AddressableCoordinates);
    }

    [Fact]
    public void FromEvent_RejectsWrongOwnerKey()
    {
        using var owner = PrivateKey.Generate();
        using var imposter = PrivateKey.Generate();

        var ev = NostrList.Create(Nip51Kinds.MuteList)
            .AddPrivatePubkey(PrivateKey.Generate().PublicKey)
            .Sign(owner);

        Assert.Throws<ArgumentException>(() => NostrList.FromEvent(ev, imposter));
    }

    [Fact]
    public void FromEvent_UndecryptableContent_LeavesPrivateEmpty_PublicWorks()
    {
        using var owner = PrivateKey.Generate();

        // Synthesize an event with a content field that isn't valid NIP-44
        // (simulating either NIP-04 legacy encryption or garbled data).
        var ev = new UnsignedEvent
        {
            PubKey = owner.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip51Kinds.MuteList,
            Tags = new[] { Tag.T("publictag") },
            Content = "not-a-nip44-payload",
        }.Sign(owner);

        var list = NostrList.FromEvent(ev, owner);
        Assert.Contains("publictag", list.Hashtags);
        Assert.Empty(list.PrivateItems);
        Assert.True(list.HasEncryptedContent);   // content was non-empty
    }

    [Fact]
    public void IsParameterizedSet_Detection()
    {
        Assert.True(Nip51Kinds.IsParameterizedSet(Nip51Kinds.FollowSets));
        Assert.True(Nip51Kinds.IsParameterizedSet(30007));
        Assert.False(Nip51Kinds.IsParameterizedSet(Nip51Kinds.MuteList));
        Assert.False(Nip51Kinds.IsParameterizedSet(1));
    }
}
