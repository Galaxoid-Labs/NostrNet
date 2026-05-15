// SPDX-License-Identifier: MIT

using NostrNet.Badges;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Core.Tests.Badges;

public class BadgeTests
{
    // ──────────────────────────────────────────────────────────────
    // BadgeDefinition (kind 30009)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void Definition_Builder_RoundTripsAllFields()
    {
        using var issuer = PrivateKey.Generate();
        var ev = BadgeDefinition.Create("bravery")
            .WithName("Medal of Bravery")
            .WithDescription("Awarded to users demonstrating bravery.")
            .WithImage("https://example.com/bravery.png", "1024x1024")
            .AddThumbnail("https://example.com/bravery_256.png", "256x256")
            .AddThumbnail("https://example.com/bravery_64.png", "64x64")
            .BuildAndSign(issuer);

        Assert.True(ev.Verify());
        Assert.Equal(Nip58Kinds.BadgeDefinition, ev.Kind);
        Assert.Empty(ev.Content);

        var def = BadgeDefinition.FromEvent(ev);
        Assert.Equal("bravery", def.Identifier);
        Assert.Equal("Medal of Bravery", def.Name);
        Assert.Equal("Awarded to users demonstrating bravery.", def.Description);
        Assert.Equal("https://example.com/bravery.png", def.Image!.Url);
        Assert.Equal("1024x1024", def.Image.Dim);
        Assert.Equal(2, def.Thumbnails.Count);
        Assert.Equal("256x256", def.Thumbnails[0].Dim);
    }

    [Fact]
    public void Definition_FromEvent_ThrowsForWrongKindOrMissingD()
    {
        using var k = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = k.PublicKey,
            CreatedAt = 1,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "x",
        }.Sign(k);
        Assert.Throws<ArgumentException>(() => BadgeDefinition.FromEvent(note));

        var noD = new UnsignedEvent
        {
            PubKey = k.PublicKey,
            CreatedAt = 1,
            Kind = Nip58Kinds.BadgeDefinition,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "",
        }.Sign(k);
        Assert.Throws<FormatException>(() => BadgeDefinition.FromEvent(noD));
    }

    [Fact]
    public void Definition_AddressString_MatchesNip58Format()
    {
        using var issuer = PrivateKey.Generate();
        var ev = BadgeDefinition.Create("honor").BuildAndSign(issuer);
        var def = BadgeDefinition.FromEvent(ev);
        Assert.Equal($"30009:{issuer.PublicKey.ToHex()}:honor", def.AddressString);
        Assert.Equal(def.AddressString, BadgeDefinition.Address(issuer.PublicKey, "honor"));
    }

    [Fact]
    public void Definition_ToNaddr_UsesIdentifierAsNaddrIdentifier()
    {
        using var issuer = PrivateKey.Generate();
        var def = BadgeDefinition.FromEvent(
            BadgeDefinition.Create("bravery").BuildAndSign(issuer));
        var naddr = def.ToNaddr(new[] { "wss://relay.example" });
        Assert.Equal(Nip58Kinds.BadgeDefinition, naddr.Kind);
        Assert.Equal("bravery", naddr.Identifier);
        Assert.Equal(issuer.PublicKey, naddr.PubKey);
    }

    // ──────────────────────────────────────────────────────────────
    // BadgeAward (kind 8)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void Award_Builder_RoundTripsRecipientsAndAddress()
    {
        using var issuer = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var charlie = PrivateKey.Generate();

        var def = BadgeDefinition.Create("bravery").BuildAndSign(issuer);
        var awardEvent = BadgeAward.Create(BadgeDefinition.FromEvent(def))
            .ToRecipient(bob.PublicKey, "wss://relay.example")
            .ToRecipient(charlie.PublicKey)
            .BuildAndSign(issuer);

        Assert.True(awardEvent.Verify());
        Assert.Equal(Nip58Kinds.BadgeAward, awardEvent.Kind);

        var award = BadgeAward.FromEvent(awardEvent);
        Assert.Equal(issuer.PublicKey, award.Issuer);
        Assert.Equal($"30009:{issuer.PublicKey.ToHex()}:bravery", award.BadgeAddress);
        Assert.Equal(2, award.Recipients.Count);
        Assert.Equal(bob.PublicKey, award.Recipients[0].Pubkey);
        Assert.Equal("wss://relay.example", award.Recipients[0].RecommendedRelay);
        Assert.Equal(charlie.PublicKey, award.Recipients[1].Pubkey);
        Assert.Null(award.Recipients[1].RecommendedRelay);
    }

    [Fact]
    public void Award_Builder_RequiresAtLeastOneRecipient()
    {
        using var issuer = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            BadgeAward.Create($"30009:{issuer.PublicKey.ToHex()}:x").BuildAndSign(issuer));
    }

    [Fact]
    public void Award_Builder_RejectsMalformedAddress()
    {
        Assert.Throws<ArgumentException>(() => BadgeAward.Create("not-an-address"));
        Assert.Throws<ArgumentException>(() => BadgeAward.Create("8:abc:foo")); // wrong kind
    }

    [Fact]
    public void Award_FromEvent_ThrowsForMissingTags()
    {
        using var issuer = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        // No `a` tag.
        var noA = new UnsignedEvent
        {
            PubKey = issuer.PublicKey,
            CreatedAt = 1,
            Kind = Nip58Kinds.BadgeAward,
            Tags = new IReadOnlyList<string>[] { Tag.P(bob.PublicKey) },
            Content = "",
        }.Sign(issuer);
        Assert.Throws<FormatException>(() => BadgeAward.FromEvent(noA));

        // No recipient.
        var noP = new UnsignedEvent
        {
            PubKey = issuer.PublicKey,
            CreatedAt = 1,
            Kind = Nip58Kinds.BadgeAward,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "a", $"30009:{issuer.PublicKey.ToHex()}:foo" },
            },
            Content = "",
        }.Sign(issuer);
        Assert.Throws<FormatException>(() => BadgeAward.FromEvent(noP));
    }

    // ──────────────────────────────────────────────────────────────
    // ProfileBadges (kind 30008)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void Profile_Builder_RoundTripsPairsInOrder()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var awardBravery = BadgeAward.FromEvent(
            BadgeAward.Create($"30009:{alice.PublicKey.ToHex()}:bravery")
                .ToRecipient(bob.PublicKey)
                .BuildAndSign(alice));
        var awardHonor = BadgeAward.FromEvent(
            BadgeAward.Create($"30009:{alice.PublicKey.ToHex()}:honor")
                .ToRecipient(bob.PublicKey)
                .BuildAndSign(alice));

        var profileEvent = ProfileBadges.Create()
            .Add(awardBravery, "wss://nostr.academy")
            .Add(awardHonor)
            .BuildAndSign(bob);

        Assert.True(profileEvent.Verify());
        Assert.Equal(Nip58Kinds.ProfileBadges, profileEvent.Kind);

        var profile = ProfileBadges.FromEvent(profileEvent);
        Assert.Equal(bob.PublicKey, profile.Owner);
        Assert.Equal(2, profile.Entries.Count);
        Assert.Equal(awardBravery.BadgeAddress, profile.Entries[0].BadgeAddress);
        Assert.Equal(awardBravery.Id, profile.Entries[0].AwardEventId);
        Assert.Equal("wss://nostr.academy", profile.Entries[0].RecommendedRelay);
        Assert.Equal(awardHonor.BadgeAddress, profile.Entries[1].BadgeAddress);
        Assert.Null(profile.Entries[1].RecommendedRelay);
    }

    [Fact]
    public void Profile_OrphanedTags_AreDropped()
    {
        // NIP-58: an `a` tag without a matching `e` tag (or vice
        // versa) should be ignored. We construct the event by hand
        // to test the dropper.
        using var owner = PrivateKey.Generate();
        using var issuer = PrivateKey.Generate();
        var validAddress = $"30009:{issuer.PublicKey.ToHex()}:bravery";
        var awardId = EventId.FromHex(new string('a', 64));

        var ev = new UnsignedEvent
        {
            PubKey = owner.PublicKey,
            CreatedAt = 1,
            Kind = Nip58Kinds.ProfileBadges,
            Tags = new IReadOnlyList<string>[]
            {
                Tag.D(Nip58Kinds.ProfileBadgesIdentifier),
                new[] { "a", validAddress },             // orphan: no following e
                new[] { "a", validAddress },             // new pair start
                new[] { "e", awardId.ToHex() },          // pairs with the second `a`
                new[] { "e", new string('b', 64) },      // orphan: no preceding a
            },
            Content = "",
        }.Sign(owner);

        var profile = ProfileBadges.FromEvent(ev);
        Assert.Single(profile.Entries);
        Assert.Equal(validAddress, profile.Entries[0].BadgeAddress);
        Assert.Equal(awardId, profile.Entries[0].AwardEventId);
    }

    [Fact]
    public void Profile_FromEvent_ThrowsWhenDTagIsWrong()
    {
        using var owner = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = owner.PublicKey,
            CreatedAt = 1,
            Kind = Nip58Kinds.ProfileBadges,
            Tags = new IReadOnlyList<string>[] { Tag.D("not_profile_badges") },
            Content = "",
        }.Sign(owner);

        Assert.Throws<FormatException>(() => ProfileBadges.FromEvent(ev));
    }

    [Fact]
    public void Profile_ToBuilderRemove_ProducesEventWithoutThatBadge()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var award1 = BadgeAward.FromEvent(
            BadgeAward.Create($"30009:{alice.PublicKey.ToHex()}:a1")
                .ToRecipient(bob.PublicKey).BuildAndSign(alice));
        var award2 = BadgeAward.FromEvent(
            BadgeAward.Create($"30009:{alice.PublicKey.ToHex()}:a2")
                .ToRecipient(bob.PublicKey).BuildAndSign(alice));

        var profileEv = ProfileBadges.Create()
            .Add(award1).Add(award2).BuildAndSign(bob);
        var profile = ProfileBadges.FromEvent(profileEv);

        var trimmedEv = profile.ToBuilder()
            .Remove(award1.BadgeAddress)
            .BuildAndSign(bob);
        var trimmed = ProfileBadges.FromEvent(trimmedEv);

        Assert.Single(trimmed.Entries);
        Assert.Equal(award2.BadgeAddress, trimmed.Entries[0].BadgeAddress);
    }

    [Fact]
    public void TryFromEvent_ReturnsFalseForWrongKindAcrossAllThree()
    {
        using var k = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = k.PublicKey,
            CreatedAt = 1,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "x",
        }.Sign(k);

        Assert.False(BadgeDefinition.TryFromEvent(note, out var d));
        Assert.Null(d);
        Assert.False(BadgeAward.TryFromEvent(note, out var a));
        Assert.Null(a);
        Assert.False(ProfileBadges.TryFromEvent(note, out var p));
        Assert.Null(p);
    }
}
