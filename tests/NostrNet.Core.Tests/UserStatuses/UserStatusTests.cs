// SPDX-License-Identifier: MIT

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.UserStatuses;

namespace NostrNet.Core.Tests.UserStatuses;

public class UserStatusTests
{
    [Fact]
    public void Builder_GeneralStatus_RoundTripsThroughFromEvent()
    {
        using var author = PrivateKey.Generate();
        var ev = UserStatus.Create(UserStatusTypes.General)
            .WithContent("Working on NostrNet")
            .BuildAndSign(author);

        Assert.True(ev.Verify());
        Assert.Equal(Nip38Kinds.UserStatus, ev.Kind);
        Assert.Equal("Working on NostrNet", ev.Content);

        var status = UserStatus.FromEvent(ev);
        Assert.Equal(UserStatusTypes.General, status.Type);
        Assert.Equal("Working on NostrNet", status.Content);
        Assert.False(status.IsCleared);
        Assert.False(status.HasExpired);
        Assert.Null(status.Expiration);
        Assert.Null(status.ReferenceUrl);
    }

    [Fact]
    public void Builder_MusicStatus_RoundTripsWithExpirationAndReference()
    {
        // Mirrors the example from the NIP-38 spec text.
        using var author = PrivateKey.Generate();
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(1_692_845_589);
        var ev = UserStatus.Create(UserStatusTypes.Music)
            .WithContent("Intergalactic - Beastie Boys")
            .WithReference("spotify:search:Intergalactic%20-%20Beastie%20Boys")
            .WithExpiration(expiresAt)
            .BuildAndSign(author);

        Assert.True(ev.Verify());
        var status = UserStatus.FromEvent(ev);
        Assert.Equal(UserStatusTypes.Music, status.Type);
        Assert.Equal("Intergalactic - Beastie Boys", status.Content);
        Assert.Equal("spotify:search:Intergalactic%20-%20Beastie%20Boys", status.ReferenceUrl);
        Assert.Equal(expiresAt, status.Expiration);
        // The expiration is in the past relative to wall-clock UTC.
        Assert.True(status.HasExpired);
    }

    [Fact]
    public void Builder_EmptyContent_MarksStatusAsCleared()
    {
        using var author = PrivateKey.Generate();
        var ev = UserStatus.Clear(UserStatusTypes.General).BuildAndSign(author);
        var status = UserStatus.FromEvent(ev);
        Assert.True(status.IsCleared);
        Assert.Equal(string.Empty, status.Content);
    }

    [Fact]
    public void Builder_TagsForReferencedEntities_RoundTrip()
    {
        using var author = PrivateKey.Generate();
        using var taggedUser = PrivateKey.Generate();
        var taggedEventId = EventId.FromHex(new string('a', 64));

        var ev = UserStatus.Create("custom-slot")
            .WithContent("Looking at this thing")
            .TagProfile(taggedUser.PublicKey)
            .TagEvent(taggedEventId)
            .TagAddress("30023:abcd:my-article")
            .BuildAndSign(author);

        var status = UserStatus.FromEvent(ev);
        Assert.Equal("custom-slot", status.Type);
        Assert.Single(status.TaggedPubkeys);
        Assert.Equal(taggedUser.PublicKey, status.TaggedPubkeys[0]);
        Assert.Single(status.TaggedEvents);
        Assert.Equal(taggedEventId, status.TaggedEvents[0]);
        Assert.Equal(new[] { "30023:abcd:my-article" }, status.TaggedAddresses);
    }

    [Fact]
    public void Builder_RejectsNullOrEmptyType()
    {
        Assert.Throws<ArgumentException>(() => UserStatus.Create(""));
        Assert.Throws<ArgumentNullException>(() => UserStatus.Create(null!));
    }

    [Fact]
    public void FromEvent_ThrowsForWrongKind()
    {
        using var key = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "x",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => UserStatus.FromEvent(note));
    }

    [Fact]
    public void FromEvent_ThrowsWhenDTagIsMissing()
    {
        using var key = PrivateKey.Generate();
        var bad = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip38Kinds.UserStatus,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "no d tag",
        }.Sign(key);

        Assert.Throws<FormatException>(() => UserStatus.FromEvent(bad));
    }

    [Fact]
    public void TryFromEvent_ReturnsFalseForWrongKindOrMalformed()
    {
        using var key = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "x",
        }.Sign(key);
        Assert.False(UserStatus.TryFromEvent(note, out var s1));
        Assert.Null(s1);

        var malformed = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip38Kinds.UserStatus,
            Tags = new IReadOnlyList<string>[] { new[] { "d", "" } },  // empty d
            Content = "x",
        }.Sign(key);
        Assert.False(UserStatus.TryFromEvent(malformed, out var s2));
        Assert.Null(s2);
    }

    [Fact]
    public void ToNaddr_UsesTypeAsIdentifier()
    {
        using var author = PrivateKey.Generate();
        var ev = UserStatus.Create(UserStatusTypes.Music)
            .WithContent("xx")
            .BuildAndSign(author);
        var status = UserStatus.FromEvent(ev);
        var naddr = status.ToNaddr(new[] { "wss://relay.example" });
        Assert.Equal(Nip38Kinds.UserStatus, naddr.Kind);
        Assert.Equal(UserStatusTypes.Music, naddr.Identifier);
        Assert.Equal(author.PublicKey, naddr.PubKey);
        Assert.Equal(new[] { "wss://relay.example" }, naddr.Relays);
    }
}
