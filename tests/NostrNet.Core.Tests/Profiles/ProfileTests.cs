// SPDX-License-Identifier: MIT
//
// Tests for the kind-0 metadata Profile parser.

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Profiles;

namespace NostrNet.Tests.Profiles;

public class ProfileTests
{
    private static NostrEvent BuildKind0Event(string contentJson)
    {
        using var key = PrivateKey.Generate();
        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 0,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = contentJson,
        }.Sign(key);
    }

    [Fact]
    public void FromEvent_ParsesAllKnownFields()
    {
        const string Content = """
        {
          "name": "bob",
          "display_name": "Bob the Builder",
          "about": "I build things on Nostr",
          "picture": "https://example.com/bob.png",
          "banner": "https://example.com/bob-banner.png",
          "nip05": "bob@example.com",
          "lud16": "bob@walletofsatoshi.com",
          "lud06": "LNURL1234",
          "website": "https://bob.example.com",
          "unknown_field": "ignored"
        }
        """;

        var ev = BuildKind0Event(Content);
        var profile = Profile.FromEvent(ev);

        Assert.Equal("bob", profile.Name);
        Assert.Equal("Bob the Builder", profile.DisplayName);
        Assert.Equal("I build things on Nostr", profile.About);
        Assert.Equal("https://example.com/bob.png", profile.Picture);
        Assert.Equal("https://example.com/bob-banner.png", profile.Banner);
        Assert.Equal("bob@example.com", profile.Nip05);
        Assert.Equal("bob@walletofsatoshi.com", profile.Lud16);
        Assert.Equal("LNURL1234", profile.Lud06);
        Assert.Equal("https://bob.example.com", profile.Website);
        Assert.Equal(ev.PubKey, profile.Owner);
    }

    [Fact]
    public void FromEvent_MissingFields_LeavesNullsButSetsOwner()
    {
        var ev = BuildKind0Event("""{"name":"alice"}""");
        var profile = Profile.FromEvent(ev);

        Assert.Equal("alice", profile.Name);
        Assert.Null(profile.About);
        Assert.Null(profile.Nip05);
        Assert.Equal(ev.PubKey, profile.Owner);
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
            Content = """{"name":"bob"}""",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => Profile.FromEvent(ev));
    }

    [Fact]
    public void FromEvent_MalformedJson_Throws()
    {
        var ev = BuildKind0Event("not even close to json");
        Assert.Throws<FormatException>(() => Profile.FromEvent(ev));
    }

    [Fact]
    public void TryFromEvent_ReturnsFalseOnFailure()
    {
        Assert.False(Profile.TryFromEvent(null, out var p));
        Assert.Null(p);

        var ev = BuildKind0Event("garbage");
        Assert.False(Profile.TryFromEvent(ev, out p));
        Assert.Null(p);
    }

    [Fact]
    public void TryFromEvent_ReturnsTrueOnSuccess()
    {
        var ev = BuildKind0Event("""{"name":"alice"}""");
        Assert.True(Profile.TryFromEvent(ev, out var profile));
        Assert.NotNull(profile);
        Assert.Equal("alice", profile!.Name);
    }
}
