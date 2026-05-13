// SPDX-License-Identifier: MIT
//
// Tests for the NIP-42 auth event builder.

using NostrNet.Auth;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Auth;

public class Nip42Tests
{
    [Fact]
    public void BuildAuthEvent_HasKind22242()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip42.BuildAuthEvent(key, new Uri("wss://relay.example.com"), "abc123");
        Assert.Equal(Nip42.AuthEventKind, ev.Kind);
        Assert.Equal(22242, Nip42.AuthEventKind);  // sanity: the constant matches the spec
    }

    [Fact]
    public void BuildAuthEvent_PopulatesRelayAndChallengeTags()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip42.BuildAuthEvent(key, new Uri("wss://relay.example.com"), "abc123");

        Assert.Equal("wss://relay.example.com/", ev.Tags.FirstValue("relay"));
        Assert.Equal("abc123", ev.Tags.FirstValue("challenge"));
        Assert.Equal(2, ev.Tags.Count);
    }

    [Fact]
    public void BuildAuthEvent_ContentIsEmpty()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip42.BuildAuthEvent(key, new Uri("wss://relay.example.com"), "challenge");
        Assert.Equal(string.Empty, ev.Content);
    }

    [Fact]
    public void BuildAuthEvent_SelfVerifies()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip42.BuildAuthEvent(key, new Uri("wss://relay.example.com"), "challenge");
        Assert.True(ev.Verify());
        Assert.Equal(key.PublicKey, ev.PubKey);
    }

    [Fact]
    public void BuildAuthEvent_CreatedAtOverride()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip42.BuildAuthEvent(key, new Uri("wss://x"), "c", createdAt: 1_700_000_000);
        Assert.Equal(1_700_000_000, ev.CreatedAt);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void BuildAuthEvent_RejectsEmptyChallenge(string? challenge)
    {
        using var key = PrivateKey.Generate();
        Assert.ThrowsAny<ArgumentException>(() =>
            Nip42.BuildAuthEvent(key, new Uri("wss://x"), challenge!));
    }

    [Fact]
    public void BuildAuthEvent_RejectsNullKey()
    {
        Assert.Throws<ArgumentNullException>(() =>
            Nip42.BuildAuthEvent(null!, new Uri("wss://x"), "c"));
    }

    [Fact]
    public void BuildAuthEvent_RejectsNullRelayUri()
    {
        using var key = PrivateKey.Generate();
        Assert.Throws<ArgumentNullException>(() =>
            Nip42.BuildAuthEvent(key, null!, "c"));
    }
}
