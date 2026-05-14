// SPDX-License-Identifier: MIT

using NostrNet.Blossom.UserServers;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Blossom.Tests.UserServers;

public class BlossomServerListTests
{
    [Fact]
    public void Builder_RoundTripsServersInOrder()
    {
        using var key = PrivateKey.Generate();
        var servers = new[]
        {
            "https://blossom.self.hosted",
            "https://cdn.blossom.cloud",
            "https://media.example",
        };

        var ev = BlossomServerList.Create().AddServers(servers).BuildAndSign(key);
        Assert.True(ev.Verify());
        Assert.Equal(BlossomKinds.UserServerList, ev.Kind);
        Assert.Equal(string.Empty, ev.Content);

        var parsed = BlossomServerList.FromEvent(ev);
        Assert.Equal(key.PublicKey, parsed.Author);
        Assert.Equal(servers, parsed.Servers);
    }

    [Fact]
    public void Builder_RequiresAtLeastOneServer()
    {
        using var key = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            BlossomServerList.Create().BuildAndSign(key));
    }

    [Fact]
    public void Builder_RejectsNullOrEmptyServer()
    {
        var builder = BlossomServerList.Create();
        Assert.Throws<ArgumentException>(() => builder.AddServer(string.Empty));
        Assert.Throws<ArgumentNullException>(() => builder.AddServer(null!));
    }

    [Fact]
    public void FromEvent_ThrowsForWrongKind()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "x",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => BlossomServerList.FromEvent(ev));
    }

    [Fact]
    public void FromEvent_IgnoresMalformedAndUnknownTags()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = BlossomKinds.UserServerList,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "server" },                  // no value — skip
                new[] { "server", "" },              // empty value — skip
                new[] { "server", "https://valid" }, // keep
                new[] { "p", key.PublicKey.ToHex() }, // unknown tag — skip
                new[] { "server", "https://second" },// keep
            },
            Content = "",
        }.Sign(key);

        var parsed = BlossomServerList.FromEvent(ev);
        Assert.Equal(new[] { "https://valid", "https://second" }, parsed.Servers);
    }

    [Fact]
    public void TryFromEvent_ReturnsFalse_ForWrongKind()
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

        Assert.False(BlossomServerList.TryFromEvent(note, out var list));
        Assert.Null(list);
    }

    [Fact]
    public void FromEvent_AcceptsSpecExample()
    {
        // Mirror the example event from the NIP-B7 spec text.
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_708_774_162,
            Kind = BlossomKinds.UserServerList,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "server", "https://blossom.self.hosted" },
                new[] { "server", "https://cdn.blossom.cloud" },
            },
            Content = "",
        }.Sign(key);

        var parsed = BlossomServerList.FromEvent(ev);
        Assert.Equal(2, parsed.Servers.Count);
        Assert.Equal("https://blossom.self.hosted", parsed.Servers[0]);
        Assert.Equal("https://cdn.blossom.cloud", parsed.Servers[1]);
    }
}
