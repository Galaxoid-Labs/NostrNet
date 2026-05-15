// SPDX-License-Identifier: MIT
//
// Tests for the typed NIP-01 filter and its JSON serialization.

using System.Text.Json;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Relay;

namespace NostrNet.Tests.Relay;

public class FilterTests
{
    [Fact]
    public void Empty_SerializesAsEmptyObject()
    {
        Assert.Equal("{}", new Filter().ToJson());
    }

    [Fact]
    public void Kinds_SerializesAsKindsArray()
    {
        string json = new Filter { Kinds = new[] { 1, 7 } }.ToJson();
        Assert.Equal("""{"kinds":[1,7]}""", json);
    }

    [Fact]
    public void AllPrimitiveFields_Serialize()
    {
        var f = new Filter
        {
            Ids = new[] { "abc" },
            Authors = new[] { "deadbeef" },
            Kinds = new[] { 1 },
            Since = 1_700_000_000L,
            Until = 1_800_000_000L,
            Limit = 50,
        };

        string json = f.ToJson();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("abc", root.GetProperty("ids")[0].GetString());
        Assert.Equal("deadbeef", root.GetProperty("authors")[0].GetString());
        Assert.Equal(1, root.GetProperty("kinds")[0].GetInt32());
        Assert.Equal(1_700_000_000L, root.GetProperty("since").GetInt64());
        Assert.Equal(1_800_000_000L, root.GetProperty("until").GetInt64());
        Assert.Equal(50, root.GetProperty("limit").GetInt32());
    }

    [Fact]
    public void TagFilters_SerializeWithHashPrefix()
    {
        var f = new Filter
        {
            TagFilters = new Dictionary<string, IReadOnlyList<string>>
            {
                ["e"] = new[] { "f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb" },
                ["p"] = new[] { "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d" },
            },
        };

        using var doc = JsonDocument.Parse(f.ToJson());
        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("#e", out _));
        Assert.True(root.TryGetProperty("#p", out _));
    }

    [Fact]
    public void ByAuthors_BuildsHexList()
    {
        var pub = PublicKey.FromHex("4b7fef1400aae7011f3121c1cbf63e72ae30ef250e0da169e0fd48427f3fb794");
        var f = Filter.ByAuthors(pub);
        Assert.NotNull(f.Authors);
        Assert.Single(f.Authors!);
        Assert.Equal(pub.ToHex(), f.Authors![0]);
    }

    [Fact]
    public void ByIds_BuildsHexList()
    {
        var id = EventId.FromHex("f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb");
        var f = Filter.ByIds(id);
        Assert.NotNull(f.Ids);
        Assert.Equal(id.ToHex(), f.Ids![0]);
    }

    [Fact]
    public void WithSyntax_ProducesDerivedFilter()
    {
        var f1 = Filter.ByKinds(1);
        var f2 = f1 with { Limit = 100 };
        Assert.NotEqual(f1, f2);
        Assert.Equal(100, f2.Limit);
        Assert.Equal(f1.Kinds, f2.Kinds);
    }

    [Fact]
    public void Search_IsEmittedAsTopLevelField()
    {
        var f = new Filter { Search = "best nostr apps" };
        Assert.Contains("\"search\":\"best nostr apps\"", f.ToJson());
    }

    [Fact]
    public void Search_OmittedWhenNullOrEmpty()
    {
        Assert.DoesNotContain("search", new Filter { Limit = 1 }.ToJson());
        Assert.DoesNotContain("search", new Filter { Search = "" }.ToJson());
    }

    [Fact]
    public void Search_CombinesWithStructuredFilters()
    {
        // NIP-50 explicitly allows combining search with other filter
        // fields; verify both serialize side by side.
        var f = new Filter
        {
            Kinds = new[] { 1 },
            Limit = 50,
            Search = "purple include:spam",
        };
        var json = f.ToJson();
        Assert.Contains("\"kinds\":[1]", json);
        Assert.Contains("\"limit\":50", json);
        Assert.Contains("\"search\":\"purple include:spam\"", json);
    }

    [Fact]
    public void ByText_ConstructsSearchOnlyFilter()
    {
        var f = Filter.ByText("orange");
        Assert.Equal("orange", f.Search);
        Assert.Null(f.Kinds);
        Assert.Null(f.Authors);
    }

    [Fact]
    public void ByText_RejectsNullOrEmpty()
    {
        Assert.Throws<ArgumentException>(() => Filter.ByText(""));
        Assert.Throws<ArgumentNullException>(() => Filter.ByText(null!));
    }

    // ----- Matches(NostrEvent): local-side filter evaluation, used by stores.

    [Fact]
    public void Matches_EmptyFilter_MatchesAnyEvent()
    {
        var ev = BuildEvent(kind: 1, content: "anything");
        Assert.True(new Filter().Matches(ev));
    }

    [Fact]
    public void Matches_Kinds_RequiresExactMembership()
    {
        var ev = BuildEvent(kind: 7);
        Assert.True(new Filter { Kinds = new[] { 7 } }.Matches(ev));
        Assert.True(new Filter { Kinds = new[] { 1, 7, 30023 } }.Matches(ev));
        Assert.False(new Filter { Kinds = new[] { 1 } }.Matches(ev));
    }

    [Fact]
    public void Matches_Authors_UsesHexPrefix()
    {
        using var key = PrivateKey.Generate();
        var ev = BuildEvent(key: key, kind: 1);
        string hex = key.PublicKey.ToHex();

        Assert.True(new Filter { Authors = new[] { hex } }.Matches(ev));
        Assert.True(new Filter { Authors = new[] { hex.Substring(0, 8) } }.Matches(ev));
        // Prefix matches are case-insensitive per NIP-01.
        Assert.True(new Filter { Authors = new[] { hex.ToUpperInvariant().Substring(0, 8) } }.Matches(ev));
        Assert.False(new Filter { Authors = new[] { new string('0', 64) } }.Matches(ev));
    }

    [Fact]
    public void Matches_Ids_UsesHexPrefix()
    {
        var ev = BuildEvent(kind: 1);
        string idHex = ev.Id.ToHex();

        Assert.True(new Filter { Ids = new[] { idHex } }.Matches(ev));
        Assert.True(new Filter { Ids = new[] { idHex.Substring(0, 16) } }.Matches(ev));
        Assert.False(new Filter { Ids = new[] { new string('0', 64) } }.Matches(ev));
    }

    [Fact]
    public void Matches_SinceUntil_AreInclusiveBounds()
    {
        var ev = BuildEvent(kind: 1, createdAt: 1_000);

        Assert.True(new Filter { Since = 999, Until = 1_001 }.Matches(ev));
        Assert.True(new Filter { Since = 1_000, Until = 1_000 }.Matches(ev));   // inclusive
        Assert.False(new Filter { Since = 1_001 }.Matches(ev));
        Assert.False(new Filter { Until = 999 }.Matches(ev));
    }

    [Fact]
    public void Matches_TagFilters_AnyValueAcrossAnyTag()
    {
        var ev = BuildEvent(kind: 1, tags: new[]
        {
            new[] { "e", "abc123" },
            new[] { "t", "nostr" },
            new[] { "t", "long-form" },
        });

        var anyT = new Dictionary<string, IReadOnlyList<string>> { ["t"] = new[] { "nostr" } };
        Assert.True(new Filter { TagFilters = anyT }.Matches(ev));

        var secondT = new Dictionary<string, IReadOnlyList<string>> { ["t"] = new[] { "long-form" } };
        Assert.True(new Filter { TagFilters = secondT }.Matches(ev));

        var miss = new Dictionary<string, IReadOnlyList<string>> { ["t"] = new[] { "absent" } };
        Assert.False(new Filter { TagFilters = miss }.Matches(ev));

        // Two clauses → both must match.
        var both = new Dictionary<string, IReadOnlyList<string>>
        {
            ["t"] = new[] { "nostr" },
            ["e"] = new[] { "abc123" },
        };
        Assert.True(new Filter { TagFilters = both }.Matches(ev));

        var oneMisses = new Dictionary<string, IReadOnlyList<string>>
        {
            ["t"] = new[] { "nostr" },
            ["e"] = new[] { "wrong-id" },
        };
        Assert.False(new Filter { TagFilters = oneMisses }.Matches(ev));
    }

    [Fact]
    public void Matches_Search_IsCaseInsensitiveSubstringOnContent()
    {
        var ev = BuildEvent(kind: 1, content: "Hello, Nostr!");
        Assert.True(new Filter { Search = "nostr" }.Matches(ev));
        Assert.True(new Filter { Search = "HELLO" }.Matches(ev));
        Assert.False(new Filter { Search = "bitcoin" }.Matches(ev));
    }

    [Fact]
    public void Matches_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new Filter().Matches(null!));
    }

    private static NostrEvent BuildEvent(
        int kind,
        PrivateKey? key = null,
        long createdAt = 1_700_000_000L,
        string content = "",
        IReadOnlyList<IReadOnlyList<string>>? tags = null)
    {
        key ??= PrivateKey.Generate();
        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt,
            Kind = kind,
            Tags = tags ?? Array.Empty<IReadOnlyList<string>>(),
            Content = content,
        }.Sign(key);
    }
}
