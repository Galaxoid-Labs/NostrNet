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
}
