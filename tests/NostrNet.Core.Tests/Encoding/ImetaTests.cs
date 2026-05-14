// SPDX-License-Identifier: MIT

using NostrNet.Encoding;

namespace NostrNet.Core.Tests.Encoding;

public class ImetaTests
{
    [Fact]
    public void Parse_DecomposesKnownEntries()
    {
        var tag = new[]
        {
            "imeta",
            "url https://example.com/x.jpg",
            "m image/jpeg",
            "x 0011223344556677889900112233445566778899001122334455667788990011",
            "dim 1024x768",
            "alt friendly alt text",
            "blurhash abc",
        };

        var parsed = Imeta.Parse(tag);
        Assert.Equal("https://example.com/x.jpg", Imeta.FirstValue(parsed, "url"));
        Assert.Equal("image/jpeg", Imeta.FirstValue(parsed, "m"));
        Assert.Equal("1024x768", Imeta.FirstValue(parsed, "dim"));
        Assert.Equal("friendly alt text", Imeta.FirstValue(parsed, "alt"));
        Assert.Equal("abc", Imeta.FirstValue(parsed, "blurhash"));
    }

    [Fact]
    public void Parse_PreservesUnknownKeysAndMultiValueOrder()
    {
        var tag = new[]
        {
            "imeta",
            "url https://x",
            "m image/jpeg",
            "fallback https://a",
            "fallback https://b",
            "futureKey hello world",  // unknown key + multi-word value
            "noSpaceShouldBeSkipped",
        };

        var parsed = Imeta.Parse(tag);
        Assert.Equal(new[] { "https://a", "https://b" }, parsed["fallback"]);
        Assert.Equal("hello world", Imeta.FirstValue(parsed, "futureKey"));
        Assert.False(parsed.ContainsKey("noSpaceShouldBeSkipped"));
    }

    [Fact]
    public void Parse_ThrowsForNonImetaTag()
    {
        Assert.Throws<ArgumentException>(() => Imeta.Parse(new[] { "image", "url foo" }));
    }

    [Fact]
    public void Build_RequiresUrlEntry()
    {
        var entries = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["m"] = new[] { "image/jpeg" },
        };
        Assert.Throws<ArgumentException>(() => Imeta.Build(entries));
    }

    [Fact]
    public void Build_RoundTripsThroughParse()
    {
        var entries = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["url"] = new[] { "https://x" },
            ["m"] = new[] { "image/jpeg" },
            ["dim"] = new[] { "1024x768" },
            ["fallback"] = new[] { "https://a", "https://b" },
        };

        var tag = Imeta.Build(entries);
        Assert.Equal("imeta", tag[0]);
        Assert.Contains("url https://x", tag);
        Assert.Contains("m image/jpeg", tag);

        var parsed = Imeta.Parse(tag);
        Assert.Equal(new[] { "https://x" }, parsed["url"]);
        Assert.Equal(new[] { "https://a", "https://b" }, parsed["fallback"]);
    }
}
