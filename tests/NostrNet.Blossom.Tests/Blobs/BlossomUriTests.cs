// SPDX-License-Identifier: MIT

using NostrNet.Blossom.Blobs;
using NostrNet.Keys;

namespace NostrNet.Blossom.Tests.Blobs;

public class BlossomUriTests
{
    private const string ExampleHash = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";

    [Fact]
    public void Parses_MinimalUri()
    {
        var u = BlossomUri.Parse($"blossom:{ExampleHash}.pdf");
        Assert.Equal(ExampleHash, u.Sha256);
        Assert.Equal("pdf", u.Extension);
        Assert.Empty(u.ServerHints);
        Assert.Empty(u.AuthorHints);
        Assert.Null(u.SizeBytes);
    }

    [Fact]
    public void Parses_AllOptionalParams_RepeatedHints()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        string uri = $"blossom:{ExampleHash}.png" +
            "?xs=cdn.satellite.earth" +
            "&xs=blossom.primal.net" +
            $"&as={alice.PublicKey.ToHex()}" +
            $"&as={bob.PublicKey.ToHex()}" +
            "&sz=2547831";

        var u = BlossomUri.Parse(uri);
        Assert.Equal(ExampleHash, u.Sha256);
        Assert.Equal("png", u.Extension);
        Assert.Equal(new[] { "cdn.satellite.earth", "blossom.primal.net" }, u.ServerHints);
        Assert.Equal(2, u.AuthorHints.Count);
        Assert.Equal(alice.PublicKey, u.AuthorHints[0]);
        Assert.Equal(bob.PublicKey, u.AuthorHints[1]);
        Assert.Equal(2_547_831, u.SizeBytes);
    }

    [Fact]
    public void Build_RoundTripsThroughParse()
    {
        using var key = PrivateKey.Generate();
        var u1 = new BlossomUri
        {
            Sha256 = ExampleHash,
            Extension = "pdf",
            ServerHints = new[] { "cdn.example.com" },
            AuthorHints = new[] { key.PublicKey },
            SizeBytes = 12345,
        };

        var u2 = BlossomUri.Parse(u1.ToString());
        Assert.Equal(u1.Sha256, u2.Sha256);
        Assert.Equal(u1.Extension, u2.Extension);
        Assert.Equal(u1.ServerHints, u2.ServerHints);
        Assert.Equal(u1.AuthorHints, u2.AuthorHints);
        Assert.Equal(u1.SizeBytes, u2.SizeBytes);
    }

    [Fact]
    public void Parse_RejectsBadInput()
    {
        Assert.Throws<FormatException>(() => BlossomUri.Parse("http://example.com"));
        Assert.Throws<FormatException>(() => BlossomUri.Parse("blossom:tooshort.pdf"));
        Assert.Throws<FormatException>(() => BlossomUri.Parse($"blossom:{ExampleHash}"));    // no extension
        Assert.Throws<FormatException>(() => BlossomUri.Parse($"blossom:{ExampleHash}."));   // empty extension
        Assert.Throws<FormatException>(() => BlossomUri.Parse($"blossom:{ExampleHash.ToUpperInvariant()}.pdf")); // mixed case hash
    }

    [Fact]
    public void TryParse_ReturnsFalseOnBadInput()
    {
        Assert.False(BlossomUri.TryParse(null, out var n));
        Assert.Null(n);
        Assert.False(BlossomUri.TryParse("not-a-uri", out var m));
        Assert.Null(m);

        Assert.True(BlossomUri.TryParse($"blossom:{ExampleHash}.bin", out var ok));
        Assert.NotNull(ok);
    }

    [Theory]
    // BUD-03 examples — every URL should yield ExampleHash.
    [InlineData($"https://blossom.example.com/{ExampleHash}.pdf")]
    [InlineData($"https://cdn.example.com/{ExampleHash}")]
    [InlineData($"https://cdn.example.com/user/ec4425ff5e9446080d2f70440188e3ca5d6da8713db7bdeef73d0ed54d9093f0/media/{ExampleHash}.pdf")]
    [InlineData($"https://cdn.example.com/media/user-name/documents/{ExampleHash}.pdf")]
    [InlineData($"http://download.example.com/downloads/{ExampleHash}")]
    [InlineData($"http://media.example.com/documents/b1/67/{ExampleHash}.pdf")]
    public void ExtractSha256_FindsLastHexRunPerBud03(string url)
    {
        Assert.Equal(ExampleHash, BlossomUri.ExtractSha256(url));
    }

    [Fact]
    public void ExtractSha256_ReturnsNullForUrlsWithoutHashes()
    {
        Assert.Null(BlossomUri.ExtractSha256("https://example.com/no-hash-here"));
        Assert.Null(BlossomUri.ExtractSha256("https://example.com/short-1234abcd"));
    }
}
