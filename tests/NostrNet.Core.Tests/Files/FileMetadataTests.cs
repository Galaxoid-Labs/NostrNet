// SPDX-License-Identifier: MIT

using NostrNet.Events;
using NostrNet.Files;
using NostrNet.Keys;

namespace NostrNet.Core.Tests.Files;

public class FileMetadataTests
{
    [Fact]
    public void Builder_RoundTripsThroughFromEvent()
    {
        using var author = PrivateKey.Generate();
        var ev = FileMetadata
            .Create("https://files.example/x.pdf", "application/pdf",
                "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
            .WithDescription("Tech manual")
            .WithSize(1_024_000)
            .WithDim("1920x1080")
            .WithBlurhash("LZN]Rb%LM_t8M{R*Rkay")
            .WithSummary("a short summary")
            .WithAlt("Document preview image")
            .WithThumbnail("https://thumb.example/x.jpg",
                "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
            .WithPreviewImage("https://preview.example/x.jpg")
            .Fallback("https://mirror.example/x.pdf")
            .Fallback("https://cdn.example/x.pdf")
            .WithService("nip96")
            .BuildAndSign(author);

        Assert.True(ev.Verify());
        Assert.Equal(Nip94Kinds.FileMetadata, ev.Kind);

        var file = FileMetadata.FromEvent(ev);
        Assert.Equal("https://files.example/x.pdf", file.Url);
        Assert.Equal("application/pdf", file.MimeType);
        Assert.Equal(1_024_000, file.SizeBytes);
        Assert.Equal("1920x1080", file.Dim);
        Assert.Equal("LZN]Rb%LM_t8M{R*Rkay", file.Blurhash);
        Assert.Equal("a short summary", file.Summary);
        Assert.Equal("Document preview image", file.Alt);
        Assert.Equal("https://thumb.example/x.jpg", file.ThumbnailUrl);
        Assert.Equal(
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
            file.ThumbnailSha256);
        Assert.Equal("https://preview.example/x.jpg", file.ImageUrl);
        Assert.Null(file.ImageSha256);
        Assert.Equal(new[] { "https://mirror.example/x.pdf", "https://cdn.example/x.pdf" }, file.FallbackUrls);
        Assert.Equal("nip96", file.Service);
        Assert.Equal("Tech manual", file.Description);
    }

    [Fact]
    public void FromEvent_RequiresUrlMimeAndHash()
    {
        using var key = PrivateKey.Generate();
        // Missing 'm' tag.
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip94Kinds.FileMetadata,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "url", "https://x" },
                new[] { "x", "00" + new string('1', 62) },
            },
            Content = "no mime",
        }.Sign(key);

        Assert.Throws<FormatException>(() => FileMetadata.FromEvent(ev));
    }

    [Fact]
    public void FromEvent_RejectsWrongKind()
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

        Assert.Throws<ArgumentException>(() => FileMetadata.FromEvent(ev));
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
        Assert.False(FileMetadata.TryFromEvent(note, out var f));
        Assert.Null(f);
    }
}
