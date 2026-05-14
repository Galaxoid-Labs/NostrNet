// SPDX-License-Identifier: MIT

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Videos;

namespace NostrNet.Core.Tests.Videos;

public class VideoEventTests
{
    [Fact]
    public void ImetaTag_RoundTrip_Minimal()
    {
        var a = new VideoMediaAttachment
        {
            Url = "https://example.com/m.mp4",
            MimeType = "video/mp4",
        };

        var tag = a.ToImetaTag();
        Assert.Equal("imeta", tag[0]);
        Assert.Equal("url https://example.com/m.mp4", tag[1]);
        Assert.Equal("m video/mp4", tag[2]);

        var parsed = VideoMediaAttachment.FromImetaTag(tag);
        Assert.Equal(a.Url, parsed.Url);
        Assert.Equal(a.MimeType, parsed.MimeType);
    }

    [Fact]
    public void ImetaTag_RoundTrip_AllFields()
    {
        var a = new VideoMediaAttachment
        {
            Url = "https://example.com/m.mp4",
            MimeType = "video/mp4",
            Sha256 = "3093509d1e0bc604ff60cb9286f4cd7c781553bc8991937befaacfdc28ec5cdc",
            Dim = "1920x1080",
            DurationSeconds = 12.5,
            Bitrate = 2_500_000,
            Service = "nip96",
            PosterImageUrls = new[] { "https://example.com/p1.jpg", "https://example.com/p2.jpg" },
            FallbackUrls = new[] { "https://cdn.example.com/m.mp4" },
        };

        var tag = a.ToImetaTag();
        var parsed = VideoMediaAttachment.FromImetaTag(tag);

        Assert.Equal(a.Url, parsed.Url);
        Assert.Equal(a.MimeType, parsed.MimeType);
        Assert.Equal(a.Sha256, parsed.Sha256);
        Assert.Equal(a.Dim, parsed.Dim);
        Assert.Equal(a.DurationSeconds, parsed.DurationSeconds);
        Assert.Equal(a.Bitrate, parsed.Bitrate);
        Assert.Equal(a.Service, parsed.Service);
        Assert.Equal(a.PosterImageUrls, parsed.PosterImageUrls);
        Assert.Equal(a.FallbackUrls, parsed.FallbackUrls);
    }

    [Fact]
    public void ImetaTag_FromTag_ThrowsOnMissingUrl()
    {
        var tag = new[] { "imeta", "m video/mp4" };
        Assert.Throws<FormatException>(() => VideoMediaAttachment.FromImetaTag(tag));
    }

    [Theory]
    [InlineData(Nip71Kinds.NormalVideo)]
    [InlineData(Nip71Kinds.ShortVideo)]
    public void Builder_RegularKinds_RoundTrip(int kind)
    {
        using var author = PrivateKey.Generate();
        var a = new VideoMediaAttachment
        {
            Url = "https://example.com/v.mp4",
            MimeType = "video/mp4",
            DurationSeconds = 60.0,
            PosterImageUrls = new[] { "https://example.com/thumb.jpg" },
        };

        var ev = VideoEvent
            .Create(kind, "My video")
            .WithDescription("First upload")
            .AddAttachment(a)
            .Hashtag("vlog")
            .WithContentWarning("loud audio")
            .WithDurationSeconds(60.0)
            .WithAlt("a person waving")
            .BuildAndSign(author);

        Assert.True(ev.Verify());
        Assert.Equal(kind, ev.Kind);

        var video = VideoEvent.FromEvent(ev);
        Assert.Equal(kind, video.Kind);
        Assert.Equal("My video", video.Title);
        Assert.Equal("First upload", video.Description);
        Assert.Single(video.Attachments);
        Assert.Equal(60.0, video.DurationSeconds);
        Assert.Equal("a person waving", video.Alt);
        Assert.Equal("loud audio", video.ContentWarning);
        Assert.Equal(kind == Nip71Kinds.ShortVideo, video.IsShortForm);
        Assert.False(video.IsAddressable);
    }

    [Theory]
    [InlineData(Nip71Kinds.NormalVideoAddressable)]
    [InlineData(Nip71Kinds.ShortVideoAddressable)]
    public void Builder_AddressableKinds_RoundTrip(int kind)
    {
        using var author = PrivateKey.Generate();
        var a = new VideoMediaAttachment
        {
            Url = "https://example.com/v.mp4",
            MimeType = "video/mp4",
        };

        var ev = VideoEvent
            .Create(kind, "My addressable", identifier: "vid-1")
            .AddAttachment(a)
            .WithPublishedAt(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000))
            .BuildAndSign(author);

        Assert.True(ev.Verify());

        var video = VideoEvent.FromEvent(ev);
        Assert.True(video.IsAddressable);
        Assert.Equal("vid-1", video.Identifier);
        Assert.Equal(1_700_000_000, video.PublishedAt!.Value.ToUnixTimeSeconds());

        var naddr = video.ToNaddr(new[] { "wss://relay.example" });
        Assert.Equal(kind, naddr.Kind);
        Assert.Equal("vid-1", naddr.Identifier);
        Assert.Equal(author.PublicKey, naddr.PubKey);
    }

    [Fact]
    public void Builder_AddressableKind_RequiresIdentifier()
    {
        // ArgumentException.ThrowIfNullOrEmpty throws ArgumentNullException
        // for null and ArgumentException for empty — both inherit from ArgumentException.
        Assert.ThrowsAny<ArgumentException>(() =>
            VideoEvent.Create(Nip71Kinds.NormalVideoAddressable, "x"));
        Assert.ThrowsAny<ArgumentException>(() =>
            VideoEvent.Create(Nip71Kinds.NormalVideoAddressable, "x", identifier: ""));
    }

    [Fact]
    public void Builder_RejectsNonVideoKind()
    {
        Assert.Throws<ArgumentException>(() => VideoEvent.Create(1, "x"));
    }

    [Fact]
    public void Builder_ThrowsWithoutAttachments()
    {
        using var key = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            VideoEvent.Create(Nip71Kinds.NormalVideo, "x").BuildAndSign(key));
    }

    [Fact]
    public void FromEvent_AddressableRequiresDTag()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip71Kinds.NormalVideoAddressable,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "title", "x" },
                new[] { "imeta", "url https://x", "m video/mp4" },
            },
            Content = "no d-tag",
        }.Sign(key);

        Assert.Throws<FormatException>(() => VideoEvent.FromEvent(ev));
    }

    [Fact]
    public void TryFromEvent_ReturnsFalse_OnWrongKind()
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
        Assert.False(VideoEvent.TryFromEvent(note, out var v));
        Assert.Null(v);
    }

    [Fact]
    public void FromEvent_AcceptsRealWorldExample()
    {
        // Mirrors the example from the NIP-71 spec.
        using var key = PrivateKey.Generate();
        using var tagged = PrivateKey.Generate();
        var imeta = new[]
        {
            "imeta",
            "url https://example.com/media.mp4",
            "m video/mp4",
            "dim 480x480",
            "image https://example.com/thumb.jpg",
            "x 3093509d1e0bc604ff60cb9286f4cd7c781553bc8991937befaacfdc28ec5cdc",
            "duration 12.5",
        };

        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip71Kinds.NormalVideoAddressable,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "d", "first-upload" },
                new[] { "title", "First upload" },
                new[] { "published_at", "1700000000" },
                new[] { "alt", "a person waving at the camera" },
                imeta,
                new[] { "duration", "12.5" },
                new[] { "content-warning", "loud audio" },
                new[] { "p", tagged.PublicKey.ToHex() },
                new[] { "t", "vlog" },
                new[] { "r", "https://nostr.com" },
            },
            Content = "First upload, summary text here.",
        }.Sign(key);

        var video = VideoEvent.FromEvent(ev);
        Assert.Equal(Nip71Kinds.NormalVideoAddressable, video.Kind);
        Assert.Equal("first-upload", video.Identifier);
        Assert.Equal("First upload", video.Title);
        Assert.Equal("First upload, summary text here.", video.Description);
        Assert.Single(video.Attachments);
        Assert.Equal("video/mp4", video.Attachments[0].MimeType);
        Assert.Equal(12.5, video.Attachments[0].DurationSeconds);
        Assert.Equal(new[] { "https://example.com/thumb.jpg" }, video.Attachments[0].PosterImageUrls);
        Assert.Equal(12.5, video.DurationSeconds);
        Assert.Equal("a person waving at the camera", video.Alt);
        Assert.Equal(1_700_000_000, video.PublishedAt!.Value.ToUnixTimeSeconds());
        Assert.Equal(new[] { tagged.PublicKey }, video.TaggedPubkeys);
        Assert.Equal(new[] { "vlog" }, video.Hashtags);
        Assert.Equal(new[] { "https://nostr.com" }, video.References);
    }
}
