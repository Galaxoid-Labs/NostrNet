// SPDX-License-Identifier: MIT

using System.Globalization;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Pictures;

namespace NostrNet.Core.Tests.Pictures;

public class PictureEventTests
{
    [Fact]
    public void ImetaTag_RoundTrip_Minimal()
    {
        var a = new PictureMediaAttachment
        {
            Url = "https://nostr.build/i/my-image.jpg",
            MimeType = "image/jpeg",
        };

        var tag = a.ToImetaTag();
        Assert.Equal("imeta", tag[0]);
        Assert.Equal("url https://nostr.build/i/my-image.jpg", tag[1]);
        Assert.Equal("m image/jpeg", tag[2]);

        var parsed = PictureMediaAttachment.FromImetaTag(tag);
        Assert.Equal(a.Url, parsed.Url);
        Assert.Equal(a.MimeType, parsed.MimeType);
        Assert.Null(parsed.Sha256);
        Assert.Null(parsed.Dim);
        Assert.Empty(parsed.FallbackUrls);
        Assert.Empty(parsed.AnnotatedUsers);
    }

    [Fact]
    public void ImetaTag_RoundTrip_AllFields()
    {
        using var alice = PrivateKey.Generate();
        var ann = new PictureUserAnnotation(alice.PublicKey, 120, 340);
        var a = new PictureMediaAttachment
        {
            Url = "https://nostr.build/i/p.jpg",
            MimeType = "image/jpeg",
            Sha256 = "0011223344556677889900112233445566778899001122334455667788990011",
            Dim = "3024x4032",
            Blurhash = "eVF$^OI:${M{o#*0",
            Thumbhash = "zOcFFIIKmXdCinaXaHcmcHUFSA==",
            Alt = "A scenic photo overlooking the coast of Costa Rica",
            FallbackUrls = new[] { "https://nostrcheck.me/alt1.jpg", "https://void.cat/alt1.jpg" },
            AnnotatedUsers = new[] { ann },
        };

        var tag = a.ToImetaTag();
        var parsed = PictureMediaAttachment.FromImetaTag(tag);

        Assert.Equal(a.Url, parsed.Url);
        Assert.Equal(a.MimeType, parsed.MimeType);
        Assert.Equal(a.Sha256, parsed.Sha256);
        Assert.Equal(a.Dim, parsed.Dim);
        Assert.Equal(a.Blurhash, parsed.Blurhash);
        Assert.Equal(a.Thumbhash, parsed.Thumbhash);
        Assert.Equal(a.Alt, parsed.Alt);
        Assert.Equal(a.FallbackUrls, parsed.FallbackUrls);
        Assert.Equal(a.AnnotatedUsers, parsed.AnnotatedUsers);
    }

    [Fact]
    public void ImetaTag_FromTag_ThrowsOnMissingUrl()
    {
        var tag = new[] { "imeta", "m image/jpeg" };
        Assert.Throws<FormatException>(() => PictureMediaAttachment.FromImetaTag(tag));
    }

    [Fact]
    public void ImetaTag_FromTag_ThrowsOnWrongHeader()
    {
        var tag = new[] { "image", "url https://x" };
        Assert.Throws<ArgumentException>(() => PictureMediaAttachment.FromImetaTag(tag));
    }

    [Fact]
    public void ImetaTag_IgnoresUnknownKeysAndMalformedEntries()
    {
        var tag = new[]
        {
            "imeta",
            "url https://x.jpg",
            "m image/jpeg",
            "futureField some-payload",
            "noSpaceKey",
            "alt friendly",
        };

        var parsed = PictureMediaAttachment.FromImetaTag(tag);
        Assert.Equal("https://x.jpg", parsed.Url);
        Assert.Equal("friendly", parsed.Alt);
    }

    [Fact]
    public void Builder_RoundTripsThroughFromEvent()
    {
        using var author = PrivateKey.Generate();
        using var taggedUser = PrivateKey.Generate();
        var a1 = new PictureMediaAttachment
        {
            Url = "https://x.example/1.jpg",
            MimeType = "image/jpeg",
            Dim = "1024x768",
            Alt = "first",
        };
        var a2 = new PictureMediaAttachment
        {
            Url = "https://x.example/2.png",
            MimeType = "image/png",
            Sha256 = "deadbeef".PadRight(64, 'a'),
        };

        var ev = PictureEvent
            .Create("Holiday in Costa Rica")
            .WithDescription("Beaches and birds")
            .AddAttachment(a1)
            .AddAttachment(a2)
            .Hashtag("travel")
            .Hashtag("costarica")
            .TagUser(taggedUser.PublicKey)
            .WithContentWarning("photos contain wildlife")
            .WithLocation("Manuel Antonio, Costa Rica")
            .WithGeohash("d1h7w")
            .WithLanguage("en")
            .BuildAndSign(author);

        Assert.True(ev.Verify());
        Assert.Equal(Nip68Kinds.PicturePost, ev.Kind);

        var pic = PictureEvent.FromEvent(ev);
        Assert.Equal("Holiday in Costa Rica", pic.Title);
        Assert.Equal("Beaches and birds", pic.Description);
        Assert.Equal(2, pic.Attachments.Count);
        Assert.Equal(a1.Url, pic.Attachments[0].Url);
        Assert.Equal(a2.Url, pic.Attachments[1].Url);
        Assert.Equal(new[] { "travel", "costarica" }, pic.Hashtags);
        Assert.Single(pic.TaggedPubkeys);
        Assert.Equal(taggedUser.PublicKey, pic.TaggedPubkeys[0]);
        Assert.Equal("photos contain wildlife", pic.ContentWarning);
        Assert.Equal("Manuel Antonio, Costa Rica", pic.Location);
        Assert.Equal("d1h7w", pic.Geohash);
        Assert.Equal("en", pic.Language);
    }

    [Fact]
    public void FromEvent_ThrowsOnWrongKind()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "not a picture",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => PictureEvent.FromEvent(ev));
    }

    [Fact]
    public void FromEvent_ThrowsOnMissingTitle()
    {
        using var key = PrivateKey.Generate();
        var imeta = new[] { "imeta", "url https://x", "m image/jpeg" };
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip68Kinds.PicturePost,
            Tags = new IReadOnlyList<string>[] { imeta },
            Content = "no title",
        }.Sign(key);

        Assert.Throws<FormatException>(() => PictureEvent.FromEvent(ev));
    }

    [Fact]
    public void FromEvent_ThrowsOnMissingImeta()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip68Kinds.PicturePost,
            Tags = new IReadOnlyList<string>[] { new[] { "title", "x" } },
            Content = "no pic",
        }.Sign(key);

        Assert.Throws<FormatException>(() => PictureEvent.FromEvent(ev));
    }

    [Fact]
    public void TryFromEvent_ReturnsFalse_OnWrongKindOrMalformed()
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
        Assert.False(PictureEvent.TryFromEvent(note, out var p1));
        Assert.Null(p1);

        var malformed = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = Nip68Kinds.PicturePost,
            Tags = new IReadOnlyList<string>[] { new[] { "title", "t" } },
            Content = "x",
        }.Sign(key);
        Assert.False(PictureEvent.TryFromEvent(malformed, out var p2));
        Assert.Null(p2);
    }

    [Fact]
    public void Builder_ThrowsWithoutAttachments()
    {
        using var key = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            PictureEvent.Create("title").BuildAndSign(key));
    }

    [Fact]
    public void FromEvent_AcceptsRealWorldExample()
    {
        // The example event from the NIP-68 spec text. We round-trip it
        // through our serializer/deserializer to confirm tag shapes match.
        using var key = PrivateKey.Generate();
        using var p1 = PrivateKey.Generate();
        var imeta1 = new[]
        {
            "imeta",
            "url https://nostr.build/i/my-image.jpg",
            "m image/jpeg",
            "thumbhash zOcFFIIKmXdCinaXaHcmcHUFSA==",
            "blurhash eVF$^OI:${M{o#*0",
            "dim 3024x4032",
            "alt A scenic photo overlooking the coast of Costa Rica",
            "x 1122334455667788991122334455667788991122334455667788991122334455",
            "fallback https://nostrcheck.me/alt1.jpg",
            "fallback https://void.cat/alt1.jpg",
        };

        var imeta2 = new[]
        {
            "imeta",
            "url https://nostr.build/i/my-image2.jpg",
            "m image/jpeg",
            "thumbhash zOcFFIIKmXgzmWaXWIcmcFQEGA",
            "dim 3024x4032",
            "alt Another scenic photo overlooking the coast of Costa Rica",
            "x aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011",
            "fallback https://nostrcheck.me/alt2.jpg",
            "fallback https://void.cat/alt2.jpg",
            "annotate-user " + p1.PublicKey.ToHex() + ":200:300",
        };

        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000,
            Kind = Nip68Kinds.PicturePost,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "title", "Holiday in Costa Rica" },
                imeta1,
                imeta2,
                new[] { "content-warning", "Animals" },
                new[] { "p", p1.PublicKey.ToHex() },
                new[] { "t", "travel" },
                new[] { "t", "costarica" },
                new[] { "location", "Costa Rica" },
                new[] { "g", "d1h7w" },
                new[] { "L", "ISO-639-1" },
                new[] { "l", "en", "ISO-639-1" },
            },
            Content = "First trip to Costa Rica!",
        }.Sign(key);

        var pic = PictureEvent.FromEvent(ev);
        Assert.Equal(2, pic.Attachments.Count);
        Assert.Equal("Holiday in Costa Rica", pic.Title);
        Assert.Equal("First trip to Costa Rica!", pic.Description);
        Assert.Equal(p1.PublicKey, pic.Attachments[1].AnnotatedUsers[0].Pubkey);
        Assert.Equal(200, pic.Attachments[1].AnnotatedUsers[0].PosX);
        Assert.Equal(300, pic.Attachments[1].AnnotatedUsers[0].PosY);
        Assert.Equal(new[] { p1.PublicKey }, pic.TaggedPubkeys);
        Assert.Equal(new[] { "travel", "costarica" }, pic.Hashtags);
        Assert.Equal("Animals", pic.ContentWarning);
        Assert.Equal("Costa Rica", pic.Location);
        Assert.Equal("d1h7w", pic.Geohash);
        Assert.Equal("en", pic.Language);
    }
}
