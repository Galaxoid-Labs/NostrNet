// SPDX-License-Identifier: MIT

using NostrNet.Blossom.Auth;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Blossom.Tests.Auth;

public class BlossomAuthTokenTests
{
    private const string ExampleHash = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";

    [Fact]
    public void Builder_EmitsRequiredTags_AndIsSignable()
    {
        using var key = PrivateKey.Generate();
        var ev = BlossomAuthToken
            .Create(BlossomAuthVerb.Upload, "Upload Blob")
            .ScopeToBlob(ExampleHash)
            .ScopeToServer("cdn.example.com")
            .WithExpiration(DateTimeOffset.UtcNow.AddMinutes(10))
            .BuildAndSign(key);

        Assert.True(ev.Verify());
        Assert.Equal(BlossomAuthKinds.Authorization, ev.Kind);
        Assert.Equal("Upload Blob", ev.Content);
        Assert.Contains(ev.Tags, t => t.Count >= 2 && t[0] == "t" && t[1] == "upload");
        Assert.Contains(ev.Tags, t => t.Count >= 2 && t[0] == "expiration");
        Assert.Contains(ev.Tags, t => t.Count >= 2 && t[0] == "x" && t[1] == ExampleHash);
        Assert.Contains(ev.Tags, t => t.Count >= 2 && t[0] == "server" && t[1] == "cdn.example.com");
    }

    [Fact]
    public void Builder_RejectsExpirationInThePast()
    {
        using var key = PrivateKey.Generate();
        Assert.Throws<InvalidOperationException>(() =>
            BlossomAuthToken.Create(BlossomAuthVerb.Get, "x")
                .WithExpiration(DateTimeOffset.UtcNow.AddMinutes(-10))
                .BuildAndSign(key));
    }

    [Fact]
    public void Builder_RejectsBadSha()
    {
        Assert.Throws<ArgumentException>(() =>
            BlossomAuthToken.Create(BlossomAuthVerb.Upload, "x").ScopeToBlob("tooshort"));
    }

    [Fact]
    public void Header_RoundTripsThroughBase64Url()
    {
        using var key = PrivateKey.Generate();
        var ev = BlossomAuthToken
            .Create(BlossomAuthVerb.Delete, "Delete blob")
            .ScopeToBlob(ExampleHash)
            .BuildAndSign(key);

        string header = BlossomAuthToken.ToAuthorizationHeader(ev);

        // No padding / URL-safe alphabet.
        Assert.DoesNotContain('=', header);
        Assert.DoesNotContain('+', header);
        Assert.DoesNotContain('/', header);

        var decoded = BlossomAuthToken.TryFromAuthorizationHeader(header);
        Assert.NotNull(decoded);
        Assert.Equal(ev.Id, decoded!.Id);
        Assert.Equal(BlossomAuthKinds.Authorization, decoded.Kind);

        // "Nostr <token>" form decodes too.
        var alsoDecoded = BlossomAuthToken.TryFromAuthorizationHeader("Nostr " + header);
        Assert.NotNull(alsoDecoded);
        Assert.Equal(ev.Id, alsoDecoded!.Id);
    }

    [Fact]
    public void TryFromHeader_ReturnsNullOnGarbage()
    {
        Assert.Null(BlossomAuthToken.TryFromAuthorizationHeader("not-base64-url"));
        Assert.Null(BlossomAuthToken.TryFromAuthorizationHeader(""));
    }

    [Fact]
    public void Header_RejectsNonAuthEvents()
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

        Assert.Throws<ArgumentException>(() => BlossomAuthToken.ToAuthorizationHeader(note));
    }
}
