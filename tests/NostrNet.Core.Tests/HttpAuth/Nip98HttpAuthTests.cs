// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Http.Headers;
using NostrNet.Events;
using NostrNet.HttpAuth;
using NostrNet.Keys;

namespace NostrNet.Core.Tests.HttpAuth;

public class Nip98HttpAuthTests
{
    private static readonly Uri ExampleUrl = new("https://api.snort.social/api/v1/n5sp/list");

    [Fact]
    public void Builder_GET_RoundTripsThroughHeader()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip98HttpAuth
            .Create(HttpMethod.Get, ExampleUrl)
            .BuildAndSign(key);

        Assert.True(ev.Verify());
        Assert.Equal(Nip98Kinds.HttpAuth, ev.Kind);
        Assert.Empty(ev.Content);

        string header = Nip98HttpAuth.ToAuthorizationHeader(ev);
        var decoded = Nip98HttpAuth.TryFromAuthorizationHeader(header);
        Assert.NotNull(decoded);
        Assert.Equal(ev.Id, decoded!.Id);

        var alsoDecoded = Nip98HttpAuth.TryFromAuthorizationHeader("Nostr " + header);
        Assert.NotNull(alsoDecoded);
        Assert.Equal(ev.Id, alsoDecoded!.Id);
    }

    [Fact]
    public void Builder_POST_WithPayloadHashesBody()
    {
        using var key = PrivateKey.Generate();
        byte[] body = System.Text.Encoding.UTF8.GetBytes("hello server");

        var ev = Nip98HttpAuth
            .Create(HttpMethod.Post, ExampleUrl)
            .WithPayload(body)
            .BuildAndSign(key);

        var payloadTag = ev.Tags.First(t => t.Count >= 2 && t[0] == "payload");
        // sha256("hello server") = 25a4d6...
        using var sha = System.Security.Cryptography.SHA256.Create();
        string expected = Convert.ToHexStringLower(sha.ComputeHash(body));
        Assert.Equal(expected, payloadTag[1]);
    }

    [Fact]
    public void ToHeaderValue_ProducesAuthenticationHeaderValue()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip98HttpAuth.Create("GET", ExampleUrl).BuildAndSign(key);
        AuthenticationHeaderValue header = Nip98HttpAuth.ToHeaderValue(ev);
        Assert.Equal("Nostr", header.Scheme);
        Assert.False(string.IsNullOrEmpty(header.Parameter));
    }

    [Fact]
    public void ToAuthorizationHeader_RejectsNonAuthEvents()
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

        Assert.Throws<ArgumentException>(() => Nip98HttpAuth.ToAuthorizationHeader(note));
    }

    [Fact]
    public void TryFromAuthorizationHeader_ReturnsNullOnGarbage()
    {
        Assert.Null(Nip98HttpAuth.TryFromAuthorizationHeader("not-base64"));
        Assert.Null(Nip98HttpAuth.TryFromAuthorizationHeader(""));
        // Valid base64 but not Nostr-event JSON.
        Assert.Null(Nip98HttpAuth.TryFromAuthorizationHeader(
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{}"))));
    }

    // ────────────────────────────────────────────────────────────
    // Validation
    // ────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_HappyPath_GET()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip98HttpAuth.Create(HttpMethod.Get, ExampleUrl).BuildAndSign(key);
        var result = Nip98HttpAuth.Validate(ev, HttpMethod.Get, ExampleUrl);
        Assert.True(result.IsValid);
        Assert.Null(result.Failure);
        Assert.Equal(key.PublicKey, result.Author);
    }

    [Fact]
    public void Validate_HappyPath_POST_WithPayload()
    {
        using var key = PrivateKey.Generate();
        byte[] body = System.Text.Encoding.UTF8.GetBytes("write me");

        var ev = Nip98HttpAuth
            .Create(HttpMethod.Post, ExampleUrl)
            .WithPayload(body)
            .BuildAndSign(key);
        var result = Nip98HttpAuth.Validate(ev, HttpMethod.Post, ExampleUrl, body);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_FailsOnMethodMismatch()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip98HttpAuth.Create(HttpMethod.Get, ExampleUrl).BuildAndSign(key);
        var result = Nip98HttpAuth.Validate(ev, HttpMethod.Post, ExampleUrl);
        Assert.False(result.IsValid);
        Assert.Equal(Nip98ValidationFailure.MethodMismatch, result.Failure);
    }

    [Fact]
    public void Validate_FailsOnUrlMismatch()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip98HttpAuth.Create(HttpMethod.Get, ExampleUrl).BuildAndSign(key);
        var result = Nip98HttpAuth.Validate(ev, HttpMethod.Get, new Uri("https://other.example/api"));
        Assert.False(result.IsValid);
        Assert.Equal(Nip98ValidationFailure.UrlMismatch, result.Failure);
    }

    [Fact]
    public void Validate_FailsOnExpired()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip98HttpAuth
            .Create(HttpMethod.Get, ExampleUrl)
            .WithCreatedAt(DateTimeOffset.UtcNow.AddMinutes(-10))
            .BuildAndSign(key);
        var result = Nip98HttpAuth.Validate(ev, HttpMethod.Get, ExampleUrl);
        Assert.False(result.IsValid);
        Assert.Equal(Nip98ValidationFailure.Expired, result.Failure);
    }

    [Fact]
    public void Validate_FailsOnPayloadMismatch()
    {
        using var key = PrivateKey.Generate();
        byte[] originalBody = System.Text.Encoding.UTF8.GetBytes("original");
        byte[] tamperedBody = System.Text.Encoding.UTF8.GetBytes("tampered");

        var ev = Nip98HttpAuth
            .Create(HttpMethod.Post, ExampleUrl)
            .WithPayload(originalBody)
            .BuildAndSign(key);

        var result = Nip98HttpAuth.Validate(ev, HttpMethod.Post, ExampleUrl, tamperedBody);
        Assert.False(result.IsValid);
        Assert.Equal(Nip98ValidationFailure.PayloadHashMismatch, result.Failure);
    }

    [Fact]
    public void Validate_FailsOnWrongKind()
    {
        using var key = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "x",
        }.Sign(key);

        var result = Nip98HttpAuth.Validate(note, HttpMethod.Get, ExampleUrl);
        Assert.False(result.IsValid);
        Assert.Equal(Nip98ValidationFailure.WrongKind, result.Failure);
    }

    [Fact]
    public void Validate_FailsOnBadSignature()
    {
        using var key = PrivateKey.Generate();
        var ev = Nip98HttpAuth.Create(HttpMethod.Get, ExampleUrl).BuildAndSign(key);

        // Tamper with the URL tag — id won't recompute to ev.Id, so
        // signature verification fails.
        var tamperedTags = ev.Tags.Select(t =>
            (IReadOnlyList<string>)(t[0] == "u" ? new[] { "u", "https://different.example" } : t.ToArray()))
            .ToArray();
        var tampered = new NostrEvent
        {
            Id = ev.Id,
            PubKey = ev.PubKey,
            CreatedAt = ev.CreatedAt,
            Kind = ev.Kind,
            Tags = tamperedTags,
            Content = ev.Content,
            Sig = ev.Sig,
        };

        var result = Nip98HttpAuth.Validate(tampered, HttpMethod.Get, new Uri("https://different.example"));
        Assert.False(result.IsValid);
        Assert.Equal(Nip98ValidationFailure.BadSignature, result.Failure);
    }

    // ────────────────────────────────────────────────────────────
    // DelegatingHandler
    // ────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuthHandler_AttachesNostrAuthorizationToOutgoingRequests()
    {
        using var key = PrivateKey.Generate();
        AuthenticationHeaderValue? observedAuth = null;
        var fake = new FakeHandler((req, _) =>
        {
            observedAuth = req.Headers.Authorization;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        using var http = new HttpClient(new Nip98AuthHandler(key) { InnerHandler = fake });
        await http.GetAsync(ExampleUrl);

        Assert.NotNull(observedAuth);
        Assert.Equal("Nostr", observedAuth!.Scheme);
        var decoded = Nip98HttpAuth.TryFromAuthorizationHeader(observedAuth.Parameter!);
        Assert.NotNull(decoded);
        var result = Nip98HttpAuth.Validate(decoded!, HttpMethod.Get, ExampleUrl);
        Assert.True(result.IsValid);
        Assert.Equal(key.PublicKey, result.Author);
    }

    [Fact]
    public async Task AuthHandler_HashesPostBody_AndPreservesBodyForInnerHandler()
    {
        using var key = PrivateKey.Generate();
        byte[]? bodySeenByServer = null;
        AuthenticationHeaderValue? observedAuth = null;
        var fake = new FakeHandler(async (req, ct) =>
        {
            observedAuth = req.Headers.Authorization;
            bodySeenByServer = req.Content is not null
                ? await req.Content.ReadAsByteArrayAsync(ct)
                : null;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        using var http = new HttpClient(new Nip98AuthHandler(key) { InnerHandler = fake });
        byte[] body = System.Text.Encoding.UTF8.GetBytes("hello server");
        using var content = new ByteArrayContent(body);
        await http.PostAsync(ExampleUrl, content);

        // The inner handler must still see the body bytes — auto-
        // hashing shouldn't drain the request stream.
        Assert.NotNull(bodySeenByServer);
        Assert.Equal(body, bodySeenByServer);

        // The auth token's payload tag should match the body hash.
        Assert.NotNull(observedAuth);
        var decoded = Nip98HttpAuth.TryFromAuthorizationHeader(observedAuth!.Parameter!);
        Assert.NotNull(decoded);
        var result = Nip98HttpAuth.Validate(decoded!, HttpMethod.Post, ExampleUrl, body);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task AuthHandler_SkipsPayloadHashing_WhenDisabled()
    {
        using var key = PrivateKey.Generate();
        AuthenticationHeaderValue? observedAuth = null;
        var fake = new FakeHandler((req, _) =>
        {
            observedAuth = req.Headers.Authorization;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        using var http = new HttpClient(new Nip98AuthHandler(key, hashRequestBodies: false) { InnerHandler = fake });
        using var content = new ByteArrayContent(System.Text.Encoding.UTF8.GetBytes("body"));
        await http.PostAsync(ExampleUrl, content);

        var decoded = Nip98HttpAuth.TryFromAuthorizationHeader(observedAuth!.Parameter!);
        Assert.NotNull(decoded);
        Assert.DoesNotContain(decoded!.Tags, t => t.Count >= 2 && t[0] == "payload");
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;

        public FakeHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> sync)
            => _send = (r, c) => Task.FromResult(sync(r, c));

        public FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> async)
            => _send = async;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => _send(request, cancellationToken);
    }
}
