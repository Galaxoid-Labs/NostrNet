// SPDX-License-Identifier: MIT
//
// Tests for NIP-05 verification. HTTP is mocked via a custom HttpMessageHandler
// so tests are hermetic.

using System.Net;
using System.Net.Http;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Profiles;
using NostrNet.Relay;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Tests.Relay;

public class Nip05Tests
{
    // ----- Identifier parsing.

    [Theory]
    [InlineData("bob@example.com", "bob", "example.com")]
    [InlineData("BOB@Example.com", "bob", "example.com")]      // lowercased
    [InlineData("example.com", "_", "example.com")]            // bare domain → root local
    [InlineData("@example.com", "_", "example.com")]           // empty local → root
    [InlineData("a.b-c_d@sub.example.io", "a.b-c_d", "sub.example.io")]
    public void ParseIdentifier_ValidInputs(string input, string expectedLocal, string expectedDomain)
    {
        Assert.True(Nip05.TryParseIdentifier(input, out var local, out var domain));
        Assert.Equal(expectedLocal, local);
        Assert.Equal(expectedDomain, domain);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("bob with space@example.com")]
    [InlineData("bob@.example.com")]      // leading dot
    [InlineData("bob@example.com.")]      // trailing dot
    [InlineData("bob@exa..mple.com")]     // double dot
    [InlineData("bob$@example.com")]      // invalid char
    public void ParseIdentifier_RejectsMalformed(string input)
    {
        Assert.False(Nip05.TryParseIdentifier(input, out _, out _));
    }

    // ----- Verification with mocked HTTP.

    [Fact]
    public async Task VerifyAsync_PubkeyIdentifier_SuccessWhenNamesMatches()
    {
        using var key = PrivateKey.Generate();
        string expectedHex = key.PublicKey.ToHex();

        using var client = StubClient((req, _) =>
        {
            Assert.Equal("/.well-known/nostr.json", req.RequestUri!.AbsolutePath);
            Assert.Equal("name=bob", req.RequestUri.Query.TrimStart('?'));
            string body = $$"""
                {
                  "names": { "bob": "{{expectedHex}}" },
                  "relays": { "{{expectedHex}}": ["wss://relay.example.com"] }
                }
                """;
            return JsonResponse(body);
        });

        var result = await Nip05.VerifyAsync(key.PublicKey, "bob@example.com", client);

        Assert.True(result.IsVerified, result.FailureReason);
        Assert.Equal("bob@example.com", result.Identifier);
        Assert.Equal(key.PublicKey, result.Pubkey);
        Assert.Single(result.Relays);
        Assert.Equal("wss://relay.example.com", result.Relays[0]);
    }

    [Fact]
    public async Task VerifyAsync_FailsWhenNamesMissing()
    {
        using var key = PrivateKey.Generate();
        using var client = StubClient((_, _) => JsonResponse("""{"names":{}}"""));

        var result = await Nip05.VerifyAsync(key.PublicKey, "bob@example.com", client);
        Assert.False(result.IsVerified);
        Assert.Contains("no entry", result.FailureReason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyAsync_FailsWhenPubkeyMismatch()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        string bobHex = bob.PublicKey.ToHex();

        using var client = StubClient((_, _) =>
            JsonResponse("{\"names\":{\"bob\":\"" + bobHex + "\"}}"));

        // The endpoint claims bob's pubkey for "bob@example.com", but we're
        // verifying against alice — verification must fail.
        var result = await Nip05.VerifyAsync(alice.PublicKey, "bob@example.com", client);
        Assert.False(result.IsVerified);
        Assert.Contains("does not match", result.FailureReason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyAsync_FailsOnHttp404()
    {
        using var key = PrivateKey.Generate();
        using var client = StubClient((_, _) => new HttpResponseMessage(HttpStatusCode.NotFound));

        var result = await Nip05.VerifyAsync(key.PublicKey, "bob@example.com", client);
        Assert.False(result.IsVerified);
        Assert.Contains("HTTP request failed", result.FailureReason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyAsync_BareDomainUsesUnderscoreName()
    {
        using var key = PrivateKey.Generate();
        string hex = key.PublicKey.ToHex();

        using var client = StubClient((req, _) =>
        {
            Assert.Equal("name=_", req.RequestUri!.Query.TrimStart('?'));
            return JsonResponse("{\"names\":{\"_\":\"" + hex + "\"}}");
        });

        var result = await Nip05.VerifyAsync(key.PublicKey, "example.com", client);
        Assert.True(result.IsVerified);
    }

    // ----- VerifyAsync(NostrEvent kind0Event).

    [Fact]
    public async Task VerifyAsync_FromKind0Event_ReadsNip05FromContent()
    {
        using var key = PrivateKey.Generate();
        string hex = key.PublicKey.ToHex();

        var kind0 = BuildKind0(key, $$"""{"name":"bob","nip05":"bob@example.com"}""");

        using var client = StubClient((_, _) =>
            JsonResponse("{\"names\":{\"bob\":\"" + hex + "\"}}"));

        var result = await Nip05.VerifyAsync(kind0, client);
        Assert.True(result.IsVerified, result.FailureReason);
        Assert.Equal("bob@example.com", result.Identifier);
    }

    [Fact]
    public async Task VerifyAsync_FromKind0Event_NoNip05FieldNotVerified()
    {
        using var key = PrivateKey.Generate();
        var kind0 = BuildKind0(key, """{"name":"alice"}""");

        using var client = StubClient((_, _) => throw new InvalidOperationException("should not fetch"));

        var result = await Nip05.VerifyAsync(kind0, client);
        Assert.False(result.IsVerified);
        Assert.Contains("nip05 field", result.FailureReason!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyAsync_FromKind0Event_RejectsNonKind0()
    {
        using var key = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "regular note",
        }.Sign(key);

        await Assert.ThrowsAsync<ArgumentException>(() => Nip05.VerifyAsync(note));
    }

    // ----- VerifyAsync(Profile).

    [Fact]
    public async Task VerifyAsync_FromProfile_UsesOwnerAndNip05()
    {
        using var key = PrivateKey.Generate();
        string hex = key.PublicKey.ToHex();

        var kind0 = BuildKind0(key, $$"""{"name":"bob","nip05":"bob@example.com"}""");
        var profile = Profile.FromEvent(kind0);

        using var client = StubClient((_, _) =>
            JsonResponse("{\"names\":{\"bob\":\"" + hex + "\"}}"));

        var result = await Nip05.VerifyAsync(profile, client);
        Assert.True(result.IsVerified, result.FailureReason);
    }

    [Fact]
    public async Task VerifyAsync_FromProfile_NoOwner_NotVerified()
    {
        var profile = new Profile { Name = "bob", Nip05 = "bob@example.com" };
        using var client = StubClient((_, _) => throw new InvalidOperationException("should not fetch"));

        var result = await Nip05.VerifyAsync(profile, client);
        Assert.False(result.IsVerified);
        Assert.Contains("Owner", result.FailureReason!, StringComparison.OrdinalIgnoreCase);
    }

    // ----- Helpers.

    private static NostrEvent BuildKind0(PrivateKey key, string content) =>
        new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 0,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = content,
        }.Sign(key);

    private static HttpClient StubClient(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> impl)
        => new HttpClient(new StubHandler(impl)) { Timeout = TimeSpan.FromSeconds(5) };

    private static HttpResponseMessage JsonResponse(string body)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, SysEncoding.UTF8, "application/json"),
        };
        return response;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _impl;
        public StubHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> impl) => _impl = impl;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_impl(request, cancellationToken));
    }
}
