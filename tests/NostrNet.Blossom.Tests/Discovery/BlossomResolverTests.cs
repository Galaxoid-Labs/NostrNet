// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Http.Headers;
using NostrNet.Blossom.Blobs;
using NostrNet.Blossom.Discovery;

namespace NostrNet.Blossom.Tests.Discovery;

public class BlossomResolverTests
{
    private const string Hash =
        "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";

    [Fact]
    public async Task ResolveAsync_ReturnsFirstSuccessfulServerHit()
    {
        var seen = new List<string>();
        var handler = new FakeHandler((req, _) =>
        {
            seen.Add(req.RequestUri!.AbsoluteUri);
            // The first server 404s; the second returns bytes.
            if (req.RequestUri!.Host == "first.example")
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[] { 1, 2, 3 })
                {
                    Headers = { ContentType = new MediaTypeHeaderValue("image/png") },
                },
            };
        });

        using var http = new HttpClient(handler);
        using var resolver = new BlossomResolver(http);

        var blob = await resolver.ResolveAsync(
            new BlossomUri
            {
                Sha256 = Hash,
                Extension = "png",
                ServerHints = new[] { "first.example", "second.example" },
            });

        Assert.NotNull(blob);
        Assert.Equal(new byte[] { 1, 2, 3 }, blob!.Bytes);
        Assert.Equal("image/png", blob.ContentType);
        Assert.Equal("https://second.example/", blob.ServerUrl);
        // BUD-10: domain-only hints get https first. We should see two
        // https requests (one per server) before the second succeeds.
        Assert.Equal($"https://first.example/{Hash}.png", seen[0]);
    }

    [Fact]
    public async Task ResolveAsync_ReturnsNullWhenEveryCandidate404s()
    {
        var handler = new FakeHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.NotFound));

        using var http = new HttpClient(handler);
        using var resolver = new BlossomResolver(http);

        var blob = await resolver.ResolveAsync(
            Hash,
            serverHints: new[] { "a.example", "b.example" });

        Assert.Null(blob);
    }

    [Fact]
    public async Task ResolveAsync_DomainOnlyHint_FallsBackHttp_AfterHttpsFails()
    {
        var seen = new List<string>();
        var handler = new FakeHandler((req, _) =>
        {
            seen.Add(req.RequestUri!.AbsoluteUri);
            if (req.RequestUri.Scheme == "https")
            {
                // Simulate a TLS error / cert-bad-server by 503'ing.
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[] { 9, 9, 9 }),
            };
        });

        using var http = new HttpClient(handler);
        using var resolver = new BlossomResolver(http);

        var blob = await resolver.ResolveAsync(Hash, serverHints: new[] { "fallback.example" });
        Assert.NotNull(blob);
        Assert.Equal("http://fallback.example/", blob!.ServerUrl);
        Assert.Equal(new byte[] { 9, 9, 9 }, blob.Bytes);
        Assert.Equal(2, seen.Count);
        Assert.StartsWith("https://", seen[0]);
        Assert.StartsWith("http://", seen[1]);
    }

    [Fact]
    public async Task ResolveAsync_HonorsExplicitSchemeInServerHint()
    {
        var seen = new List<string>();
        var handler = new FakeHandler((req, _) =>
        {
            seen.Add(req.RequestUri!.AbsoluteUri);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[] { 1 }),
            };
        });

        using var http = new HttpClient(handler);
        using var resolver = new BlossomResolver(http);

        await resolver.ResolveAsync(Hash, serverHints: new[] { "http://only-http.example" });
        Assert.Single(seen);
        Assert.StartsWith("http://", seen[0]);
    }

    [Fact]
    public async Task ResolveAsync_SkipsServerWhenSizeMismatchesHead()
    {
        // sz=10 but the wrong server's HEAD reports Content-Length=99
        // — resolver should skip without doing the GET. Second server
        // returns the right length and bytes.
        int wrongHeads = 0, wrongGets = 0;
        int rightHits = 0;
        var handler = new FakeHandler((req, _) =>
        {
            if (req.RequestUri!.Host == "wrong.example")
            {
                if (req.Method == HttpMethod.Head)
                {
                    wrongHeads++;
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(Array.Empty<byte>())
                        {
                            Headers = { ContentLength = 99 },
                        },
                    };
                }

                wrongGets++;
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(new byte[99]),
                };
            }

            // right.example — HEAD says 10, GET delivers 10 bytes.
            if (req.Method == HttpMethod.Head)
            {
                rightHits++;
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(Array.Empty<byte>())
                    {
                        Headers = { ContentLength = 10 },
                    },
                };
            }

            rightHits++;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[10]),
            };
        });

        using var http = new HttpClient(handler);
        using var resolver = new BlossomResolver(http);

        var blob = await resolver.ResolveAsync(
            Hash,
            // Use explicit schemes so we don't double-probe with http fallback.
            serverHints: new[] { "https://wrong.example", "https://right.example" },
            expectedSize: 10);

        Assert.NotNull(blob);
        Assert.Equal(10, blob!.Bytes.Length);
        Assert.Equal("https://right.example/", blob.ServerUrl);
        Assert.Equal(1, wrongHeads);
        Assert.Equal(0, wrongGets);  // never bothered to GET
        Assert.Equal(2, rightHits);  // HEAD + GET on right.example
    }

    [Fact]
    public async Task ResolveAsync_ReturnsNullWhenBodySizeDiffersFromExpected()
    {
        // The server returns the wrong number of bytes despite a
        // plausible Content-Length-less HEAD. Resolver must reject.
        var handler = new FakeHandler((req, _) =>
        {
            if (req.Method == HttpMethod.Head)
            {
                // No Content-Length advertised — resolver should still GET.
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[5]),
            };
        });

        using var http = new HttpClient(handler);
        using var resolver = new BlossomResolver(http);

        var blob = await resolver.ResolveAsync(
            Hash,
            serverHints: new[] { "one.example" },
            expectedSize: 10);
        Assert.Null(blob);
    }

    [Fact]
    public async Task ResolveBrokenUrlAsync_ExtractsHashAndTriesFallbackServers()
    {
        bool fallbackHit = false;
        var handler = new FakeHandler((req, _) =>
        {
            fallbackHit |= req.RequestUri!.Host == "fallback.example";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[] { 7 }),
            };
        });

        using var http = new HttpClient(handler);
        using var resolver = new BlossomResolver(
            http,
            nostrClient: null,
            fallbackServers: new[] { "fallback.example" });

        var blob = await resolver.ResolveBrokenUrlAsync(
            brokenUrl: $"https://cdn.broken.example/{Hash}.pdf",
            authorHints: null);

        Assert.NotNull(blob);
        Assert.Equal(Hash, blob!.Sha256);
        Assert.True(fallbackHit);
    }

    [Fact]
    public async Task ResolveBrokenUrlAsync_ReturnsNullWhenNoHashExtractable()
    {
        using var http = new HttpClient(new FakeHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.OK)));
        using var resolver = new BlossomResolver(http);

        var blob = await resolver.ResolveBrokenUrlAsync(
            "https://example.com/no-hash-here",
            authorHints: null);
        Assert.Null(blob);
    }

    [Fact]
    public async Task ResolveAsync_NoNostrClient_SilentlySkipsAuthorHints()
    {
        // The resolver was constructed without a NostrClient. Author
        // hints should be ignored (no exception), and the resolver
        // returns null when there are no server-hint or fallback
        // routes either.
        using var http = new HttpClient(new FakeHandler((_, _) =>
            new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var resolver = new BlossomResolver(http);

        var blob = await resolver.ResolveAsync(
            Hash,
            authorHints: new[] { NostrNet.Keys.PrivateKey.Generate().PublicKey });
        Assert.Null(blob);
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _send;

        public FakeHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> send)
        {
            _send = send;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_send(request, cancellationToken));
    }
}
