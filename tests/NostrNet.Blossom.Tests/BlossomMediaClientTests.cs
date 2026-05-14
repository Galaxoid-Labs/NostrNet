// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Http.Headers;
using NostrNet.Blossom.Blobs;
using NostrNet.Blossom.Client;
using NostrNet.Keys;

namespace NostrNet.Blossom.Tests;

public class BlossomMediaClientTests
{
    private const string ExampleMime = "image/png";

    [Fact]
    public async Task UploadAsync_UploadsToPrimary_AndMirrorsToRest()
    {
        var primaryUploads = 0;
        var mirrorBHits = 0;
        var mirrorCHits = 0;
        string? expectedSha = null;

        var handler = new FakeHandler((req, _) =>
        {
            switch (req.RequestUri!.Host)
            {
                case "a.example":
                    // Primary: regular upload.
                    Assert.Equal(HttpMethod.Put, req.Method);
                    Assert.EndsWith("/upload", req.RequestUri.AbsoluteUri);
                    Assert.True(req.Headers.Contains("Authorization"));
                    Assert.Equal("Nostr", req.Headers.Authorization!.Scheme);
                    primaryUploads++;
                    expectedSha = req.Content!.Headers.GetValues("X-SHA-256").Single();
                    return DescriptorResponse(expectedSha, HttpStatusCode.Created);

                case "b.example":
                    mirrorBHits++;
                    Assert.EndsWith("/mirror", req.RequestUri.AbsoluteUri);
                    return DescriptorResponse(expectedSha!, HttpStatusCode.Created);

                case "c.example":
                    mirrorCHits++;
                    Assert.EndsWith("/mirror", req.RequestUri.AbsoluteUri);
                    return DescriptorResponse(expectedSha!, HttpStatusCode.Created);

                default:
                    throw new InvalidOperationException(req.RequestUri.AbsoluteUri);
            }
        });

        using var http = new HttpClient(handler);
        using var key = PrivateKey.Generate();
        using var media = BlossomMediaClient.Builder(key)
            .UseHttpClient(http)
            .UseServers("https://a.example", "https://b.example", "https://c.example")
            .Build();

        byte[] bytes = new byte[] { 1, 2, 3, 4 };
        var result = await media.UploadAsync(bytes, ExampleMime);

        Assert.Equal(1, primaryUploads);
        Assert.Equal(1, mirrorBHits);
        Assert.Equal(1, mirrorCHits);
        Assert.Equal(BlossomMediaClient.ComputeSha256(bytes), result.Sha256);
        Assert.Equal("https://a.example", result.PrimaryServer);
        Assert.Equal(2, result.Mirrors.Count);
        Assert.All(result.Mirrors.Values, m => Assert.True(m.IsSuccess));
    }

    [Fact]
    public async Task UploadAsync_RecordsMirrorFailures_DoesNotThrow()
    {
        var handler = new FakeHandler((req, _) =>
        {
            if (req.RequestUri!.Host == "a.example")
            {
                return DescriptorResponse(SyntheticHash(req), HttpStatusCode.Created);
            }

            // b.example refuses to mirror.
            return new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent("nope"),
            };
        });

        using var http = new HttpClient(handler);
        using var key = PrivateKey.Generate();
        using var media = BlossomMediaClient.Builder(key)
            .UseHttpClient(http)
            .UseServers("https://a.example", "https://b.example")
            .Build();

        var result = await media.UploadAsync(new byte[] { 1, 2 }, ExampleMime);
        Assert.Equal("https://a.example", result.PrimaryServer);
        Assert.Single(result.Mirrors);
        Assert.False(result.Mirrors["https://b.example"].IsSuccess);
        Assert.IsType<BlossomHttpException>(result.Mirrors["https://b.example"].Failure);
    }

    [Fact]
    public async Task UploadAsync_MirrorDisabled_OnlyHitsPrimary()
    {
        var hits = new List<string>();
        var handler = new FakeHandler((req, _) =>
        {
            hits.Add(req.RequestUri!.Host);
            return DescriptorResponse(SyntheticHash(req), HttpStatusCode.Created);
        });

        using var http = new HttpClient(handler);
        using var key = PrivateKey.Generate();
        using var media = BlossomMediaClient.Builder(key)
            .UseHttpClient(http)
            .UseServers("https://a.example", "https://b.example")
            .Build();

        var result = await media.UploadAsync(new byte[] { 7 }, ExampleMime, mirrorToAllServers: false);
        Assert.Empty(result.Mirrors);
        Assert.Equal(new[] { "a.example" }, hits);
    }

    [Fact]
    public async Task UploadAsync_ThrowsWhenNoServersConfigured()
    {
        using var http = new HttpClient(new FakeHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)));
        using var key = PrivateKey.Generate();
        using var media = BlossomMediaClient.Builder(key).UseHttpClient(http).Build();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            media.UploadAsync(new byte[] { 1 }, ExampleMime));
    }

    [Fact]
    public async Task DownloadAsync_UsesMyServersBeforeAuthorHints()
    {
        const string Hash = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
        var hits = new List<string>();
        var handler = new FakeHandler((req, _) =>
        {
            hits.Add(req.RequestUri!.AbsoluteUri);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[] { 1 }),
            };
        });

        using var http = new HttpClient(handler);
        using var key = PrivateKey.Generate();
        using var media = BlossomMediaClient.Builder(key)
            .UseHttpClient(http)
            .UseServers("https://my.example")
            .Build();

        var blob = await media.DownloadAsync(Hash);
        Assert.NotNull(blob);
        Assert.Equal("https://my.example/", blob!.ServerUrl);
        Assert.Single(hits);
        Assert.Contains("my.example", hits[0]);
    }

    [Fact]
    public async Task DownloadAsync_BlossomUri_UriHintsTakePrecedence()
    {
        const string Hash = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
        var hits = new List<string>();
        var handler = new FakeHandler((req, _) =>
        {
            hits.Add(req.RequestUri!.Host);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[] { 1 }),
            };
        });

        using var http = new HttpClient(handler);
        using var key = PrivateKey.Generate();
        using var media = BlossomMediaClient.Builder(key)
            .UseHttpClient(http)
            .UseServers("https://mine.example")
            .Build();

        var uri = new BlossomUri
        {
            Sha256 = Hash,
            Extension = "png",
            ServerHints = new[] { "https://from-uri.example" },
        };
        var blob = await media.DownloadAsync(uri);
        Assert.NotNull(blob);
        // URI hint MUST be tried first; "mine.example" only goes
        // into the candidate list after URI hints + author hints.
        Assert.Equal("from-uri.example", hits[0]);
    }

    [Fact]
    public async Task ListMyBlobs_AggregatesAcrossServers_DedupsBySha()
    {
        using var owner = PrivateKey.Generate();
        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Get, req.Method);
            // Each server returns one blob; sha "aa..." appears on both.
            string body = req.RequestUri!.Host switch
            {
                "a.example" => """[{"url":"https://a.example/x.bin","sha256":"aa","size":1,"type":"application/octet-stream","uploaded":1}]""",
                "b.example" => """[{"url":"https://b.example/x.bin","sha256":"aa","size":1,"type":"application/octet-stream","uploaded":1},{"url":"https://b.example/y.bin","sha256":"bb","size":2,"type":"application/octet-stream","uploaded":2}]""",
                _ => "[]",
            };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
            };
        });

        using var http = new HttpClient(handler);
        using var media = BlossomMediaClient.Builder(owner)
            .UseHttpClient(http)
            .UseServers("https://a.example", "https://b.example")
            .Build();

        var blobs = await media.ListMyBlobsAsync();
        Assert.Equal(2, blobs.Count);
        Assert.Contains(blobs, b => b.Sha256 == "aa");
        Assert.Contains(blobs, b => b.Sha256 == "bb");
        // a.example wins the duplicate (it appears first in the server order).
        var aa = blobs.First(b => b.Sha256 == "aa");
        Assert.Equal("https://a.example/x.bin", aa.Url);
    }

    [Fact]
    public async Task ListMyBlobs_TolerateServersThatReject()
    {
        using var owner = PrivateKey.Generate();
        var handler = new FakeHandler((req, _) =>
        {
            if (req.RequestUri!.Host == "blocked.example")
            {
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """[{"url":"https://ok.example/x.bin","sha256":"cc","size":1,"type":"application/octet-stream","uploaded":1}]""",
                    System.Text.Encoding.UTF8, "application/json"),
            };
        });

        using var http = new HttpClient(handler);
        using var media = BlossomMediaClient.Builder(owner)
            .UseHttpClient(http)
            .UseServers("https://blocked.example", "https://ok.example")
            .Build();

        var blobs = await media.ListMyBlobsAsync();
        Assert.Single(blobs);
        Assert.Equal("cc", blobs[0].Sha256);
    }

    [Fact]
    public async Task DeleteAsync_ReportsPerServerOutcome()
    {
        using var key = PrivateKey.Generate();
        const string Hash = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";

        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Delete, req.Method);
            Assert.Equal("Nostr", req.Headers.Authorization!.Scheme);
            return req.RequestUri!.Host switch
            {
                "okay.example" => new HttpResponseMessage(HttpStatusCode.NoContent),
                "gone.example" => new HttpResponseMessage(HttpStatusCode.NotFound),
                "policy.example" => new HttpResponseMessage(HttpStatusCode.Forbidden),
                _ => new HttpResponseMessage(HttpStatusCode.InternalServerError),
            };
        });

        using var http = new HttpClient(handler);
        using var media = BlossomMediaClient.Builder(key)
            .UseHttpClient(http)
            .UseServers("https://okay.example", "https://gone.example", "https://policy.example")
            .Build();

        var result = await media.DeleteAsync(Hash);
        Assert.True(result["https://okay.example"]);  // 204
        Assert.False(result["https://gone.example"]); // 404 → already gone (we report false here for "not present")
        Assert.False(result["https://policy.example"]); // 403 → BlossomHttpException → false
    }

    [Fact]
    public async Task UploadAsync_StreamOverload_HashesIdentically()
    {
        var handler = new FakeHandler((req, _) =>
        {
            return DescriptorResponse(SyntheticHash(req), HttpStatusCode.Created);
        });

        using var http = new HttpClient(handler);
        using var key = PrivateKey.Generate();
        using var media = BlossomMediaClient.Builder(key)
            .UseHttpClient(http)
            .UseServers("https://a.example")
            .Build();

        byte[] data = System.Text.Encoding.UTF8.GetBytes("hello blossom");
        using var ms = new MemoryStream(data);
        var streamResult = await media.UploadAsync(ms, "text/plain");

        var bytesResult = await media.UploadAsync(data, "text/plain");
        Assert.Equal(streamResult.Sha256, bytesResult.Sha256);
    }

    [Fact]
    public void Builder_NoServers_AndNoUpload_IsValid()
    {
        using var key = PrivateKey.Generate();
        using var media = BlossomMediaClient.Builder(key).Build();
        Assert.Empty(media.Servers);
    }

    private static HttpResponseMessage DescriptorResponse(string sha, HttpStatusCode code)
    {
        string body = $$"""
            {"url":"https://example.com/{{sha}}.bin","sha256":"{{sha}}","size":4,"type":"application/octet-stream","uploaded":1}
            """;
        return new HttpResponseMessage(code)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
        };
    }

    // Best-effort: when a request has X-SHA-256 pinned, echo it back.
    // For mirror calls (no X-SHA-256) we just return a placeholder.
    private static string SyntheticHash(HttpRequestMessage req)
    {
        if (req.Content?.Headers.TryGetValues("X-SHA-256", out var values) == true)
        {
            return values.First();
        }

        return new string('a', 64);
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _send;
        public FakeHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> send) => _send = send;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_send(request, cancellationToken));
    }
}
