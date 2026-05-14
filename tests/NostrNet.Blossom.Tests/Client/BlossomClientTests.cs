// SPDX-License-Identifier: MIT
//
// Drives BlossomClient against an in-process HttpMessageHandler that
// replays canned responses, so we cover the wire layout (URLs,
// methods, auth header) without needing a real Blossom server.

using System.Net;
using System.Net.Http.Headers;
using NostrNet.Blossom.Auth;
using NostrNet.Blossom.Blobs;
using NostrNet.Blossom.Client;
using NostrNet.Keys;

namespace NostrNet.Blossom.Tests.Client;

public class BlossomClientTests
{
    private const string Hash = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
    private static readonly Uri ServerBase = new("https://cdn.example.com/");

    [Fact]
    public async Task GetBlob_HitsRootRelativePath()
    {
        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Get, req.Method);
            Assert.Equal($"https://cdn.example.com/{Hash}.pdf", req.RequestUri!.AbsoluteUri);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[] { 1, 2, 3, 4 })
                {
                    Headers = { ContentType = new MediaTypeHeaderValue("application/pdf") },
                },
            };
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        var bytes = await client.GetBlobBytesAsync(Hash, "pdf");
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, bytes);
    }

    [Fact]
    public async Task HeadBlob_Returns404AsNull()
    {
        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Head, req.Method);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        Assert.Null(await client.HeadBlobAsync(Hash));
    }

    [Fact]
    public async Task HeadBlob_SurfacesMetadataHeaders()
    {
        var handler = new FakeHandler((req, _) =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Array.Empty<byte>())
                {
                    Headers =
                    {
                        ContentType = new MediaTypeHeaderValue("video/mp4"),
                        ContentLength = 1_234_567,
                    },
                },
            };
            resp.Headers.AcceptRanges.Add("bytes");
            resp.Headers.Add("Sunset", "Wed, 11 Nov 2026 11:11:11 GMT");
            return resp;
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        var head = await client.HeadBlobAsync(Hash);
        Assert.NotNull(head);
        Assert.Equal("video/mp4", head!.ContentType);
        Assert.Equal(1_234_567, head.ContentLength);
        Assert.True(head.AcceptsRanges);
        Assert.Equal("Wed, 11 Nov 2026 11:11:11 GMT", head.Sunset);
    }

    [Fact]
    public async Task Upload_AttachesNostrAuthorizationHeader()
    {
        using var key = PrivateKey.Generate();
        var auth = BlossomAuthToken
            .Create(BlossomAuthVerb.Upload, "Upload Blob")
            .ScopeToBlob(Hash)
            .BuildAndSign(key);

        AuthenticationHeaderValue? receivedAuth = null;
        string? receivedXSha = null;
        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Put, req.Method);
            Assert.Equal("https://cdn.example.com/upload", req.RequestUri!.AbsoluteUri);
            receivedAuth = req.Headers.Authorization;
            receivedXSha = req.Content!.Headers.GetValues("X-SHA-256").FirstOrDefault();

            string descriptor = $$"""
            {"url":"https://cdn.example.com/{{Hash}}.bin","sha256":"{{Hash}}","size":4,"type":"application/octet-stream","uploaded":1}
            """;
            return new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent(descriptor, System.Text.Encoding.UTF8, "application/json"),
            };
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);

        using var content = new ByteArrayContent(new byte[] { 1, 2, 3, 4 });
        var desc = await client.UploadAsync(content, auth, expectedSha256: Hash);

        Assert.Equal(BlossomAuthToken.Scheme, receivedAuth!.Scheme);
        Assert.False(string.IsNullOrEmpty(receivedAuth.Parameter));
        Assert.Equal(Hash, receivedXSha);
        Assert.Equal(Hash, desc.Sha256);
    }

    [Fact]
    public async Task ServerError_ThrowsWithReason()
    {
        var handler = new FakeHandler((_, _) =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.BadRequest);
            r.Headers.Add("X-Reason", "Invalid X-SHA-256 header format. Expected a string.");
            return r;
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        var ex = await Assert.ThrowsAsync<BlossomHttpException>(() =>
            client.UploadAsync(new ByteArrayContent(Array.Empty<byte>())));
        Assert.Equal(400, ex.StatusCode);
        Assert.Equal("Invalid X-SHA-256 header format. Expected a string.", ex.ServerReason);
    }

    [Fact]
    public async Task PaymentRequired_SurfacesAsTypedException()
    {
        var handler = new FakeHandler((_, _) =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.PaymentRequired);
            r.Headers.Add("X-Lightning", "lnbc30n1pn...");
            r.Headers.Add("X-Cashu", "creqApWF0gaN...");
            r.Headers.Add("X-Reason", "Upload requires 30 sats");
            return r;
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        var ex = await Assert.ThrowsAsync<BlossomPaymentRequiredException>(() =>
            client.UploadAsync(new ByteArrayContent(Array.Empty<byte>())));
        Assert.Equal(402, ex.StatusCode);
        Assert.Equal("Upload requires 30 sats", ex.ServerReason);
        Assert.Single(ex.LightningInvoices);
        Assert.Single(ex.CashuQuotes);
    }

    [Fact]
    public async Task UploadHead_ReturnsServerStatus()
    {
        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Head, req.Method);
            Assert.Equal("https://cdn.example.com/upload", req.RequestUri!.AbsoluteUri);
            Assert.Equal(Hash, req.Headers.GetValues("X-SHA-256").Single());
            Assert.Equal("4", req.Headers.GetValues("X-Content-Length").Single());
            Assert.Equal("image/png", req.Headers.GetValues("X-Content-Type").Single());
            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        Assert.Equal(HttpStatusCode.OK,
            await client.UploadHeadAsync(Hash, "image/png", 4));
    }

    [Fact]
    public async Task Mirror_PostsJsonBody()
    {
        string? bodySeen = null;
        var handler = new FakeHandler(async (req, ct) =>
        {
            Assert.Equal(HttpMethod.Put, req.Method);
            Assert.Equal("https://cdn.example.com/mirror", req.RequestUri!.AbsoluteUri);
            bodySeen = await req.Content!.ReadAsStringAsync(ct);
            string descriptor = $$"""
            {"url":"https://cdn.example.com/{{Hash}}.bin","sha256":"{{Hash}}","size":4,"type":"application/octet-stream","uploaded":1}
            """;
            return new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent(descriptor, System.Text.Encoding.UTF8, "application/json"),
            };
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        var desc = await client.MirrorAsync("https://origin.example.com/file.bin");
        Assert.Equal($$"""{"url":"https://origin.example.com/file.bin"}""", bodySeen);
        Assert.Equal(Hash, desc.Sha256);
    }

    [Fact]
    public async Task List_BuildsPagedQueryString()
    {
        using var owner = PrivateKey.Generate();

        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Get, req.Method);
            Assert.Equal($"https://cdn.example.com/list/{owner.PublicKey.ToHex()}?cursor=abc&limit=10",
                req.RequestUri!.AbsoluteUri);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("[]", System.Text.Encoding.UTF8, "application/json"),
            };
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        var list = await client.ListAsync(owner.PublicKey, cursor: "abc", limit: 10);
        Assert.Empty(list);
    }

    [Fact]
    public async Task Delete_RequiresAuthAndReportsNotFound()
    {
        using var key = PrivateKey.Generate();
        var auth = BlossomAuthToken
            .Create(BlossomAuthVerb.Delete, "Delete blob")
            .ScopeToBlob(Hash)
            .BuildAndSign(key);

        var handler = new FakeHandler((req, _) =>
        {
            Assert.Equal(HttpMethod.Delete, req.Method);
            Assert.Equal($"https://cdn.example.com/{Hash}", req.RequestUri!.AbsoluteUri);
            Assert.Equal(BlossomAuthToken.Scheme, req.Headers.Authorization!.Scheme);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        using var http = new HttpClient(handler);
        using var client = new BlossomClient(ServerBase, http);
        Assert.False(await client.DeleteBlobAsync(Hash, auth));
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;

        public FakeHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> sync)
        {
            _send = (req, ct) => Task.FromResult(sync(req, ct));
        }

        public FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> async)
        {
            _send = async;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => _send(request, cancellationToken);
    }
}
