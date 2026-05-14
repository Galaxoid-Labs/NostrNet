// SPDX-License-Identifier: MIT

using NostrNet.Blossom.Blobs;

namespace NostrNet.Blossom.Tests.Blobs;

public class BlobDescriptorTests
{
    [Fact]
    public void RoundTrip_MatchesSpecExample()
    {
        // From BUD-02
        const string json = """
        {
            "url": "https://cdn.example.com/b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553.pdf",
            "sha256": "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553",
            "size": 184292,
            "type": "application/pdf",
            "uploaded": 1725105921
        }
        """;

        var d = BlobDescriptor.FromJson(json);
        Assert.Equal("b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553", d.Sha256);
        Assert.Equal(184292, d.Size);
        Assert.Equal("application/pdf", d.Type);
        Assert.Equal(1725105921, d.Uploaded);
        Assert.Null(d.Nip94Tags);

        var rt = BlobDescriptor.FromJson(d.ToJson());
        Assert.Equal(d.Sha256, rt.Sha256);
        Assert.Equal(d.Size, rt.Size);
    }

    [Fact]
    public void Nip94Field_ParsesAsBud08Example()
    {
        // From BUD-08
        const string json = """
        {
            "url": "https://cdn.example.com/b1674.pdf",
            "sha256": "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553",
            "size": 184292,
            "type": "application/pdf",
            "uploaded": 1725909682,
            "nip94": [
                ["url", "https://cdn.example.com/b1674.pdf"],
                ["m", "application/pdf"],
                ["x", "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553"],
                ["size", "184292"]
            ]
        }
        """;

        var d = BlobDescriptor.FromJson(json);
        Assert.NotNull(d.Nip94Tags);
        Assert.Equal(4, d.Nip94Tags!.Count);
        Assert.Equal(new[] { "m", "application/pdf" }, d.Nip94Tags[1]);
    }

    [Fact]
    public void ArrayFromJson_HandlesEmptyAndPopulatedLists()
    {
        Assert.Empty(BlobDescriptor.ArrayFromJson("[]"));

        var arr = BlobDescriptor.ArrayFromJson("""
            [
              {"url":"https://x/a.bin","sha256":"aa","size":1,"type":"application/octet-stream","uploaded":1},
              {"url":"https://x/b.bin","sha256":"bb","size":2,"type":"application/octet-stream","uploaded":2}
            ]
            """);

        Assert.Equal(2, arr.Count);
        Assert.Equal("aa", arr[0].Sha256);
        Assert.Equal(2, arr[1].Size);
    }
}
