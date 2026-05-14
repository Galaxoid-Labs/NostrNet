// SPDX-License-Identifier: MIT
//
// BUD-02 + BUD-08: Blob descriptor.
//
// The JSON shape every Blossom server returns from /upload, /mirror,
// /media, and (as an array) from /list/{pubkey}:
//
// {
//   "url":       "https://cdn.example.com/<sha256>.<ext>",
//   "sha256":    "<lowercase-hex>",
//   "size":       <bytes>,
//   "type":      "<mime>",
//   "uploaded":   <unix-seconds>,
//
//   // BUD-08: servers MAY include the NIP-94 tag set so callers can
//   // build a kind-1063 event without re-deriving anything.
//   "nip94": [ ["url", "..."], ["m", "..."], ["x", "..."], ... ]
// }
//
// Servers MAY append additional fields (magnet, infohash, ipfs, etc.).
// Source-generated JSON contracts only know the documented keys; any
// unknown fields are dropped on round-trip. Callers who need them
// should re-parse the raw response with their own context.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace NostrNet.Blossom.Blobs;

/// <summary>BUD-02 blob descriptor returned by every Blossom write endpoint.</summary>
public sealed class BlobDescriptor
{
    /// <summary>Publicly accessible URL to the blob, including a file extension.</summary>
    [JsonPropertyName("url")]
    public required string Url { get; init; }

    /// <summary>Lowercase hex sha256 of the stored blob bytes.</summary>
    [JsonPropertyName("sha256")]
    public required string Sha256 { get; init; }

    /// <summary>Size of the blob in bytes.</summary>
    [JsonPropertyName("size")]
    public required long Size { get; init; }

    /// <summary>MIME type. <c>application/octet-stream</c> when the server can't infer one.</summary>
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    /// <summary>Unix-seconds timestamp the server first stored the blob.</summary>
    [JsonPropertyName("uploaded")]
    public required long Uploaded { get; init; }

    /// <summary>
    /// BUD-08: optional NIP-94 tag set (kind 1063 tag rows). When
    /// the server includes this, callers can mint a NIP-94 file event
    /// directly without recomputing url/m/x/size.
    /// </summary>
    [JsonPropertyName("nip94")]
    public List<List<string>>? Nip94Tags { get; init; }

    /// <summary>Parses one descriptor from JSON text.</summary>
    public static BlobDescriptor FromJson(string json) =>
        JsonSerializer.Deserialize(json, BlossomJsonContext.Default.BlobDescriptor)
            ?? throw new FormatException("Empty JSON body when a BlobDescriptor was expected.");

    /// <summary>Parses an array of descriptors from JSON text (BUD-12 list response).</summary>
    public static IReadOnlyList<BlobDescriptor> ArrayFromJson(string json)
    {
        var list = JsonSerializer.Deserialize(json, BlossomJsonContext.Default.ListBlobDescriptor);
        return list ?? new List<BlobDescriptor>();
    }

    /// <summary>Serializes back to JSON (handy for tests, fakes, mock servers).</summary>
    public string ToJson() => JsonSerializer.Serialize(this, BlossomJsonContext.Default.BlobDescriptor);
}

/// <summary>
/// Source-generated JSON serializer context for Blossom descriptor
/// types. Keeps the package AOT-clean (no reflection-based JSON).
/// </summary>
[JsonSerializable(typeof(BlobDescriptor))]
[JsonSerializable(typeof(List<BlobDescriptor>))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal partial class BlossomJsonContext : JsonSerializerContext
{
}
