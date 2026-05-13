// SPDX-License-Identifier: MIT

using System.Text.Json;
using System.Text.Json.Serialization;
using NostrNet.Cryptography;
using NostrNet.Keys;

namespace NostrNet.Events;

/// <summary>
/// A fully-formed, signed Nostr event as defined by NIP-01.
/// </summary>
/// <remarks>
/// Instances are produced by <see cref="UnsignedEvent.Sign(PrivateKey, ReadOnlySpan{byte})"/>
/// or by parsing wire JSON via <see cref="FromJson"/>. Properties are immutable;
/// modifying any field requires constructing a new event and re-signing.
/// </remarks>
public sealed class NostrEvent
{
    /// <summary>The event id (32-byte SHA-256 of canonical serialization).</summary>
    public required EventId Id { get; init; }

    /// <summary>The author's x-only public key.</summary>
    public required PublicKey PubKey { get; init; }

    /// <summary>Unix timestamp in seconds.</summary>
    public required long CreatedAt { get; init; }

    /// <summary>The NIP-01 event kind.</summary>
    public required int Kind { get; init; }

    /// <summary>Tag rows.</summary>
    public required IReadOnlyList<IReadOnlyList<string>> Tags { get; init; }

    /// <summary>The event content string.</summary>
    public required string Content { get; init; }

    /// <summary>The BIP-340 Schnorr signature over <see cref="Id"/>.</summary>
    public required Signature Sig { get; init; }

    /// <summary>
    /// Verifies that the event id matches the canonical serialization and that
    /// the signature is valid for that id under <see cref="PubKey"/>.
    /// </summary>
    /// <returns><c>true</c> if both checks pass.</returns>
    public bool Verify()
    {
        EventId expectedId = EventSerializer.ComputeId(PubKey, CreatedAt, Kind, Tags, Content);
        if (!expectedId.Equals(Id))
        {
            return false;
        }

        return Secp256k1.SchnorrVerify(Sig.AsSpan(), Id.AsSpan(), PubKey.AsSpan());
    }

    /// <summary>Parses a relay-wire JSON event.</summary>
    /// <exception cref="FormatException">The JSON is malformed or a field is invalid.</exception>
    public static NostrEvent FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        NostrEventDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize(json, NostrJsonContext.Default.NostrEventDto);
        }
        catch (JsonException ex)
        {
            throw new FormatException("Event JSON is malformed.", ex);
        }

        if (dto is null)
        {
            throw new FormatException("Event JSON is null.");
        }

        return FromDto(dto);
    }

    /// <summary>Serializes this event into NIP-01 wire JSON.</summary>
    public string ToJson()
    {
        var dto = new NostrEventDto
        {
            id = Id.ToHex(),
            pubkey = PubKey.ToHex(),
            created_at = CreatedAt,
            kind = Kind,
            tags = MaterializeTags(Tags),
            content = Content,
            sig = Sig.ToHex(),
        };

        return JsonSerializer.Serialize(dto, NostrJsonContext.Default.NostrEventDto);
    }

    private static NostrEvent FromDto(NostrEventDto dto)
    {
        if (dto.id is null || dto.pubkey is null || dto.content is null || dto.sig is null || dto.tags is null)
        {
            throw new FormatException("Event JSON is missing required fields.");
        }

        return new NostrEvent
        {
            Id = EventId.FromHex(dto.id),
            PubKey = PublicKey.FromHex(dto.pubkey),
            CreatedAt = dto.created_at,
            Kind = dto.kind,
            Tags = MaterializeTagsImmutable(dto.tags),
            Content = dto.content,
            Sig = Signature.FromHex(dto.sig),
        };
    }

    private static string[][] MaterializeTags(IReadOnlyList<IReadOnlyList<string>> tags)
    {
        var result = new string[tags.Count][];
        for (int i = 0; i < tags.Count; i++)
        {
            var row = tags[i];
            var arr = new string[row.Count];
            for (int j = 0; j < row.Count; j++)
            {
                arr[j] = row[j];
            }

            result[i] = arr;
        }

        return result;
    }

    private static IReadOnlyList<IReadOnlyList<string>> MaterializeTagsImmutable(string[][] tags)
    {
        var rows = new IReadOnlyList<string>[tags.Length];
        for (int i = 0; i < tags.Length; i++)
        {
            rows[i] = tags[i];
        }

        return rows;
    }
}

// DTO used solely for STJ source-generated (de)serialization. Field names match
// the NIP-01 wire format exactly (lower_snake_case where applicable).
internal sealed class NostrEventDto
{
#pragma warning disable IDE1006 // naming styles — wire format requires these names
    public string? id { get; set; }
    public string? pubkey { get; set; }
    public long created_at { get; set; }
    public int kind { get; set; }
    public string[][]? tags { get; set; }
    public string? content { get; set; }
    public string? sig { get; set; }
#pragma warning restore IDE1006
}

[JsonSerializable(typeof(NostrEventDto))]
[JsonSourceGenerationOptions(
    GenerationMode = JsonSourceGenerationMode.Default,
    PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified)]
internal partial class NostrJsonContext : JsonSerializerContext
{
}
