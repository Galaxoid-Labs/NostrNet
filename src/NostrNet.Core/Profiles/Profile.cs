// SPDX-License-Identifier: MIT
//
// A typed view of a kind-0 (user metadata) event's content.
//
// NIP-01 defines kind 0 as user metadata where `content` is a stringified
// JSON object. The exact field names below ("name", "display_name",
// "picture", "banner", "nip05", "lud16", "lud06", "website", "about") are
// de-facto standardized across major clients but are NOT part of NIP-01
// itself. Unknown fields in the JSON are ignored.

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Profiles;

/// <summary>
/// A typed view of the JSON content of a kind-0 (user metadata) event.
/// </summary>
/// <remarks>
/// All fields are optional. Use <see cref="FromEvent"/> to parse a kind-0
/// <see cref="NostrEvent"/>; the resulting profile carries <see cref="Owner"/>
/// equal to the event's pubkey so it can be verified against external
/// identity proofs (e.g., NIP-05).
/// </remarks>
public sealed record Profile : INostrTypedEvent<Profile>
{
    /// <summary>Nostr kind(s) this type represents.</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { 0 };

    /// <summary>The pubkey that authored the metadata event. <c>null</c> when constructed without an event.</summary>
    /// <remarks>Not serialized — it comes from the event's <c>pubkey</c> field, not the content JSON.</remarks>
    [JsonIgnore]
    public PublicKey? Owner { get; init; }

    /// <summary>Short username.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    /// <summary>Display name (typically with spacing/capitalization).</summary>
    [JsonPropertyName("display_name")]
    public string? DisplayName { get; init; }

    /// <summary>Free-text "about" / bio.</summary>
    [JsonPropertyName("about")]
    public string? About { get; init; }

    /// <summary>URL of the profile picture.</summary>
    [JsonPropertyName("picture")]
    public string? Picture { get; init; }

    /// <summary>URL of the banner / header image.</summary>
    [JsonPropertyName("banner")]
    public string? Banner { get; init; }

    /// <summary>NIP-05 identifier (e.g., <c>bob@example.com</c>).</summary>
    [JsonPropertyName("nip05")]
    public string? Nip05 { get; init; }

    /// <summary>Lightning address in <c>user@domain</c> form.</summary>
    [JsonPropertyName("lud16")]
    public string? Lud16 { get; init; }

    /// <summary>LNURL-pay address (LUD-06).</summary>
    [JsonPropertyName("lud06")]
    public string? Lud06 { get; init; }

    /// <summary>Personal website URL.</summary>
    [JsonPropertyName("website")]
    public string? Website { get; init; }

    /// <summary>
    /// NIP-39 external-identity claims. Sourced from the kind-0
    /// event's <c>i</c> tags (NOT from the content JSON). Malformed
    /// <c>i</c> tags are silently skipped.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<ExternalIdentity> ExternalIdentities { get; init; } = Array.Empty<ExternalIdentity>();

    /// <summary>
    /// Parses a kind-0 metadata event into a <see cref="Profile"/>. The
    /// resulting profile's <see cref="Owner"/> is the event's pubkey,
    /// and <see cref="ExternalIdentities"/> is populated from any
    /// NIP-39 <c>i</c> tags.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="kind0Event"/> is not kind 0.</exception>
    /// <exception cref="FormatException">The event's content is not a JSON object.</exception>
    public static Profile FromEvent(NostrEvent kind0Event)
    {
        ArgumentNullException.ThrowIfNull(kind0Event);
        if (kind0Event.Kind != 0)
        {
            throw new ArgumentException(
                $"Expected a kind-0 metadata event; got kind {kind0Event.Kind}.",
                nameof(kind0Event));
        }

        Profile parsed;
        try
        {
            parsed = JsonSerializer.Deserialize(kind0Event.Content, ProfileJsonContext.Default.Profile)
                ?? new Profile();
        }
        catch (JsonException ex)
        {
            throw new FormatException("Kind-0 event content is not a valid JSON object.", ex);
        }

        // Pull NIP-39 `i` tags out of the event's tag list.
        var identities = new List<ExternalIdentity>();
        foreach (var tag in kind0Event.Tags)
        {
            if (tag.Count >= 3
                && string.Equals(tag[0], "i", StringComparison.Ordinal)
                && ExternalIdentity.TryParse(tag, out var ident)
                && ident is not null)
            {
                identities.Add(ident);
            }
        }

        return parsed with { Owner = kind0Event.PubKey, ExternalIdentities = identities };
    }

    /// <summary>
    /// Try-parse variant of <see cref="FromEvent"/>. Returns <c>false</c> on
    /// any failure (wrong kind, malformed content, etc.).
    /// </summary>
    public static bool TryFromEvent(NostrEvent? kind0Event, [NotNullWhen(true)] out Profile? profile)
    {
        profile = null;
        if (kind0Event is null || kind0Event.Kind != 0)
        {
            return false;
        }

        try
        {
            profile = FromEvent(kind0Event);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

[JsonSerializable(typeof(Profile))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal partial class ProfileJsonContext : JsonSerializerContext
{
}
