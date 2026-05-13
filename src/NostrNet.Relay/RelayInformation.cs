// SPDX-License-Identifier: MIT
//
// NIP-11 Relay Information Document.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/11.md
//
// Fetch model: a plain HTTPS GET against the relay's URL with scheme rewritten
// from wss → https (or ws → http), carrying `Accept: application/nostr+json`.
// The response is a JSON object describing the relay's capabilities, limits,
// fees, and metadata. All fields are optional; consumers should null-check.

using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NostrNet.Relay;

/// <summary>
/// A NIP-11 Relay Information Document describing a relay's capabilities,
/// limits, and metadata.
/// </summary>
/// <remarks>
/// All fields are optional and may be <c>null</c>. Unknown fields in the JSON
/// response are ignored. Use <see cref="FetchAsync"/> to retrieve a document
/// from a relay URI.
/// </remarks>
public sealed record RelayInformation
{
    /// <summary>The relay's display name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    /// <summary>Human-readable description of the relay's purpose.</summary>
    [JsonPropertyName("description")]
    public string? Description { get; init; }

    /// <summary>URL of a banner image.</summary>
    [JsonPropertyName("banner")]
    public string? Banner { get; init; }

    /// <summary>URL of an icon.</summary>
    [JsonPropertyName("icon")]
    public string? Icon { get; init; }

    /// <summary>Admin pubkey (32-byte hex).</summary>
    [JsonPropertyName("pubkey")]
    public string? Pubkey { get; init; }

    /// <summary>The relay's own pubkey, if it publishes events itself (32-byte hex).</summary>
    [JsonPropertyName("self")]
    public string? Self { get; init; }

    /// <summary>Contact URI (mailto:, https://, etc.).</summary>
    [JsonPropertyName("contact")]
    public string? Contact { get; init; }

    /// <summary>NIPs supported by this relay, as integer numbers.</summary>
    [JsonPropertyName("supported_nips")]
    public IReadOnlyList<int>? SupportedNips { get; init; }

    /// <summary>URL or identifier of the relay implementation.</summary>
    [JsonPropertyName("software")]
    public string? Software { get; init; }

    /// <summary>Version string of the relay implementation.</summary>
    [JsonPropertyName("version")]
    public string? Version { get; init; }

    /// <summary>URL of the relay's privacy policy.</summary>
    [JsonPropertyName("privacy_policy")]
    public string? PrivacyPolicy { get; init; }

    /// <summary>URL of the relay's terms of service.</summary>
    [JsonPropertyName("terms_of_service")]
    public string? TermsOfService { get; init; }

    /// <summary>URL of the relay's posting policy.</summary>
    [JsonPropertyName("posting_policy")]
    public string? PostingPolicy { get; init; }

    /// <summary>URL where users can pay for relay access.</summary>
    [JsonPropertyName("payments_url")]
    public string? PaymentsUrl { get; init; }

    /// <summary>Operational limits (max message size, subscription count, etc.).</summary>
    [JsonPropertyName("limitation")]
    public RelayLimitation? Limitation { get; init; }

    /// <summary>Fee structure for admission / subscription / publication.</summary>
    [JsonPropertyName("fees")]
    public RelayFees? Fees { get; init; }

    /// <summary>ISO 3166-1 country codes where the relay operates.</summary>
    [JsonPropertyName("relay_countries")]
    public IReadOnlyList<string>? RelayCountries { get; init; }

    /// <summary>IETF BCP 47 language tags spoken on the relay.</summary>
    [JsonPropertyName("language_tags")]
    public IReadOnlyList<string>? LanguageTags { get; init; }

    /// <summary>Topical tags describing the relay's focus.</summary>
    [JsonPropertyName("tags")]
    public IReadOnlyList<string>? Tags { get; init; }

    /// <summary>True if this relay advertises support for the given NIP number.</summary>
    public bool SupportsNip(int nipNumber)
        => SupportedNips is not null && SupportedNips.Contains(nipNumber);

    /// <summary>
    /// Fetches the NIP-11 Relay Information Document for the relay at
    /// <paramref name="relayUri"/>. The URI may use any of the
    /// <c>wss</c>, <c>ws</c>, <c>https</c>, or <c>http</c> schemes; ws/wss
    /// are rewritten to http/https for the GET request.
    /// </summary>
    /// <param name="relayUri">The relay URI (typically a <c>wss://</c> URL).</param>
    /// <param name="httpClient">
    /// Optional <see cref="HttpClient"/> to use. If null, a shared default
    /// instance is used. Callers needing custom timeouts, headers, or proxies
    /// should pass their own.
    /// </param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <returns>The parsed relay information document.</returns>
    /// <exception cref="HttpRequestException">The HTTP request failed or returned a non-success status.</exception>
    /// <exception cref="JsonException">The response body could not be parsed as a NIP-11 document.</exception>
    /// <exception cref="ArgumentException"><paramref name="relayUri"/> uses an unsupported scheme.</exception>
    public static async Task<RelayInformation> FetchAsync(
        Uri relayUri,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(relayUri);

        Uri httpUri = ToHttpUri(relayUri);
        HttpClient client = httpClient ?? SharedClient.Value;

        using var request = new HttpRequestMessage(HttpMethod.Get, httpUri);
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/nostr+json"));

        using var response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);

        var info = await JsonSerializer
            .DeserializeAsync(stream, RelayInfoJsonContext.Default.RelayInformation, cancellationToken)
            .ConfigureAwait(false);

        return info ?? throw new JsonException("Relay returned an empty or null NIP-11 document.");
    }

    /// <summary>
    /// Parses a NIP-11 document from a JSON string. Useful when the JSON has
    /// already been retrieved (e.g., from a cache, snapshot file, or custom
    /// HTTP path).
    /// </summary>
    /// <exception cref="JsonException">The JSON is malformed.</exception>
    public static RelayInformation Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        var info = JsonSerializer.Deserialize(json, RelayInfoJsonContext.Default.RelayInformation);
        return info ?? throw new JsonException("NIP-11 document is null or empty.");
    }

    /// <summary>
    /// Rewrites a relay URI's scheme for the NIP-11 HTTP fetch:
    /// <c>wss</c>→<c>https</c>, <c>ws</c>→<c>http</c>; <c>https</c>/<c>http</c>
    /// pass through unchanged.
    /// </summary>
    public static Uri ToHttpUri(Uri relayUri)
    {
        ArgumentNullException.ThrowIfNull(relayUri);
        string scheme = relayUri.Scheme.ToLowerInvariant() switch
        {
            "wss" => "https",
            "ws" => "http",
            "https" => "https",
            "http" => "http",
            _ => throw new ArgumentException(
                $"Unsupported scheme '{relayUri.Scheme}'. Expected ws, wss, http, or https.",
                nameof(relayUri)),
        };

        var builder = new UriBuilder(relayUri) { Scheme = scheme };
        // Clear the port if it matches the default for the new scheme, so the
        // resulting URI is clean (no explicit :443/:80).
        if ((scheme == "https" && builder.Port == 443) || (scheme == "http" && builder.Port == 80))
        {
            builder.Port = -1;
        }

        return builder.Uri;
    }

    // Lazy shared HttpClient so we don't pay creation cost unless used and so
    // tests can inject their own client without forcing this allocation.
    private static readonly Lazy<HttpClient> SharedClient = new(() =>
        new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15),
        });
}

/// <summary>Operational limits advertised by the relay.</summary>
public sealed record RelayLimitation
{
    /// <summary>Maximum size of an incoming WebSocket message in bytes.</summary>
    [JsonPropertyName("max_message_length")]
    public int? MaxMessageLength { get; init; }

    /// <summary>Maximum number of concurrent subscriptions per connection.</summary>
    [JsonPropertyName("max_subscriptions")]
    public int? MaxSubscriptions { get; init; }

    /// <summary>Maximum number of filters per subscription.</summary>
    [JsonPropertyName("max_filters")]
    public int? MaxFilters { get; init; }

    /// <summary>Maximum value the relay will honor for a filter's <c>limit</c>.</summary>
    [JsonPropertyName("max_limit")]
    public int? MaxLimit { get; init; }

    /// <summary>Default value the relay applies when a filter omits <c>limit</c>.</summary>
    [JsonPropertyName("default_limit")]
    public int? DefaultLimit { get; init; }

    /// <summary>Maximum length of a subscription id.</summary>
    [JsonPropertyName("max_subid_length")]
    public int? MaxSubscriptionIdLength { get; init; }

    /// <summary>Maximum number of tags on an event the relay will accept.</summary>
    [JsonPropertyName("max_event_tags")]
    public int? MaxEventTags { get; init; }

    /// <summary>Maximum length of an event's content field.</summary>
    [JsonPropertyName("max_content_length")]
    public int? MaxContentLength { get; init; }

    /// <summary>Minimum NIP-13 PoW difficulty (leading zero bits) required to publish.</summary>
    [JsonPropertyName("min_pow_difficulty")]
    public int? MinPowDifficulty { get; init; }

    /// <summary>True if NIP-42 AUTH is required before writes are accepted.</summary>
    [JsonPropertyName("auth_required")]
    public bool? AuthRequired { get; init; }

    /// <summary>True if payment is required before writes are accepted.</summary>
    [JsonPropertyName("payment_required")]
    public bool? PaymentRequired { get; init; }

    /// <summary>True if only specific authors are permitted to publish.</summary>
    [JsonPropertyName("restricted_writes")]
    public bool? RestrictedWrites { get; init; }

    /// <summary>Minimum acceptable <c>created_at</c> (unix seconds).</summary>
    [JsonPropertyName("created_at_lower_limit")]
    public long? CreatedAtLowerLimit { get; init; }

    /// <summary>Maximum acceptable <c>created_at</c> (unix seconds).</summary>
    [JsonPropertyName("created_at_upper_limit")]
    public long? CreatedAtUpperLimit { get; init; }
}

/// <summary>Fee structure broken down by category.</summary>
public sealed record RelayFees
{
    /// <summary>One-time fees to gain write access.</summary>
    [JsonPropertyName("admission")]
    public IReadOnlyList<RelayFee>? Admission { get; init; }

    /// <summary>Recurring fees for subscription access.</summary>
    [JsonPropertyName("subscription")]
    public IReadOnlyList<RelayFee>? Subscription { get; init; }

    /// <summary>Fees per published event, optionally limited to specific kinds.</summary>
    [JsonPropertyName("publication")]
    public IReadOnlyList<RelayFee>? Publication { get; init; }
}

/// <summary>A single fee entry in a <see cref="RelayFees"/> bucket.</summary>
public sealed record RelayFee
{
    /// <summary>The fee amount in the smallest unit of <see cref="Unit"/>.</summary>
    [JsonPropertyName("amount")]
    public long? Amount { get; init; }

    /// <summary>The fee unit (typically <c>"msats"</c>).</summary>
    [JsonPropertyName("unit")]
    public string? Unit { get; init; }

    /// <summary>The period in seconds over which a recurring fee applies.</summary>
    [JsonPropertyName("period")]
    public int? Period { get; init; }

    /// <summary>Event kinds this fee applies to (null = all kinds).</summary>
    [JsonPropertyName("kinds")]
    public IReadOnlyList<int>? Kinds { get; init; }
}

[JsonSerializable(typeof(RelayInformation))]
[JsonSerializable(typeof(RelayLimitation))]
[JsonSerializable(typeof(RelayFees))]
[JsonSerializable(typeof(RelayFee))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal partial class RelayInfoJsonContext : JsonSerializerContext
{
}
