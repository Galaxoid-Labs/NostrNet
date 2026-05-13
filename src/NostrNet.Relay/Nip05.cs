// SPDX-License-Identifier: MIT
//
// NIP-05: DNS-based identifier verification.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/05.md
//
// An identifier of the form "<local-part>@<domain>" is verified by fetching
//   https://<domain>/.well-known/nostr.json?name=<local-part>
// and checking that the returned `names[<local-part>]` hex pubkey matches the
// pubkey we're verifying.
//
// Per spec:
//   - The /.well-known/nostr.json endpoint MUST NOT use HTTP redirects, and
//     fetchers MUST ignore any redirects given. We disable auto-redirect on
//     the shared HttpClient.
//   - Local part must use only [a-z0-9-_.].
//   - A bare domain (no '@') is equivalent to "_@domain".
//   - Verification is the responsibility of the fetcher; the relay/client only
//     trusts that the domain administrator vouches for the mapping.

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Profiles;

namespace NostrNet.Relay;

/// <summary>
/// NIP-05 DNS-based identifier verification.
/// </summary>
public static class Nip05
{
    /// <summary>The fixed well-known path served by NIP-05 endpoints.</summary>
    public const string WellKnownPath = "/.well-known/nostr.json";

    /// <summary>
    /// The "root" local part returned when an identifier is just a bare domain
    /// (e.g. <c>example.com</c> → <c>_@example.com</c>).
    /// </summary>
    public const string RootLocalPart = "_";

    /// <summary>
    /// Verifies that <paramref name="identifier"/> maps to <paramref name="expectedPubkey"/>.
    /// </summary>
    /// <param name="expectedPubkey">The pubkey we expect the identifier to resolve to.</param>
    /// <param name="identifier">A NIP-05 identifier such as <c>bob@example.com</c>.</param>
    /// <param name="httpClient">Optional HttpClient. If null, a shared no-redirect client is used.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    public static async Task<Nip05VerificationResult> VerifyAsync(
        PublicKey expectedPubkey,
        string identifier,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedPubkey);
        ArgumentNullException.ThrowIfNull(identifier);

        if (!TryParseIdentifier(identifier, out var localPart, out var domain))
        {
            return Nip05VerificationResult.Failure(identifier, "identifier is malformed");
        }

        Nip05Document doc;
        try
        {
            doc = await FetchAsync(localPart!, domain!, httpClient, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return Nip05VerificationResult.Failure(identifier, $"HTTP request failed: {ex.Message}");
        }
        catch (JsonException ex)
        {
            return Nip05VerificationResult.Failure(identifier, $"response is not valid JSON: {ex.Message}");
        }

        if (doc.Names is null || !doc.Names.TryGetValue(localPart!, out var hex) || hex is null)
        {
            return Nip05VerificationResult.Failure(identifier, $"no entry for '{localPart}' in names");
        }

        if (!PublicKey.TryFromHex(hex, out var resolved))
        {
            return Nip05VerificationResult.Failure(identifier, "names entry is not a 32-byte hex pubkey");
        }

        if (!resolved.Equals(expectedPubkey))
        {
            return Nip05VerificationResult.Failure(identifier, "names entry does not match the expected pubkey");
        }

        IReadOnlyList<string> relays = Array.Empty<string>();
        if (doc.Relays is not null && doc.Relays.TryGetValue(hex, out var maybeRelays) && maybeRelays is not null)
        {
            relays = maybeRelays;
        }

        return new Nip05VerificationResult(IsVerified: true, identifier, expectedPubkey, relays, FailureReason: null);
    }

    /// <summary>
    /// Verifies a kind-0 metadata event's claimed <c>nip05</c> identifier.
    /// </summary>
    /// <remarks>
    /// Reads the <c>nip05</c> field from the event's content JSON, then runs
    /// the standard verification against the event's pubkey. If the event has
    /// no <c>nip05</c> field, the result is "not verified" with a clear reason
    /// (rather than throwing).
    /// </remarks>
    /// <param name="kind0Event">A kind-0 (user metadata) event.</param>
    /// <param name="httpClient">Optional HttpClient. If null, a shared no-redirect client is used.</param>
    /// <param name="cancellationToken">Cancels the HTTP request.</param>
    /// <exception cref="ArgumentException"><paramref name="kind0Event"/> is not kind 0.</exception>
    public static async Task<Nip05VerificationResult> VerifyAsync(
        NostrEvent kind0Event,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(kind0Event);
        if (kind0Event.Kind != 0)
        {
            throw new ArgumentException(
                $"Expected a kind-0 metadata event; got kind {kind0Event.Kind}.",
                nameof(kind0Event));
        }

        string? identifier = TryReadNip05Field(kind0Event.Content);
        if (identifier is null)
        {
            return Nip05VerificationResult.Failure(identifier: null, "event content has no nip05 field");
        }

        return await VerifyAsync(kind0Event.PubKey, identifier, httpClient, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that a parsed <see cref="Profile"/>'s <see cref="Profile.Nip05"/>
    /// claim resolves to its <see cref="Profile.Owner"/>.
    /// </summary>
    /// <remarks>
    /// Returns a not-verified result if the profile has no NIP-05 identifier
    /// or no Owner set (e.g., constructed manually rather than via
    /// <see cref="Profile.FromEvent"/>).
    /// </remarks>
    public static Task<Nip05VerificationResult> VerifyAsync(
        Profile profile,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);

        if (profile.Owner is null)
        {
            return Task.FromResult(Nip05VerificationResult.Failure(profile.Nip05, "profile has no Owner pubkey"));
        }

        if (string.IsNullOrEmpty(profile.Nip05))
        {
            return Task.FromResult(Nip05VerificationResult.Failure(identifier: null, "profile has no nip05 field"));
        }

        return VerifyAsync(profile.Owner, profile.Nip05, httpClient, cancellationToken);
    }

    /// <summary>
    /// Fetches and parses the <c>/.well-known/nostr.json?name=&lt;local-part&gt;</c>
    /// document for the given identifier.
    /// </summary>
    public static Task<Nip05Document> FetchAsync(
        string identifier,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        if (!TryParseIdentifier(identifier, out var localPart, out var domain))
        {
            throw new ArgumentException("Identifier is malformed.", nameof(identifier));
        }

        return FetchAsync(localPart!, domain!, httpClient, cancellationToken);
    }

    /// <summary>
    /// Parses a NIP-05 identifier of the form <c>"local-part@domain"</c> into
    /// its two parts. A bare domain (no <c>@</c>) yields the <c>"_"</c> root
    /// local part. Returns <c>false</c> on any malformed input.
    /// </summary>
    public static bool TryParseIdentifier(
        string identifier,
        out string? localPart,
        out string? domain)
    {
        localPart = null;
        domain = null;
        if (string.IsNullOrWhiteSpace(identifier) || identifier.Length > 256)
        {
            return false;
        }

        int at = identifier.IndexOf('@');
        string local;
        string host;

        if (at < 0)
        {
            local = RootLocalPart;
            host = identifier;
        }
        else
        {
            local = identifier[..at];
            host = identifier[(at + 1)..];
            if (local.Length == 0)
            {
                local = RootLocalPart;
            }
        }

        // Normalize to lowercase per spec (local part is required to be
        // lowercase; domains are case-insensitive in DNS).
        local = local.ToLowerInvariant();
        host = host.ToLowerInvariant();

        if (!IsValidLocalPart(local) || !IsValidDomain(host))
        {
            return false;
        }

        localPart = local;
        domain = host;
        return true;
    }

    private static async Task<Nip05Document> FetchAsync(
        string localPart,
        string domain,
        HttpClient? httpClient,
        CancellationToken cancellationToken)
    {
        var uri = new Uri($"https://{domain}{WellKnownPath}?name={Uri.EscapeDataString(localPart)}");
        HttpClient client = httpClient ?? SharedClient.Value;

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        // Accept hint for relays that content-negotiate.
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);

        var doc = await JsonSerializer
            .DeserializeAsync(stream, Nip05JsonContext.Default.Nip05Document, cancellationToken)
            .ConfigureAwait(false);

        return doc ?? throw new JsonException("NIP-05 response was empty or null.");
    }

    private static string? TryReadNip05Field(string content)
    {
        if (string.IsNullOrEmpty(content))
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(content);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (!doc.RootElement.TryGetProperty("nip05", out var nip05El)
                || nip05El.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            return nip05El.GetString();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool IsValidLocalPart(string s)
    {
        if (s.Length == 0)
        {
            return false;
        }

        foreach (char c in s)
        {
            bool ok = (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c is '-' or '_' or '.';
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsValidDomain(string s)
    {
        if (s.Length is 0 or > 253)
        {
            return false;
        }

        // Basic sanity: at least one '.', no leading/trailing dot, valid chars.
        if (s.StartsWith('.') || s.EndsWith('.') || s.Contains(".."))
        {
            return false;
        }

        foreach (char c in s)
        {
            bool ok = (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c is '-' or '.';
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    // Lazy shared HttpClient with auto-redirect DISABLED, per NIP-05's
    // "fetchers MUST ignore any HTTP redirects" rule.
    private static readonly Lazy<HttpClient> SharedClient = new(() =>
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
        };
        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(15),
        };
    });
}

/// <summary>
/// The parsed contents of a <c>/.well-known/nostr.json</c> response.
/// </summary>
/// <param name="Names">Map of local-part → 32-byte hex pubkey.</param>
/// <param name="Relays">Optional map of hex pubkey → recommended relay URLs.</param>
public sealed record Nip05Document(
    [property: JsonPropertyName("names")] IReadOnlyDictionary<string, string>? Names,
    [property: JsonPropertyName("relays")] IReadOnlyDictionary<string, IReadOnlyList<string>>? Relays);

/// <summary>
/// The outcome of a NIP-05 verification.
/// </summary>
/// <param name="IsVerified">True iff the identifier resolves to the expected pubkey.</param>
/// <param name="Identifier">The identifier that was checked (may be null if no nip05 field was found).</param>
/// <param name="Pubkey">The pubkey the verification was for (only set on success).</param>
/// <param name="Relays">Recommended relays from the document (empty on failure).</param>
/// <param name="FailureReason">A human-readable explanation when <see cref="IsVerified"/> is false.</param>
public sealed record Nip05VerificationResult(
    bool IsVerified,
    string? Identifier,
    PublicKey? Pubkey,
    IReadOnlyList<string> Relays,
    string? FailureReason)
{
    internal static Nip05VerificationResult Failure(string? identifier, string reason)
        => new(IsVerified: false, identifier, Pubkey: null, Array.Empty<string>(), reason);
}

[JsonSerializable(typeof(Nip05Document))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.Unspecified)]
internal partial class Nip05JsonContext : JsonSerializerContext
{
}
