// SPDX-License-Identifier: MIT
//
// NIP-42 client-to-relay authentication.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/42.md
//
// Wire flow:
//   1. Relay sends:        ["AUTH", "<challenge>"]
//   2. Client signs an ephemeral kind-22242 event tagged with the relay URL
//      and the challenge, then sends:
//                          ["AUTH", <signed-event>]
//   3. Relay validates and responds with an OK keyed on the event id:
//                          ["OK", "<event-id>", true, ""]
//      or ["OK", "<event-id>", false, "<reason>"] on rejection.
//
// The auth event:
//   kind:        22242
//   created_at:  must be within ~10 minutes of the relay's "now"
//   tags:        [["relay", "<relay-url>"], ["challenge", "<challenge>"]]
//   content:     empty (recommended)

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Auth;

/// <summary>
/// Helpers for NIP-42 client-to-relay authentication.
/// </summary>
public static class Nip42
{
    /// <summary>The event kind used for NIP-42 AUTH events.</summary>
    public const int AuthEventKind = 22242;

    /// <summary>The NIP-01 / NIP-42 rejection-reason prefix indicating an AUTH is required.</summary>
    public const string AuthRequiredPrefix = "auth-required";

    /// <summary>
    /// True if <paramref name="reason"/> is a NIP-42 <c>auth-required</c>
    /// rejection (case-insensitive, optional <c>":</c>" suffix).
    /// </summary>
    public static bool IsAuthRequired(string? reason)
        => reason is not null
            && reason.StartsWith(AuthRequiredPrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Builds a signed NIP-42 auth event for the given challenge and relay.
    /// </summary>
    /// <param name="key">The signing key.</param>
    /// <param name="relayUri">The relay URI the challenge came from.</param>
    /// <param name="challenge">The challenge string from the relay's <c>["AUTH", ...]</c> message.</param>
    /// <param name="createdAt">
    /// Optional unix-seconds timestamp. Defaults to <see cref="DateTimeOffset.UtcNow"/>.
    /// Per spec the relay validates this against its own clock with a ±10-minute window,
    /// so use the system clock unless your clock is known to be off.
    /// </param>
    public static NostrEvent BuildAuthEvent(
        PrivateKey key,
        Uri relayUri,
        string challenge,
        long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(relayUri);
        ArgumentException.ThrowIfNullOrEmpty(challenge);

        var tags = new IReadOnlyList<string>[]
        {
            new[] { "relay", relayUri.ToString() },
            new[] { "challenge", challenge },
        };

        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = AuthEventKind,
            Tags = tags,
            Content = string.Empty,
        }.Sign(key);
    }
}
