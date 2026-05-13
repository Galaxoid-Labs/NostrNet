// SPDX-License-Identifier: MIT
//
// NIP-21: the "nostr:" URI scheme — a thin wrapper around NIP-19 entities.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/21.md

using System.Diagnostics.CodeAnalysis;

namespace NostrNet.Nip19;

/// <summary>
/// Helpers for the NIP-21 <c>nostr:</c> URI scheme.
/// </summary>
public static class Nip21
{
    /// <summary>The URI scheme prefix, including the trailing colon.</summary>
    public const string Scheme = "nostr:";

    /// <summary>Wraps a NIP-19 entity in a <c>nostr:</c> URI.</summary>
    public static string ToUri(Nip19Entity entity)
    {
        ArgumentNullException.ThrowIfNull(entity);
        return Scheme + entity.Encode();
    }

    /// <summary>
    /// Parses a <c>nostr:</c> URI into a typed NIP-19 entity.
    /// </summary>
    /// <exception cref="FormatException">The URI is malformed or wraps an unrecognized entity.</exception>
    public static Nip19Entity Parse(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.StartsWith(Scheme, StringComparison.Ordinal))
        {
            throw new FormatException($"NIP-21 URIs must start with '{Scheme}'.");
        }

        return Nip19.Parse(uri[Scheme.Length..]);
    }

    /// <summary>Attempts to parse a <c>nostr:</c> URI. Returns <c>false</c> on any failure.</summary>
    public static bool TryParse(string? uri, [NotNullWhen(true)] out Nip19Entity? entity)
    {
        entity = null;
        if (uri is null || !uri.StartsWith(Scheme, StringComparison.Ordinal))
        {
            return false;
        }

        return Nip19.TryParse(uri[Scheme.Length..], out entity);
    }
}
