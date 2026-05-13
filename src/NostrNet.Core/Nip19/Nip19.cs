// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;
using NostrNet.Encoding;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Nip19;

/// <summary>
/// Entry points for parsing arbitrary NIP-19 bech32 entities.
/// </summary>
/// <remarks>
/// Use this when the caller has a string that could be any of <c>npub</c>,
/// <c>note</c>, <c>nprofile</c>, <c>nevent</c>, or <c>naddr</c>. For a
/// specific entity type, prefer the typed constructor on that type
/// (<see cref="PublicKey.FromNpub"/>, <see cref="EventId.FromNote"/>, etc.).
///
/// <para>
/// <c>nsec</c> is deliberately not handled here. Decoding an nsec via a
/// generic "parse any nostr identifier" path makes accidental secret leakage
/// too easy. Callers that specifically want to load a private key must use
/// <see cref="PrivateKey.FromNsec"/>, which enforces lifetime management
/// through <see cref="PrivateKey.Dispose"/>.
/// </para>
/// </remarks>
public static class Nip19
{
    /// <summary>
    /// Parses a NIP-19 bech32 string.
    /// </summary>
    /// <exception cref="FormatException">The string is not a recognized NIP-19 entity.</exception>
    public static Nip19Entity Parse(string source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var decoded = Bech32.Decode(source);
        return BuildEntity(decoded.Hrp, decoded.Data);
    }

    /// <summary>Attempts to parse a NIP-19 bech32 string. Returns <c>false</c> on any failure.</summary>
    public static bool TryParse(string? source, [NotNullWhen(true)] out Nip19Entity? entity)
    {
        entity = null;
        if (source is null)
        {
            return false;
        }

        try
        {
            entity = Parse(source);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static Nip19Entity BuildEntity(string hrp, byte[] data)
    {
        switch (hrp)
        {
            case PublicKey.NpubHrp:
                if (data.Length != PublicKey.Size)
                {
                    throw new FormatException("npub payload must be 32 bytes.");
                }

                return new NpubEntity { PubKey = new PublicKey(data) };

            case EventId.NoteHrp:
                if (data.Length != EventId.Size)
                {
                    throw new FormatException("note payload must be 32 bytes.");
                }

                return new NoteEntity { Id = new EventId(data) };

            case NprofileEntity.HrpValue:
                return NprofileEntity.Decode(data);

            case NeventEntity.HrpValue:
                return NeventEntity.Decode(data);

            case NaddrEntity.HrpValue:
                return NaddrEntity.Decode(data);

            case PrivateKey.NsecHrp:
                throw new FormatException(
                    "nsec entities are not decoded by Nip19.Parse. Use PrivateKey.FromNsec for explicit lifetime management.");

            default:
                throw new FormatException($"Unknown NIP-19 prefix: {hrp}");
        }
    }
}
