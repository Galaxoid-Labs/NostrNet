// SPDX-License-Identifier: MIT
//
// NIP-19 entity types: bech32-encoded Nostr identifiers.
//
// Simple entities (32-byte payload, no TLV):
//   npub  — public key
//   note  — bare event id
//   (nsec  — private key; handled via PrivateKey.FromNsec for lifetime safety.
//            Nip19.Parse does NOT return nsec to avoid accidental exposure.)
//
// TLV entities:
//   nprofile — pubkey + relays
//   nevent   — event id + relays + optional author + optional kind
//   naddr    — pubkey + kind + identifier + relays  (parameterized replaceable
//              event coordinate per NIP-33)
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/19.md

using System.Buffers;
using System.Buffers.Binary;
using NostrNet.Encoding;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Nip19;

/// <summary>
/// Base class for typed NIP-19 entities. Each subtype maps to one
/// bech32 HRP (<c>npub</c>, <c>note</c>, <c>nprofile</c>, <c>nevent</c>,
/// <c>naddr</c>).
/// </summary>
public abstract class Nip19Entity
{
    /// <summary>The bech32 HRP for this entity type.</summary>
    public abstract string Hrp { get; }

    /// <summary>Encodes this entity as its NIP-19 bech32 string.</summary>
    public abstract string Encode();

    /// <inheritdoc/>
    public override string ToString() => Encode();
}

/// <summary>NIP-19 <c>npub</c>: a bare public key.</summary>
public sealed class NpubEntity : Nip19Entity
{
    /// <summary>The wrapped public key.</summary>
    public required PublicKey PubKey { get; init; }

    /// <inheritdoc/>
    public override string Hrp => PublicKey.NpubHrp;

    /// <inheritdoc/>
    public override string Encode() => PubKey.ToNpub();
}

/// <summary>NIP-19 <c>note</c>: a bare event id.</summary>
public sealed class NoteEntity : Nip19Entity
{
    /// <summary>The wrapped event id.</summary>
    public required EventId Id { get; init; }

    /// <inheritdoc/>
    public override string Hrp => EventId.NoteHrp;

    /// <inheritdoc/>
    public override string Encode() => Id.ToNote();
}

/// <summary>NIP-19 <c>nprofile</c>: a public key with recommended relays.</summary>
public sealed class NprofileEntity : Nip19Entity
{
    /// <summary>The HRP for nprofile.</summary>
    public const string HrpValue = "nprofile";

    /// <summary>The wrapped public key.</summary>
    public required PublicKey PubKey { get; init; }

    /// <summary>Zero or more relay URLs hinting where the author posts.</summary>
    public IReadOnlyList<string> Relays { get; init; } = Array.Empty<string>();

    /// <inheritdoc/>
    public override string Hrp => HrpValue;

    /// <inheritdoc/>
    public override string Encode()
    {
        Span<byte> buffer = stackalloc byte[1024];
        var writer = new TlvWriter(buffer);
        Span<byte> pubKeyBytes = stackalloc byte[PublicKey.Size];
        PubKey.CopyTo(pubKeyBytes);
        if (!writer.TryWrite(TlvTypes.Special, pubKeyBytes))
        {
            throw new InvalidOperationException("Buffer too small for nprofile pubkey.");
        }

        foreach (string relay in Relays)
        {
            if (!writer.TryWriteUtf8(TlvTypes.Relay, relay))
            {
                throw new InvalidOperationException($"Relay URL too long or buffer too small: {relay}");
            }
        }

        return Bech32.Encode(Hrp, buffer[..writer.BytesWritten]);
    }

    internal static NprofileEntity Decode(ReadOnlySpan<byte> tlv)
    {
        PublicKey? pubKey = null;
        var relays = new List<string>();

        var reader = new TlvReader(tlv);
        while (reader.TryReadNext(out byte type, out var value))
        {
            switch (type)
            {
                case TlvTypes.Special:
                    if (value.Length != PublicKey.Size)
                    {
                        throw new FormatException("nprofile special must be 32 bytes.");
                    }

                    pubKey = new PublicKey(value);
                    break;

                case TlvTypes.Relay:
                    relays.Add(SysEncoding.UTF8.GetString(value));
                    break;

                default:
                    // Unknown TLV types are ignored per NIP-19.
                    break;
            }
        }

        if (pubKey is null)
        {
            throw new FormatException("nprofile missing required pubkey (TLV 0).");
        }

        return new NprofileEntity { PubKey = pubKey, Relays = relays };
    }
}

/// <summary>NIP-19 <c>nevent</c>: an event reference with optional metadata.</summary>
public sealed class NeventEntity : Nip19Entity
{
    /// <summary>The HRP for nevent.</summary>
    public const string HrpValue = "nevent";

    /// <summary>The event id.</summary>
    public required EventId Id { get; init; }

    /// <summary>Zero or more relay URLs that may carry the event.</summary>
    public IReadOnlyList<string> Relays { get; init; } = Array.Empty<string>();

    /// <summary>The author's public key, if encoded.</summary>
    public PublicKey? Author { get; init; }

    /// <summary>The event kind, if encoded.</summary>
    public int? Kind { get; init; }

    /// <inheritdoc/>
    public override string Hrp => HrpValue;

    /// <inheritdoc/>
    public override string Encode()
    {
        Span<byte> buffer = stackalloc byte[1024];
        var writer = new TlvWriter(buffer);

        Span<byte> idBytes = stackalloc byte[EventId.Size];
        Id.AsSpan().CopyTo(idBytes);
        if (!writer.TryWrite(TlvTypes.Special, idBytes))
        {
            throw new InvalidOperationException("Buffer too small for nevent id.");
        }

        foreach (string relay in Relays)
        {
            if (!writer.TryWriteUtf8(TlvTypes.Relay, relay))
            {
                throw new InvalidOperationException($"Relay URL too long or buffer too small: {relay}");
            }
        }

        if (Author is not null)
        {
            Span<byte> authorBytes = stackalloc byte[PublicKey.Size];
            Author.CopyTo(authorBytes);
            writer.TryWrite(TlvTypes.Author, authorBytes);
        }

        if (Kind is int kindValue)
        {
            writer.TryWriteUInt32BigEndian(TlvTypes.Kind, (uint)kindValue);
        }

        return Bech32.Encode(Hrp, buffer[..writer.BytesWritten]);
    }

    internal static NeventEntity Decode(ReadOnlySpan<byte> tlv)
    {
        EventId? id = null;
        var relays = new List<string>();
        PublicKey? author = null;
        int? kind = null;

        var reader = new TlvReader(tlv);
        while (reader.TryReadNext(out byte type, out var value))
        {
            switch (type)
            {
                case TlvTypes.Special:
                    if (value.Length != EventId.Size)
                    {
                        throw new FormatException("nevent special must be 32 bytes.");
                    }

                    id = new EventId(value);
                    break;

                case TlvTypes.Relay:
                    relays.Add(SysEncoding.UTF8.GetString(value));
                    break;

                case TlvTypes.Author:
                    if (value.Length != PublicKey.Size)
                    {
                        throw new FormatException("nevent author must be 32 bytes.");
                    }

                    author = new PublicKey(value);
                    break;

                case TlvTypes.Kind:
                    if (value.Length != 4)
                    {
                        throw new FormatException("nevent kind must be 4 bytes.");
                    }

                    kind = (int)BinaryPrimitives.ReadUInt32BigEndian(value);
                    break;
            }
        }

        if (id is null)
        {
            throw new FormatException("nevent missing required id (TLV 0).");
        }

        return new NeventEntity
        {
            Id = id,
            Relays = relays,
            Author = author,
            Kind = kind,
        };
    }
}

/// <summary>
/// NIP-19 <c>naddr</c>: a coordinate to a parameterized replaceable event
/// (kind + author + <c>d</c>-tag identifier + relays).
/// </summary>
public sealed class NaddrEntity : Nip19Entity
{
    /// <summary>The HRP for naddr.</summary>
    public const string HrpValue = "naddr";

    /// <summary>The author's public key.</summary>
    public required PublicKey PubKey { get; init; }

    /// <summary>The event kind (a replaceable kind, typically 30000–39999).</summary>
    public required int Kind { get; init; }

    /// <summary>The <c>d</c>-tag identifier string.</summary>
    public required string Identifier { get; init; }

    /// <summary>Zero or more relay URLs that may carry the event.</summary>
    public IReadOnlyList<string> Relays { get; init; } = Array.Empty<string>();

    /// <inheritdoc/>
    public override string Hrp => HrpValue;

    /// <inheritdoc/>
    public override string Encode()
    {
        Span<byte> buffer = stackalloc byte[1024];
        var writer = new TlvWriter(buffer);

        if (!writer.TryWriteUtf8(TlvTypes.Special, Identifier))
        {
            throw new InvalidOperationException("Identifier too long for naddr.");
        }

        foreach (string relay in Relays)
        {
            if (!writer.TryWriteUtf8(TlvTypes.Relay, relay))
            {
                throw new InvalidOperationException($"Relay URL too long or buffer too small: {relay}");
            }
        }

        Span<byte> authorBytes = stackalloc byte[PublicKey.Size];
        PubKey.CopyTo(authorBytes);
        if (!writer.TryWrite(TlvTypes.Author, authorBytes))
        {
            throw new InvalidOperationException("Buffer too small for naddr author.");
        }

        if (!writer.TryWriteUInt32BigEndian(TlvTypes.Kind, (uint)Kind))
        {
            throw new InvalidOperationException("Buffer too small for naddr kind.");
        }

        return Bech32.Encode(Hrp, buffer[..writer.BytesWritten]);
    }

    internal static NaddrEntity Decode(ReadOnlySpan<byte> tlv)
    {
        string? identifier = null;
        var relays = new List<string>();
        PublicKey? author = null;
        int? kind = null;

        var reader = new TlvReader(tlv);
        while (reader.TryReadNext(out byte type, out var value))
        {
            switch (type)
            {
                case TlvTypes.Special:
                    identifier = SysEncoding.UTF8.GetString(value);
                    break;

                case TlvTypes.Relay:
                    relays.Add(SysEncoding.UTF8.GetString(value));
                    break;

                case TlvTypes.Author:
                    if (value.Length != PublicKey.Size)
                    {
                        throw new FormatException("naddr author must be 32 bytes.");
                    }

                    author = new PublicKey(value);
                    break;

                case TlvTypes.Kind:
                    if (value.Length != 4)
                    {
                        throw new FormatException("naddr kind must be 4 bytes.");
                    }

                    kind = (int)BinaryPrimitives.ReadUInt32BigEndian(value);
                    break;
            }
        }

        if (identifier is null)
        {
            throw new FormatException("naddr missing required identifier (TLV 0).");
        }

        if (author is null)
        {
            throw new FormatException("naddr missing required author (TLV 2).");
        }

        if (kind is null)
        {
            throw new FormatException("naddr missing required kind (TLV 3).");
        }

        return new NaddrEntity
        {
            PubKey = author,
            Kind = kind.Value,
            Identifier = identifier,
            Relays = relays,
        };
    }
}

internal static class TlvTypes
{
    public const byte Special = 0;
    public const byte Relay = 1;
    public const byte Author = 2;
    public const byte Kind = 3;
}
