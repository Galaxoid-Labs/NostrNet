// SPDX-License-Identifier: MIT
//
// NIP-65: Relay List Metadata.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/65.md
//
// A user advertises their preferred read/write relays via a single
// replaceable kind-10002 event whose tags are entries of the form:
//
//   ["r", "wss://relay.example.com"]            both read AND write
//   ["r", "wss://relay.example.com", "read"]    read only
//   ["r", "wss://relay.example.com", "write"]   write only
//
// The event's content field is unused per spec.

using System.Diagnostics.CodeAnalysis;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.RelayList;

/// <summary>NIP-65 event-kind constants.</summary>
public static class Nip65Kinds
{
    /// <summary>The kind for a user's relay list metadata event.</summary>
    public const int RelayListMetadata = 10002;
}

/// <summary>How an author intends a given relay to be used.</summary>
public enum RelayUsage
{
    /// <summary>The relay is used for both reading and writing (no marker on the tag).</summary>
    ReadAndWrite = 0,

    /// <summary>The relay is read-only (<c>"read"</c> marker).</summary>
    ReadOnly = 1,

    /// <summary>The relay is write-only (<c>"write"</c> marker).</summary>
    WriteOnly = 2,
}

/// <summary>A single relay entry on a NIP-65 list.</summary>
/// <param name="Url">The relay URL (typically <c>wss://...</c>).</param>
/// <param name="Usage">How the author uses this relay.</param>
public sealed record RelayEntry(string Url, RelayUsage Usage);

/// <summary>
/// A typed view of a NIP-65 kind-10002 relay list metadata event.
/// </summary>
/// <remarks>
/// Use <see cref="FromEvent"/> to parse a received event or
/// <see cref="Create"/> to build a new one.
/// </remarks>
public sealed class RelayListMetadata
{
    /// <summary>The list author.</summary>
    public required PublicKey Owner { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Every <c>"r"</c> entry on the list, in their original order.</summary>
    public required IReadOnlyList<RelayEntry> Relays { get; init; }

    /// <summary>The relay URLs intended for reading (both read+write and read-only).</summary>
    public IEnumerable<string> ReadRelays
        => Relays.Where(r => r.Usage is RelayUsage.ReadAndWrite or RelayUsage.ReadOnly).Select(r => r.Url);

    /// <summary>The relay URLs intended for writing (both read+write and write-only).</summary>
    public IEnumerable<string> WriteRelays
        => Relays.Where(r => r.Usage is RelayUsage.ReadAndWrite or RelayUsage.WriteOnly).Select(r => r.Url);

    /// <summary>Parses a kind-10002 event into a <see cref="RelayListMetadata"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not a NIP-65 event.</exception>
    public static RelayListMetadata FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip65Kinds.RelayListMetadata)
        {
            throw new ArgumentException(
                $"Expected a NIP-65 kind ({Nip65Kinds.RelayListMetadata}); got {ev.Kind}.",
                nameof(ev));
        }

        var entries = new List<RelayEntry>();
        foreach (var tag in ev.Tags.Named("r"))
        {
            if (tag.Count < 2 || string.IsNullOrEmpty(tag[1]))
            {
                // Malformed "r" tag (no URL) — skip.
                continue;
            }

            RelayUsage usage = (tag.Count >= 3 ? tag[2] : null) switch
            {
                "read" => RelayUsage.ReadOnly,
                "write" => RelayUsage.WriteOnly,
                _ => RelayUsage.ReadAndWrite,
            };

            entries.Add(new RelayEntry(tag[1], usage));
        }

        return new RelayListMetadata
        {
            Owner = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Relays = entries,
        };
    }

    /// <summary>Try-parse variant; returns <c>false</c> on the wrong kind.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out RelayListMetadata? metadata)
    {
        metadata = null;
        if (ev is null || ev.Kind != Nip65Kinds.RelayListMetadata)
        {
            return false;
        }

        metadata = FromEvent(ev);
        return true;
    }

    /// <summary>Begins building a new relay list event.</summary>
    public static RelayListMetadataBuilder Create() => new();
}

/// <summary>
/// Fluent builder for NIP-65 relay list events. Add entries via
/// <see cref="AddRelay"/>, <see cref="AddReadRelay"/>, or
/// <see cref="AddWriteRelay"/>, then call <see cref="Sign"/>.
/// </summary>
public sealed class RelayListMetadataBuilder
{
    private readonly List<RelayEntry> _entries = new();

    internal RelayListMetadataBuilder()
    {
    }

    /// <summary>Adds a relay with the given usage (default: read+write).</summary>
    public RelayListMetadataBuilder AddRelay(string url, RelayUsage usage = RelayUsage.ReadAndWrite)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);
        _entries.Add(new RelayEntry(url, usage));
        return this;
    }

    /// <summary>Adds a read-only relay (<c>"read"</c> marker).</summary>
    public RelayListMetadataBuilder AddReadRelay(string url) => AddRelay(url, RelayUsage.ReadOnly);

    /// <summary>Adds a write-only relay (<c>"write"</c> marker).</summary>
    public RelayListMetadataBuilder AddWriteRelay(string url) => AddRelay(url, RelayUsage.WriteOnly);

    /// <summary>Builds and signs the relay list event.</summary>
    /// <remarks>
    /// Per NIP-65, the spec recommends keeping the list small (≤ 10 relays).
    /// The library does not enforce this — keep your lists trim yourself.
    /// </remarks>
    public NostrEvent Sign(PrivateKey key, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        var tags = new List<IReadOnlyList<string>>(_entries.Count);
        foreach (var entry in _entries)
        {
            tags.Add(entry.Usage switch
            {
                RelayUsage.ReadOnly => new[] { "r", entry.Url, "read" },
                RelayUsage.WriteOnly => new[] { "r", entry.Url, "write" },
                _ => new[] { "r", entry.Url },
            });
        }

        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = Nip65Kinds.RelayListMetadata,
            Tags = tags,
            Content = string.Empty,
        }.Sign(key);
    }
}
