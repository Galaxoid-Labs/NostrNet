// SPDX-License-Identifier: MIT
//
// NIP-B7: Blossom user server list.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/B7.md
//
// A user publishes a kind:10063 event listing which Blossom servers
// they store their files on. The list is replaceable per NIP-33's
// non-addressable rules (kind 10000-19999) — a fresh publish replaces
// the previous list under (kind, pubkey).
//
// Wire format:
//
//   kind     = 10063
//   content  = ""        (empty by convention)
//   tags:
//     ["server", "<https-url>"]    (repeatable; at least one expected)
//
// Server order MAY be meaningful: clients SHOULD try servers in the
// order the user listed them (Blossom BUD-03 calls this an
// "ordered list of preferred servers"). NostrNet preserves the
// tag-order on parse and emit.

using System.Diagnostics.CodeAnalysis;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Blossom.UserServers;

/// <summary>Kind constants for the Blossom NIPs.</summary>
public static class BlossomKinds
{
    /// <summary>NIP-B7 user server list (kind 10063).</summary>
    public const int UserServerList = 10063;
}

/// <summary>
/// A typed view of a NIP-B7 user server list event. The
/// <see cref="Servers"/> list is in user-declared preference order:
/// clients trying to fetch a file by sha256 should walk the list
/// from index 0 onward.
/// </summary>
public sealed class BlossomServerList : INostrTypedEvent<BlossomServerList>
{
    /// <summary>Nostr kind(s) this type represents.</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { BlossomKinds.UserServerList };

    /// <summary>The owner of this list.</summary>
    public required PublicKey Author { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Server URLs in the user's declared preference order.</summary>
    public required IReadOnlyList<string> Servers { get; init; }

    /// <summary>Parses a kind-10063 event into a typed <see cref="BlossomServerList"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not kind 10063.</exception>
    public static BlossomServerList FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != BlossomKinds.UserServerList)
        {
            throw new ArgumentException(
                $"Expected NIP-B7 kind {BlossomKinds.UserServerList}; got {ev.Kind}.",
                nameof(ev));
        }

        var servers = new List<string>();
        foreach (var tag in ev.Tags)
        {
            if (tag.Count >= 2
                && string.Equals(tag[0], "server", StringComparison.Ordinal)
                && !string.IsNullOrEmpty(tag[1]))
            {
                servers.Add(tag[1]);
            }
        }

        return new BlossomServerList
        {
            Author = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Servers = servers,
        };
    }

    /// <summary>
    /// Tries to parse <paramref name="ev"/> as a NIP-B7 user server list.
    /// Returns <c>false</c> for non-10063 events; never throws.
    /// </summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out BlossomServerList? list)
    {
        list = null;
        if (ev is null || ev.Kind != BlossomKinds.UserServerList)
        {
            return false;
        }

        list = FromEvent(ev);
        return true;
    }

    /// <summary>Starts building a fresh server list.</summary>
    public static BlossomServerListBuilder Create() => new();
}

/// <summary>Fluent builder for NIP-B7 kind-10063 user-server-list events.</summary>
public sealed class BlossomServerListBuilder
{
    private readonly List<string> _servers = new();

    internal BlossomServerListBuilder() { }

    /// <summary>
    /// Appends a server URL to the list. Order is significant — the
    /// first one added is the user's preferred server.
    /// </summary>
    public BlossomServerListBuilder AddServer(string serverUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(serverUrl);
        _servers.Add(serverUrl);
        return this;
    }

    /// <summary>Convenience: appends every URL in <paramref name="serverUrls"/> in order.</summary>
    public BlossomServerListBuilder AddServers(IEnumerable<string> serverUrls)
    {
        ArgumentNullException.ThrowIfNull(serverUrls);
        foreach (var s in serverUrls)
        {
            AddServer(s);
        }

        return this;
    }

    /// <summary>Builds the unsigned event.</summary>
    /// <exception cref="InvalidOperationException">No servers were added.</exception>
    public UnsignedEvent BuildUnsigned(PublicKey author, long createdAt)
    {
        ArgumentNullException.ThrowIfNull(author);
        if (_servers.Count == 0)
        {
            throw new InvalidOperationException(
                "BlossomServerList requires at least one server URL.");
        }

        var tags = new List<IReadOnlyList<string>>(_servers.Count);
        foreach (var s in _servers)
        {
            tags.Add(new[] { "server", s });
        }

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = createdAt,
            Kind = BlossomKinds.UserServerList,
            Tags = tags,
            Content = string.Empty,
        };
    }

    /// <summary>Builds and signs the event.</summary>
    public NostrEvent BuildAndSign(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return BuildUnsigned(key.PublicKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds()).Sign(key);
    }
}
