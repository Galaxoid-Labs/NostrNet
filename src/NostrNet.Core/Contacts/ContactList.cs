// SPDX-License-Identifier: MIT
//
// NIP-02: Follow / Contact List.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/02.md
//
// A user advertises who they follow via a single replaceable kind-3 event
// whose tags are entries of the form:
//
//   ["p", <hex pubkey>]
//   ["p", <hex pubkey>, <recommended-relay-url>]
//   ["p", <hex pubkey>, <recommended-relay-url>, <petname>]
//
// All trailing positional fields are optional. The event's `content` was
// historically used to carry a relay-list JSON blob; that usage is
// deprecated in favor of NIP-65 but we preserve any raw content the
// caller passes through (or that we read off the wire).

using System.Diagnostics.CodeAnalysis;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Contacts;

/// <summary>NIP-02 event-kind constants.</summary>
public static class Nip02Kinds
{
    /// <summary>The kind for a user's contact (follow) list event.</summary>
    public const int ContactList = 3;
}

/// <summary>A single entry on a NIP-02 follow list.</summary>
/// <param name="PubKey">The followed pubkey.</param>
/// <param name="RecommendedRelay">Optional relay where the follower thinks events from this pubkey can be found.</param>
/// <param name="Petname">Optional local nickname assigned by the follower.</param>
public sealed record Contact(PublicKey PubKey, string? RecommendedRelay = null, string? Petname = null);

/// <summary>
/// A typed view of a NIP-02 kind-3 contact list event.
/// </summary>
public sealed class ContactList
{
    /// <summary>The list author.</summary>
    public required PublicKey Owner { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Every <c>"p"</c> entry on the list, in their original order.</summary>
    public required IReadOnlyList<Contact> Contacts { get; init; }

    /// <summary>
    /// The event's raw <c>content</c> field, passed through unchanged.
    /// Per NIP-02 this is usually empty; some legacy clients carried a
    /// relay-list JSON blob here. Prefer NIP-65 for relay advertisements.
    /// </summary>
    public required string RawContent { get; init; }

    /// <summary>
    /// Returns <c>true</c> iff this list contains a contact entry for
    /// <paramref name="pubkey"/>.
    /// </summary>
    public bool Follows(PublicKey pubkey)
    {
        ArgumentNullException.ThrowIfNull(pubkey);
        for (int i = 0; i < Contacts.Count; i++)
        {
            if (Contacts[i].PubKey.Equals(pubkey))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Parses a kind-3 event into a <see cref="ContactList"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not a NIP-02 event.</exception>
    public static ContactList FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip02Kinds.ContactList)
        {
            throw new ArgumentException(
                $"Expected a NIP-02 kind ({Nip02Kinds.ContactList}); got {ev.Kind}.",
                nameof(ev));
        }

        var contacts = new List<Contact>();
        foreach (var tag in ev.Tags.Named("p"))
        {
            if (tag.Count < 2 || string.IsNullOrEmpty(tag[1]))
            {
                continue;
            }

            if (!PublicKey.TryFromHex(tag[1], out var pubkey))
            {
                continue;
            }

            string? relay = (tag.Count >= 3 && !string.IsNullOrEmpty(tag[2])) ? tag[2] : null;
            string? petname = (tag.Count >= 4 && !string.IsNullOrEmpty(tag[3])) ? tag[3] : null;
            contacts.Add(new Contact(pubkey, relay, petname));
        }

        return new ContactList
        {
            Owner = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Contacts = contacts,
            RawContent = ev.Content,
        };
    }

    /// <summary>Try-parse variant; returns <c>false</c> on the wrong kind.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out ContactList? list)
    {
        list = null;
        if (ev is null || ev.Kind != Nip02Kinds.ContactList)
        {
            return false;
        }

        list = FromEvent(ev);
        return true;
    }

    /// <summary>Begins building a new contact list event.</summary>
    public static ContactListBuilder Create() => new();
}

/// <summary>
/// Fluent builder for NIP-02 contact list events.
/// </summary>
public sealed class ContactListBuilder
{
    private readonly List<Contact> _contacts = new();
    private string _content = string.Empty;

    internal ContactListBuilder()
    {
    }

    /// <summary>Adds a contact to the list.</summary>
    public ContactListBuilder AddContact(PublicKey pubkey, string? recommendedRelay = null, string? petname = null)
    {
        ArgumentNullException.ThrowIfNull(pubkey);
        _contacts.Add(new Contact(pubkey, recommendedRelay, petname));
        return this;
    }

    /// <summary>
    /// Sets the event's <c>content</c> field verbatim. Per NIP-02, leaving
    /// this empty (the default) is recommended; prefer NIP-65 for relay
    /// advertisements.
    /// </summary>
    public ContactListBuilder WithRawContent(string content)
    {
        _content = content ?? string.Empty;
        return this;
    }

    /// <summary>Builds and signs the contact list event.</summary>
    public NostrEvent Sign(PrivateKey key, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        var tags = new List<IReadOnlyList<string>>(_contacts.Count);
        foreach (var c in _contacts)
        {
            if (c.Petname is not null)
            {
                tags.Add(new[] { "p", c.PubKey.ToHex(), c.RecommendedRelay ?? string.Empty, c.Petname });
            }
            else if (c.RecommendedRelay is not null)
            {
                tags.Add(new[] { "p", c.PubKey.ToHex(), c.RecommendedRelay });
            }
            else
            {
                tags.Add(new[] { "p", c.PubKey.ToHex() });
            }
        }

        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = Nip02Kinds.ContactList,
            Tags = tags,
            Content = _content,
        }.Sign(key);
    }
}
