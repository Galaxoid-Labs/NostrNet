// SPDX-License-Identifier: MIT
//
// NIP-09: Event Deletion Request.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/09.md
//
// A user requests that one or more of their previously-published events be
// deleted by emitting a kind-5 event:
//
//   {
//     "kind": 5,
//     "pubkey": <author>,
//     "content": "<optional human-readable reason>",
//     "tags": [
//       ["e", <event-id>],                                    // non-replaceable
//       ["a", "<kind>:<pubkey>:<d-tag>"],                     // parameterized-replaceable
//       ["k", "<kind>"]                                       // optional; one per kind
//     ]
//   }
//
// Deletion is advisory:
//   - A relay SHOULD stop publishing events that match the request AND
//     share the deletion request's `pubkey`.
//   - A relay MAY refuse to act on the request.
//   - The deletion request itself stays published (so clients see "this
//     was deleted" rather than a silent disappearance).
//
// The `pubkey` check is critical — Alice cannot delete Bob's events even
// if she references them. `Targets` enforces this on the read side.

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Deletions;

/// <summary>NIP-09 event-kind constants.</summary>
public static class Nip09Kinds
{
    /// <summary>The kind for a deletion request.</summary>
    public const int DeletionRequest = 5;
}

/// <summary>Identifier of a parameterized-replaceable event (NIP-01 "a" tag).</summary>
/// <param name="Kind">The event kind.</param>
/// <param name="Author">The pubkey that authored the addressable event.</param>
/// <param name="Identifier">The <c>d</c>-tag identifier within the (kind, pubkey) namespace.</param>
public sealed record AddressableEventCoordinates(int Kind, PublicKey Author, string Identifier)
{
    /// <summary>Encodes as the NIP-01 <c>"a"</c> tag value: <c>kind:pubkey:identifier</c>.</summary>
    public string ToTagValue() => $"{Kind}:{Author.ToHex()}:{Identifier}";

    /// <summary>Parses the NIP-01 <c>"a"</c> tag value.</summary>
    public static bool TryParse(string? value, [NotNullWhen(true)] out AddressableEventCoordinates? coords)
    {
        coords = null;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        var parts = value.Split(':', 3);
        if (parts.Length != 3
            || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out int kind)
            || !PublicKey.TryFromHex(parts[1], out var author))
        {
            return false;
        }

        coords = new AddressableEventCoordinates(kind, author, parts[2]);
        return true;
    }
}

/// <summary>
/// A typed view of a NIP-09 kind-5 deletion request.
/// </summary>
public sealed class DeletionRequest
{
    /// <summary>The pubkey requesting deletion. Only this author's events can be deleted by this request.</summary>
    public required PublicKey Requester { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Event ids referenced by <c>"e"</c> tags.</summary>
    public required IReadOnlyList<EventId> EventIds { get; init; }

    /// <summary>Addressable (parameterized-replaceable) events referenced by <c>"a"</c> tags.</summary>
    public required IReadOnlyList<AddressableEventCoordinates> AddressableEvents { get; init; }

    /// <summary>Optional <c>"k"</c> tag values — the kinds the deletion claims to affect.</summary>
    public required IReadOnlyList<int> Kinds { get; init; }

    /// <summary>Optional reason supplied in the event's <c>content</c>.</summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Returns <c>true</c> iff this deletion request applies to
    /// <paramref name="candidate"/>. Specifically: the candidate's pubkey
    /// matches the requester, AND the candidate is referenced either by
    /// its event id (non-replaceable) or by its <c>(kind, pubkey, d-tag)</c>
    /// coordinates (parameterized-replaceable, NIP-33).
    /// </summary>
    public bool Targets(NostrEvent candidate)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (!candidate.PubKey.Equals(Requester))
        {
            return false;
        }

        for (int i = 0; i < EventIds.Count; i++)
        {
            if (EventIds[i].Equals(candidate.Id))
            {
                return true;
            }
        }

        if (AddressableEvents.Count > 0)
        {
            string? candidateD = candidate.Tags.FirstValue("d");
            if (candidateD is not null)
            {
                for (int i = 0; i < AddressableEvents.Count; i++)
                {
                    var a = AddressableEvents[i];
                    if (a.Kind == candidate.Kind
                        && a.Author.Equals(candidate.PubKey)
                        && string.Equals(a.Identifier, candidateD, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /// <summary>Parses a kind-5 event into a <see cref="DeletionRequest"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not a NIP-09 event.</exception>
    public static DeletionRequest FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip09Kinds.DeletionRequest)
        {
            throw new ArgumentException(
                $"Expected a NIP-09 kind ({Nip09Kinds.DeletionRequest}); got {ev.Kind}.",
                nameof(ev));
        }

        var ids = new List<EventId>();
        foreach (var tag in ev.Tags.Named("e"))
        {
            if (tag.Count >= 2 && EventId.TryFromHex(tag[1], out var id))
            {
                ids.Add(id);
            }
        }

        var addressables = new List<AddressableEventCoordinates>();
        foreach (var tag in ev.Tags.Named("a"))
        {
            if (tag.Count >= 2 && AddressableEventCoordinates.TryParse(tag[1], out var coords))
            {
                addressables.Add(coords);
            }
        }

        var kinds = new List<int>();
        foreach (var tag in ev.Tags.Named("k"))
        {
            if (tag.Count >= 2
                && int.TryParse(tag[1], NumberStyles.None, CultureInfo.InvariantCulture, out int k))
            {
                kinds.Add(k);
            }
        }

        return new DeletionRequest
        {
            Requester = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            EventIds = ids,
            AddressableEvents = addressables,
            Kinds = kinds,
            Reason = ev.Content,
        };
    }

    /// <summary>Try-parse variant.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out DeletionRequest? request)
    {
        request = null;
        if (ev is null || ev.Kind != Nip09Kinds.DeletionRequest)
        {
            return false;
        }

        request = FromEvent(ev);
        return true;
    }

    /// <summary>Begins building a new deletion request.</summary>
    public static DeletionRequestBuilder Create() => new();
}

/// <summary>Fluent builder for NIP-09 deletion requests.</summary>
public sealed class DeletionRequestBuilder
{
    private readonly List<EventId> _ids = new();
    private readonly List<AddressableEventCoordinates> _addressables = new();
    private readonly List<int> _kinds = new();
    private string _reason = string.Empty;

    internal DeletionRequestBuilder()
    {
    }

    /// <summary>Adds an event id (non-replaceable event) to the deletion request.</summary>
    public DeletionRequestBuilder AddEvent(EventId id)
    {
        ArgumentNullException.ThrowIfNull(id);
        _ids.Add(id);
        return this;
    }

    /// <summary>Adds an event id from its hex string form.</summary>
    public DeletionRequestBuilder AddEvent(string idHex) => AddEvent(EventId.FromHex(idHex));

    /// <summary>Adds an addressable (parameterized-replaceable) event reference.</summary>
    public DeletionRequestBuilder AddAddressableEvent(int kind, PublicKey author, string identifier)
    {
        ArgumentNullException.ThrowIfNull(author);
        ArgumentNullException.ThrowIfNull(identifier);
        _addressables.Add(new AddressableEventCoordinates(kind, author, identifier));
        return this;
    }

    /// <summary>Adds a <c>k</c> tag declaring an affected event kind.</summary>
    public DeletionRequestBuilder AddKind(int kind)
    {
        _kinds.Add(kind);
        return this;
    }

    /// <summary>Sets the human-readable reason carried in <c>content</c>.</summary>
    public DeletionRequestBuilder WithReason(string reason)
    {
        _reason = reason ?? string.Empty;
        return this;
    }

    /// <summary>Builds and signs the deletion-request event.</summary>
    public NostrEvent Sign(PrivateKey key, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(key);

        var tags = new List<IReadOnlyList<string>>(_ids.Count + _addressables.Count + _kinds.Count);
        foreach (var id in _ids)
        {
            tags.Add(new[] { "e", id.ToHex() });
        }

        foreach (var a in _addressables)
        {
            tags.Add(new[] { "a", a.ToTagValue() });
        }

        foreach (var k in _kinds)
        {
            tags.Add(new[] { "k", k.ToString(CultureInfo.InvariantCulture) });
        }

        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = Nip09Kinds.DeletionRequest,
            Tags = tags,
            Content = _reason,
        }.Sign(key);
    }
}
