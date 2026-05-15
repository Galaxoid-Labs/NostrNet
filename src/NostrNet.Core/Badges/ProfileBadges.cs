// SPDX-License-Identifier: MIT
//
// NIP-58 kind-30008 Profile Badges. Parameterized replaceable with a
// fixed <c>d</c>-tag value of "profile_badges". Recipients use this
// event to choose which badges they want to display, and in what
// order. The tag list is a sequence of consecutive (a, e) pairs:
//
//   ["d", "profile_badges"]
//   ["a", "30009:<issuer-hex>:<identifier>"]
//   ["e", "<award-event-id-hex>", "<optional-relay>"]
//   ["a", "30009:<issuer-hex>:<identifier>"]
//   ["e", "<award-event-id-hex>", "<optional-relay>"]
//   ...
//
// Per spec, clients SHOULD ignore an `a` tag without a matching `e`
// tag, and vice versa. Award events referenced by an `e` tag should
// themselves carry the same `a` tag (which we don't enforce here —
// callers can cross-check by fetching the award and comparing
// addresses).

using System.Diagnostics.CodeAnalysis;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Badges;

/// <summary>One displayed badge on a user's profile.</summary>
/// <param name="BadgeAddress">The badge definition address string (<c>30009:issuer-hex:identifier</c>).</param>
/// <param name="AwardEventId">Id of the kind-8 award that proves the badge was conferred.</param>
/// <param name="RecommendedRelay">Optional relay URL hint where the award event can be fetched.</param>
public sealed record ProfileBadgeEntry(
    string BadgeAddress,
    EventId AwardEventId,
    string? RecommendedRelay);

/// <summary>A typed view of a NIP-58 kind-30008 Profile Badges event.</summary>
public sealed class ProfileBadges : INostrTypedEvent<ProfileBadges>
{
    /// <summary>Nostr kind(s) this type represents.</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { Nip58Kinds.ProfileBadges };

    /// <summary>The user whose profile these badges belong to.</summary>
    public required PublicKey Owner { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Badges in display order. Orphaned <c>a</c>/<c>e</c> tags (missing partner) are filtered out per spec.</summary>
    public required IReadOnlyList<ProfileBadgeEntry> Entries { get; init; }

    /// <summary>Parses a kind-30008 event into a typed <see cref="ProfileBadges"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not kind 30008.</exception>
    /// <exception cref="FormatException">Required <c>d=profile_badges</c> tag is missing or wrong.</exception>
    public static ProfileBadges FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip58Kinds.ProfileBadges)
        {
            throw new ArgumentException(
                $"Expected NIP-58 kind {Nip58Kinds.ProfileBadges}; got {ev.Kind}.",
                nameof(ev));
        }

        bool sawIdentifier = false;
        var entries = new List<ProfileBadgeEntry>();
        // Pair `a` with the FIRST `e` that follows it. NIP-58's
        // example shows consecutive a/e pairs; we read sequentially
        // so out-of-pair tags are dropped without misaligning.
        string? pendingAddress = null;
        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0) continue;
            switch (tag[0])
            {
                case "d":
                    if (tag.Count >= 2 && tag[1] == Nip58Kinds.ProfileBadgesIdentifier)
                    {
                        sawIdentifier = true;
                    }
                    break;
                case "a":
                    if (tag.Count >= 2 && BadgeAward.IsBadgeAddress(tag[1]))
                    {
                        // Orphan any prior pending `a` per spec.
                        pendingAddress = tag[1];
                    }
                    else
                    {
                        pendingAddress = null;
                    }

                    break;
                case "e":
                    if (pendingAddress is not null && tag.Count >= 2 && tag[1]?.Length == 64)
                    {
                        try
                        {
                            var id = EventId.FromHex(tag[1]);
                            string? relay = tag.Count >= 3 && !string.IsNullOrEmpty(tag[2]) ? tag[2] : null;
                            entries.Add(new ProfileBadgeEntry(pendingAddress, id, relay));
                        }
                        catch
                        {
                            // bad hex — drop the pair
                        }
                    }

                    pendingAddress = null;
                    break;
            }
        }

        if (!sawIdentifier)
        {
            throw new FormatException(
                $"NIP-58 Profile Badges event missing required ['d', '{Nip58Kinds.ProfileBadgesIdentifier}'] tag.");
        }

        return new ProfileBadges
        {
            Owner = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Entries = entries,
        };
    }

    /// <summary>Tries to parse <paramref name="ev"/> as a kind-30008 Profile Badges event.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out ProfileBadges? profile)
    {
        profile = null;
        if (ev is null || ev.Kind != Nip58Kinds.ProfileBadges)
        {
            return false;
        }

        try
        {
            profile = FromEvent(ev);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Starts building a Profile Badges event for the calling user.</summary>
    public static ProfileBadgesBuilder Create() => new();

    /// <summary>Returns a builder pre-populated with this event's current entries.</summary>
    public ProfileBadgesBuilder ToBuilder() => new ProfileBadgesBuilder().AddRange(Entries);
}

/// <summary>Fluent builder for NIP-58 kind-30008 Profile Badges events.</summary>
public sealed class ProfileBadgesBuilder
{
    private readonly List<ProfileBadgeEntry> _entries = new();

    internal ProfileBadgesBuilder() { }

    /// <summary>Adds a (badge, award) pair to the display list, in order.</summary>
    public ProfileBadgesBuilder Add(BadgeAward award, string? recommendedRelay = null)
    {
        ArgumentNullException.ThrowIfNull(award);
        _entries.Add(new ProfileBadgeEntry(award.BadgeAddress, award.Id, recommendedRelay));
        return this;
    }

    /// <summary>Adds a (badge, award) pair using raw values (useful when you already have the address + id from elsewhere).</summary>
    public ProfileBadgesBuilder Add(string badgeAddress, EventId awardEventId, string? recommendedRelay = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(badgeAddress);
        if (!BadgeAward.IsBadgeAddress(badgeAddress))
        {
            throw new ArgumentException(
                $"Badge address must be in the form '30009:<64-hex-pubkey>:<identifier>'; got '{badgeAddress}'.",
                nameof(badgeAddress));
        }

        ArgumentNullException.ThrowIfNull(awardEventId);
        _entries.Add(new ProfileBadgeEntry(badgeAddress, awardEventId, recommendedRelay));
        return this;
    }

    /// <summary>Appends every entry in the input sequence.</summary>
    public ProfileBadgesBuilder AddRange(IEnumerable<ProfileBadgeEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        foreach (var e in entries) _entries.Add(e);
        return this;
    }

    /// <summary>Removes every entry referencing <paramref name="badgeAddress"/>.</summary>
    public ProfileBadgesBuilder Remove(string badgeAddress)
    {
        ArgumentException.ThrowIfNullOrEmpty(badgeAddress);
        _entries.RemoveAll(e => string.Equals(e.BadgeAddress, badgeAddress, StringComparison.Ordinal));
        return this;
    }

    /// <summary>Builds the unsigned event for the given owner + timestamp.</summary>
    public UnsignedEvent BuildUnsigned(PublicKey owner, long createdAt)
    {
        ArgumentNullException.ThrowIfNull(owner);
        var tags = new List<IReadOnlyList<string>>(1 + _entries.Count * 2)
        {
            Tag.D(Nip58Kinds.ProfileBadgesIdentifier),
        };

        foreach (var entry in _entries)
        {
            tags.Add(new[] { "a", entry.BadgeAddress });
            tags.Add(entry.RecommendedRelay is null
                ? new[] { "e", entry.AwardEventId.ToHex() }
                : new[] { "e", entry.AwardEventId.ToHex(), entry.RecommendedRelay });
        }

        return new UnsignedEvent
        {
            PubKey = owner,
            CreatedAt = createdAt,
            Kind = Nip58Kinds.ProfileBadges,
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
