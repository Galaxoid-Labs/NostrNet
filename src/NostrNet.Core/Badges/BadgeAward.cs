// SPDX-License-Identifier: MIT
//
// NIP-58 kind-8 Badge Award. Immutable: each award is its own event.
// Per spec the same event may award the same badge to multiple
// recipients via repeated `p` tags.
//
// Wire format:
//
//   kind     = 8
//   content  = ""        (not used)
//   tags:
//     ["a", "30009:<issuer-pubkey-hex>:<badge-identifier>"]   required
//     ["p", <recipient-hex>, <optional-relay>]                required, repeatable
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/58.md

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Badges;

/// <summary>One recipient of a badge award.</summary>
/// <param name="Pubkey">The recipient's Nostr pubkey.</param>
/// <param name="RecommendedRelay">Optional relay URL from the <c>p</c> tag's third element.</param>
public sealed record BadgeRecipient(PublicKey Pubkey, string? RecommendedRelay);

/// <summary>A typed view of a NIP-58 kind-8 Badge Award event.</summary>
public sealed class BadgeAward
{
    /// <summary>The issuer (the pubkey that signed the award event).</summary>
    public required PublicKey Issuer { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>The award event's own id — referenced from <see cref="ProfileBadges"/> via <c>e</c> tags.</summary>
    public required EventId Id { get; init; }

    /// <summary>The badge being awarded (NIP-58 address string <c>30009:issuer:identifier</c>).</summary>
    public required string BadgeAddress { get; init; }

    /// <summary>Every pubkey awarded by this event, in tag order. At least one entry.</summary>
    public required IReadOnlyList<BadgeRecipient> Recipients { get; init; }

    /// <summary>NIP-13 leading-zero bits achieved by this award's id.</summary>
    public required int PowDifficulty { get; init; }

    /// <summary>Target difficulty the issuer committed to via the <c>nonce</c> tag, if any.</summary>
    public required int? CommittedPowDifficulty { get; init; }

    /// <summary>Parses a kind-8 event into a typed <see cref="BadgeAward"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not kind 8.</exception>
    /// <exception cref="FormatException">Required <c>a</c> or <c>p</c> tags are missing / malformed.</exception>
    public static BadgeAward FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip58Kinds.BadgeAward)
        {
            throw new ArgumentException(
                $"Expected NIP-58 kind {Nip58Kinds.BadgeAward}; got {ev.Kind}.",
                nameof(ev));
        }

        string? address = null;
        var recipients = new List<BadgeRecipient>();

        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0) continue;
            switch (tag[0])
            {
                case "a":
                    if (tag.Count >= 2 && address is null && IsBadgeAddress(tag[1]))
                    {
                        address = tag[1];
                    }
                    break;
                case "p":
                    if (tag.Count >= 2 && tag[1]?.Length == 64)
                    {
                        try
                        {
                            var pk = PublicKey.FromHex(tag[1]);
                            string? relay = tag.Count >= 3 && !string.IsNullOrEmpty(tag[2]) ? tag[2] : null;
                            recipients.Add(new BadgeRecipient(pk, relay));
                        }
                        catch
                        {
                            // skip malformed
                        }
                    }
                    break;
            }
        }

        if (address is null)
        {
            throw new FormatException("NIP-58 Badge Award is missing the required 'a' tag (badge definition reference).");
        }

        if (recipients.Count == 0)
        {
            throw new FormatException("NIP-58 Badge Award has no recipient 'p' tags.");
        }

        return new BadgeAward
        {
            Issuer = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Id = ev.Id,
            BadgeAddress = address,
            Recipients = recipients,
            PowDifficulty = ProofOfWork.Difficulty(ev),
            CommittedPowDifficulty = ProofOfWork.CommittedDifficulty(ev),
        };
    }

    /// <summary>Tries to parse <paramref name="ev"/> as a kind-8 Badge Award.</summary>
    public static bool TryFromEvent(NostrEvent? ev, out BadgeAward? award)
    {
        award = null;
        if (ev is null || ev.Kind != Nip58Kinds.BadgeAward)
        {
            return false;
        }

        try
        {
            award = FromEvent(ev);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Starts building a Badge Award for the given badge address.</summary>
    public static BadgeAwardBuilder Create(string badgeAddress) => new(badgeAddress);

    /// <summary>Starts building a Badge Award for the given <paramref name="definition"/>.</summary>
    public static BadgeAwardBuilder Create(BadgeDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        return new BadgeAwardBuilder(definition.AddressString);
    }

    internal static bool IsBadgeAddress(string s)
    {
        // Quick shape check: "30009:<64hex>:<identifier>". We don't
        // fully validate the identifier — anything non-empty works.
        if (string.IsNullOrEmpty(s)) return false;
        int firstColon = s.IndexOf(':');
        if (firstColon < 0) return false;
        int secondColon = s.IndexOf(':', firstColon + 1);
        if (secondColon < 0) return false;
        if (s[..firstColon] != Nip58Kinds.BadgeDefinition.ToString(System.Globalization.CultureInfo.InvariantCulture))
        {
            return false;
        }

        int hexLen = secondColon - firstColon - 1;
        if (hexLen != 64) return false;
        return s.Length > secondColon + 1;
    }
}

/// <summary>Fluent builder for NIP-58 kind-8 Badge Award events.</summary>
public sealed class BadgeAwardBuilder
{
    private readonly string _badgeAddress;
    private readonly List<(PublicKey, string?)> _recipients = new();

    internal BadgeAwardBuilder(string badgeAddress)
    {
        ArgumentException.ThrowIfNullOrEmpty(badgeAddress);
        if (!BadgeAward.IsBadgeAddress(badgeAddress))
        {
            throw new ArgumentException(
                $"Badge address must be in the form '30009:<64-hex-pubkey>:<identifier>'; got '{badgeAddress}'.",
                nameof(badgeAddress));
        }

        _badgeAddress = badgeAddress;
    }

    /// <summary>Adds one recipient (a <c>p</c> tag).</summary>
    public BadgeAwardBuilder ToRecipient(PublicKey recipient, string? recommendedRelay = null)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        _recipients.Add((recipient, recommendedRelay));
        return this;
    }

    /// <summary>Convenience: adds multiple recipients in one call.</summary>
    public BadgeAwardBuilder ToRecipients(IEnumerable<PublicKey> recipients)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        foreach (var p in recipients)
        {
            _recipients.Add((p, null));
        }

        return this;
    }

    /// <summary>Builds the unsigned event for the given issuer + timestamp.</summary>
    /// <exception cref="InvalidOperationException">No recipients were added.</exception>
    public UnsignedEvent BuildUnsigned(PublicKey issuer, long createdAt)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        if (_recipients.Count == 0)
        {
            throw new InvalidOperationException(
                "BadgeAward requires at least one recipient — call ToRecipient(...) first.");
        }

        var tags = new List<IReadOnlyList<string>>(1 + _recipients.Count)
        {
            new[] { "a", _badgeAddress },
        };

        foreach ((var pk, var relay) in _recipients)
        {
            tags.Add(Tag.P(pk, relay));
        }

        return new UnsignedEvent
        {
            PubKey = issuer,
            CreatedAt = createdAt,
            Kind = Nip58Kinds.BadgeAward,
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

    /// <summary>
    /// Mines the award to <paramref name="targetDifficulty"/> leading
    /// zero bits per NIP-13, attaches the committed <c>nonce</c> tag,
    /// and signs. NIP-58 allows issuers to embed PoW as a "minting
    /// cost" signal on awards too.
    /// </summary>
    public NostrEvent BuildMineAndSign(PrivateKey key, int targetDifficulty, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (_recipients.Count == 0)
        {
            throw new InvalidOperationException(
                "BadgeAward requires at least one recipient — call ToRecipient(...) first.");
        }

        var unsigned = BuildUnsigned(key.PublicKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var mined = ProofOfWork.Mine(unsigned, targetDifficulty, cancellationToken);
        return mined.Sign(key);
    }
}
