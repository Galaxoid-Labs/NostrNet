// SPDX-License-Identifier: MIT
//
// NIP-58: Badges.
//
// Three event kinds that compose:
//
//   30009  BadgeDefinition  — issuer publishes (parameterized replaceable)
//   8      BadgeAward       — issuer awards to one or more recipients
//   30008  ProfileBadges    — recipient curates which badges to display
//
// This file defines kind 30009 (BadgeDefinition).
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/58.md
//
// Wire format:
//
//   kind     = 30009
//   content  = ""        (not used)
//   tags:
//     ["d", <identifier>]                    required
//     ["name", <short title>]                optional
//     ["description", <long form>]           optional
//     ["image", <url>, <dim?>]               optional, recommended 1024×1024
//     ["thumb", <url>, <dim?>]               optional, repeatable

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Nip19;

namespace NostrNet.Badges;

/// <summary>Kind constants for NIP-58 badge events.</summary>
public static class Nip58Kinds
{
    /// <summary>Badge Definition (parameterized replaceable; kind 30009).</summary>
    public const int BadgeDefinition = 30009;

    /// <summary>Badge Award (immutable; kind 8).</summary>
    public const int BadgeAward = 8;

    /// <summary>Profile Badges (parameterized replaceable, d=<c>profile_badges</c>; kind 30008).</summary>
    public const int ProfileBadges = 30008;

    /// <summary>The fixed <c>d</c>-tag value every Profile Badges event uses.</summary>
    public const string ProfileBadgesIdentifier = "profile_badges";
}

/// <summary>One image entry on a badge definition — URL plus optional dimensions like <c>"1024x1024"</c>.</summary>
/// <param name="Url">The image URL.</param>
/// <param name="Dim">Optional <c>WxH</c> dimensions string from the second tag value.</param>
public sealed record BadgeImage(string Url, string? Dim);

/// <summary>A typed view of a NIP-58 kind-30009 Badge Definition event.</summary>
public sealed class BadgeDefinition
{
    /// <summary>The issuer's pubkey — the entity defining this badge.</summary>
    public required PublicKey Issuer { get; init; }

    /// <summary>The badge identifier (the <c>d</c>-tag value).</summary>
    public required string Identifier { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Short title (the <c>name</c> tag), if present.</summary>
    public string? Name { get; init; }

    /// <summary>Long-form description (the <c>description</c> tag), if present.</summary>
    public string? Description { get; init; }

    /// <summary>The badge's canonical full-size image (the first <c>image</c> tag).</summary>
    public BadgeImage? Image { get; init; }

    /// <summary>Thumbnail images, one per <c>thumb</c> tag, in tag order.</summary>
    public IReadOnlyList<BadgeImage> Thumbnails { get; init; } = Array.Empty<BadgeImage>();

    /// <summary>
    /// NIP-13 leading-zero bits achieved by this event's id. NIP-58
    /// allows issuers to embed PoW as a "minting cost" signal — this
    /// is what they achieved.
    /// </summary>
    public required int PowDifficulty { get; init; }

    /// <summary>
    /// The target difficulty the issuer committed to via the
    /// <c>nonce</c> tag's third value, if any. When this and
    /// <see cref="PowDifficulty"/> both meet or exceed the same
    /// threshold, the event satisfies the issuer's own commitment.
    /// </summary>
    public required int? CommittedPowDifficulty { get; init; }

    /// <summary>Returns the NIP-58 address string for this badge: <c>30009:pubkey-hex:identifier</c>.</summary>
    public string AddressString => $"{Nip58Kinds.BadgeDefinition}:{Issuer.ToHex()}:{Identifier}";

    /// <summary>Returns the NIP-19 <c>naddr</c> coordinate for this badge.</summary>
    public NaddrEntity ToNaddr(IReadOnlyList<string>? relays = null)
        => new()
        {
            PubKey = Issuer,
            Kind = Nip58Kinds.BadgeDefinition,
            Identifier = Identifier,
            Relays = relays ?? Array.Empty<string>(),
        };

    /// <summary>Parses a kind-30009 event into a typed <see cref="BadgeDefinition"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="ev"/> is not kind 30009.</exception>
    /// <exception cref="FormatException">Required <c>d</c> tag is missing or empty.</exception>
    public static BadgeDefinition FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip58Kinds.BadgeDefinition)
        {
            throw new ArgumentException(
                $"Expected NIP-58 kind {Nip58Kinds.BadgeDefinition}; got {ev.Kind}.",
                nameof(ev));
        }

        string? identifier = null;
        string? name = null;
        string? description = null;
        BadgeImage? image = null;
        var thumbs = new List<BadgeImage>();

        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0) continue;
            switch (tag[0])
            {
                case "d":
                    if (tag.Count >= 2) identifier = tag[1];
                    break;
                case "name":
                    if (tag.Count >= 2) name = tag[1];
                    break;
                case "description":
                    if (tag.Count >= 2) description = tag[1];
                    break;
                case "image":
                    if (tag.Count >= 2 && image is null && !string.IsNullOrEmpty(tag[1]))
                    {
                        image = new BadgeImage(tag[1], tag.Count >= 3 ? tag[2] : null);
                    }
                    break;
                case "thumb":
                    if (tag.Count >= 2 && !string.IsNullOrEmpty(tag[1]))
                    {
                        thumbs.Add(new BadgeImage(tag[1], tag.Count >= 3 ? tag[2] : null));
                    }
                    break;
            }
        }

        if (string.IsNullOrEmpty(identifier))
        {
            throw new FormatException("NIP-58 Badge Definition is missing the required 'd' tag.");
        }

        return new BadgeDefinition
        {
            Issuer = ev.PubKey,
            Identifier = identifier,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Name = name,
            Description = description,
            Image = image,
            Thumbnails = thumbs,
            PowDifficulty = ProofOfWork.Difficulty(ev),
            CommittedPowDifficulty = ProofOfWork.CommittedDifficulty(ev),
        };
    }

    /// <summary>Tries to parse <paramref name="ev"/> as a kind-30009 Badge Definition.</summary>
    public static bool TryFromEvent(NostrEvent? ev, out BadgeDefinition? definition)
    {
        definition = null;
        if (ev is null || ev.Kind != Nip58Kinds.BadgeDefinition)
        {
            return false;
        }

        try
        {
            definition = FromEvent(ev);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Starts building a fresh Badge Definition under <paramref name="identifier"/>.</summary>
    public static BadgeDefinitionBuilder Create(string identifier) => new(identifier);

    /// <summary>Builds the NIP-58 address string <c>30009:pubkey-hex:identifier</c> directly.</summary>
    public static string Address(PublicKey issuer, string identifier)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        return $"{Nip58Kinds.BadgeDefinition}:{issuer.ToHex()}:{identifier}";
    }
}

/// <summary>Fluent builder for NIP-58 kind-30009 Badge Definition events.</summary>
public sealed class BadgeDefinitionBuilder
{
    private readonly string _identifier;
    private string? _name;
    private string? _description;
    private BadgeImage? _image;
    private readonly List<BadgeImage> _thumbs = new();

    internal BadgeDefinitionBuilder(string identifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        _identifier = identifier;
    }

    /// <summary>Sets the short title (the <c>name</c> tag).</summary>
    public BadgeDefinitionBuilder WithName(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        _name = name;
        return this;
    }

    /// <summary>Sets the long-form description.</summary>
    public BadgeDefinitionBuilder WithDescription(string description)
    {
        ArgumentNullException.ThrowIfNull(description);
        _description = description;
        return this;
    }

    /// <summary>Sets the full-size image URL with optional <c>WxH</c> dimensions (recommended <c>1024x1024</c>).</summary>
    public BadgeDefinitionBuilder WithImage(string url, string? dim = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);
        _image = new BadgeImage(url, dim);
        return this;
    }

    /// <summary>Adds a thumbnail URL with optional <c>WxH</c> dimensions. Repeatable.</summary>
    public BadgeDefinitionBuilder AddThumbnail(string url, string? dim = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(url);
        _thumbs.Add(new BadgeImage(url, dim));
        return this;
    }

    /// <summary>Builds the unsigned event for the given issuer + timestamp.</summary>
    public UnsignedEvent BuildUnsigned(PublicKey issuer, long createdAt)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        var tags = new List<IReadOnlyList<string>> { Tag.D(_identifier) };
        if (_name is not null) tags.Add(new[] { "name", _name });
        if (_description is not null) tags.Add(new[] { "description", _description });
        if (_image is BadgeImage img)
        {
            tags.Add(img.Dim is null
                ? new[] { "image", img.Url }
                : new[] { "image", img.Url, img.Dim });
        }

        foreach (var t in _thumbs)
        {
            tags.Add(t.Dim is null
                ? new[] { "thumb", t.Url }
                : new[] { "thumb", t.Url, t.Dim });
        }

        return new UnsignedEvent
        {
            PubKey = issuer,
            CreatedAt = createdAt,
            Kind = Nip58Kinds.BadgeDefinition,
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
    /// Mines the event to <paramref name="targetDifficulty"/> leading
    /// zero bits per NIP-13, attaches the committed <c>nonce</c> tag,
    /// and signs. NIP-58 notes badge issuers MAY embed PoW to give
    /// badges a verifiable "minting cost" signal.
    /// </summary>
    /// <param name="key">The issuer's signing key.</param>
    /// <param name="targetDifficulty">Leading-zero bits to mine for (0–256). 20-bit takes seconds on a laptop, 24-bit minutes, 28-bit ~an hour.</param>
    /// <param name="cancellationToken">Cancels mining (e.g., to enforce a budget).</param>
    public NostrEvent BuildMineAndSign(PrivateKey key, int targetDifficulty, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        var unsigned = BuildUnsigned(key.PublicKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var mined = ProofOfWork.Mine(unsigned, targetDifficulty, cancellationToken);
        return mined.Sign(key);
    }
}
