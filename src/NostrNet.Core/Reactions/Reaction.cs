// SPDX-License-Identifier: MIT
//
// NIP-25: Reactions.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/25.md
//
//   {
//     "kind": 7,
//     "pubkey": <reactor>,
//     "content": "+" | "-" | "<emoji>" | ":<shortcode>:" | "",
//     "tags": [
//       ["e", <reacted-event-id>, <relay-url-hint>],
//       ["p", <reacted-event-author-pubkey>],
//       ["a", "<kind>:<pubkey>:<d-tag>"],        // optional, addressable target
//       ["k", "<kind>"],                          // optional, the reacted kind
//       ["emoji", "<shortcode>", "<image-url>"]   // optional, paired with `:shortcode:`
//     ]
//   }
//
// Spec interpretation:
//   - Empty content OR "+" → like.
//   - "-" → dislike.
//   - Single Unicode emoji → emoji reaction.
//   - ":foo:" with a matching `emoji` tag → custom emoji reaction.
//   - The LAST e and p tags MUST be the target.

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using NostrNet.Deletions;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Reactions;

/// <summary>NIP-25 event-kind constants.</summary>
public static class Nip25Kinds
{
    /// <summary>The kind for a reaction event.</summary>
    public const int Reaction = 7;
}

/// <summary>The semantic class of a NIP-25 reaction.</summary>
public enum ReactionKind
{
    /// <summary>Empty content or <c>"+"</c>.</summary>
    Like,

    /// <summary>Content is <c>"-"</c>.</summary>
    Dislike,

    /// <summary>Content is a single emoji (Unicode), e.g. <c>🤙</c>.</summary>
    Emoji,

    /// <summary>Content is <c>:shortcode:</c> with a matching <c>emoji</c> tag.</summary>
    CustomEmoji,
}

/// <summary>A custom emoji declared by an <c>emoji</c> tag on a reaction.</summary>
/// <param name="Shortcode">The bareword (no surrounding colons) referenced in the content.</param>
/// <param name="ImageUrl">URL to the emoji image.</param>
public sealed record CustomEmoji(string Shortcode, string ImageUrl);

/// <summary>
/// A typed view of a NIP-25 kind-7 reaction event.
/// </summary>
public sealed class Reaction : INostrTypedEvent<Reaction>
{
    /// <summary>Nostr kind(s) this type represents.</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { 7 };

    /// <summary>The reactor's pubkey.</summary>
    public required PublicKey Reactor { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Event id of the event being reacted to (the LAST <c>e</c>-tag).</summary>
    public required EventId TargetId { get; init; }

    /// <summary>Pubkey of the author of the event being reacted to (the LAST <c>p</c>-tag).</summary>
    public required PublicKey TargetAuthor { get; init; }

    /// <summary>If the target is an addressable event, its NIP-33 coordinates.</summary>
    public required AddressableEventCoordinates? AddressableTarget { get; init; }

    /// <summary>Optional <c>k</c>-tag value — the kind of the event being reacted to.</summary>
    public required int? TargetKind { get; init; }

    /// <summary>Raw <c>content</c> of the reaction event.</summary>
    public required string Content { get; init; }

    /// <summary>Classified reaction kind based on <see cref="Content"/> + any <c>emoji</c> tag.</summary>
    public required ReactionKind Kind { get; init; }

    /// <summary>The custom emoji metadata if <see cref="Kind"/> is <see cref="ReactionKind.CustomEmoji"/>.</summary>
    public required CustomEmoji? CustomEmoji { get; init; }

    /// <summary>Parses a kind-7 event into a <see cref="Reaction"/>.</summary>
    /// <exception cref="ArgumentException">Not a NIP-25 event, or missing required target tags.</exception>
    public static Reaction FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip25Kinds.Reaction)
        {
            throw new ArgumentException(
                $"Expected a NIP-25 kind ({Nip25Kinds.Reaction}); got {ev.Kind}.",
                nameof(ev));
        }

        // Find the LAST valid e- and p- tags.
        EventId? targetId = null;
        for (int i = ev.Tags.Count - 1; i >= 0; i--)
        {
            var tag = ev.Tags[i];
            if (tag.Count >= 2 && tag[0] == "e" && EventId.TryFromHex(tag[1], out var id))
            {
                targetId = id;
                break;
            }
        }

        if (targetId is null)
        {
            throw new ArgumentException("NIP-25 reaction is missing a valid `e`-tag.", nameof(ev));
        }

        PublicKey? targetAuthor = null;
        for (int i = ev.Tags.Count - 1; i >= 0; i--)
        {
            var tag = ev.Tags[i];
            if (tag.Count >= 2 && tag[0] == "p" && PublicKey.TryFromHex(tag[1], out var pk))
            {
                targetAuthor = pk;
                break;
            }
        }

        if (targetAuthor is null)
        {
            throw new ArgumentException("NIP-25 reaction is missing a valid `p`-tag.", nameof(ev));
        }

        AddressableEventCoordinates? addressable = null;
        for (int i = ev.Tags.Count - 1; i >= 0; i--)
        {
            var tag = ev.Tags[i];
            if (tag.Count >= 2 && tag[0] == "a" && AddressableEventCoordinates.TryParse(tag[1], out var coords))
            {
                addressable = coords;
                break;
            }
        }

        int? targetKind = null;
        foreach (var tag in ev.Tags.Named("k"))
        {
            if (tag.Count >= 2
                && int.TryParse(tag[1], NumberStyles.None, CultureInfo.InvariantCulture, out int k))
            {
                targetKind = k;
                break;
            }
        }

        // emoji tag (look at the FIRST one — we don't expect multiples).
        CustomEmoji? customEmoji = null;
        foreach (var tag in ev.Tags.Named("emoji"))
        {
            if (tag.Count >= 3 && !string.IsNullOrEmpty(tag[1]) && !string.IsNullOrEmpty(tag[2]))
            {
                customEmoji = new CustomEmoji(tag[1], tag[2]);
                break;
            }
        }

        ReactionKind kind = ClassifyContent(ev.Content, customEmoji);

        return new Reaction
        {
            Reactor = ev.PubKey,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            TargetId = targetId,
            TargetAuthor = targetAuthor,
            AddressableTarget = addressable,
            TargetKind = targetKind,
            Content = ev.Content,
            Kind = kind,
            CustomEmoji = customEmoji,
        };
    }

    /// <summary>Try-parse variant.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out Reaction? reaction)
    {
        reaction = null;
        if (ev is null || ev.Kind != Nip25Kinds.Reaction)
        {
            return false;
        }

        try
        {
            reaction = FromEvent(ev);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>Begins building a new reaction event.</summary>
    public static ReactionBuilder Create() => new();

    private static ReactionKind ClassifyContent(string content, CustomEmoji? customEmoji)
    {
        if (string.IsNullOrEmpty(content) || content == "+")
        {
            return ReactionKind.Like;
        }

        if (content == "-")
        {
            return ReactionKind.Dislike;
        }

        // ":shortcode:" with matching emoji tag → custom.
        if (customEmoji is not null
            && content.Length >= 3
            && content[0] == ':' && content[^1] == ':'
            && content.AsSpan(1, content.Length - 2).SequenceEqual(customEmoji.Shortcode.AsSpan()))
        {
            return ReactionKind.CustomEmoji;
        }

        return ReactionKind.Emoji;
    }
}

/// <summary>Fluent builder for NIP-25 reaction events.</summary>
public sealed class ReactionBuilder
{
    private EventId? _targetId;
    private PublicKey? _targetAuthor;
    private int? _targetKind;
    private AddressableEventCoordinates? _addressable;
    private CustomEmoji? _customEmoji;
    private string _content = "+";

    internal ReactionBuilder()
    {
    }

    /// <summary>Sets the target by referencing a known event directly.</summary>
    public ReactionBuilder To(NostrEvent target)
    {
        ArgumentNullException.ThrowIfNull(target);
        _targetId = target.Id;
        _targetAuthor = target.PubKey;
        _targetKind = target.Kind;
        return this;
    }

    /// <summary>Sets the target by id + author (and optional kind).</summary>
    public ReactionBuilder To(EventId targetId, PublicKey targetAuthor, int? targetKind = null)
    {
        ArgumentNullException.ThrowIfNull(targetId);
        ArgumentNullException.ThrowIfNull(targetAuthor);
        _targetId = targetId;
        _targetAuthor = targetAuthor;
        _targetKind = targetKind;
        return this;
    }

    /// <summary>Marks this reaction as targeting an addressable (parameterized-replaceable) event.</summary>
    public ReactionBuilder ToAddressable(int kind, PublicKey author, string identifier)
    {
        ArgumentNullException.ThrowIfNull(author);
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        _addressable = new AddressableEventCoordinates(kind, author, identifier);
        return this;
    }

    /// <summary>Sets the content. Use <see cref="AsLike"/>, <see cref="AsDislike"/>, etc. for typed cases.</summary>
    public ReactionBuilder WithContent(string content)
    {
        _content = content ?? string.Empty;
        return this;
    }

    /// <summary>"+" — a positive reaction.</summary>
    public ReactionBuilder AsLike() => WithContent("+");

    /// <summary>"-" — a negative reaction.</summary>
    public ReactionBuilder AsDislike() => WithContent("-");

    /// <summary>A single Unicode emoji reaction.</summary>
    public ReactionBuilder WithEmoji(string emoji)
    {
        ArgumentException.ThrowIfNullOrEmpty(emoji);
        return WithContent(emoji);
    }

    /// <summary>
    /// A custom emoji reaction: <c>:shortcode:</c> in content + an
    /// <c>emoji</c> tag pointing at the image.
    /// </summary>
    public ReactionBuilder WithCustomEmoji(string shortcode, string imageUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(shortcode);
        ArgumentException.ThrowIfNullOrEmpty(imageUrl);
        _customEmoji = new CustomEmoji(shortcode, imageUrl);
        _content = $":{shortcode}:";
        return this;
    }

    /// <summary>Builds and signs the reaction event.</summary>
    public NostrEvent Sign(PrivateKey key, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (_targetId is null || _targetAuthor is null)
        {
            throw new InvalidOperationException("Set the reaction target via `To(...)` before signing.");
        }

        var tags = new List<IReadOnlyList<string>>();
        tags.Add(new[] { "e", _targetId.ToHex() });
        tags.Add(new[] { "p", _targetAuthor.ToHex() });
        if (_addressable is not null)
        {
            tags.Add(new[] { "a", _addressable.ToTagValue() });
        }

        if (_targetKind is int k)
        {
            tags.Add(new[] { "k", k.ToString(CultureInfo.InvariantCulture) });
        }

        if (_customEmoji is not null)
        {
            tags.Add(new[] { "emoji", _customEmoji.Shortcode, _customEmoji.ImageUrl });
        }

        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = Nip25Kinds.Reaction,
            Tags = tags,
            Content = _content,
        }.Sign(key);
    }
}
