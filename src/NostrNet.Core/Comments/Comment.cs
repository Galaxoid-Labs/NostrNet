// SPDX-License-Identifier: MIT
//
// NIP-22: Comments.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/22.md
//
// Kind 1111 events with plain-text content. Threading uses paired tag sets:
//
//   uppercase (root scope, REQUIRED):
//     E/A/I  — identifier of the original target
//     K      — root kind
//     P      — root author pubkey (omitted for external "I" targets)
//
//   lowercase (direct parent):
//     e/a/i  — identifier of the immediate parent
//     k      — parent kind
//     p      — parent author pubkey (omitted for external "i" targets)
//
// Top-level comments have parent == root, so both tag sets reference the
// same target.
//
// Comments MUST NOT reply to kind:1 notes — use NIP-10 for those.

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Comments;

/// <summary>Kind constants for NIP-22.</summary>
public static class Nip22Kinds
{
    /// <summary>The kind for a NIP-22 comment event.</summary>
    public const int Comment = 1111;
}

/// <summary>
/// Discriminated union of what a NIP-22 comment can scope to.
/// </summary>
public abstract record CommentTarget;

/// <summary>A reference to a regular (non-addressable) event by its id.</summary>
public sealed record EventCommentTarget(EventId Id, int Kind, PublicKey Author) : CommentTarget;

/// <summary>A reference to a NIP-33 addressable event by (kind, author, identifier).</summary>
public sealed record AddressableCommentTarget(int Kind, PublicKey Author, string Identifier) : CommentTarget
{
    /// <summary>Returns the <c>kind:author:identifier</c> coordinate string used in tag values.</summary>
    public string ToCoordinate() => $"{Kind}:{Author.ToHex()}:{Identifier}";
}

/// <summary>
/// A reference to an external resource per NIP-73 (URL, hashtag, geohash, …).
/// </summary>
/// <param name="Identifier">The external identifier (e.g., a URL).</param>
/// <param name="Kind">Optional kind hint (NIP-73 may suggest values like <c>"url"</c>).</param>
public sealed record ExternalCommentTarget(string Identifier, string? Kind = null) : CommentTarget;

/// <summary>
/// A typed view of a NIP-22 comment event.
/// </summary>
public sealed class Comment : INostrTypedEvent<Comment>
{
    /// <summary>Nostr kind(s) this type represents.</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { 1111 };

    /// <summary>The comment author.</summary>
    public required PublicKey Author { get; init; }

    /// <summary>The comment text (event content; plain text per spec).</summary>
    public required string Content { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>The root of the thread (the original object being commented on).</summary>
    public required CommentTarget Root { get; init; }

    /// <summary>
    /// The direct parent of this comment. Equals <see cref="Root"/> for
    /// top-level comments; differs for nested replies.
    /// </summary>
    public required CommentTarget Parent { get; init; }

    /// <summary>Additional pubkeys mentioned via <c>p</c> tags beyond the parent author.</summary>
    public IReadOnlyList<PublicKey> Mentions { get; init; } = Array.Empty<PublicKey>();

    /// <summary>Quoted event ids via NIP-21 <c>q</c> tags.</summary>
    public IReadOnlyList<EventId> Quotes { get; init; } = Array.Empty<EventId>();

    /// <summary>True if this is a top-level comment (parent == root).</summary>
    public bool IsTopLevel => Root.Equals(Parent);

    /// <summary>Parses a kind-1111 event.</summary>
    /// <exception cref="ArgumentException">The event is not kind 1111.</exception>
    /// <exception cref="FormatException">Required root tags are missing.</exception>
    public static Comment FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != Nip22Kinds.Comment)
        {
            throw new ArgumentException(
                $"Expected a NIP-22 kind ({Nip22Kinds.Comment}); got {ev.Kind}.",
                nameof(ev));
        }

        var root = ExtractTarget(ev.Tags, uppercase: true)
            ?? throw new FormatException("NIP-22 comment is missing required root tags (E/A/I + K).");

        // Parent defaults to root for top-level comments. If lowercase tags
        // are present, they describe a nested reply.
        var parent = ExtractTarget(ev.Tags, uppercase: false) ?? root;

        // Mentions: every "p" tag after the parent's author. Parent author
        // already accounted for inside the target — additional p tags are
        // free-form mentions.
        var parentAuthorHex = parent switch
        {
            EventCommentTarget e => e.Author.ToHex(),
            AddressableCommentTarget a => a.Author.ToHex(),
            _ => null,
        };

        var mentions = new List<PublicKey>();
        bool skippedParentAuthor = parentAuthorHex is null;
        foreach (string hex in ev.Tags.AllValues("p"))
        {
            if (!skippedParentAuthor && string.Equals(hex, parentAuthorHex, StringComparison.OrdinalIgnoreCase))
            {
                skippedParentAuthor = true;
                continue;
            }

            if (PublicKey.TryFromHex(hex, out var pub))
            {
                mentions.Add(pub);
            }
        }

        var quotes = new List<EventId>();
        foreach (string hex in ev.Tags.AllValues("q"))
        {
            if (EventId.TryFromHex(hex, out var id))
            {
                quotes.Add(id);
            }
        }

        return new Comment
        {
            Author = ev.PubKey,
            Content = ev.Content,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Root = root,
            Parent = parent,
            Mentions = mentions,
            Quotes = quotes,
        };
    }

    /// <summary>Try-parse variant. Returns <c>false</c> on the wrong kind or malformed tags.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out Comment? comment)
    {
        comment = null;
        if (ev is null)
        {
            return false;
        }

        try
        {
            comment = FromEvent(ev);
            return true;
        }
        catch (Exception e) when (e is ArgumentException or FormatException)
        {
            return false;
        }
    }

    /// <summary>Starts building a new comment.</summary>
    public static CommentBuilder Create() => new();

    /// <summary>
    /// Convenience constructor for the common case: reply to an existing event.
    /// If <paramref name="target"/> is itself a NIP-22 comment, the new
    /// comment inherits its root scope. Otherwise root and parent both
    /// reference <paramref name="target"/> (top-level comment).
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="target"/> is kind 1 — use NIP-10 reply markers instead.</exception>
    public static CommentBuilder ReplyTo(NostrEvent target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.Kind == 1)
        {
            throw new ArgumentException(
                "NIP-22 comments must not reply to kind:1 notes; use NIP-10 reply tags instead.",
                nameof(target));
        }

        return new CommentBuilder().ReplyToInternal(target);
    }

    private static CommentTarget? ExtractTarget(IReadOnlyList<IReadOnlyList<string>> tags, bool uppercase)
    {
        string eTag = uppercase ? "E" : "e";
        string aTag = uppercase ? "A" : "a";
        string iTag = uppercase ? "I" : "i";
        string kTag = uppercase ? "K" : "k";
        string pTag = uppercase ? "P" : "p";

        // K is mandatory for all target shapes.
        string? kStr = tags.FirstValue(kTag);
        int? kindParsed = (kStr is not null
            && int.TryParse(kStr, NumberStyles.None, CultureInfo.InvariantCulture, out int k))
            ? k
            : null;

        // E-tag: event id (regular)
        if (tags.FirstValue(eTag) is string eHex && EventId.TryFromHex(eHex, out var id))
        {
            if (kindParsed is null) return null;
            if (tags.FirstValue(pTag) is not string pHex || !PublicKey.TryFromHex(pHex, out var pub))
            {
                return null;
            }

            return new EventCommentTarget(id, kindParsed.Value, pub);
        }

        // A-tag: addressable coordinate "kind:author:identifier"
        if (tags.FirstValue(aTag) is string coord)
        {
            int firstColon = coord.IndexOf(':');
            int secondColon = firstColon < 0 ? -1 : coord.IndexOf(':', firstColon + 1);
            if (firstColon > 0 && secondColon > firstColon
                && int.TryParse(coord[..firstColon], NumberStyles.None, CultureInfo.InvariantCulture, out int aKind)
                && PublicKey.TryFromHex(coord[(firstColon + 1)..secondColon], out var aAuthor))
            {
                return new AddressableCommentTarget(aKind, aAuthor, coord[(secondColon + 1)..]);
            }
        }

        // I-tag: external identifier (NIP-73). P is omitted for external targets.
        if (tags.FirstValue(iTag) is string ident)
        {
            return new ExternalCommentTarget(ident, kStr);
        }

        return null;
    }

    internal static void AppendTargetTags(
        List<IReadOnlyList<string>> tags,
        CommentTarget target,
        bool uppercase)
    {
        string eTag = uppercase ? "E" : "e";
        string aTag = uppercase ? "A" : "a";
        string iTag = uppercase ? "I" : "i";
        string kTag = uppercase ? "K" : "k";
        string pTag = uppercase ? "P" : "p";

        switch (target)
        {
            case EventCommentTarget e:
                tags.Add(new[] { eTag, e.Id.ToHex() });
                tags.Add(new[] { kTag, e.Kind.ToString(CultureInfo.InvariantCulture) });
                tags.Add(new[] { pTag, e.Author.ToHex() });
                break;

            case AddressableCommentTarget a:
                tags.Add(new[] { aTag, a.ToCoordinate() });
                tags.Add(new[] { kTag, a.Kind.ToString(CultureInfo.InvariantCulture) });
                tags.Add(new[] { pTag, a.Author.ToHex() });
                break;

            case ExternalCommentTarget i:
                tags.Add(new[] { iTag, i.Identifier });
                if (!string.IsNullOrEmpty(i.Kind))
                {
                    tags.Add(new[] { kTag, i.Kind });
                }

                break;
        }
    }
}

/// <summary>
/// Fluent builder for NIP-22 comment events. Set a target via
/// <see cref="ReplyTo"/>, <see cref="OnAddressable"/>, or
/// <see cref="OnExternal"/>, then <see cref="Sign"/>.
/// </summary>
public sealed class CommentBuilder
{
    private CommentTarget? _root;
    private CommentTarget? _parent;
    private string _content = string.Empty;
    private readonly List<PublicKey> _mentions = new();
    private readonly List<EventId> _quotes = new();
    private readonly List<IReadOnlyList<string>> _extraTags = new();

    internal CommentBuilder()
    {
    }

    /// <summary>
    /// Replies to an existing event. If it's a NIP-22 comment, the new
    /// comment inherits that comment's root scope. Otherwise root and
    /// parent both point at the event (top-level comment).
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="target"/> is kind 1.</exception>
    public CommentBuilder ReplyTo(NostrEvent target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (target.Kind == 1)
        {
            throw new ArgumentException(
                "NIP-22 comments must not reply to kind:1 notes; use NIP-10 reply tags instead.",
                nameof(target));
        }

        return ReplyToInternal(target);
    }

    internal CommentBuilder ReplyToInternal(NostrEvent target)
    {
        if (target.Kind == Nip22Kinds.Comment
            && Comment.TryFromEvent(target, out var parentComment))
        {
            _root = parentComment.Root;
            _parent = new EventCommentTarget(target.Id, target.Kind, target.PubKey);
        }
        else
        {
            var t = new EventCommentTarget(target.Id, target.Kind, target.PubKey);
            _root = t;
            _parent = t;
        }

        return this;
    }

    /// <summary>Comments on a NIP-33 addressable event (top-level scope).</summary>
    public CommentBuilder OnAddressable(int kind, PublicKey author, string identifier)
    {
        var t = new AddressableCommentTarget(kind, author, identifier);
        _root = t;
        _parent = t;
        return this;
    }

    /// <summary>Comments on an external resource per NIP-73 (URL, hashtag, geohash, …).</summary>
    public CommentBuilder OnExternal(string identifier, string? kind = null)
    {
        var t = new ExternalCommentTarget(identifier, kind);
        _root = t;
        _parent = t;
        return this;
    }

    /// <summary>
    /// Overrides the root scope. Use after <see cref="ReplyTo"/> when the
    /// builder couldn't infer the root from the parent (e.g., the parent
    /// isn't a NIP-22 comment but you're explicitly threading deeper).
    /// </summary>
    public CommentBuilder InThreadOf(CommentTarget root)
    {
        _root = root;
        return this;
    }

    /// <summary>Sets the comment text.</summary>
    public CommentBuilder WithContent(string content)
    {
        _content = content ?? throw new ArgumentNullException(nameof(content));
        return this;
    }

    /// <summary>Adds an additional <c>p</c>-tag mention beyond the parent author.</summary>
    public CommentBuilder Mention(PublicKey pubkey)
    {
        ArgumentNullException.ThrowIfNull(pubkey);
        _mentions.Add(pubkey);
        return this;
    }

    /// <summary>Adds a NIP-21 <c>q</c>-tag citation of another event.</summary>
    public CommentBuilder Quote(EventId eventId)
    {
        ArgumentNullException.ThrowIfNull(eventId);
        _quotes.Add(eventId);
        return this;
    }

    /// <summary>Adds an arbitrary tag for non-standard metadata.</summary>
    public CommentBuilder WithTag(IReadOnlyList<string> tag)
    {
        _extraTags.Add(tag);
        return this;
    }

    /// <summary>Builds and signs the comment event.</summary>
    public NostrEvent Sign(PrivateKey key, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (_root is null || _parent is null)
        {
            throw new InvalidOperationException(
                "Set a target first via ReplyTo / OnAddressable / OnExternal before signing.");
        }

        var tags = new List<IReadOnlyList<string>>();
        Comment.AppendTargetTags(tags, _root, uppercase: true);
        Comment.AppendTargetTags(tags, _parent, uppercase: false);

        foreach (var p in _mentions)
        {
            tags.Add(Tag.P(p));
        }

        foreach (var q in _quotes)
        {
            tags.Add(new[] { "q", q.ToHex() });
        }

        foreach (var t in _extraTags)
        {
            tags.Add(t);
        }

        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = Nip22Kinds.Comment,
            Tags = tags,
            Content = _content,
        }.Sign(key);
    }
}
