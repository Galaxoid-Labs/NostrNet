// SPDX-License-Identifier: MIT

using NostrNet.Keys;

namespace NostrNet.Events;

/// <summary>
/// Factory helpers for constructing event tags with the conventional naming
/// used across NIPs.
/// </summary>
/// <remarks>
/// Each method returns an <see cref="IReadOnlyList{T}"/> of <see cref="string"/>
/// shaped per the NIP wire format. Use these to avoid manually writing the
/// tag name as a magic string.
///
/// <para>
/// Tags are typically aggregated into the <see cref="NostrEvent.Tags"/> or
/// <see cref="UnsignedEvent.Tags"/> field:
/// </para>
/// <code>
/// Tags = new[] { Tag.P(recipient), Tag.E(parentId), Tag.T("nostr") }
/// </code>
/// </remarks>
public static class Tag
{
    /// <summary>A <c>"p"</c> (pubkey reference) tag.</summary>
    public static IReadOnlyList<string> P(PublicKey pubKey)
    {
        ArgumentNullException.ThrowIfNull(pubKey);
        return new[] { "p", pubKey.ToHex() };
    }

    /// <summary>A <c>"p"</c> tag with an optional recommended relay URL.</summary>
    public static IReadOnlyList<string> P(PublicKey pubKey, string? relay)
    {
        ArgumentNullException.ThrowIfNull(pubKey);
        return relay is null
            ? new[] { "p", pubKey.ToHex() }
            : new[] { "p", pubKey.ToHex(), relay };
    }

    /// <summary>An <c>"e"</c> (event reference) tag.</summary>
    public static IReadOnlyList<string> E(EventId id)
    {
        ArgumentNullException.ThrowIfNull(id);
        return new[] { "e", id.ToHex() };
    }

    /// <summary>An <c>"e"</c> tag with an optional recommended relay URL.</summary>
    public static IReadOnlyList<string> E(EventId id, string? relay)
    {
        ArgumentNullException.ThrowIfNull(id);
        return relay is null
            ? new[] { "e", id.ToHex() }
            : new[] { "e", id.ToHex(), relay };
    }

    /// <summary>
    /// An <c>"e"</c> tag with a NIP-10 marker (<c>"root"</c>, <c>"reply"</c>, <c>"mention"</c>).
    /// </summary>
    public static IReadOnlyList<string> E(EventId id, string relay, string marker)
    {
        ArgumentNullException.ThrowIfNull(id);
        return new[] { "e", id.ToHex(), relay ?? string.Empty, marker };
    }

    /// <summary>
    /// An <c>"a"</c> (addressable event coordinate) tag of the form
    /// <c>kind:author:identifier</c>.
    /// </summary>
    public static IReadOnlyList<string> A(int kind, PublicKey author, string identifier)
    {
        ArgumentNullException.ThrowIfNull(author);
        ArgumentNullException.ThrowIfNull(identifier);
        return new[] { "a", $"{kind}:{author.ToHex()}:{identifier}" };
    }

    /// <summary>An <c>"a"</c> tag with an optional recommended relay URL.</summary>
    public static IReadOnlyList<string> A(int kind, PublicKey author, string identifier, string? relay)
    {
        ArgumentNullException.ThrowIfNull(author);
        ArgumentNullException.ThrowIfNull(identifier);
        return relay is null
            ? new[] { "a", $"{kind}:{author.ToHex()}:{identifier}" }
            : new[] { "a", $"{kind}:{author.ToHex()}:{identifier}", relay };
    }

    /// <summary>A <c>"t"</c> (hashtag) tag.</summary>
    public static IReadOnlyList<string> T(string hashtag)
    {
        ArgumentNullException.ThrowIfNull(hashtag);
        return new[] { "t", hashtag };
    }

    /// <summary>
    /// A <c>"d"</c> (identifier) tag used by NIP-33 parameterized
    /// replaceable events to distinguish multiple events of the same kind
    /// from the same author.
    /// </summary>
    public static IReadOnlyList<string> D(string identifier)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        return new[] { "d", identifier };
    }

    /// <summary>A <c>"word"</c> tag (NIP-51 muted word).</summary>
    public static IReadOnlyList<string> Word(string word)
    {
        ArgumentNullException.ThrowIfNull(word);
        return new[] { "word", word };
    }

    /// <summary>A <c>"relay"</c> tag carrying a relay URL.</summary>
    public static IReadOnlyList<string> Relay(string url)
    {
        ArgumentNullException.ThrowIfNull(url);
        return new[] { "relay", url };
    }

    /// <summary>A <c>"title"</c> tag (e.g., NIP-51 set name, NIP-23 article title).</summary>
    public static IReadOnlyList<string> Title(string title)
    {
        ArgumentNullException.ThrowIfNull(title);
        return new[] { "title", title };
    }

    /// <summary>A <c>"description"</c> tag.</summary>
    public static IReadOnlyList<string> Description(string description)
    {
        ArgumentNullException.ThrowIfNull(description);
        return new[] { "description", description };
    }

    /// <summary>An <c>"image"</c> tag carrying an image URL.</summary>
    public static IReadOnlyList<string> Image(string url)
    {
        ArgumentNullException.ThrowIfNull(url);
        return new[] { "image", url };
    }

    /// <summary>An <c>"r"</c> tag, conventionally a URL reference.</summary>
    public static IReadOnlyList<string> R(string url)
    {
        ArgumentNullException.ThrowIfNull(url);
        return new[] { "r", url };
    }
}
