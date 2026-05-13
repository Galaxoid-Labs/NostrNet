// SPDX-License-Identifier: MIT

using NostrNet.Keys;

namespace NostrNet.Events;

/// <summary>
/// Query helpers over an event's tag list. Available on any
/// <see cref="IReadOnlyList{T}"/> of <see cref="IReadOnlyList{T}"/> of
/// <see cref="string"/> — typically <see cref="NostrEvent.Tags"/> or
/// <see cref="UnsignedEvent.Tags"/>.
/// </summary>
/// <remarks>
/// A "tag" in NIP-01 is an array of strings whose first element is the tag
/// name. These extensions provide common lookups: enumerate all tags with a
/// given name, get the first or all "values" (the second element of each
/// matching tag), check existence.
/// </remarks>
public static class TagExtensions
{
    /// <summary>Enumerates every tag whose first element equals <paramref name="name"/>.</summary>
    /// <param name="tags">The tag list to query.</param>
    /// <param name="name">The tag name to match (case-sensitive).</param>
    public static IEnumerable<IReadOnlyList<string>> Named(
        this IReadOnlyList<IReadOnlyList<string>> tags,
        string name)
    {
        ArgumentNullException.ThrowIfNull(tags);
        ArgumentNullException.ThrowIfNull(name);
        for (int i = 0; i < tags.Count; i++)
        {
            var tag = tags[i];
            if (tag.Count > 0 && string.Equals(tag[0], name, StringComparison.Ordinal))
            {
                yield return tag;
            }
        }
    }

    /// <summary>True if at least one tag in <paramref name="tags"/> has the given name.</summary>
    public static bool Has(this IReadOnlyList<IReadOnlyList<string>> tags, string name)
        => tags.Named(name).Any();

    /// <summary>Returns the first tag with the given name, or <c>null</c> if none.</summary>
    public static IReadOnlyList<string>? FirstWithName(
        this IReadOnlyList<IReadOnlyList<string>> tags,
        string name)
        => tags.Named(name).FirstOrDefault();

    /// <summary>
    /// Returns the second element ("value") of the first tag with the given
    /// name, or <c>null</c> if no such tag exists or it has no second element.
    /// </summary>
    /// <remarks>
    /// Convenient for tags whose canonical shape is <c>[name, value]</c> —
    /// e.g., <c>FirstValue("d")</c> gets a parameterized event's identifier.
    /// </remarks>
    public static string? FirstValue(this IReadOnlyList<IReadOnlyList<string>> tags, string name)
    {
        var tag = tags.FirstWithName(name);
        return tag is { Count: >= 2 } ? tag[1] : null;
    }

    /// <summary>
    /// Returns the second element of every tag with the given name.
    /// </summary>
    /// <example>
    /// <code>
    /// var mentionedPubkeys = ev.Tags.AllValues("p");
    /// var referencedEventIds = ev.Tags.AllValues("e");
    /// </code>
    /// </example>
    public static IEnumerable<string> AllValues(
        this IReadOnlyList<IReadOnlyList<string>> tags,
        string name)
    {
        foreach (var tag in tags.Named(name))
        {
            if (tag.Count >= 2)
            {
                yield return tag[1];
            }
        }
    }

    /// <summary>
    /// Returns every <c>"p"</c> tag's pubkey value as a parsed
    /// <see cref="PublicKey"/>. Malformed entries are skipped.
    /// </summary>
    public static IEnumerable<PublicKey> Pubkeys(this IReadOnlyList<IReadOnlyList<string>> tags)
    {
        foreach (string hex in tags.AllValues("p"))
        {
            if (PublicKey.TryFromHex(hex, out var pub))
            {
                yield return pub;
            }
        }
    }

    /// <summary>
    /// Returns every <c>"e"</c> tag's event-id value as a parsed
    /// <see cref="EventId"/>. Malformed entries are skipped.
    /// </summary>
    public static IEnumerable<EventId> EventIds(this IReadOnlyList<IReadOnlyList<string>> tags)
    {
        foreach (string hex in tags.AllValues("e"))
        {
            if (EventId.TryFromHex(hex, out var id))
            {
                yield return id;
            }
        }
    }

    /// <summary>Returns every <c>"t"</c> tag's hashtag value.</summary>
    public static IEnumerable<string> Hashtags(this IReadOnlyList<IReadOnlyList<string>> tags)
        => tags.AllValues("t");

    /// <summary>
    /// Returns the <c>"d"</c> tag's value (NIP-33 parameterized replaceable
    /// event identifier), or <c>null</c> if no <c>"d"</c> tag is present.
    /// </summary>
    public static string? Identifier(this IReadOnlyList<IReadOnlyList<string>> tags)
        => tags.FirstValue("d");
}
