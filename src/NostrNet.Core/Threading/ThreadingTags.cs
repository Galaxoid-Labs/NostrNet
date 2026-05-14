// SPDX-License-Identifier: MIT
//
// NIP-10: thread / reply tagging for kind-1 text notes.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/10.md
//
// Modern ("marker") form:
//
//   ["e", <id>, <relay-url>, "root"]      — root of the thread
//   ["e", <id>, <relay-url>, "reply"]     — direct parent being replied to
//   ["e", <id>, <relay-url>, "mention"]   — quoted / referenced, not a parent
//
//   ["e", <id>, <relay-url>, <marker>, <pubkey>]  — optional 5th field
//
//   ["p", <pubkey>, ...]                  — every participant in the thread
//                                            (transitive: include parent's p-tags
//                                            and the parent author)
//
// Legacy ("positional") form, still in the wild:
//
//   one  e-tag:   the single e-tag is BOTH root AND direct parent
//   two+ e-tags:  first is root, last is direct parent, middles are mentions
//
// On parse we prefer marker form when ANY e-tag carries a recognized
// marker; otherwise we fall back to positional.

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Threading;

/// <summary>Recognized NIP-10 e-tag markers.</summary>
public enum ThreadMarker
{
    /// <summary>The e-tag is positional (no marker); meaning depends on tag order.</summary>
    None = 0,

    /// <summary>"root" marker — top of the thread.</summary>
    Root,

    /// <summary>"reply" marker — direct parent of the new event.</summary>
    Reply,

    /// <summary>"mention" marker — a quoted reference, not a structural reply.</summary>
    Mention,
}

/// <summary>
/// The structural view of a kind-1 note's thread metadata, derived from
/// its <c>"e"</c> and <c>"p"</c> tags per NIP-10.
/// </summary>
/// <param name="Root">The root event id of the thread, or <c>null</c> for a top-level post.</param>
/// <param name="Reply">The event being directly replied to, or <c>null</c> for top-level posts or posts that reply directly to the root.</param>
/// <param name="Mentions">Quoted events (marker form) or middle e-tags (positional form).</param>
/// <param name="Participants">Pubkeys carried in <c>p</c> tags (everyone the post addresses).</param>
public sealed record ThreadInfo(
    EventId? Root,
    EventId? Reply,
    IReadOnlyList<EventId> Mentions,
    IReadOnlyList<PublicKey> Participants);

/// <summary>NIP-10 thread/reply tag helpers.</summary>
public static class ThreadingTags
{
    /// <summary>The reserved marker strings, in canonical form.</summary>
    public static class Markers
    {
        /// <summary>"root" marker string.</summary>
        public const string Root = "root";

        /// <summary>"reply" marker string.</summary>
        public const string Reply = "reply";

        /// <summary>"mention" marker string.</summary>
        public const string Mention = "mention";
    }

    /// <summary>
    /// Parses the <c>"e"</c> and <c>"p"</c> tags on an event into a
    /// <see cref="ThreadInfo"/>. Tolerates malformed tags by skipping them.
    /// </summary>
    public static ThreadInfo Parse(IReadOnlyList<IReadOnlyList<string>> tags)
    {
        ArgumentNullException.ThrowIfNull(tags);

        // First pass: collect all e-tags with their parsed shape.
        var eEntries = new List<(EventId Id, ThreadMarker Marker)>();
        bool anyMarker = false;
        for (int i = 0; i < tags.Count; i++)
        {
            var tag = tags[i];
            if (tag.Count < 2 || tag[0] != "e")
            {
                continue;
            }

            if (!EventId.TryFromHex(tag[1], out var id))
            {
                continue;
            }

            ThreadMarker marker = (tag.Count >= 4 ? tag[3] : null) switch
            {
                Markers.Root => ThreadMarker.Root,
                Markers.Reply => ThreadMarker.Reply,
                Markers.Mention => ThreadMarker.Mention,
                _ => ThreadMarker.None,
            };

            if (marker != ThreadMarker.None)
            {
                anyMarker = true;
            }

            eEntries.Add((id, marker));
        }

        // p-tag participants.
        var participants = new List<PublicKey>();
        for (int i = 0; i < tags.Count; i++)
        {
            var tag = tags[i];
            if (tag.Count < 2 || tag[0] != "p")
            {
                continue;
            }

            if (PublicKey.TryFromHex(tag[1], out var pk))
            {
                participants.Add(pk);
            }
        }

        EventId? root = null;
        EventId? reply = null;
        var mentions = new List<EventId>();

        if (anyMarker)
        {
            for (int i = 0; i < eEntries.Count; i++)
            {
                var entry = eEntries[i];
                switch (entry.Marker)
                {
                    case ThreadMarker.Root:
                        root ??= entry.Id;
                        break;
                    case ThreadMarker.Reply:
                        reply ??= entry.Id;
                        break;
                    case ThreadMarker.Mention:
                        mentions.Add(entry.Id);
                        break;
                }
            }

            // NIP-10: if only "reply" exists with no "root", treat that reply
            // as both root and reply (the thread is one level deep).
            if (root is null && reply is not null)
            {
                root = reply;
                reply = null;
            }
        }
        else if (eEntries.Count == 1)
        {
            // Positional: single e-tag is both root and direct parent.
            root = eEntries[0].Id;
        }
        else if (eEntries.Count >= 2)
        {
            root = eEntries[0].Id;
            reply = eEntries[^1].Id;
            for (int i = 1; i < eEntries.Count - 1; i++)
            {
                mentions.Add(eEntries[i].Id);
            }
        }

        return new ThreadInfo(root, reply, mentions, participants);
    }

    /// <summary>Convenience overload for parsing an event's tags directly.</summary>
    public static ThreadInfo Parse(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        return Parse(ev.Tags);
    }

    /// <summary>
    /// Builds the <c>"e"</c> and <c>"p"</c> tags for a reply to
    /// <paramref name="parent"/>, using the marker form. If
    /// <paramref name="parent"/> is itself a reply, the existing thread's
    /// root is preserved and parent is marked as <c>"reply"</c>; otherwise
    /// <paramref name="parent"/> becomes the <c>"root"</c>.
    /// </summary>
    /// <param name="parent">The event being replied to.</param>
    /// <param name="parentRelay">Optional relay hint for the parent.</param>
    /// <param name="rootRelay">Optional relay hint for the root (if different from parent).</param>
    /// <param name="extraParticipants">Additional <c>p</c>-tag pubkeys beyond the transitive set.</param>
    public static IReadOnlyList<IReadOnlyList<string>> BuildReplyTags(
        NostrEvent parent,
        string? parentRelay = null,
        string? rootRelay = null,
        IEnumerable<PublicKey>? extraParticipants = null)
    {
        ArgumentNullException.ThrowIfNull(parent);

        var parentInfo = Parse(parent);
        var tags = new List<IReadOnlyList<string>>();

        EventId rootId = parentInfo.Root ?? parent.Id;
        bool parentIsRoot = parentInfo.Root is null;

        // Root e-tag. If the parent IS the root, the root tag IS the parent tag.
        tags.Add(new[] { "e", rootId.ToHex(), rootRelay ?? string.Empty, Markers.Root });

        // Direct parent — only emitted as a distinct "reply" tag when it's
        // not the same as the root.
        if (!parentIsRoot)
        {
            tags.Add(new[] { "e", parent.Id.ToHex(), parentRelay ?? string.Empty, Markers.Reply });
        }

        // p-tags: parent's participants + parent's author + extras, deduped, ordered.
        var seenPubkeys = new HashSet<string>(StringComparer.Ordinal);
        void AddParticipant(PublicKey pk)
        {
            string hex = pk.ToHex();
            if (seenPubkeys.Add(hex))
            {
                tags.Add(new[] { "p", hex });
            }
        }

        foreach (var pk in parentInfo.Participants)
        {
            AddParticipant(pk);
        }

        AddParticipant(parent.PubKey);

        if (extraParticipants is not null)
        {
            foreach (var pk in extraParticipants)
            {
                AddParticipant(pk);
            }
        }

        return tags;
    }
}
