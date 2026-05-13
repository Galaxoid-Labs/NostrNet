// SPDX-License-Identifier: MIT
//
// NIP-51 list kind numbers.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/51.md

namespace NostrNet.Lists;

/// <summary>
/// Kind constants defined by NIP-51.
/// </summary>
/// <remarks>
/// Kinds 10000-10102 are replaceable (one event per kind per author).
/// Kinds 30000+ are NIP-33 parameterized replaceable (multiple per kind
/// per author, distinguished by the <c>"d"</c> tag).
/// </remarks>
public static class Nip51Kinds
{
    // ----- Replaceable lists (one per author per kind).

    /// <summary>Mute list — pubkeys, hashtags, words, and events to filter out.</summary>
    public const int MuteList = 10000;

    /// <summary>Notes pinned to the author's profile.</summary>
    public const int PinnedNotes = 10001;

    /// <summary>Bookmarked content.</summary>
    public const int Bookmarks = 10003;

    /// <summary>Community memberships.</summary>
    public const int Communities = 10004;

    /// <summary>Subscribed public chat channels.</summary>
    public const int PublicChats = 10005;

    /// <summary>Relays the author refuses to read or write from.</summary>
    public const int BlockedRelays = 10006;

    /// <summary>Relays the author prefers for search queries.</summary>
    public const int SearchRelays = 10007;

    /// <summary>Profile badges the author has accepted.</summary>
    public const int AcceptedBadges = 10008;

    /// <summary>Simple-group memberships.</summary>
    public const int SimpleGroups = 10009;

    /// <summary>Hashtag interests.</summary>
    public const int Interests = 10015;

    /// <summary>Emoji sets the author wants available.</summary>
    public const int Emojis = 10030;

    /// <summary>Relays where the author receives NIP-17 direct messages.</summary>
    public const int DmRelays = 10050;

    /// <summary>Pubkeys whose wiki edits the author trusts.</summary>
    public const int GoodWikiAuthors = 10101;

    /// <summary>Relays the author considers good for wiki content.</summary>
    public const int GoodWikiRelays = 10102;

    // ----- Parameterized sets (multiple per author per kind, indexed by "d").

    /// <summary>Named groups of pubkeys (e.g., "close friends").</summary>
    public const int FollowSets = 30000;

    /// <summary>Named relay groupings.</summary>
    public const int RelaySets = 30002;

    /// <summary>Named bookmark groupings.</summary>
    public const int BookmarkSets = 30003;

    /// <summary>Curated sets of long-form articles.</summary>
    public const int ArticleCurationSets = 30004;

    /// <summary>Curated sets of videos.</summary>
    public const int VideoCurationSets = 30005;

    /// <summary>Curated sets of pictures.</summary>
    public const int PictureCurationSets = 30006;

    /// <summary>Mute sets scoped to specific event kinds.</summary>
    public const int KindMuteSets = 30007;

    /// <summary>Hashtag interest groupings.</summary>
    public const int InterestSets = 30015;

    /// <summary>Named emoji groupings.</summary>
    public const int EmojiSets = 30030;

    /// <summary>Release artifact sets (e.g., software releases).</summary>
    public const int ReleaseArtifactSets = 30063;

    /// <summary>Curated application listings.</summary>
    public const int AppCurationSets = 30267;

    /// <summary>Onboarding starter packs.</summary>
    public const int StarterPacks = 39089;

    /// <summary>Media starter packs.</summary>
    public const int MediaStarterPacks = 39092;

    /// <summary>
    /// True if <paramref name="kind"/> is a parameterized replaceable set
    /// (kind ≥ 30000 and &lt; 40000), which requires a <c>"d"</c> tag.
    /// </summary>
    public static bool IsParameterizedSet(int kind) => kind is >= 30000 and < 40000;
}
