// SPDX-License-Identifier: MIT
//
// NIP-17 private direct messages on top of NIP-44 v2 and NIP-59 gift wrap.
//
// Reference:
//   - NIP-17 (kind 14 chat messages):       https://github.com/nostr-protocol/nips/blob/master/17.md
//   - NIP-59 (gift wrap / sealed events):    https://github.com/nostr-protocol/nips/blob/master/59.md
//   - NIP-10 (thread markers used inside DM rumors for replies):
//                                            https://github.com/nostr-protocol/nips/blob/master/10.md
//   - NIP-25 (reactions, kind 7, layered inside DM wraps):
//                                            https://github.com/nostr-protocol/nips/blob/master/25.md
//
// The seal/wrap mechanics live in Nip59 — this file is a thin wrapper
// that shapes inner rumors (chat, reactions, replies, anything in the
// "DM family") and surfaces a DM-friendly view of the result.

using System.Security.Cryptography;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Crypto;

/// <summary>
/// NIP-17 private direct messages (sealed under NIP-59 gift wrap),
/// including the in-wrap conventions for replies (NIP-10) and reactions
/// (NIP-25).
/// </summary>
public static class Nip17
{
    /// <summary>The kind of an unsigned chat-message rumor.</summary>
    public const int RumorKind = 14;

    /// <summary>The kind of an unsigned file-message rumor (NIP-17 file message).</summary>
    public const int FileRumorKind = 15;

    /// <summary>The kind of a NIP-25 reaction rumor, when sent privately inside a NIP-17 wrap.</summary>
    public const int ReactionRumorKind = 7;

    /// <summary>The kind of a NIP-59 seal. Re-exported from <see cref="Nip59"/>.</summary>
    public const int SealKind = Nip59.SealKind;

    /// <summary>The kind of a NIP-59 gift wrap. Re-exported from <see cref="Nip59"/>.</summary>
    public const int GiftWrapKind = Nip59.GiftWrapKind;

    /// <summary>
    /// The set of rumor kinds that <see cref="Unwrap"/> accepts as
    /// belonging to the NIP-17 DM family: chat (14), file (15), and
    /// reactions (7). Other kinds wrapped in NIP-59 (e.g. Marmot
    /// Welcomes, kind 444) are rejected so they don't leak into the DM
    /// stream.
    /// </summary>
    private static readonly HashSet<int> DmFamilyKinds = new() { RumorKind, FileRumorKind, ReactionRumorKind };

    /// <summary>
    /// Creates a NIP-17 chat-message direct message — two kind-1059 gift wraps
    /// (one for the recipient, one for the sender), both wrapping the same
    /// inner kind-14 rumor.
    /// </summary>
    /// <param name="plaintext">The UTF-8 message body.</param>
    /// <param name="senderPrivateKey">The sender's private key.</param>
    /// <param name="recipientPublicKey">The recipient's x-only public key.</param>
    /// <param name="replyTo">
    /// Optional — the inner-rumor id of the message being replied to. When supplied,
    /// the rumor includes <c>["e", &lt;id&gt;, "", "reply"]</c> per NIP-10 markers.
    /// </param>
    /// <param name="replyRoot">
    /// Optional — the inner-rumor id of the thread root, for replies that aren't to
    /// the root itself. When supplied, the rumor includes <c>["e", &lt;id&gt;, "", "root"]</c>.
    /// Pass the same value as <paramref name="replyTo"/> for top-level replies, or
    /// omit when the parent is the root.
    /// </param>
    /// <param name="additionalTags">
    /// Optional extra tags to attach to the rumor (e.g. extra <c>p</c> mentions,
    /// NIP-40 <c>expiration</c>, content warnings). The recipient <c>p</c> tag is
    /// always added by the helper; do not duplicate it here.
    /// </param>
    /// <param name="createdAt">
    /// Optional real timestamp (unix seconds). If null, <see cref="DateTimeOffset.UtcNow"/>
    /// is used. Both wraps' outer timestamps are independently jittered backward.
    /// </param>
    /// <returns>Both signed gift-wrap events. See <see cref="Nip17DirectMessage"/>.</returns>
    public static Nip17DirectMessage CreateDirectMessage(
        string plaintext,
        PrivateKey senderPrivateKey,
        PublicKey recipientPublicKey,
        EventId? replyTo = null,
        EventId? replyRoot = null,
        IReadOnlyList<IReadOnlyList<string>>? additionalTags = null,
        long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(senderPrivateKey);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        var tags = new List<IReadOnlyList<string>>
        {
            new[] { "p", recipientPublicKey.ToHex() },
        };

        if (replyRoot is not null)
        {
            tags.Add(new[] { "e", replyRoot.ToHex(), string.Empty, "root" });
        }

        if (replyTo is not null)
        {
            tags.Add(new[] { "e", replyTo.ToHex(), string.Empty, "reply" });
        }

        if (additionalTags is not null)
        {
            foreach (var t in additionalTags)
            {
                tags.Add(t);
            }
        }

        return WrapRumor(RumorKind, plaintext, tags, senderPrivateKey, recipientPublicKey, createdAt);
    }

    /// <summary>
    /// Creates a NIP-25 reaction wrapped as a NIP-17 DM. The rumor is kind 7
    /// with <c>e</c> and <c>p</c> tags referencing the target message's
    /// <em>inner rumor id</em> and author. Both ends use this exclusively
    /// for reactions to private messages — emitting a clear kind-7 would
    /// leak the conversation's existence.
    /// </summary>
    /// <param name="reaction">
    /// The reaction body per NIP-25: <c>"+"</c> (default like), <c>"-"</c>
    /// (dislike), a Unicode emoji, or a <c>:shortcode:</c> reference (caller
    /// must add the matching <c>emoji</c> tag via <paramref name="additionalTags"/>
    /// in that case).
    /// </param>
    /// <param name="targetRumorId">The inner rumor id of the DM being reacted to.</param>
    /// <param name="targetAuthor">The author of the DM being reacted to — also the recipient of the wrap.</param>
    /// <param name="senderPrivateKey">The reactor's private key.</param>
    /// <param name="additionalTags">Optional extra tags (e.g. NIP-25 custom-emoji declaration).</param>
    /// <param name="createdAt">Optional real timestamp (unix seconds); defaults to now.</param>
    /// <returns>Both signed gift-wrap events.</returns>
    public static Nip17DirectMessage CreateReaction(
        string reaction,
        EventId targetRumorId,
        PublicKey targetAuthor,
        PrivateKey senderPrivateKey,
        IReadOnlyList<IReadOnlyList<string>>? additionalTags = null,
        long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(reaction);
        ArgumentNullException.ThrowIfNull(targetRumorId);
        ArgumentNullException.ThrowIfNull(targetAuthor);
        ArgumentNullException.ThrowIfNull(senderPrivateKey);

        var tags = new List<IReadOnlyList<string>>
        {
            new[] { "e", targetRumorId.ToHex() },
            new[] { "p", targetAuthor.ToHex() },
        };

        if (additionalTags is not null)
        {
            foreach (var t in additionalTags)
            {
                tags.Add(t);
            }
        }

        return WrapRumor(ReactionRumorKind, reaction, tags, senderPrivateKey, targetAuthor, createdAt);
    }

    /// <summary>
    /// Low-level: wrap an arbitrary rumor (any kind, any content, any tags)
    /// as a NIP-17 DM. Use this when the high-level helpers
    /// (<see cref="CreateDirectMessage"/>, <see cref="CreateReaction"/>)
    /// don't cover what you need — for example, file messages (kind 15),
    /// edits, typing indicators, or app-specific rumor kinds.
    /// </summary>
    /// <param name="kind">The rumor kind.</param>
    /// <param name="content">The rumor content (UTF-8).</param>
    /// <param name="tags">The rumor's tags. The caller is responsible for including a recipient <c>p</c> tag if needed for spec compliance.</param>
    /// <param name="senderPrivateKey">The sender's private key.</param>
    /// <param name="recipientPublicKey">The wrap recipient's x-only public key.</param>
    /// <param name="createdAt">Optional real timestamp (unix seconds); defaults to now.</param>
    /// <returns>Both signed gift-wrap events (recipient-addressed and self-addressed).</returns>
    /// <remarks>
    /// If you wrap a kind outside the DM family (chat 14 / file 15 / reaction 7),
    /// <see cref="Unwrap"/> will reject it on receive. Use <see cref="Nip59.Unwrap"/>
    /// directly when you need full kind flexibility on both ends.
    /// </remarks>
    public static Nip17DirectMessage WrapRumor(
        int kind,
        string content,
        IReadOnlyList<IReadOnlyList<string>> tags,
        PrivateKey senderPrivateKey,
        PublicKey recipientPublicKey,
        long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(tags);
        ArgumentNullException.ThrowIfNull(senderPrivateKey);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        long realCreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var rumor = new Rumor(
            Kind: kind,
            CreatedAt: realCreatedAt,
            Tags: tags,
            Content: content);

        return new Nip17DirectMessage(
            ToRecipient: Nip59.Wrap(rumor, senderPrivateKey, recipientPublicKey),
            ToSelf: Nip59.Wrap(rumor, senderPrivateKey, senderPrivateKey.PublicKey));
    }

    /// <summary>
    /// Unwraps a NIP-17 / NIP-59 gift wrap addressed to <paramref name="recipientPrivateKey"/>.
    /// Accepts any DM-family rumor kind (chat 14 / file 15 / reaction 7);
    /// other kinds — e.g. Marmot Welcomes (444) — are rejected so they
    /// don't leak into the DM stream.
    /// </summary>
    /// <param name="giftWrap">The kind-1059 event received from a relay.</param>
    /// <param name="recipientPrivateKey">The recipient's private key.</param>
    /// <returns>The decrypted rumor with the verified sender and rumor id.</returns>
    /// <exception cref="ArgumentException"><paramref name="giftWrap"/> is not a kind-1059 event.</exception>
    /// <exception cref="CryptographicException">A signature/pubkey check failed during unwrapping, or the inner rumor is not a DM-family kind.</exception>
    public static UnwrappedDirectMessage Unwrap(NostrEvent giftWrap, PrivateKey recipientPrivateKey)
    {
        var rumor = Nip59.Unwrap(giftWrap, recipientPrivateKey);

        if (!DmFamilyKinds.Contains(rumor.Kind))
        {
            throw new CryptographicException(
                $"Rumor kind {rumor.Kind} is not in the NIP-17 DM family ({string.Join(", ", DmFamilyKinds)}).");
        }

        return new UnwrappedDirectMessage(
            Sender: rumor.Sender,
            RumorId: rumor.RumorId,
            Kind: rumor.Kind,
            Plaintext: rumor.Content,
            CreatedAt: DateTimeOffset.FromUnixTimeSeconds(rumor.CreatedAt),
            Tags: rumor.Tags);
    }
}

/// <summary>
/// The pair of gift wraps produced by <see cref="Nip17.CreateDirectMessage"/>,
/// <see cref="Nip17.CreateReaction"/>, and <see cref="Nip17.WrapRumor"/>.
/// Publish <see cref="ToRecipient"/> for delivery and <see cref="ToSelf"/>
/// so the sender's other devices can reconstruct sent-message history.
/// </summary>
/// <param name="ToRecipient">The kind-1059 gift wrap addressed to the recipient.</param>
/// <param name="ToSelf">The kind-1059 gift wrap addressed to the sender (same inner rumor as <see cref="ToRecipient"/>).</param>
public sealed record Nip17DirectMessage(NostrEvent ToRecipient, NostrEvent ToSelf);

/// <summary>
/// The result of unwrapping a NIP-17 gift wrap.
/// </summary>
/// <param name="Sender">The sender's x-only public key (taken from the verified seal).</param>
/// <param name="RumorId">The canonical event id of the inner rumor — use this when targeting replies / reactions.</param>
/// <param name="Kind">The rumor kind: <c>14</c> chat, <c>15</c> file, <c>7</c> reaction.</param>
/// <param name="Plaintext">The decrypted rumor content (chat body for kind 14/15; reaction symbol/emoji for kind 7).</param>
/// <param name="CreatedAt">The real (non-jittered) timestamp from the inner rumor.</param>
/// <param name="Tags">The rumor's tags (recipient <c>p</c>, reply <c>e</c> markers, reaction targets, etc.).</param>
/// <param name="Relay">The relay that delivered the gift wrap, or <c>null</c> if unwrap was performed offline.</param>
public sealed record UnwrappedDirectMessage(
    PublicKey Sender,
    EventId RumorId,
    int Kind,
    string Plaintext,
    DateTimeOffset CreatedAt,
    IReadOnlyList<IReadOnlyList<string>> Tags,
    Uri? Relay = null);
