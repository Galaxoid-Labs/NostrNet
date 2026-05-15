// SPDX-License-Identifier: MIT
//
// NIP-17 private direct messages on top of NIP-44 v2 and NIP-59 gift wrap.
//
// Reference:
//   - NIP-17 (kind 14 chat messages):       https://github.com/nostr-protocol/nips/blob/master/17.md
//   - NIP-59 (gift wrap / sealed events):    https://github.com/nostr-protocol/nips/blob/master/59.md
//
// The seal/wrap mechanics live in Nip59 — this file is a thin wrapper
// that shapes a kind-14 chat rumor and surfaces a DM-friendly view of
// the result.

using System.Security.Cryptography;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Crypto;

/// <summary>
/// NIP-17 private direct messages (sealed under NIP-59 gift wrap).
/// </summary>
public static class Nip17
{
    /// <summary>The kind of an unsigned chat-message rumor.</summary>
    public const int RumorKind = 14;

    /// <summary>The kind of a NIP-59 seal. Re-exported from <see cref="Nip59"/>.</summary>
    public const int SealKind = Nip59.SealKind;

    /// <summary>The kind of a NIP-59 gift wrap. Re-exported from <see cref="Nip59"/>.</summary>
    public const int GiftWrapKind = Nip59.GiftWrapKind;

    /// <summary>
    /// Creates a NIP-17 direct message: <em>two</em> kind-1059 gift wraps —
    /// one addressed to the recipient, one addressed to the sender. Both
    /// wrap the same inner rumor (identical rumor id) so a multi-device
    /// sender can subscribe to its own inbox and recover sent-message
    /// history without round-tripping through the recipient.
    /// </summary>
    /// <param name="plaintext">The UTF-8 message body.</param>
    /// <param name="senderPrivateKey">The sender's private key.</param>
    /// <param name="recipientPublicKey">The recipient's x-only public key.</param>
    /// <param name="createdAt">
    /// Optional real timestamp (unix seconds). If null, <see cref="DateTimeOffset.UtcNow"/>
    /// is used. The seals and gift wraps each carry independently jittered
    /// (backward) timestamps.
    /// </param>
    /// <returns>
    /// Both signed gift-wrap events. Publish <see cref="Nip17DirectMessage.ToRecipient"/>
    /// to the recipient's inbox and <see cref="Nip17DirectMessage.ToSelf"/>
    /// to your own — typically the same relay set unless you're routing via
    /// NIP-65 inbox lists.
    /// </returns>
    /// <remarks>
    /// The two wraps use the same inner rumor and seal, so they decrypt to
    /// identical content. They differ in outer encryption: the recipient's
    /// wrap uses an ECDH key derived from <paramref name="recipientPublicKey"/>;
    /// the sender's wrap uses one derived from the sender's own public key.
    /// Each outer is signed by a fresh ephemeral key per NIP-59.
    /// </remarks>
    public static Nip17DirectMessage CreateDirectMessage(
        string plaintext,
        PrivateKey senderPrivateKey,
        PublicKey recipientPublicKey,
        long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(senderPrivateKey);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        long realCreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var rumor = new Rumor(
            Kind: RumorKind,
            CreatedAt: realCreatedAt,
            Tags: new IReadOnlyList<string>[]
            {
                new[] { "p", recipientPublicKey.ToHex() },
            },
            Content: plaintext);

        return new Nip17DirectMessage(
            ToRecipient: Nip59.Wrap(rumor, senderPrivateKey, recipientPublicKey),
            ToSelf: Nip59.Wrap(rumor, senderPrivateKey, senderPrivateKey.PublicKey));
    }

    /// <summary>
    /// Unwraps a NIP-17 / NIP-59 gift wrap addressed to <paramref name="recipientPrivateKey"/>.
    /// </summary>
    /// <param name="giftWrap">The kind-1059 event received from a relay.</param>
    /// <param name="recipientPrivateKey">The recipient's private key.</param>
    /// <returns>The decrypted message with the verified sender.</returns>
    /// <exception cref="ArgumentException"><paramref name="giftWrap"/> is not a kind-1059 event.</exception>
    /// <exception cref="CryptographicException">A signature, kind, or pubkey check failed during unwrapping.</exception>
    public static UnwrappedDirectMessage Unwrap(NostrEvent giftWrap, PrivateKey recipientPrivateKey)
    {
        var rumor = Nip59.Unwrap(giftWrap, recipientPrivateKey);

        if (rumor.Kind != RumorKind)
        {
            throw new CryptographicException(
                $"Rumor is not a NIP-17 chat message (kind {RumorKind}); got kind {rumor.Kind}.");
        }

        return new UnwrappedDirectMessage(
            Sender: rumor.Sender,
            Plaintext: rumor.Content,
            CreatedAt: DateTimeOffset.FromUnixTimeSeconds(rumor.CreatedAt),
            Tags: rumor.Tags);
    }
}

/// <summary>
/// The pair of gift wraps produced by <see cref="Nip17.CreateDirectMessage"/>.
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
/// <param name="Plaintext">The decrypted message text.</param>
/// <param name="CreatedAt">The real (non-jittered) timestamp from the inner rumor.</param>
/// <param name="Tags">The rumor's tags (typically including the <c>p</c>-tag for the recipient).</param>
/// <param name="Relay">The relay that delivered the gift wrap, or <c>null</c> if unwrap was performed offline.</param>
public sealed record UnwrappedDirectMessage(
    PublicKey Sender,
    string Plaintext,
    DateTimeOffset CreatedAt,
    IReadOnlyList<IReadOnlyList<string>> Tags,
    Uri? Relay = null);
