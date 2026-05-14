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
    /// Creates a NIP-17 direct message: a kind-1059 gift wrap addressed to
    /// the recipient. Publish the returned event to relays for delivery.
    /// </summary>
    /// <param name="plaintext">The UTF-8 message body.</param>
    /// <param name="senderPrivateKey">The sender's private key.</param>
    /// <param name="recipientPublicKey">The recipient's x-only public key.</param>
    /// <param name="createdAt">
    /// Optional real timestamp (unix seconds). If null, <see cref="DateTimeOffset.UtcNow"/>
    /// is used. The seal and gift wrap each carry a jittered (backward) timestamp.
    /// </param>
    /// <returns>The signed gift-wrap event ready for publication.</returns>
    public static NostrEvent CreateDirectMessage(
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

        return Nip59.Wrap(rumor, senderPrivateKey, recipientPublicKey);
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
