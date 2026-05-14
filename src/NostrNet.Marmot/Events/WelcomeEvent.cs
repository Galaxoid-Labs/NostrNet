// SPDX-License-Identifier: MIT
//
// MIP-02 Welcome event (kind 444 wrapped in NIP-59 gift wrap).
//
// Wire shape:
//   - Outer kind 1059 "gift wrap" event, signed by an EPHEMERAL keypair,
//     with a `p` tag for the recipient. Its content is NIP-44(seal JSON)
//     encrypted ephemeral→recipient.
//   - Middle kind 13 "seal", signed by the SENDER. Its content is
//     NIP-44(rumor JSON) encrypted sender→recipient.
//   - Inner kind 444 "Welcome rumor": UNSIGNED. Its content is the
//     base64-encoded MLSMessage (wire_format=mls_welcome). Tags:
//       ["e",        <key-package event id>]
//       ["relays",   <wss://relay1>, <wss://relay2>, ...]
//       ["encoding", "base64"]
//
// All seal/wrap mechanics are delegated to Nip59. This module only
// shapes the kind-444 rumor and extracts Welcome-specific tags on the
// receive side.
//
// MLS Welcome processing (extracting group secrets, joining the group)
// is the MLS provider's job; this module just delivers the bytes.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Marmot.Events;

/// <summary>
/// The result of unwrapping a Marmot Welcome gift wrap.
/// </summary>
/// <param name="Sender">The verified sender pubkey (from the seal).</param>
/// <param name="MlsWelcomeBytes">
/// Raw MLSMessage bytes with <c>wire_format = mls_welcome</c>. Opaque to
/// NostrNet — pass to your MLS provider to actually join the group.
/// </param>
/// <param name="KeyPackageEventId">The kind-30443 event id that introduced this user.</param>
/// <param name="RecommendedRelays">Relays where the new member should look for group events.</param>
/// <param name="RumorCreatedAt">Original (non-jittered) timestamp from the inner rumor.</param>
public sealed record UnwrappedWelcome(
    PublicKey Sender,
    byte[] MlsWelcomeBytes,
    string KeyPackageEventId,
    IReadOnlyList<string> RecommendedRelays,
    DateTimeOffset RumorCreatedAt);

/// <summary>
/// Builder and parser for MIP-02 Welcome events.
/// </summary>
public static class WelcomeEvent
{
    /// <summary>
    /// Builds and gift-wraps a Marmot Welcome event addressed to
    /// <paramref name="recipientPubkey"/>. The returned event is a kind-1059
    /// signed by an ephemeral key and ready to publish.
    /// </summary>
    /// <param name="mlsWelcomeBytes">Serialized MLSMessage with wire_format=mls_welcome.</param>
    /// <param name="keyPackageEventId">The kind-30443 event id the sender used to add this user.</param>
    /// <param name="senderKey">The admin/sender's private key (signs the inner seal).</param>
    /// <param name="recipientPubkey">The new member's public key.</param>
    /// <param name="recommendedRelays">Relays where group events will be published.</param>
    /// <param name="createdAt">Optional unix timestamp (defaults to now). Seal and gift wrap each get a backward-jittered copy per NIP-59.</param>
    public static NostrEvent Build(
        byte[] mlsWelcomeBytes,
        string keyPackageEventId,
        PrivateKey senderKey,
        PublicKey recipientPubkey,
        IReadOnlyList<string> recommendedRelays,
        long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(mlsWelcomeBytes);
        ArgumentException.ThrowIfNullOrEmpty(keyPackageEventId);
        ArgumentNullException.ThrowIfNull(senderKey);
        ArgumentNullException.ThrowIfNull(recipientPubkey);
        ArgumentNullException.ThrowIfNull(recommendedRelays);

        long realCreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var rumor = new Rumor(
            Kind: MarmotKinds.WelcomeRumor,
            CreatedAt: realCreatedAt,
            Tags: BuildRumorTags(keyPackageEventId, recommendedRelays),
            Content: Convert.ToBase64String(mlsWelcomeBytes));

        return Nip59.Wrap(rumor, senderKey, recipientPubkey);
    }

    /// <summary>
    /// Unwraps a Marmot Welcome gift wrap addressed to
    /// <paramref name="recipientKey"/>. Verifies the inner seal's signature
    /// and ensures the rumor's pubkey matches the seal's pubkey before
    /// returning the MLS Welcome bytes.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="giftWrap"/> is not a kind-1059 event.</exception>
    /// <exception cref="CryptographicException">A signature or pubkey-consistency check failed.</exception>
    public static UnwrappedWelcome Unwrap(NostrEvent giftWrap, PrivateKey recipientKey)
    {
        var rumor = Nip59.Unwrap(giftWrap, recipientKey);

        if (rumor.Kind != MarmotKinds.WelcomeRumor)
        {
            throw new CryptographicException(
                $"Rumor is not a Marmot Welcome (kind {MarmotKinds.WelcomeRumor}); got {rumor.Kind}.");
        }

        ParseWelcomeTags(rumor.Tags, out string? keyPackageEventId, out var relays, out bool sawBase64Encoding);

        if (string.IsNullOrEmpty(keyPackageEventId))
        {
            throw new CryptographicException(
                "Welcome rumor is missing the required 'e' tag (KeyPackage event id).");
        }

        if (!sawBase64Encoding)
        {
            throw new CryptographicException(
                "Welcome rumor is missing 'encoding' tag or doesn't declare base64 (hex is no longer supported per MIP-02).");
        }

        byte[] mlsBytes;
        try
        {
            mlsBytes = Convert.FromBase64String(rumor.Content);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("Welcome rumor content is not valid base64.", ex);
        }

        return new UnwrappedWelcome(
            Sender: rumor.Sender,
            MlsWelcomeBytes: mlsBytes,
            KeyPackageEventId: keyPackageEventId,
            RecommendedRelays: relays,
            RumorCreatedAt: DateTimeOffset.FromUnixTimeSeconds(rumor.CreatedAt));
    }

    /// <summary>Try-unwrap variant. Returns <c>false</c> for any signature, decrypt, or parse failure.</summary>
    public static bool TryUnwrap(
        NostrEvent giftWrap,
        PrivateKey recipientKey,
        [NotNullWhen(true)] out UnwrappedWelcome? unwrapped)
    {
        try
        {
            unwrapped = Unwrap(giftWrap, recipientKey);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            unwrapped = null;
            return false;
        }
    }

    private static IReadOnlyList<IReadOnlyList<string>> BuildRumorTags(
        string keyPackageEventId, IReadOnlyList<string> relays)
    {
        var tags = new List<IReadOnlyList<string>>
        {
            new[] { "e", keyPackageEventId },
        };

        if (relays.Count > 0)
        {
            var relayTag = new List<string>(1 + relays.Count) { "relays" };
            relayTag.AddRange(relays);
            tags.Add(relayTag);
        }

        tags.Add(new[] { "encoding", "base64" });
        return tags;
    }

    private static void ParseWelcomeTags(
        IReadOnlyList<IReadOnlyList<string>> tags,
        out string? keyPackageEventId,
        out List<string> relays,
        out bool sawBase64Encoding)
    {
        keyPackageEventId = null;
        relays = new List<string>();
        sawBase64Encoding = false;

        for (int i = 0; i < tags.Count; i++)
        {
            var tag = tags[i];
            if (tag.Count < 2)
            {
                continue;
            }

            switch (tag[0])
            {
                case "e":
                    keyPackageEventId ??= tag[1];
                    break;
                case "relays":
                    for (int j = 1; j < tag.Count; j++)
                    {
                        relays.Add(tag[j]);
                    }

                    break;
                case "encoding":
                    if (string.Equals(tag[1], "base64", StringComparison.Ordinal))
                    {
                        sawBase64Encoding = true;
                    }

                    break;
            }
        }
    }
}
