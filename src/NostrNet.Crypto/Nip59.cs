// SPDX-License-Identifier: MIT
//
// NIP-59 Gift Wrap
//
//   https://github.com/nostr-protocol/nips/blob/master/59.md
//
// Three-layered "rumor / seal / gift wrap" construction for sending any
// event privately to a single recipient. NIP-17 (encrypted DMs) and
// MIP-02 (Marmot Welcome events) both ride on top of this.
//
// Layering:
//   rumor      = UNSIGNED event of arbitrary kind. Carries the actual
//                payload. Has a computed `id` but no `sig`. The rumor's
//                `pubkey` is the sender.
//   seal       = kind-13 event SIGNED by the sender; its content is
//                NIP-44(rumor JSON, sender_priv, recipient_pub).
//                No tags. The seal's verified pubkey is what proves who
//                actually sent the rumor.
//   gift wrap  = kind-1059 event SIGNED by a FRESH EPHEMERAL key; its
//                content is NIP-44(seal JSON, ephemeral_priv, recipient_pub)
//                and carries a `p` tag for the recipient. `created_at`
//                is randomly back-dated by up to 2 days (§3) to obscure
//                the real send time.
//
// Important invariants checked on unwrap:
//   - Outer event kind is 1059.
//   - Seal kind is 13 AND seal.Verify() succeeds (Schnorr).
//   - rumor.pubkey == seal.pubkey  (an attacker can't replay someone
//     else's seal with a forged rumor pubkey because the seal is signed).
//   - If the rumor includes an `id`, it MUST match the canonical id
//     recomputed from its other fields (tampering check inside the
//     NIP-44-authenticated envelope is belt-and-braces).

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Crypto;

/// <summary>
/// An unsigned event ready to be sealed and gift-wrapped per NIP-59. The
/// rumor's <c>pubkey</c> is supplied implicitly by the sender's private
/// key passed to <see cref="Nip59.Wrap"/>.
/// </summary>
public sealed record Rumor(
    int Kind,
    long CreatedAt,
    IReadOnlyList<IReadOnlyList<string>> Tags,
    string Content);

/// <summary>
/// The decrypted rumor recovered from a NIP-59 gift wrap, together with
/// the cryptographically-verified sender identity (from the seal).
/// <c>Sender</c> is the sender's pubkey from the verified seal — NOT
/// the gift wrap's outer ephemeral pubkey. <c>RumorId</c> is the
/// canonical event id of the rumor (recomputed and verified on unwrap).
/// </summary>
public sealed record UnwrappedRumor(
    PublicKey Sender,
    EventId RumorId,
    int Kind,
    long CreatedAt,
    IReadOnlyList<IReadOnlyList<string>> Tags,
    string Content);

/// <summary>
/// NIP-59 gift wrap operations: seal a rumor for a single recipient, or
/// unwrap an incoming gift wrap.
/// </summary>
public static class Nip59
{
    /// <summary>The kind of a NIP-59 seal.</summary>
    public const int SealKind = 13;

    /// <summary>The kind of a NIP-59 gift wrap.</summary>
    public const int GiftWrapKind = 1059;

    /// <summary>The maximum amount of backward jitter applied to seal/wrap timestamps.</summary>
    public const int MaxBackwardJitterSeconds = 2 * 24 * 60 * 60;

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false,
        SkipValidation = false,
    };

    /// <summary>
    /// Seals <paramref name="rumor"/> with <paramref name="senderKey"/>
    /// and gift-wraps the seal for <paramref name="recipientKey"/>.
    /// Returns the kind-1059 gift wrap event ready to publish.
    /// </summary>
    public static NostrEvent Wrap(Rumor rumor, PrivateKey senderKey, PublicKey recipientKey)
    {
        ArgumentNullException.ThrowIfNull(rumor);
        ArgumentNullException.ThrowIfNull(senderKey);
        ArgumentNullException.ThrowIfNull(recipientKey);

        // ----- 1. Build and serialize the rumor (UNSIGNED event with computed id).
        string rumorJson = SerializeRumor(
            senderKey.PublicKey,
            rumor.CreatedAt,
            rumor.Kind,
            rumor.Tags,
            rumor.Content);

        // ----- 2. Seal: kind 13, signed by sender, content = NIP-44(rumor).
        string sealContent = Nip44.Encrypt(rumorJson, senderKey, recipientKey);
        long sealCreatedAt = JitterCreatedAt(rumor.CreatedAt);
        var seal = new UnsignedEvent
        {
            PubKey = senderKey.PublicKey,
            CreatedAt = sealCreatedAt,
            Kind = SealKind,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = sealContent,
        }.Sign(senderKey);

        // ----- 3. Gift wrap: kind 1059, signed by a fresh ephemeral key,
        //          content = NIP-44(seal), with a p-tag for the recipient.
        using var ephemeral = PrivateKey.Generate();
        string giftWrapContent = Nip44.Encrypt(seal.ToJson(), ephemeral, recipientKey);
        long giftWrapCreatedAt = JitterCreatedAt(rumor.CreatedAt);

        return new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = giftWrapCreatedAt,
            Kind = GiftWrapKind,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "p", recipientKey.ToHex() },
            },
            Content = giftWrapContent,
        }.Sign(ephemeral);
    }

    /// <summary>
    /// Unwraps a kind-1059 NIP-59 gift wrap. Verifies the inner seal's
    /// signature, decrypts the rumor, and validates that the rumor's
    /// pubkey matches the seal's pubkey.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="giftWrap"/> is not a kind-1059 event.</exception>
    /// <exception cref="CryptographicException">Any signature, decrypt, or pubkey-consistency check failed.</exception>
    public static UnwrappedRumor Unwrap(NostrEvent giftWrap, PrivateKey recipientKey)
    {
        ArgumentNullException.ThrowIfNull(giftWrap);
        ArgumentNullException.ThrowIfNull(recipientKey);

        if (giftWrap.Kind != GiftWrapKind)
        {
            throw new ArgumentException(
                $"Expected kind {GiftWrapKind} (gift wrap); got {giftWrap.Kind}.", nameof(giftWrap));
        }

        // 1. Decrypt outer (gift wrap → seal JSON).
        string sealJson;
        try
        {
            sealJson = Nip44.Decrypt(giftWrap.Content, recipientKey, giftWrap.PubKey);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new CryptographicException("Failed to decrypt gift wrap.", ex);
        }

        // 2. Parse and verify seal.
        NostrEvent seal;
        try
        {
            seal = NostrEvent.FromJson(sealJson);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("Seal JSON is malformed.", ex);
        }

        if (seal.Kind != SealKind)
        {
            throw new CryptographicException(
                $"Inner event is not a seal (kind {SealKind}); got kind {seal.Kind}.");
        }

        if (!seal.Verify())
        {
            throw new CryptographicException("Seal signature is invalid.");
        }

        // 3. Decrypt inner (seal → rumor JSON).
        string rumorJson;
        try
        {
            rumorJson = Nip44.Decrypt(seal.Content, recipientKey, seal.PubKey);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new CryptographicException("Failed to decrypt seal content.", ex);
        }

        // 4. Parse rumor (unsigned: NostrEvent.FromJson requires sig, so use JsonDocument directly).
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(rumorJson);
        }
        catch (JsonException ex)
        {
            throw new CryptographicException("Rumor JSON is malformed.", ex);
        }

        using (doc)
        {
            JsonElement root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new CryptographicException("Rumor is not a JSON object.");
            }

            string rumorPubkeyHex = root.GetProperty("pubkey").GetString()
                ?? throw new CryptographicException("Rumor is missing pubkey.");
            if (!string.Equals(rumorPubkeyHex, seal.PubKey.ToHex(), StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException("Rumor pubkey does not match seal pubkey.");
            }

            int rumorKind = root.GetProperty("kind").GetInt32();
            long createdAt = root.GetProperty("created_at").GetInt64();
            string content = root.GetProperty("content").GetString() ?? string.Empty;
            var tags = ExtractTags(root);

            // Recompute the canonical rumor id and (if present) verify the claimed id matches.
            EventId computedId = EventSerializer.ComputeId(
                seal.PubKey, createdAt, rumorKind, tags, content);

            if (root.TryGetProperty("id", out var idElement) && idElement.ValueKind == JsonValueKind.String)
            {
                string claimedIdHex = idElement.GetString() ?? string.Empty;
                if (!string.Equals(claimedIdHex, computedId.ToHex(), StringComparison.OrdinalIgnoreCase))
                {
                    throw new CryptographicException("Rumor id does not match its computed canonical id.");
                }
            }

            return new UnwrappedRumor(
                Sender: seal.PubKey,
                RumorId: computedId,
                Kind: rumorKind,
                CreatedAt: createdAt,
                Tags: tags,
                Content: content);
        }
    }

    /// <summary>
    /// Non-throwing variant of <see cref="Unwrap"/>. Returns <c>false</c>
    /// for any decrypt, signature, or consistency failure — typically
    /// what you want when iterating over inbox events of unknown origin.
    /// </summary>
    public static bool TryUnwrap(
        NostrEvent giftWrap,
        PrivateKey recipientKey,
        [NotNullWhen(true)] out UnwrappedRumor? rumor)
    {
        try
        {
            rumor = Unwrap(giftWrap, recipientKey);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rumor = null;
            return false;
        }
    }

    private static long JitterCreatedAt(long baseTimestamp)
    {
        int backward = RandomNumberGenerator.GetInt32(0, MaxBackwardJitterSeconds);
        return baseTimestamp - backward;
    }

    private static string SerializeRumor(
        PublicKey pubKey,
        long createdAt,
        int kind,
        IReadOnlyList<IReadOnlyList<string>> tags,
        string content)
    {
        EventId id = EventSerializer.ComputeId(pubKey, createdAt, kind, tags, content);

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("id", id.ToHex());
            writer.WriteString("pubkey", pubKey.ToHex());
            writer.WriteNumber("created_at", createdAt);
            writer.WriteNumber("kind", kind);

            writer.WriteStartArray("tags");
            for (int i = 0; i < tags.Count; i++)
            {
                writer.WriteStartArray();
                IReadOnlyList<string> tag = tags[i];
                for (int j = 0; j < tag.Count; j++)
                {
                    writer.WriteStringValue(tag[j]);
                }

                writer.WriteEndArray();
            }

            writer.WriteEndArray();

            writer.WriteString("content", content);
            writer.WriteEndObject();
        }

        return SysEncoding.UTF8.GetString(ms.ToArray());
    }

    private static IReadOnlyList<IReadOnlyList<string>> ExtractTags(JsonElement rumorRoot)
    {
        if (!rumorRoot.TryGetProperty("tags", out var tagsElement)
            || tagsElement.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<IReadOnlyList<string>>();
        }

        var result = new List<IReadOnlyList<string>>(tagsElement.GetArrayLength());
        foreach (var rowElement in tagsElement.EnumerateArray())
        {
            if (rowElement.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var row = new List<string>(rowElement.GetArrayLength());
            foreach (var cell in rowElement.EnumerateArray())
            {
                row.Add(cell.GetString() ?? string.Empty);
            }

            result.Add(row);
        }

        return result;
    }
}
