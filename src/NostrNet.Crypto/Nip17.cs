// SPDX-License-Identifier: MIT
//
// NIP-17 private direct messages on top of NIP-44 v2 and NIP-59 gift wrap.
//
// Reference:
//   - NIP-17 (kind 14 chat messages):       https://github.com/nostr-protocol/nips/blob/master/17.md
//   - NIP-59 (gift wrap / sealed events):    https://github.com/nostr-protocol/nips/blob/master/59.md
//
// Layering:
//   rumor      = unsigned kind-14 event with the plaintext content
//   seal       = kind-13 event signed by the sender; content is NIP-44(rumor)
//   gift wrap  = kind-1059 event signed by a fresh EPHEMERAL key; content is
//                NIP-44(seal); has a p-tag for the recipient. Its `created_at`
//                is jittered backward by up to 2 days per NIP-59 §3 to obscure
//                the real send time.

using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Crypto;

/// <summary>
/// NIP-17 private direct messages (sealed under NIP-59 gift wrap).
/// </summary>
public static class Nip17
{
    /// <summary>The kind of an unsigned chat-message rumor.</summary>
    public const int RumorKind = 14;

    /// <summary>The kind of a NIP-59 seal.</summary>
    public const int SealKind = 13;

    /// <summary>The kind of a NIP-59 gift wrap.</summary>
    public const int GiftWrapKind = 1059;

    private const int MaxBackwardJitterSeconds = 2 * 24 * 60 * 60;

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Indented = false,
        SkipValidation = false,
    };

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

        // ----- 1. Rumor (unsigned kind 14).
        IReadOnlyList<IReadOnlyList<string>> rumorTags = new IReadOnlyList<string>[]
        {
            new[] { "p", recipientPublicKey.ToHex() },
        };

        string rumorJson = SerializeRumor(
            senderPrivateKey.PublicKey,
            realCreatedAt,
            RumorKind,
            rumorTags,
            plaintext);

        // ----- 2. Seal (kind 13, signed by sender, content = NIP-44(rumor)).
        string sealContent = Nip44.Encrypt(rumorJson, senderPrivateKey, recipientPublicKey);
        long sealCreatedAt = JitterCreatedAt(realCreatedAt);
        var seal = new UnsignedEvent
        {
            PubKey = senderPrivateKey.PublicKey,
            CreatedAt = sealCreatedAt,
            Kind = SealKind,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = sealContent,
        }.Sign(senderPrivateKey);

        // ----- 3. Gift wrap (kind 1059, signed by ephemeral key,
        // content = NIP-44(seal), p-tag for recipient).
        using var ephemeral = PrivateKey.Generate();
        string giftWrapContent = Nip44.Encrypt(seal.ToJson(), ephemeral, recipientPublicKey);
        long giftWrapCreatedAt = JitterCreatedAt(realCreatedAt);
        var giftWrap = new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = giftWrapCreatedAt,
            Kind = GiftWrapKind,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "p", recipientPublicKey.ToHex() },
            },
            Content = giftWrapContent,
        }.Sign(ephemeral);

        return giftWrap;
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
        ArgumentNullException.ThrowIfNull(giftWrap);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);

        if (giftWrap.Kind != GiftWrapKind)
        {
            throw new ArgumentException($"Expected kind {GiftWrapKind} (gift wrap); got {giftWrap.Kind}.", nameof(giftWrap));
        }

        // 1. Decrypt outer (gift wrap → seal JSON).
        string sealJson;
        try
        {
            sealJson = Nip44.Decrypt(giftWrap.Content, recipientPrivateKey, giftWrap.PubKey);
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
            throw new CryptographicException($"Inner event is not a seal (kind {SealKind}); got kind {seal.Kind}.");
        }

        if (!seal.Verify())
        {
            throw new CryptographicException("Seal signature is invalid.");
        }

        // 3. Decrypt inner (seal → rumor JSON).
        string rumorJson;
        try
        {
            rumorJson = Nip44.Decrypt(seal.Content, recipientPrivateKey, seal.PubKey);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new CryptographicException("Failed to decrypt seal content.", ex);
        }

        // 4. Parse rumor (an unsigned event — JsonDocument since NostrEvent.FromJson requires sig).
        using var doc = JsonDocument.Parse(rumorJson);
        JsonElement root = doc.RootElement;

        string rumorPubkeyHex = root.GetProperty("pubkey").GetString()
            ?? throw new CryptographicException("Rumor is missing pubkey.");
        if (!string.Equals(rumorPubkeyHex, seal.PubKey.ToHex(), StringComparison.OrdinalIgnoreCase))
        {
            throw new CryptographicException("Rumor pubkey does not match seal pubkey.");
        }

        int rumorKind = root.GetProperty("kind").GetInt32();
        if (rumorKind != RumorKind)
        {
            throw new CryptographicException($"Rumor is not kind {RumorKind}; got kind {rumorKind}.");
        }

        long createdAt = root.GetProperty("created_at").GetInt64();
        string content = root.GetProperty("content").GetString() ?? string.Empty;
        var tags = ExtractTags(root);

        return new UnwrappedDirectMessage(
            Sender: seal.PubKey,
            Plaintext: content,
            CreatedAt: DateTimeOffset.FromUnixTimeSeconds(createdAt),
            Tags: tags);
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

/// <summary>
/// The result of unwrapping a NIP-17 gift wrap.
/// </summary>
/// <param name="Sender">The sender's x-only public key (taken from the verified seal).</param>
/// <param name="Plaintext">The decrypted message text.</param>
/// <param name="CreatedAt">The real (non-jittered) timestamp from the inner rumor.</param>
/// <param name="Tags">The rumor's tags (typically including the <c>p</c>-tag for the recipient).</param>
public sealed record UnwrappedDirectMessage(
    PublicKey Sender,
    string Plaintext,
    DateTimeOffset CreatedAt,
    IReadOnlyList<IReadOnlyList<string>> Tags);
