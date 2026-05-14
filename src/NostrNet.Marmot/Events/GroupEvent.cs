// SPDX-License-Identifier: MIT
//
// MIP-03 Group event (kind 445).
//
// Wire shape per spec:
//
//   {
//     "id": ...,
//     "kind": 445,
//     "pubkey": <ephemeral pubkey, never reused>,
//     "created_at": ...,
//     "content": base64(nonce(12) || ChaCha20-Poly1305.encrypt(
//                  key=mls_exporter_secret, nonce=nonce, plaintext=mls_message, aad=b"")),
//     "tags": [
//       ["h", <nostr_group_id from Marmot Group Data extension, hex>],
//       ["expiration", "<unix>"]  // optional, when disappearing_message_secs is set
//     ],
//     "sig": ...
//   }
//
// The MLSMessage plaintext is opaque to this library — building and
// processing it is the job of the MLS provider. We handle:
//   - ChaCha20-Poly1305 with the empty AAD per spec
//   - The base64(nonce ‖ ciphertext) layout
//   - Ephemeral keypair generation per event
//   - h-tag routing and NIP-40 expiration tagging

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Marmot.Events;

/// <summary>
/// A parsed kind-445 group event with its MLSMessage already decrypted into
/// opaque bytes — the consumer hands those bytes to an MLS provider.
/// </summary>
/// <param name="MlsMessageBytes">The decrypted MLSMessage payload (opaque to NostrNet).</param>
/// <param name="EphemeralPubkey">The ephemeral pubkey that signed the wire event.</param>
/// <param name="NostrGroupId">The 32-byte group id, from the <c>h</c> tag.</param>
/// <param name="CreatedAt">Event timestamp.</param>
/// <param name="Expiration">NIP-40 expiration if the group has disappearing messages enabled.</param>
public sealed record DecryptedGroupEvent(
    byte[] MlsMessageBytes,
    PublicKey EphemeralPubkey,
    byte[] NostrGroupId,
    DateTimeOffset CreatedAt,
    DateTimeOffset? Expiration);

/// <summary>
/// Builder / parser for kind-445 group events.
/// </summary>
/// <remarks>
/// Group-event encryption is keyed off the per-epoch MLS exporter secret,
/// which only the MLS provider can derive. This API takes that 32-byte
/// secret as input and handles the ChaCha20-Poly1305 envelope, ephemeral
/// keypair generation, <c>h</c>-tag routing, and NIP-40 expiration tagging.
/// </remarks>
public static class GroupEvent
{
    /// <summary>The 32-byte MLS exporter secret used as the ChaCha20-Poly1305 key.</summary>
    public const int ExporterSecretLength = 32;

    /// <summary>The 12-byte ChaCha20-Poly1305 nonce length.</summary>
    public const int NonceLength = 12;

    /// <summary>The 16-byte ChaCha20-Poly1305 authentication tag length.</summary>
    public const int TagLength = 16;

    /// <summary>
    /// Minimum length, in bytes, of a decoded <c>content</c> field — 12 bytes
    /// of nonce plus at least 16 bytes of tag.
    /// </summary>
    public const int MinDecodedContentLength = NonceLength + TagLength;

    /// <summary>The recommended MLS exporter label inputs per MIP-03 §"Derive exporter secret".</summary>
    public const string ExporterLabel = "marmot";

    /// <summary>The recommended MLS exporter context per MIP-03 §"Derive exporter secret".</summary>
    public const string ExporterContext = "group-event";

    /// <summary>
    /// Builds and signs a kind-445 group event. The caller provides the MLS
    /// exporter secret (the 32-byte output of
    /// <c>MLS-Exporter(ExporterLabel, ExporterContext, 32)</c> for the
    /// current group epoch) and the serialized MLSMessage bytes.
    /// </summary>
    /// <param name="mlsMessageBytes">The serialized MLSMessage to encrypt.</param>
    /// <param name="exporterSecret">32-byte key from the MLS exporter for this epoch.</param>
    /// <param name="nostrGroupId">32-byte group id from the Marmot Group Data extension.</param>
    /// <param name="disappearingMessageDuration">If set, adds a NIP-40 <c>expiration</c> tag.</param>
    /// <param name="createdAt">Optional override for <c>created_at</c>.</param>
    /// <returns>A signed Nostr event ready to publish.</returns>
    /// <exception cref="ArgumentException">An input has the wrong length.</exception>
    public static NostrEvent Build(
        ReadOnlySpan<byte> mlsMessageBytes,
        ReadOnlySpan<byte> exporterSecret,
        ReadOnlySpan<byte> nostrGroupId,
        TimeSpan? disappearingMessageDuration = null,
        long? createdAt = null)
    {
        if (exporterSecret.Length != ExporterSecretLength)
        {
            throw new ArgumentException(
                $"Exporter secret must be {ExporterSecretLength} bytes.", nameof(exporterSecret));
        }

        if (nostrGroupId.Length != 32)
        {
            throw new ArgumentException("Nostr group id must be 32 bytes.", nameof(nostrGroupId));
        }

        if (mlsMessageBytes.IsEmpty)
        {
            throw new ArgumentException("MLSMessage bytes must not be empty.", nameof(mlsMessageBytes));
        }

        // ChaCha20-Poly1305: nonce(12) || ciphertext+tag(N+16).
        byte[] nonce = new byte[NonceLength];
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[mlsMessageBytes.Length];
        byte[] tag = new byte[TagLength];

        using (var chacha = new ChaCha20Poly1305(exporterSecret))
        {
            chacha.Encrypt(nonce, mlsMessageBytes, ciphertext, tag, associatedData: ReadOnlySpan<byte>.Empty);
        }

        // event.content = base64(nonce || ciphertext || tag)
        byte[] payload = new byte[NonceLength + ciphertext.Length + TagLength];
        nonce.CopyTo(payload, 0);
        Buffer.BlockCopy(ciphertext, 0, payload, NonceLength, ciphertext.Length);
        tag.CopyTo(payload, NonceLength + ciphertext.Length);

        long timestamp = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var tags = new List<IReadOnlyList<string>>
        {
            new[] { "h", Convert.ToHexStringLower(nostrGroupId) },
        };

        if (disappearingMessageDuration is TimeSpan ttl && ttl > TimeSpan.Zero)
        {
            long expiration = timestamp + (long)ttl.TotalSeconds;
            tags.Add(new[] { "expiration", expiration.ToString(CultureInfo.InvariantCulture) });
        }

        // Each kind-445 event is signed by a fresh ephemeral keypair.
        // We dispose it after signing — the secret material isn't needed again.
        using var ephemeral = PrivateKey.Generate();

        return new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = timestamp,
            Kind = MarmotKinds.GroupEvent,
            Tags = tags,
            Content = Convert.ToBase64String(payload),
        }.Sign(ephemeral);
    }

    /// <summary>
    /// Decrypts a kind-445 event. The caller provides the MLS exporter
    /// secret for the group's current epoch.
    /// </summary>
    /// <exception cref="ArgumentException">The event isn't kind 445.</exception>
    /// <exception cref="FormatException">The event's tags or content are malformed.</exception>
    /// <exception cref="CryptographicException">ChaCha20-Poly1305 authentication failed.</exception>
    public static DecryptedGroupEvent Decrypt(NostrEvent ev, ReadOnlySpan<byte> exporterSecret)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != MarmotKinds.GroupEvent)
        {
            throw new ArgumentException(
                $"Expected a Marmot group event kind ({MarmotKinds.GroupEvent}); got {ev.Kind}.", nameof(ev));
        }

        if (exporterSecret.Length != ExporterSecretLength)
        {
            throw new ArgumentException(
                $"Exporter secret must be {ExporterSecretLength} bytes.", nameof(exporterSecret));
        }

        string? hTagHex = ev.Tags.FirstValue("h");
        if (hTagHex is null || hTagHex.Length != 64)
        {
            throw new FormatException("Group event is missing or has malformed 'h' tag (must be 32 bytes hex).");
        }

        byte[] groupId;
        try
        {
            groupId = Convert.FromHexString(hTagHex);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Group event 'h' tag is not valid hex.", ex);
        }

        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(ev.Content);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Group event content is not valid base64.", ex);
        }

        if (payload.Length < MinDecodedContentLength)
        {
            throw new FormatException(
                $"Group event content is too short ({payload.Length} bytes; minimum {MinDecodedContentLength}).");
        }

        // payload = nonce(12) || ciphertext(N) || tag(16)
        int ciphertextLen = payload.Length - NonceLength - TagLength;
        var nonce = payload.AsSpan(0, NonceLength);
        var ciphertext = payload.AsSpan(NonceLength, ciphertextLen);
        var tag = payload.AsSpan(NonceLength + ciphertextLen, TagLength);

        byte[] plaintext = new byte[ciphertextLen];
        using (var chacha = new ChaCha20Poly1305(exporterSecret))
        {
            // Throws AuthenticationTagMismatchException (subtype of CryptographicException) on bad tag.
            chacha.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: ReadOnlySpan<byte>.Empty);
        }

        DateTimeOffset? expiration = null;
        if (ev.Tags.FirstValue("expiration") is string expStr
            && long.TryParse(expStr, NumberStyles.None, CultureInfo.InvariantCulture, out long expUnix))
        {
            expiration = DateTimeOffset.FromUnixTimeSeconds(expUnix);
        }

        return new DecryptedGroupEvent(
            MlsMessageBytes: plaintext,
            EphemeralPubkey: ev.PubKey,
            NostrGroupId: groupId,
            CreatedAt: DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            Expiration: expiration);
    }

    /// <summary>
    /// Try-decrypt variant. Returns <c>false</c> for any decode/auth failure
    /// — typically when the event is for a different epoch's key.
    /// </summary>
    public static bool TryDecrypt(
        NostrEvent ev,
        ReadOnlySpan<byte> exporterSecret,
        [NotNullWhen(true)] out DecryptedGroupEvent? decrypted)
    {
        decrypted = null;
        try
        {
            decrypted = Decrypt(ev, exporterSecret);
            return true;
        }
        catch (Exception e) when (e is ArgumentException or FormatException or CryptographicException)
        {
            return false;
        }
    }
}
