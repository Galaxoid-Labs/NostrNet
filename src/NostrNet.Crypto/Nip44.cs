// SPDX-License-Identifier: MIT
//
// NIP-44 v2 encrypted payloads.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/44.md
//
// Wire format (after base64 decoding):
//   version (1B = 0x02)
//   nonce (32B)
//   ciphertext (padded_len + 2 B)
//   mac (32B)
//
// Per-message key derivation:
//   conversation_key = HKDF-Extract(SHA256, IKM=ecdh_x, salt="nip44-v2")
//   keys             = HKDF-Expand(SHA256, prk=conversation_key, info=nonce, L=76)
//   chacha_key  = keys[ 0..32]
//   chacha_nonce= keys[32..44]
//   hmac_key    = keys[44..76]
//
// Authenticated content:
//   ciphertext = ChaCha20(chacha_key, chacha_nonce, counter=0, padded_plaintext)
//   mac        = HMAC-SHA256(hmac_key, nonce || ciphertext)
//
// Padding (§3.7):
//   unpadded_len must be in [1, 65535]
//   padded plaintext = u16_be(unpadded_len) || plaintext || zero_padding

using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using NostrNet.Cryptography;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Crypto;

/// <summary>
/// NIP-44 v2 encrypted payload encryption and decryption.
/// </summary>
public static class Nip44
{
    /// <summary>The version byte for v2 payloads.</summary>
    public const byte Version = 0x02;

    /// <summary>Per-message random nonce length in bytes.</summary>
    public const int NonceSize = 32;

    /// <summary>Minimum plaintext length in bytes.</summary>
    public const int MinPlaintextLength = 1;

    /// <summary>Maximum plaintext length in bytes.</summary>
    public const int MaxPlaintextLength = 65535;

    /// <summary>HKDF-Extract salt used for conversation-key derivation.</summary>
    private static ReadOnlySpan<byte> Nip44Salt => "nip44-v2"u8;

    private const int ConversationKeySize = 32;
    private const int MessageKeysSize = 76;   // 32 + 12 + 32

    /// <summary>
    /// Encrypts a UTF-8 plaintext into a NIP-44 v2 payload (base64 string).
    /// A fresh random nonce is generated for each call.
    /// </summary>
    /// <param name="plaintext">The plaintext (1 to 65535 bytes when UTF-8 encoded).</param>
    /// <param name="senderPrivateKey">The sender's private key.</param>
    /// <param name="recipientPublicKey">The recipient's x-only public key.</param>
    /// <returns>The base64-encoded NIP-44 v2 payload.</returns>
    public static string Encrypt(string plaintext, PrivateKey senderPrivateKey, PublicKey recipientPublicKey)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(senderPrivateKey);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        Span<byte> conversationKey = stackalloc byte[ConversationKeySize];
        DeriveConversationKey(senderPrivateKey, recipientPublicKey, conversationKey);

        Span<byte> nonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        try
        {
            return EncryptInternal(plaintext, conversationKey, nonce);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(conversationKey);
        }
    }

    /// <summary>
    /// Decrypts a NIP-44 v2 payload.
    /// </summary>
    /// <param name="payload">The base64-encoded payload.</param>
    /// <param name="recipientPrivateKey">The recipient's private key.</param>
    /// <param name="senderPublicKey">The sender's x-only public key.</param>
    /// <returns>The decrypted UTF-8 plaintext.</returns>
    /// <exception cref="CryptographicException">The MAC failed verification, the version is unsupported, or padding is invalid.</exception>
    /// <exception cref="FormatException">The payload is not valid base64 or has an invalid structural length.</exception>
    public static string Decrypt(string payload, PrivateKey recipientPrivateKey, PublicKey senderPublicKey)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(senderPublicKey);

        Span<byte> conversationKey = stackalloc byte[ConversationKeySize];
        DeriveConversationKey(recipientPrivateKey, senderPublicKey, conversationKey);

        try
        {
            return DecryptInternal(payload, conversationKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(conversationKey);
        }
    }

    /// <summary>
    /// Computes the NIP-44 conversation key shared between two peers.
    /// </summary>
    /// <param name="privateKey">One party's private key.</param>
    /// <param name="publicKey">The other party's x-only public key.</param>
    /// <param name="conversationKey32">A 32-byte buffer to receive the conversation key.</param>
    /// <remarks>
    /// This is the HKDF-Extract output. It is symmetric: Alice computing it
    /// with (alicePriv, bobPub) produces the same value as Bob computing it
    /// with (bobPriv, alicePub).
    /// </remarks>
    public static void DeriveConversationKey(PrivateKey privateKey, PublicKey publicKey, Span<byte> conversationKey32)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(publicKey);
        if (conversationKey32.Length != ConversationKeySize)
        {
            throw new ArgumentException($"Conversation key buffer must be {ConversationKeySize} bytes.", nameof(conversationKey32));
        }

        Span<byte> privBytes = stackalloc byte[PrivateKey.Size];
        Span<byte> pubBytes = stackalloc byte[PublicKey.Size];
        Span<byte> sharedX = stackalloc byte[32];

        try
        {
            privateKey.CopyTo(privBytes);
            publicKey.CopyTo(pubBytes);
            Secp256k1.EcdhSharedXCoord(privBytes, pubBytes, sharedX);

            HKDF.Extract(HashAlgorithmName.SHA256, sharedX, Nip44Salt, conversationKey32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privBytes);
            CryptographicOperations.ZeroMemory(sharedX);
        }
    }

    /// <summary>
    /// Computes the NIP-44 padded length for a given unpadded plaintext length.
    /// </summary>
    /// <remarks>
    /// This is a pure helper. It requires <paramref name="unpaddedLength"/> ≥ 1
    /// but does not enforce <see cref="MaxPlaintextLength"/>; the upper-bound
    /// check happens at encrypt/decrypt time.
    /// </remarks>
    public static int CalcPaddedLength(int unpaddedLength)
    {
        if (unpaddedLength < MinPlaintextLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(unpaddedLength),
                $"Unpadded length must be at least {MinPlaintextLength}.");
        }

        if (unpaddedLength <= 32)
        {
            return 32;
        }

        // next_power_of_2 of (unpaddedLength - 1)
        int log2 = BitOperations.Log2((uint)(unpaddedLength - 1));
        int nextPower = 1 << (log2 + 1);
        int chunk = nextPower <= 256 ? 32 : nextPower / 8;
        return chunk * (((unpaddedLength - 1) / chunk) + 1);
    }

    // ----- Internal helpers (separated for vector-based testing with fixed nonces).

    internal static string EncryptWithNonce(
        string plaintext,
        ReadOnlySpan<byte> conversationKey,
        ReadOnlySpan<byte> nonce)
    {
        if (conversationKey.Length != ConversationKeySize)
        {
            throw new ArgumentException($"Conversation key must be {ConversationKeySize} bytes.", nameof(conversationKey));
        }

        return EncryptInternal(plaintext, conversationKey, nonce);
    }

    internal static string DecryptWithConversationKey(string payload, ReadOnlySpan<byte> conversationKey)
    {
        if (conversationKey.Length != ConversationKeySize)
        {
            throw new ArgumentException($"Conversation key must be {ConversationKeySize} bytes.", nameof(conversationKey));
        }

        return DecryptInternal(payload, conversationKey);
    }

    private static string EncryptInternal(string plaintext, ReadOnlySpan<byte> conversationKey, ReadOnlySpan<byte> nonce)
    {
        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException($"Nonce must be {NonceSize} bytes.", nameof(nonce));
        }

        int unpaddedLen = SysEncoding.UTF8.GetByteCount(plaintext);
        if (unpaddedLen < MinPlaintextLength || unpaddedLen > MaxPlaintextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(plaintext),
                $"Plaintext UTF-8 length must be in [{MinPlaintextLength}, {MaxPlaintextLength}], was {unpaddedLen}.");
        }

        int paddedLen = CalcPaddedLength(unpaddedLen);
        int paddedTotal = 2 + paddedLen;     // 2-byte length prefix
        int ciphertextLen = paddedTotal;     // ChaCha20 preserves length

        // payload structure: version || nonce || ciphertext || mac
        int payloadLen = 1 + NonceSize + ciphertextLen + 32;

        byte[]? paddedRent = paddedTotal > 4096 ? ArrayPool<byte>.Shared.Rent(paddedTotal) : null;
        byte[]? cipherRent = ciphertextLen > 4096 ? ArrayPool<byte>.Shared.Rent(ciphertextLen) : null;
        byte[]? payloadRent = payloadLen > 4096 ? ArrayPool<byte>.Shared.Rent(payloadLen) : null;

        try
        {
            Span<byte> padded = paddedRent is null ? stackalloc byte[4096] : paddedRent;
            padded = padded[..paddedTotal];
            padded.Clear();

            // Big-endian 16-bit unpadded length.
            padded[0] = (byte)(unpaddedLen >> 8);
            padded[1] = (byte)unpaddedLen;
            SysEncoding.UTF8.GetBytes(plaintext, padded.Slice(2, unpaddedLen));

            // Derive per-message keys.
            Span<byte> messageKeys = stackalloc byte[MessageKeysSize];
            HKDF.Expand(HashAlgorithmName.SHA256, conversationKey, messageKeys, nonce);
            ReadOnlySpan<byte> chachaKey = messageKeys[..32];
            ReadOnlySpan<byte> chachaNonce = messageKeys.Slice(32, 12);
            ReadOnlySpan<byte> hmacKey = messageKeys.Slice(44, 32);

            Span<byte> ciphertext = cipherRent is null ? stackalloc byte[4096] : cipherRent;
            ciphertext = ciphertext[..ciphertextLen];
            ChaCha20.Apply(chachaKey, chachaNonce, initialCounter: 0, padded, ciphertext);

            // MAC over nonce || ciphertext.
            int macInputLen = NonceSize + ciphertextLen;
            byte[]? macInputRent = macInputLen > 4096 ? ArrayPool<byte>.Shared.Rent(macInputLen) : null;
            try
            {
                Span<byte> macInput = macInputRent is null ? stackalloc byte[4096] : macInputRent;
                macInput = macInput[..macInputLen];
                nonce.CopyTo(macInput);
                ciphertext.CopyTo(macInput[NonceSize..]);

                Span<byte> mac = stackalloc byte[32];
                HMACSHA256.HashData(hmacKey, macInput, mac);

                Span<byte> payload = payloadRent is null ? stackalloc byte[4096] : payloadRent;
                payload = payload[..payloadLen];
                payload[0] = Version;
                nonce.CopyTo(payload[1..]);
                ciphertext.CopyTo(payload.Slice(1 + NonceSize));
                mac.CopyTo(payload.Slice(1 + NonceSize + ciphertextLen));

                return Convert.ToBase64String(payload);
            }
            finally
            {
                if (macInputRent is not null)
                {
                    ArrayPool<byte>.Shared.Return(macInputRent);
                }
            }
        }
        finally
        {
            if (paddedRent is not null)
            {
                ArrayPool<byte>.Shared.Return(paddedRent);
            }

            if (cipherRent is not null)
            {
                ArrayPool<byte>.Shared.Return(cipherRent);
            }

            if (payloadRent is not null)
            {
                ArrayPool<byte>.Shared.Return(payloadRent);
            }
        }
    }

    private static string DecryptInternal(string payload, ReadOnlySpan<byte> conversationKey)
    {
        // Reject the "#" sentinel commonly used to mark "unsupported" payloads
        // (this also catches obviously-wrong inputs early).
        if (payload.Length == 0)
        {
            throw new FormatException("Payload is empty.");
        }

        if (payload[0] == '#')
        {
            throw new FormatException("Payload uses an unsupported version sentinel ('#').");
        }

        byte[] data;
        try
        {
            data = Convert.FromBase64String(payload);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Payload is not valid base64.", ex);
        }

        // Minimum: version (1) + nonce (32) + ciphertext (2 + 32 = 34, padded_len min 32) + mac (32) = 99
        const int MinPayloadLen = 1 + NonceSize + 2 + 32 + 32;
        if (data.Length < MinPayloadLen)
        {
            throw new FormatException("Payload is too short.");
        }

        if (data[0] != Version)
        {
            throw new CryptographicException($"Unsupported NIP-44 version: 0x{data[0]:x2}.");
        }

        int ciphertextLen = data.Length - 1 - NonceSize - 32;
        if (ciphertextLen < 2 + 32)
        {
            throw new FormatException("Ciphertext is too short.");
        }

        ReadOnlySpan<byte> dataSpan = data;
        ReadOnlySpan<byte> nonce = dataSpan.Slice(1, NonceSize);
        ReadOnlySpan<byte> ciphertext = dataSpan.Slice(1 + NonceSize, ciphertextLen);
        ReadOnlySpan<byte> receivedMac = dataSpan.Slice(1 + NonceSize + ciphertextLen, 32);

        Span<byte> messageKeys = stackalloc byte[MessageKeysSize];
        HKDF.Expand(HashAlgorithmName.SHA256, conversationKey, messageKeys, nonce);
        ReadOnlySpan<byte> chachaKey = messageKeys[..32];
        ReadOnlySpan<byte> chachaNonce = messageKeys.Slice(32, 12);
        ReadOnlySpan<byte> hmacKey = messageKeys.Slice(44, 32);

        // Verify MAC in constant time.
        int macInputLen = NonceSize + ciphertextLen;
        byte[]? macRent = macInputLen > 4096 ? ArrayPool<byte>.Shared.Rent(macInputLen) : null;
        Span<byte> macInput = macRent is null ? stackalloc byte[4096] : macRent;
        macInput = macInput[..macInputLen];

        try
        {
            nonce.CopyTo(macInput);
            ciphertext.CopyTo(macInput[NonceSize..]);

            Span<byte> expectedMac = stackalloc byte[32];
            HMACSHA256.HashData(hmacKey, macInput, expectedMac);

            if (!CryptographicOperations.FixedTimeEquals(expectedMac, receivedMac))
            {
                throw new CryptographicException("Invalid NIP-44 MAC.");
            }
        }
        finally
        {
            if (macRent is not null)
            {
                ArrayPool<byte>.Shared.Return(macRent);
            }
        }

        // Decrypt.
        byte[]? plaintextRent = ciphertextLen > 4096 ? ArrayPool<byte>.Shared.Rent(ciphertextLen) : null;
        Span<byte> padded = plaintextRent is null ? stackalloc byte[4096] : plaintextRent;
        padded = padded[..ciphertextLen];

        try
        {
            ChaCha20.Apply(chachaKey, chachaNonce, initialCounter: 0, ciphertext, padded);

            int unpaddedLen = (padded[0] << 8) | padded[1];
            if (unpaddedLen < MinPlaintextLength || unpaddedLen > MaxPlaintextLength)
            {
                throw new CryptographicException("Decrypted plaintext has invalid length.");
            }

            int paddedLen = ciphertextLen - 2;
            if (paddedLen != CalcPaddedLength(unpaddedLen))
            {
                throw new CryptographicException("Decrypted plaintext has mismatched padding.");
            }

            // Verify all trailing padding bytes are zero (defense in depth).
            for (int i = 2 + unpaddedLen; i < ciphertextLen; i++)
            {
                if (padded[i] != 0)
                {
                    throw new CryptographicException("Non-zero padding byte detected.");
                }
            }

            return SysEncoding.UTF8.GetString(padded.Slice(2, unpaddedLen));
        }
        finally
        {
            if (plaintextRent is not null)
            {
                ArrayPool<byte>.Shared.Return(plaintextRent);
            }
        }
    }
}
