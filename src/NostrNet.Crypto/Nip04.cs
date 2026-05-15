// SPDX-License-Identifier: MIT
//
// NIP-04 legacy encrypted direct messages — DECODE ONLY.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/04.md
//
// NIP-04 was officially deprecated in mid-2024 in favor of NIP-44 v2
// payloads (better key derivation, authenticated encryption) and NIP-17
// (gift-wrapped DMs). New clients SHOULD NOT produce NIP-04 events.
//
// Wire format (kind 4, content):
//   <base64(ciphertext)>?iv=<base64(iv)>
//
// Crypto:
//   key   = ECDH(my_priv, peer_pub) → 32-byte x-coordinate (no hashing).
//   iv    = 16 random bytes per message.
//   ct    = AES-256-CBC(key, iv, PKCS7-padded UTF-8 plaintext).
//
// This file deliberately omits an Encrypt method. The spec is obsolete
// and producing new NIP-04 messages is actively harmful (no MAC, key
// derivation is contributory in name only). If you need to send DMs,
// use Nip17.CreateDirectMessage.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using NostrNet.Cryptography;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Crypto;

/// <summary>
/// NIP-04 legacy direct message decryption. Decode-only by design — the
/// scheme is deprecated and there is no <c>Encrypt</c> counterpart.
/// </summary>
/// <remarks>
/// Provided for apps that need to read DMs sent by clients older than
/// mid-2024. For new messages, use <see cref="Nip17.CreateDirectMessage"/>.
/// </remarks>
public static class Nip04
{
    /// <summary>The Nostr event kind for legacy direct messages.</summary>
    public const int Kind = 4;

    private const int IvSize = 16;
    private const int SharedKeySize = 32;
    private const string IvSeparator = "?iv=";

    /// <summary>
    /// Decrypts a NIP-04 content payload directly. Use this overload when
    /// you already know which key is the peer; otherwise prefer
    /// <see cref="TryDecrypt(NostrEvent, PrivateKey, out string, out PublicKey)"/>
    /// which resolves the peer from the event.
    /// </summary>
    /// <param name="content">The raw event content (<c>"&lt;base64_ct&gt;?iv=&lt;base64_iv&gt;"</c>).</param>
    /// <param name="myKey">The local private key (recipient when reading inbound DMs, sender when reading your own outbound).</param>
    /// <param name="peerPublicKey">The other party's x-only public key.</param>
    /// <returns>The decrypted UTF-8 plaintext.</returns>
    /// <exception cref="FormatException">The content isn't a valid NIP-04 payload (missing <c>?iv=</c>, bad base64, wrong IV length).</exception>
    /// <exception cref="CryptographicException">AES decryption failed (wrong key, corrupted ciphertext, invalid padding).</exception>
    public static string Decrypt(string content, PrivateKey myKey, PublicKey peerPublicKey)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(myKey);
        ArgumentNullException.ThrowIfNull(peerPublicKey);

        int sep = content.IndexOf(IvSeparator, StringComparison.Ordinal);
        if (sep < 0)
        {
            throw new FormatException("NIP-04 content missing '?iv=' separator.");
        }

        byte[] ciphertext = Convert.FromBase64String(content[..sep]);
        byte[] iv = Convert.FromBase64String(content[(sep + IvSeparator.Length)..]);
        if (iv.Length != IvSize)
        {
            throw new FormatException($"NIP-04 IV must decode to {IvSize} bytes (got {iv.Length}).");
        }

        Span<byte> privBytes = stackalloc byte[PrivateKey.Size];
        Span<byte> pubBytes = stackalloc byte[PublicKey.Size];
        Span<byte> sharedKey = stackalloc byte[SharedKeySize];

        try
        {
            myKey.CopyTo(privBytes);
            peerPublicKey.CopyTo(pubBytes);
            Secp256k1.EcdhSharedXCoord(privBytes, pubBytes, sharedKey);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = sharedKey.ToArray();
            aes.IV = iv;

            byte[] plaintextBytes = aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
            return SysEncoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privBytes);
            CryptographicOperations.ZeroMemory(sharedKey);
        }
    }

    /// <summary>
    /// Tries to decrypt a kind-4 NIP-04 event. Identifies the peer pubkey
    /// automatically: if the event's <c>pubkey</c> matches <paramref name="myKey"/>'s
    /// public key the peer comes from the <c>p</c> tag (this is an outbound DM
    /// from you); otherwise the peer is the event's <c>pubkey</c> (inbound).
    /// </summary>
    /// <param name="ev">The event to decrypt. Must be kind 4.</param>
    /// <param name="myKey">The local private key.</param>
    /// <param name="plaintext">On success, the decrypted UTF-8 plaintext.</param>
    /// <param name="peer">On success, the other party's public key.</param>
    /// <returns>
    /// <c>true</c> if the event was decrypted; <c>false</c> if it isn't a
    /// kind-4 event, the peer pubkey can't be resolved, or decryption fails
    /// for any reason (malformed content, wrong key, etc.). Fail-closed by
    /// design — apps shouldn't have to catch exceptions for a routine
    /// "is this DM mine?" check.
    /// </returns>
    public static bool TryDecrypt(
        NostrEvent ev,
        PrivateKey myKey,
        [NotNullWhen(true)] out string? plaintext,
        [NotNullWhen(true)] out PublicKey? peer)
    {
        ArgumentNullException.ThrowIfNull(ev);
        ArgumentNullException.ThrowIfNull(myKey);

        plaintext = null;
        peer = null;

        if (ev.Kind != Kind)
        {
            return false;
        }

        PublicKey? resolved;
        if (ev.PubKey.Equals(myKey.PublicKey))
        {
            // Outbound — peer is the recipient in the p tag.
            string? pHex = ev.Tags.FirstValue("p");
            if (pHex is null)
            {
                return false;
            }

            try
            {
                resolved = PublicKey.FromHex(pHex);
            }
            catch
            {
                return false;
            }
        }
        else
        {
            // Inbound — peer is the event author.
            resolved = ev.PubKey;
        }

        try
        {
            plaintext = Decrypt(ev.Content, myKey, resolved);
            peer = resolved;
            return true;
        }
        catch
        {
            plaintext = null;
            peer = null;
            return false;
        }
    }
}
