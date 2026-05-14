// SPDX-License-Identifier: MIT
//
// HPKE base-mode for the single MLS ciphersuite this provider supports.
//
//   KEM   = DHKEM(X25519, HKDF-SHA256)   kem_id  = 0x0020
//   KDF   = HKDF-SHA256                  kdf_id  = 0x0001
//   AEAD  = AES-128-GCM                  aead_id = 0x0001
//
// References:
//   RFC 9180 (HPKE):   https://datatracker.ietf.org/doc/html/rfc9180
//   RFC 9420 §5.1.2:   HPKE usage in MLS
//
// Scope:
//   - Mode: Base (no PSK, no auth).
//   - Single-shot encrypt / decrypt — we do not expose a streaming
//     context. MLS Welcome encryption is single-shot per recipient.
//   - All input/output is byte arrays. Internal key material is wiped
//     in `finally` blocks where practical.

using System.Buffers.Binary;
using System.Security.Cryptography;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference.Crypto;

/// <summary>HPKE (RFC 9180) base-mode primitives for ciphersuite 0x0001.</summary>
internal static class Hpke
{
    // ─────────────────────────────────────────────────────────────
    // Constants.
    // ─────────────────────────────────────────────────────────────

    /// <summary>HPKE "mode_base" identifier per RFC 9180 §5.1.</summary>
    public const byte ModeBase = 0x00;

    private static ReadOnlySpan<byte> KemSuiteId =>
        // "KEM" || I2OSP(0x0020, 2)
        new byte[] { 0x4B, 0x45, 0x4D, 0x00, 0x20 };

    private static ReadOnlySpan<byte> HpkeSuiteId =>
        // "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
        // = "HPKE" || 0x0020 || 0x0001 || 0x0001
        new byte[] { 0x48, 0x50, 0x4B, 0x45, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01 };

    // ─────────────────────────────────────────────────────────────
    // DHKEM(X25519, HKDF-SHA256).
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// DHKEM Encap. Generates an ephemeral keypair, performs DH against
    /// <paramref name="recipientPublicKey"/>, and derives the HPKE
    /// shared secret. Returns the shared secret and the encapsulated
    /// ephemeral public key (<c>enc</c>).
    /// </summary>
    public static (byte[] SharedSecret, byte[] Enc) Encap(ReadOnlySpan<byte> recipientPublicKey)
    {
        X25519.GenerateKeyPair(out byte[] ephSk, out byte[] ephPk);
        try
        {
            byte[] dh = X25519.Dh(ephSk, recipientPublicKey);
            try
            {
                byte[] kemContext = Concat(ephPk, recipientPublicKey);
                byte[] sharedSecret = ExtractAndExpand(dh, kemContext);
                return (sharedSecret, ephPk);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dh);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ephSk);
        }
    }

    /// <summary>
    /// DHKEM Decap. Computes the same shared secret as
    /// <see cref="Encap"/>, given the recipient's private key and the
    /// sender's encapsulated ephemeral public key.
    /// </summary>
    public static byte[] Decap(ReadOnlySpan<byte> enc, ReadOnlySpan<byte> recipientPrivateKey)
    {
        byte[] recipientPublicKey = X25519.DerivePublicKey(recipientPrivateKey);
        byte[] dh = X25519.Dh(recipientPrivateKey, enc);
        try
        {
            byte[] kemContext = Concat(enc, recipientPublicKey);
            return ExtractAndExpand(dh, kemContext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dh);
        }
    }

    private static byte[] ExtractAndExpand(ReadOnlySpan<byte> dh, ReadOnlySpan<byte> kemContext)
    {
        byte[] eaePrk = Hkdf.HpkeLabeledExtract(
            salt: ReadOnlySpan<byte>.Empty,
            suiteId: KemSuiteId,
            label: SysEncoding.ASCII.GetBytes("eae_prk"),
            ikm: dh);
        try
        {
            return Hkdf.HpkeLabeledExpand(
                prk: eaePrk,
                suiteId: KemSuiteId,
                label: SysEncoding.ASCII.GetBytes("shared_secret"),
                info: kemContext,
                length: CiphersuiteInfo.Nsecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(eaePrk);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // HPKE base-mode key schedule.
    // ─────────────────────────────────────────────────────────────

    private static (byte[] Key, byte[] BaseNonce, byte[] ExporterSecret) KeyScheduleBase(
        ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> info)
    {
        // For mode_base, default_psk = default_psk_id = "".
        byte[] pskIdHash = Hkdf.HpkeLabeledExtract(
            salt: ReadOnlySpan<byte>.Empty,
            suiteId: HpkeSuiteId,
            label: SysEncoding.ASCII.GetBytes("psk_id_hash"),
            ikm: ReadOnlySpan<byte>.Empty);

        byte[] infoHash = Hkdf.HpkeLabeledExtract(
            salt: ReadOnlySpan<byte>.Empty,
            suiteId: HpkeSuiteId,
            label: SysEncoding.ASCII.GetBytes("info_hash"),
            ikm: info);

        byte[] keyScheduleContext = new byte[1 + pskIdHash.Length + infoHash.Length];
        keyScheduleContext[0] = ModeBase;
        pskIdHash.CopyTo(keyScheduleContext, 1);
        infoHash.CopyTo(keyScheduleContext, 1 + pskIdHash.Length);

        byte[] secret = Hkdf.HpkeLabeledExtract(
            salt: sharedSecret,
            suiteId: HpkeSuiteId,
            label: SysEncoding.ASCII.GetBytes("secret"),
            ikm: ReadOnlySpan<byte>.Empty); // default_psk

        try
        {
            byte[] key = Hkdf.HpkeLabeledExpand(
                prk: secret,
                suiteId: HpkeSuiteId,
                label: SysEncoding.ASCII.GetBytes("key"),
                info: keyScheduleContext,
                length: CiphersuiteInfo.Nk);

            byte[] baseNonce = Hkdf.HpkeLabeledExpand(
                prk: secret,
                suiteId: HpkeSuiteId,
                label: SysEncoding.ASCII.GetBytes("base_nonce"),
                info: keyScheduleContext,
                length: CiphersuiteInfo.Nn);

            byte[] exporterSecret = Hkdf.HpkeLabeledExpand(
                prk: secret,
                suiteId: HpkeSuiteId,
                label: SysEncoding.ASCII.GetBytes("exp"),
                info: keyScheduleContext,
                length: CiphersuiteInfo.Nh);

            return (key, baseNonce, exporterSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Single-shot Seal / Open.
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// HPKE single-shot encrypt to a public key. Returns the encapsulated
    /// ephemeral public key (<c>enc</c>) and the AEAD ciphertext (which
    /// includes the GCM tag appended).
    /// </summary>
    /// <param name="recipientPublicKey">Recipient's X25519 public key.</param>
    /// <param name="info">HPKE setup info string (may be empty).</param>
    /// <param name="aad">Additional authenticated data (may be empty).</param>
    /// <param name="plaintext">Plaintext to encrypt.</param>
    public static (byte[] Enc, byte[] Ciphertext) Seal(
        ReadOnlySpan<byte> recipientPublicKey,
        ReadOnlySpan<byte> info,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> plaintext)
    {
        var (sharedSecret, enc) = Encap(recipientPublicKey);
        try
        {
            var (key, baseNonce, _) = KeyScheduleBase(sharedSecret, info);
            try
            {
                // For sequence number 0, nonce = base_nonce ^ 0 = base_nonce.
                byte[] nonce = (byte[])baseNonce.Clone();
                XorSeq(nonce, 0);

                byte[] ciphertext = new byte[plaintext.Length + CiphersuiteInfo.Nt];
                using var aes = new AesGcm(key, CiphersuiteInfo.Nt);
                aes.Encrypt(
                    nonce,
                    plaintext,
                    ciphertext.AsSpan(0, plaintext.Length),
                    ciphertext.AsSpan(plaintext.Length, CiphersuiteInfo.Nt),
                    aad);

                CryptographicOperations.ZeroMemory(nonce);
                return (enc, ciphertext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(baseNonce);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>
    /// HPKE single-shot decrypt. Mirrors <see cref="Seal"/>.
    /// </summary>
    /// <exception cref="CryptographicException">Decryption / tag-verification failed.</exception>
    public static byte[] Open(
        ReadOnlySpan<byte> enc,
        ReadOnlySpan<byte> recipientPrivateKey,
        ReadOnlySpan<byte> info,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < CiphersuiteInfo.Nt)
        {
            throw new CryptographicException("HPKE ciphertext is shorter than the AEAD tag length.");
        }

        byte[] sharedSecret = Decap(enc, recipientPrivateKey);
        try
        {
            var (key, baseNonce, _) = KeyScheduleBase(sharedSecret, info);
            try
            {
                byte[] nonce = (byte[])baseNonce.Clone();
                XorSeq(nonce, 0);

                int ptLen = ciphertext.Length - CiphersuiteInfo.Nt;
                byte[] plaintext = new byte[ptLen];
                using var aes = new AesGcm(key, CiphersuiteInfo.Nt);
                aes.Decrypt(
                    nonce,
                    ciphertext[..ptLen],
                    ciphertext[ptLen..],
                    plaintext,
                    aad);

                CryptographicOperations.ZeroMemory(nonce);
                return plaintext;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(baseNonce);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    // XOR the 8-byte big-endian sequence number into the last 8 bytes of nonce.
    private static void XorSeq(Span<byte> nonce, ulong seq)
    {
        Span<byte> seqBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(seqBytes, seq);
        int offset = nonce.Length - 8;
        for (int i = 0; i < 8; i++)
        {
            nonce[offset + i] ^= seqBytes[i];
        }
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        byte[] result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
