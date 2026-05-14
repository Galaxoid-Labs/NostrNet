// SPDX-License-Identifier: MIT
//
// MLS ciphersuite descriptor.
//
// RFC 9420 §17.1 defines several ciphersuites; this reference provider
// supports exactly one:
//
//   MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519  (0x0001)
//
//   HPKE KEM     = DHKEM(X25519, HKDF-SHA256)        kem_id   = 0x0020
//   HPKE KDF     = HKDF-SHA256                        kdf_id   = 0x0001
//   HPKE AEAD    = AES-128-GCM                        aead_id  = 0x0001
//   Hash         = SHA-256
//   Signature    = Ed25519

using System.Diagnostics.CodeAnalysis;

namespace NostrNet.Marmot.Mls.Reference.Crypto;

/// <summary>
/// Identifies an MLS ciphersuite per RFC 9420 §17.1. Only one suite is
/// supported by the reference provider; the enum is open-ended so future
/// providers can share the same id space.
/// </summary>
internal enum Ciphersuite : ushort
{
    /// <summary>MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.</summary>
    X25519_Aes128Gcm_Sha256_Ed25519 = 0x0001,
}

/// <summary>
/// Static descriptor of the one ciphersuite implemented by the reference
/// provider. Other suites throw <see cref="NotSupportedException"/>.
/// </summary>
internal static class CiphersuiteInfo
{
    /// <summary>The only ciphersuite the reference provider implements.</summary>
    public const Ciphersuite Supported = Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519;

    /// <summary>HPKE KEM id (DHKEM(X25519, HKDF-SHA256)).</summary>
    public const ushort KemId = 0x0020;

    /// <summary>HPKE KDF id (HKDF-SHA256).</summary>
    public const ushort KdfId = 0x0001;

    /// <summary>HPKE AEAD id (AES-128-GCM).</summary>
    public const ushort AeadId = 0x0001;

    /// <summary>Length of the KDF hash output in bytes (SHA-256 = 32).</summary>
    public const int Nh = 32;

    /// <summary>Length of an HPKE shared secret in bytes (= Nh for HKDF-SHA256).</summary>
    public const int Nsecret = 32;

    /// <summary>Length of an AEAD key in bytes (AES-128-GCM = 16).</summary>
    public const int Nk = 16;

    /// <summary>Length of an AEAD nonce in bytes (AES-128-GCM = 12).</summary>
    public const int Nn = 12;

    /// <summary>Length of an AES-128-GCM authentication tag in bytes.</summary>
    public const int Nt = 16;

    /// <summary>Length of an X25519 public key.</summary>
    public const int Npk = 32;

    /// <summary>Length of an X25519 private key (scalar).</summary>
    public const int Nsk = 32;

    /// <summary>Length of an X25519 KEM "enc" (ephemeral public key) in bytes.</summary>
    public const int Nenc = 32;

    /// <summary>Length of an Ed25519 signature in bytes.</summary>
    public const int SignatureLength = 64;

    /// <summary>Length of an Ed25519 public key in bytes.</summary>
    public const int SignaturePublicKeyLength = 32;

    /// <summary>Length of an Ed25519 seed/private key in bytes.</summary>
    public const int SignaturePrivateKeyLength = 32;

    /// <summary>
    /// Throws <see cref="NotSupportedException"/> if the given ciphersuite
    /// is not <see cref="Supported"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1062", Justification = "ushort can't be null.")]
    public static void EnsureSupported(Ciphersuite suite)
    {
        if (suite != Supported)
        {
            throw new NotSupportedException(
                $"NostrNet.Marmot.Mls.Reference only supports ciphersuite 0x{(ushort)Supported:X4} "
                + $"({nameof(Ciphersuite.X25519_Aes128Gcm_Sha256_Ed25519)}); got 0x{(ushort)suite:X4}.");
        }
    }
}
