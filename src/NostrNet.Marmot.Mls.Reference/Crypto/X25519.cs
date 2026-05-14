// SPDX-License-Identifier: MIT
//
// X25519 (Curve25519 ECDH) wrapper around BouncyCastle. RFC 7748.

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;

namespace NostrNet.Marmot.Mls.Reference.Crypto;

/// <summary>X25519 keypair generation and Diffie-Hellman. RFC 7748.</summary>
internal static class X25519
{
    /// <summary>Length of an X25519 public key in bytes.</summary>
    public const int PublicKeyLength = CiphersuiteInfo.Npk;

    /// <summary>Length of an X25519 private key (scalar) in bytes.</summary>
    public const int PrivateKeyLength = CiphersuiteInfo.Nsk;

    /// <summary>Generates a fresh X25519 keypair.</summary>
    public static void GenerateKeyPair(out byte[] privateKey, out byte[] publicKey)
    {
        privateKey = new byte[PrivateKeyLength];
        RandomNumberGenerator.Fill(privateKey);
        publicKey = DerivePublicKey(privateKey);
    }

    /// <summary>Derives the X25519 public key from a 32-byte scalar.</summary>
    public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != PrivateKeyLength)
        {
            throw new ArgumentException(
                $"X25519 private key must be {PrivateKeyLength} bytes.", nameof(privateKey));
        }

        var priv = new X25519PrivateKeyParameters(privateKey.ToArray(), 0);
        var pub = priv.GeneratePublicKey();
        return pub.GetEncoded();
    }

    /// <summary>
    /// Computes the X25519 Diffie-Hellman shared secret. Equivalent to
    /// <c>X25519(privateKey, publicKey)</c> in RFC 7748 §6.1.
    /// </summary>
    /// <exception cref="CryptographicException">
    /// The shared secret is the all-zero output (small-subgroup point). Per
    /// RFC 7748 §6.1 and RFC 9180, the agreement MUST be rejected.
    /// </exception>
    public static byte[] Dh(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        if (privateKey.Length != PrivateKeyLength)
        {
            throw new ArgumentException(
                $"X25519 private key must be {PrivateKeyLength} bytes.", nameof(privateKey));
        }

        if (publicKey.Length != PublicKeyLength)
        {
            throw new ArgumentException(
                $"X25519 public key must be {PublicKeyLength} bytes.", nameof(publicKey));
        }

        var priv = new X25519PrivateKeyParameters(privateKey.ToArray(), 0);
        var pub = new X25519PublicKeyParameters(publicKey.ToArray(), 0);
        var agreement = new X25519Agreement();
        agreement.Init(priv);
        byte[] shared = new byte[agreement.AgreementSize];
        try
        {
            agreement.CalculateAgreement(pub, shared, 0);
        }
        catch (Exception ex) when (ex is not CryptographicException)
        {
            // BouncyCastle detects low-order points internally and throws
            // its own exception types; normalize to CryptographicException.
            CryptographicOperations.ZeroMemory(shared);
            throw new CryptographicException("X25519 agreement failed (likely a low-order public key).", ex);
        }

        // Belt-and-braces: reject all-zero output even if BC didn't catch it.
        byte acc = 0;
        for (int i = 0; i < shared.Length; i++)
        {
            acc |= shared[i];
        }

        if (acc == 0)
        {
            CryptographicOperations.ZeroMemory(shared);
            throw new CryptographicException("X25519 produced an all-zero shared secret (small-subgroup point).");
        }

        return shared;
    }
}
