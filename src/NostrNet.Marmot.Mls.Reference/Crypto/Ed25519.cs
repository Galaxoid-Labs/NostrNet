// SPDX-License-Identifier: MIT
//
// Ed25519 signing wrapper around BouncyCastle. RFC 8032 / RFC 9420 use
// "pure Ed25519" (PureEdDSA, no context).

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace NostrNet.Marmot.Mls.Reference.Crypto;

/// <summary>Ed25519 sign / verify primitives. RFC 8032 PureEdDSA, 32-byte seeds.</summary>
public static class Ed25519
{
    /// <summary>Length of the public key in bytes.</summary>
    public const int PublicKeyLength = CiphersuiteInfo.SignaturePublicKeyLength;

    /// <summary>Length of the seed / private-key scalar in bytes.</summary>
    public const int PrivateKeyLength = CiphersuiteInfo.SignaturePrivateKeyLength;

    /// <summary>Length of a signature in bytes.</summary>
    public const int SignatureLength = CiphersuiteInfo.SignatureLength;

    /// <summary>
    /// Generates a new Ed25519 keypair. The returned <paramref name="privateKey"/>
    /// is the 32-byte seed; the public key is derived from it.
    /// </summary>
    public static void GenerateKeyPair(out byte[] privateKey, out byte[] publicKey)
    {
        privateKey = new byte[PrivateKeyLength];
        RandomNumberGenerator.Fill(privateKey);
        publicKey = DerivePublicKey(privateKey);
    }

    /// <summary>Derives the Ed25519 public key from a 32-byte seed.</summary>
    public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != PrivateKeyLength)
        {
            throw new ArgumentException(
                $"Ed25519 private key must be {PrivateKeyLength} bytes.", nameof(privateKey));
        }

        var priv = new Ed25519PrivateKeyParameters(privateKey.ToArray(), 0);
        var pub = priv.GeneratePublicKey();
        return pub.GetEncoded();
    }

    /// <summary>Signs <paramref name="message"/> with the given Ed25519 seed.</summary>
    public static byte[] Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> message)
    {
        if (privateKey.Length != PrivateKeyLength)
        {
            throw new ArgumentException(
                $"Ed25519 private key must be {PrivateKeyLength} bytes.", nameof(privateKey));
        }

        var priv = new Ed25519PrivateKeyParameters(privateKey.ToArray(), 0);
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, priv);
        byte[] msg = message.ToArray();
        signer.BlockUpdate(msg, 0, msg.Length);
        return signer.GenerateSignature();
    }

    /// <summary>Verifies an Ed25519 signature. Returns <c>true</c> iff the signature is valid.</summary>
    public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != PublicKeyLength)
        {
            return false;
        }

        if (signature.Length != SignatureLength)
        {
            return false;
        }

        var pub = new Ed25519PublicKeyParameters(publicKey.ToArray(), 0);
        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, pub);
        byte[] msg = message.ToArray();
        verifier.BlockUpdate(msg, 0, msg.Length);
        return verifier.VerifySignature(signature.ToArray());
    }
}
