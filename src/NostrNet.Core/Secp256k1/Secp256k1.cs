// SPDX-License-Identifier: MIT
//
// Internal secp256k1 wrapper.
//
// This file is the single seam where NostrNet meets a specific secp256k1
// implementation. The rest of the library reaches the curve via the methods
// defined here; swapping NBitcoin.Secp256k1 for a different backend (e.g.,
// libsecp256k1 P/Invoke) means rewriting this file alone.
//
// No public abstraction is exposed. Consumers see typed `PrivateKey` /
// `PublicKey` / `NostrEvent` APIs in Core; the curve library is never visible
// in NostrNet's public surface.

using NBitcoin.Secp256k1;

namespace NostrNet.Cryptography;

/// <summary>
/// Internal facade over the underlying secp256k1 implementation. All inputs
/// and outputs are raw bytes (span-based); no allocations on the hot path
/// beyond what the backend itself performs.
/// </summary>
internal static class Secp256k1
{
    /// <summary>Length of a private key in bytes.</summary>
    public const int PrivateKeySize = 32;

    /// <summary>Length of an x-only (BIP-340) public key in bytes.</summary>
    public const int XOnlyPublicKeySize = 32;

    /// <summary>Length of a BIP-340 Schnorr signature in bytes.</summary>
    public const int SchnorrSignatureSize = 64;

    /// <summary>Length of the raw ECDH shared x-coordinate in bytes.</summary>
    public const int EcdhSharedSecretSize = 32;

    /// <summary>
    /// Derives the x-only (BIP-340) public key from a 32-byte private key.
    /// </summary>
    /// <param name="privateKey">A 32-byte private key.</param>
    /// <param name="publicKey32">A 32-byte buffer to receive the x-only public key.</param>
    /// <exception cref="ArgumentException">The private key is not a valid secp256k1 scalar.</exception>
    public static void GetXOnlyPublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey32)
    {
        ValidateLengths(privateKey, publicKey32, PrivateKeySize, XOnlyPublicKeySize);

        if (!Context.Instance.TryCreateECPrivKey(privateKey, out var priv))
        {
            throw new ArgumentException("Invalid private key.", nameof(privateKey));
        }

        using (priv)
        {
            priv.CreateXOnlyPubKey().WriteToSpan(publicKey32);
        }
    }

    /// <summary>
    /// BIP-340 Schnorr signing.
    /// </summary>
    /// <param name="message32">The 32-byte message digest to sign.</param>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <param name="auxRand">
    /// Either empty (deterministic signing per BIP-340 §3.3.1 with k derived
    /// from priv||msg) or exactly 32 bytes of fresh randomness.
    /// </param>
    /// <param name="signature64">A 64-byte buffer to receive the signature (r || s).</param>
    /// <exception cref="ArgumentException">The private key or auxRand length is invalid.</exception>
    public static void SchnorrSign(
        ReadOnlySpan<byte> message32,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> auxRand,
        Span<byte> signature64)
    {
        if (message32.Length != 32)
        {
            throw new ArgumentException("Message must be 32 bytes.", nameof(message32));
        }

        ValidateLengths(privateKey, signature64, PrivateKeySize, SchnorrSignatureSize);

        if (auxRand.Length is not 0 and not 32)
        {
            throw new ArgumentException("auxRand must be empty or 32 bytes.", nameof(auxRand));
        }

        if (!Context.Instance.TryCreateECPrivKey(privateKey, out var priv))
        {
            throw new ArgumentException("Invalid private key.", nameof(privateKey));
        }

        using (priv)
        {
            SecpSchnorrSignature sig = auxRand.IsEmpty
                ? priv.SignBIP340(message32)
                : priv.SignBIP340(message32, auxRand.ToArray());
            sig.WriteToSpan(signature64);
        }
    }

    /// <summary>
    /// BIP-340 Schnorr verification.
    /// </summary>
    /// <param name="signature64">A 64-byte BIP-340 signature.</param>
    /// <param name="message32">The 32-byte message digest.</param>
    /// <param name="publicKey32">A 32-byte x-only public key.</param>
    /// <returns><c>true</c> if the signature is valid; <c>false</c> otherwise.</returns>
    public static bool SchnorrVerify(
        ReadOnlySpan<byte> signature64,
        ReadOnlySpan<byte> message32,
        ReadOnlySpan<byte> publicKey32)
    {
        if (signature64.Length != SchnorrSignatureSize
            || message32.Length != 32
            || publicKey32.Length != XOnlyPublicKeySize)
        {
            return false;
        }

        if (!SecpSchnorrSignature.TryCreate(signature64, out var sig))
        {
            return false;
        }

        if (!Context.Instance.TryCreateXOnlyPubKey(publicKey32, out var pub))
        {
            return false;
        }

        return pub.SigVerifyBIP340(sig, message32);
    }

    /// <summary>
    /// NIP-44 ECDH: returns the raw 32-byte x-coordinate of <c>privateKey * publicKey</c>.
    /// </summary>
    /// <remarks>
    /// This is NOT libsecp256k1's default hashed ECDH (which applies SHA-256
    /// to the serialized shared point). NIP-44 §3 specifies the unhashed
    /// x-coordinate as the input to its HKDF-based key derivation.
    ///
    /// <para>
    /// The 32-byte x-only public key is lifted to a full curve point with
    /// even-Y parity per BIP-340 convention. Y parity does not affect the
    /// resulting x-coordinate (a point and its negation share an x), so this
    /// choice is irrelevant to the output value.
    /// </para>
    /// </remarks>
    /// <param name="privateKey">A 32-byte private key.</param>
    /// <param name="publicKey32">A 32-byte x-only public key.</param>
    /// <param name="sharedX32">A 32-byte buffer to receive the shared x-coordinate.</param>
    /// <exception cref="ArgumentException">A key is invalid.</exception>
    public static void EcdhSharedXCoord(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> publicKey32,
        Span<byte> sharedX32)
    {
        ValidateLengths(privateKey, sharedX32, PrivateKeySize, EcdhSharedSecretSize);
        if (publicKey32.Length != XOnlyPublicKeySize)
        {
            throw new ArgumentException("Public key must be 32 bytes.", nameof(publicKey32));
        }

        if (!Context.Instance.TryCreateECPrivKey(privateKey, out var priv))
        {
            throw new ArgumentException("Invalid private key.", nameof(privateKey));
        }

        using (priv)
        {
            // Lift x-only public key to a full ECPubKey with the 0x02 prefix
            // (even Y); the x-coordinate of priv * pub is unaffected by parity.
            Span<byte> compressed = stackalloc byte[33];
            compressed[0] = 0x02;
            publicKey32.CopyTo(compressed[1..]);

            if (!Context.Instance.TryCreatePubKey(compressed, out var pub))
            {
                throw new ArgumentException("Invalid public key.", nameof(publicKey32));
            }

            ECPubKey shared = pub.GetSharedPubkey(priv);
            shared.ToXOnlyPubKey().WriteToSpan(sharedX32);
        }
    }

    private static void ValidateLengths(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        int expectedInput,
        int expectedOutput)
    {
        if (input.Length != expectedInput)
        {
            throw new ArgumentException($"Input must be {expectedInput} bytes.", nameof(input));
        }

        if (output.Length != expectedOutput)
        {
            throw new ArgumentException($"Output must be {expectedOutput} bytes.", nameof(output));
        }
    }
}
