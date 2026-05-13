// SPDX-License-Identifier: MIT
//
// Conformance tests for the internal Secp256k1 wrapper.
//
// Schnorr sign/verify is tested against the official BIP-340 test vectors
// (https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).
// ECDH is exercised via a round-trip property test (Alice computing
// priv_A · pub_B equals Bob computing priv_B · pub_A).

using System.Reflection;
using NostrNet.Cryptography;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Tests.Cryptography;

public class Secp256k1Tests
{
    public static TheoryData<Bip340Vector> Bip340Vectors => LoadBip340Vectors();

    // Nostr always signs a 32-byte event id (SHA-256 of canonical JSON). The
    // wrapper enforces 32-byte messages, so we skip the BIP-340 variable-
    // length-message vectors added in 2022-12. They're not in scope for Nostr.
    private static bool IsNostrApplicable(Bip340Vector v) => v.Message.Length == 32;

    [Theory]
    [MemberData(nameof(Bip340Vectors))]
    public void Schnorr_Verify_MatchesBip340Vector(Bip340Vector v)
    {
        if (!IsNostrApplicable(v))
        {
            return;
        }

        bool result = Secp256k1.SchnorrVerify(v.Signature, v.Message, v.PublicKey);
        Assert.Equal(v.ExpectedValid, result);
    }

    [Theory]
    [MemberData(nameof(Bip340Vectors))]
    public void Schnorr_Sign_MatchesBip340Vector(Bip340Vector v)
    {
        if (!IsNostrApplicable(v) || v.SecretKey is null)
        {
            return;
        }

        Span<byte> sig = stackalloc byte[64];
        Secp256k1.SchnorrSign(v.Message, v.SecretKey, v.AuxRand ?? ReadOnlySpan<byte>.Empty, sig);
        Assert.Equal(v.Signature, sig.ToArray());
    }

    [Theory]
    [MemberData(nameof(Bip340Vectors))]
    public void GetXOnlyPublicKey_MatchesBip340Vector(Bip340Vector v)
    {
        if (v.SecretKey is null)
        {
            return;
        }

        Span<byte> pub = stackalloc byte[32];
        Secp256k1.GetXOnlyPublicKey(v.SecretKey, pub);
        Assert.Equal(v.PublicKey, pub.ToArray());
    }

    [Fact]
    public void Ecdh_AliceAndBobAgree()
    {
        // Two known private keys; ECDH must produce the same shared x both
        // ways regardless of who multiplies.
        byte[] alicePriv = Convert.FromHexString("1fb9778c834be7e147f507362cb1c502a14f721570803ccda1eb1729fb8c2507");
        byte[] bobPriv = Convert.FromHexString("4b7fef1400aae7011f3121c1cbf63e72ae30ef250e0da169e0fd48427f3fb794");

        Span<byte> alicePub = stackalloc byte[32];
        Span<byte> bobPub = stackalloc byte[32];
        Secp256k1.GetXOnlyPublicKey(alicePriv, alicePub);
        Secp256k1.GetXOnlyPublicKey(bobPriv, bobPub);

        Span<byte> shared1 = stackalloc byte[32];
        Span<byte> shared2 = stackalloc byte[32];
        Secp256k1.EcdhSharedXCoord(alicePriv, bobPub, shared1);
        Secp256k1.EcdhSharedXCoord(bobPriv, alicePub, shared2);

        Assert.Equal(shared1.ToArray(), shared2.ToArray());
    }

    [Fact]
    public void SchnorrVerify_RejectsTamperedSignature()
    {
        // Use vector 1 (a known-valid signature). Flip a bit in the signature
        // and verify must return false.
        var v = ReadVectors().First(x => x.ExpectedValid && x.SecretKey is not null);

        byte[] tampered = (byte[])v.Signature.Clone();
        tampered[0] ^= 0x01;
        Assert.False(Secp256k1.SchnorrVerify(tampered, v.Message, v.PublicKey));
    }

    [Fact]
    public void SchnorrVerify_RejectsWrongMessage()
    {
        var v = ReadVectors().First(x => x.ExpectedValid && x.SecretKey is not null);

        byte[] wrongMsg = (byte[])v.Message.Clone();
        wrongMsg[0] ^= 0xff;
        Assert.False(Secp256k1.SchnorrVerify(v.Signature, wrongMsg, v.PublicKey));
    }

    public record Bip340Vector(
        int Index,
        byte[]? SecretKey,
        byte[] PublicKey,
        byte[]? AuxRand,
        byte[] Message,
        byte[] Signature,
        bool ExpectedValid,
        string Comment);

    private static TheoryData<Bip340Vector> LoadBip340Vectors()
    {
        var data = new TheoryData<Bip340Vector>();
        foreach (var v in ReadVectors())
        {
            data.Add(v);
        }
        return data;
    }

    private static IEnumerable<Bip340Vector> ReadVectors()
    {
        var assembly = typeof(Secp256k1Tests).Assembly;
        var resourceName = assembly.GetManifestResourceNames()
            .Single(n => n.EndsWith("bip340-test-vectors.csv", StringComparison.Ordinal));

        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException("BIP-340 vector resource not found.");
        using var reader = new StreamReader(stream, SysEncoding.UTF8);

        // skip header
        reader.ReadLine();

        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var cols = line.Split(',');
            yield return new Bip340Vector(
                Index: int.Parse(cols[0], System.Globalization.CultureInfo.InvariantCulture),
                SecretKey: cols[1].Length == 0 ? null : Convert.FromHexString(cols[1]),
                PublicKey: Convert.FromHexString(cols[2]),
                AuxRand: cols[3].Length == 0 ? null : Convert.FromHexString(cols[3]),
                Message: Convert.FromHexString(cols[4]),
                Signature: Convert.FromHexString(cols[5]),
                ExpectedValid: string.Equals(cols[6], "TRUE", StringComparison.OrdinalIgnoreCase),
                Comment: cols.Length > 7 ? cols[7] : string.Empty);
        }
    }
}
