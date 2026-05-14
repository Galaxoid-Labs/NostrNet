// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using NostrNet.Marmot.Mls.Reference.Crypto;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference.Tests.Crypto;

public class HpkeTests
{
    [Fact]
    public void Ed25519_SignAndVerify_RoundTrip()
    {
        Ed25519.GenerateKeyPair(out byte[] sk, out byte[] pk);
        Assert.Equal(Ed25519.PrivateKeyLength, sk.Length);
        Assert.Equal(Ed25519.PublicKeyLength, pk.Length);

        byte[] msg = SysEncoding.UTF8.GetBytes("hello mls");
        byte[] sig = Ed25519.Sign(sk, msg);
        Assert.Equal(Ed25519.SignatureLength, sig.Length);

        Assert.True(Ed25519.Verify(pk, msg, sig));

        // Flip a bit anywhere — signature must fail.
        sig[0] ^= 0x01;
        Assert.False(Ed25519.Verify(pk, msg, sig));
    }

    [Fact]
    public void X25519_DhAgreement_BothSidesMatch()
    {
        X25519.GenerateKeyPair(out byte[] askSk, out byte[] askPk);
        X25519.GenerateKeyPair(out byte[] bobSk, out byte[] bobPk);

        byte[] aliceSide = X25519.Dh(askSk, bobPk);
        byte[] bobSide = X25519.Dh(bobSk, askPk);

        Assert.Equal(aliceSide, bobSide);
        Assert.Equal(32, aliceSide.Length);
    }

    [Fact]
    public void X25519_RejectsAllZeroSharedSecret()
    {
        // The all-zero scalar is one of the small-subgroup points that
        // forces the output to all-zero. RFC 7748 requires rejection.
        byte[] sk = new byte[32];
        RandomNumberGenerator.Fill(sk);
        byte[] zeroPub = new byte[32]; // all-zero public key

        Assert.Throws<CryptographicException>(() => X25519.Dh(sk, zeroPub));
    }

    [Fact]
    public void Hpke_Seal_Open_RoundTrip()
    {
        X25519.GenerateKeyPair(out byte[] recipSk, out byte[] recipPk);

        byte[] info = SysEncoding.ASCII.GetBytes("test info");
        byte[] aad = SysEncoding.ASCII.GetBytes("test aad");
        byte[] pt = SysEncoding.UTF8.GetBytes("hello hpke world");

        var (enc, ct) = Hpke.Seal(recipPk, info, aad, pt);

        Assert.Equal(32, enc.Length);           // X25519 enc length
        Assert.Equal(pt.Length + 16, ct.Length); // plaintext + GCM tag

        byte[] roundtrip = Hpke.Open(enc, recipSk, info, aad, ct);
        Assert.Equal(pt, roundtrip);
    }

    [Fact]
    public void Hpke_Open_FailsWithWrongAad()
    {
        X25519.GenerateKeyPair(out byte[] recipSk, out byte[] recipPk);
        var (enc, ct) = Hpke.Seal(
            recipPk,
            info: SysEncoding.ASCII.GetBytes("info"),
            aad: SysEncoding.ASCII.GetBytes("correct aad"),
            plaintext: SysEncoding.UTF8.GetBytes("secret"));

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            Hpke.Open(
                enc,
                recipSk,
                info: SysEncoding.ASCII.GetBytes("info"),
                aad: SysEncoding.ASCII.GetBytes("wrong aad"),
                ciphertext: ct));
    }

    [Fact]
    public void Hpke_Open_FailsWithWrongInfo()
    {
        X25519.GenerateKeyPair(out byte[] recipSk, out byte[] recipPk);
        var (enc, ct) = Hpke.Seal(
            recipPk,
            info: SysEncoding.ASCII.GetBytes("info-a"),
            aad: ReadOnlySpan<byte>.Empty,
            plaintext: SysEncoding.UTF8.GetBytes("secret"));

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            Hpke.Open(
                enc,
                recipSk,
                info: SysEncoding.ASCII.GetBytes("info-b"),
                aad: ReadOnlySpan<byte>.Empty,
                ciphertext: ct));
    }

    [Fact]
    public void Hpke_Open_FailsWithWrongRecipient()
    {
        X25519.GenerateKeyPair(out byte[] recipSk, out byte[] recipPk);
        X25519.GenerateKeyPair(out byte[] strangerSk, out _);

        var (enc, ct) = Hpke.Seal(
            recipPk,
            info: ReadOnlySpan<byte>.Empty,
            aad: ReadOnlySpan<byte>.Empty,
            plaintext: SysEncoding.UTF8.GetBytes("for recipient only"));

        Assert.ThrowsAny<CryptographicException>(() =>
            Hpke.Open(enc, strangerSk, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ct));
    }

    [Fact]
    public void Hkdf_LabeledExtractExpand_DerivesDeterministicSecrets()
    {
        // The MLS exporter secret should be deterministic given the same
        // inputs — a smoke test for our labeled-HKDF wiring.
        byte[] ikm = SysEncoding.UTF8.GetBytes("input keying material");
        byte[] salt = SysEncoding.UTF8.GetBytes("salt");

        byte[] s1 = Hkdf.MlsLabeledExtract(salt, SysEncoding.ASCII.GetBytes("test"), ikm);
        byte[] s2 = Hkdf.MlsLabeledExtract(salt, SysEncoding.ASCII.GetBytes("test"), ikm);
        Assert.Equal(s1, s2);

        byte[] sDifferent = Hkdf.MlsLabeledExtract(salt, SysEncoding.ASCII.GetBytes("other"), ikm);
        Assert.NotEqual(s1, sDifferent);

        // DeriveSecret = LabeledExpand(secret, label, "", Nh)
        byte[] d1 = Hkdf.DeriveSecret(s1, SysEncoding.ASCII.GetBytes("epoch"));
        byte[] d2 = Hkdf.DeriveSecret(s1, SysEncoding.ASCII.GetBytes("epoch"));
        Assert.Equal(d1, d2);
        Assert.Equal(32, d1.Length);

        byte[] dOther = Hkdf.DeriveSecret(s1, SysEncoding.ASCII.GetBytes("welcome"));
        Assert.NotEqual(d1, dOther);
    }
}
