// SPDX-License-Identifier: MIT
//
// ChaCha20 conformance against the RFC 8439 §2.4.2 test vector.

using NostrNet.Cryptography;

namespace NostrNet.Tests.Crypto;

public class ChaCha20Tests
{
    [Fact]
    public void Rfc8439_Section_2_4_2_TestVector()
    {
        // RFC 8439 §2.4.2 — sample chacha20 encryption.
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000000000000004a00000000");
        uint counter = 1;
        const string PlaintextText =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(PlaintextText);

        // Expected ciphertext (from the RFC).
        byte[] expectedCiphertext = Convert.FromHexString(
            "6e2e359a2568f98041ba0728dd0d6981" +
            "e97e7aec1d4360c20a27afccfd9fae0b" +
            "f91b65c5524733ab8f593dabcd62b357" +
            "1639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e" +
            "52bc514d16ccf806818ce91ab7793736" +
            "5af90bbf74a35be6b40b8eedf2785e42" +
            "874d");

        byte[] actual = new byte[plaintext.Length];
        ChaCha20.Apply(key, nonce, counter, plaintext, actual);
        Assert.Equal(expectedCiphertext, actual);

        // Round-trip: re-applying decrypts.
        byte[] roundTrip = new byte[plaintext.Length];
        ChaCha20.Apply(key, nonce, counter, actual, roundTrip);
        Assert.Equal(plaintext, roundTrip);
    }

    [Fact]
    public void ZeroKeyZeroNonceCounter0_MatchesRfc8439_Section_2_3_2()
    {
        // RFC 8439 §2.3.2 — test vector for the ChaCha20 block function with
        // zero key, zero nonce, counter 0.
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[64]; // zeros — XOR with keystream yields keystream
        byte[] expectedKeystream = Convert.FromHexString(
            "76b8e0ada0f13d90405d6ae55386bd28" +
            "bdd219b8a08ded1aa836efcc8b770dc7" +
            "da41597c5157488d7724e03fb8d84a37" +
            "6a43b8f41518a11cc387b669b2ee6586");

        byte[] actual = new byte[64];
        ChaCha20.Apply(key, nonce, initialCounter: 0, plaintext, actual);
        Assert.Equal(expectedKeystream, actual);
    }
}
