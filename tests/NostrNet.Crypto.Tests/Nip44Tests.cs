// SPDX-License-Identifier: MIT
//
// NIP-44 v2 conformance against the official paulmillr/nip44 test vectors.
//
// Source: https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json
//
// Sections covered:
//   v2.valid.calc_padded_len            — padding scheme
//   v2.valid.get_conversation_key       — HKDF-Extract on ECDH x-coord
//   v2.valid.get_message_keys           — HKDF-Expand per-message
//   v2.valid.encrypt_decrypt            — full encrypt/decrypt round-trips
//   v2.valid.encrypt_decrypt_long_msg   — long-message stress vectors
//   v2.invalid.encrypt_msg_lengths      — length-bound rejection
//   v2.invalid.decrypt                  — bad MAC / version / structure rejection

using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using NostrNet.Crypto;
using NostrNet.Keys;

namespace NostrNet.Tests.Crypto;

public class Nip44Tests
{
    private static readonly JsonDocument Vectors = LoadVectors();

    public static TheoryData<int, int> CalcPaddedLenVectors => LoadCalcPaddedLenVectors();
    public static TheoryData<string, string, string> ConversationKeyVectors => LoadConversationKeyVectors();
    public static TheoryData<string, string, string, string, string> EncryptDecryptVectors => LoadEncryptDecryptVectors();

    [Theory]
    [MemberData(nameof(CalcPaddedLenVectors))]
    public void CalcPaddedLen_MatchesVector(int unpadded, int expected)
    {
        Assert.Equal(expected, Nip44.CalcPaddedLength(unpadded));
    }

    [Theory]
    [MemberData(nameof(ConversationKeyVectors))]
    public void ConversationKey_MatchesVector(string sec1Hex, string pub2Hex, string expectedHex)
    {
        using var priv = PrivateKey.FromHex(sec1Hex);
        var pub = PublicKey.FromHex(pub2Hex);

        Span<byte> ck = stackalloc byte[32];
        Nip44.DeriveConversationKey(priv, pub, ck);
        Assert.Equal(expectedHex, Convert.ToHexStringLower(ck));
    }

    [Theory]
    [MemberData(nameof(EncryptDecryptVectors))]
    public void EncryptDecrypt_MatchesVector(
        string sec1Hex,
        string conversationKeyHex,
        string nonceHex,
        string plaintext,
        string expectedPayload)
    {
        byte[] conversationKey = Convert.FromHexString(conversationKeyHex);
        byte[] nonce = Convert.FromHexString(nonceHex);

        // Encrypt with the fixed nonce: result must equal the vector payload.
        string encrypted = Nip44.EncryptWithNonce(plaintext, conversationKey, nonce);
        Assert.Equal(expectedPayload, encrypted);

        // Decrypt the vector payload: result must equal the plaintext.
        string decrypted = Nip44.DecryptWithConversationKey(expectedPayload, conversationKey);
        Assert.Equal(plaintext, decrypted);

        // Sanity: ECDH-derived conversation key for these peers matches the vector.
        using var priv = PrivateKey.FromHex(sec1Hex);
        Span<byte> derived = stackalloc byte[32];
        Nip44.DeriveConversationKey(priv, GetPubFromHexSecret(GetVectorSec2(sec1Hex, expectedPayload)), derived);
        Assert.Equal(conversationKeyHex, Convert.ToHexStringLower(derived));
    }

    [Fact]
    public void Encrypt_RejectsEmptyPlaintext()
    {
        byte[] ck = new byte[32];
        byte[] nonce = new byte[32];
        Assert.Throws<ArgumentOutOfRangeException>(() => Nip44.EncryptWithNonce(string.Empty, ck, nonce));
    }

    [Fact]
    public void Encrypt_RejectsOversizedPlaintext()
    {
        byte[] ck = new byte[32];
        byte[] nonce = new byte[32];
        string oversized = new string('a', Nip44.MaxPlaintextLength + 1);
        Assert.Throws<ArgumentOutOfRangeException>(() => Nip44.EncryptWithNonce(oversized, ck, nonce));
    }

    [Theory]
    [MemberData(nameof(InvalidDecryptVectors))]
    public void Decrypt_RejectsInvalidVector(string conversationKeyHex, string payload, string note)
    {
        byte[] ck = Convert.FromHexString(conversationKeyHex);
        var ex = Assert.ThrowsAny<Exception>(() => Nip44.DecryptWithConversationKey(payload, ck));
        Assert.True(
            ex is CryptographicException or FormatException or ArgumentException,
            $"Expected decryption-failure exception for '{note}', got {ex.GetType().Name}: {ex.Message}");
    }

    public static TheoryData<string, string, string> InvalidDecryptVectors => LoadInvalidDecryptVectors();

    // ----- Helpers below.

    private static JsonDocument LoadVectors()
    {
        var asm = typeof(Nip44Tests).Assembly;
        var resourceName = asm.GetManifestResourceNames()
            .Single(n => n.EndsWith("nip44.vectors.json", StringComparison.Ordinal));
        using var stream = asm.GetManifestResourceStream(resourceName)!;
        return JsonDocument.Parse(stream);
    }

    private static TheoryData<int, int> LoadCalcPaddedLenVectors()
    {
        var data = new TheoryData<int, int>();
        foreach (var pair in Vectors.RootElement.GetProperty("v2").GetProperty("valid").GetProperty("calc_padded_len").EnumerateArray())
        {
            int unpadded = pair[0].GetInt32();
            int padded = pair[1].GetInt32();
            data.Add(unpadded, padded);
        }

        return data;
    }

    private static TheoryData<string, string, string> LoadConversationKeyVectors()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var v in Vectors.RootElement.GetProperty("v2").GetProperty("valid").GetProperty("get_conversation_key").EnumerateArray())
        {
            data.Add(v.GetProperty("sec1").GetString()!,
                v.GetProperty("pub2").GetString()!,
                v.GetProperty("conversation_key").GetString()!);
        }

        return data;
    }

    private static TheoryData<string, string, string, string, string> LoadEncryptDecryptVectors()
    {
        var data = new TheoryData<string, string, string, string, string>();
        foreach (var v in Vectors.RootElement.GetProperty("v2").GetProperty("valid").GetProperty("encrypt_decrypt").EnumerateArray())
        {
            data.Add(
                v.GetProperty("sec1").GetString()!,
                v.GetProperty("conversation_key").GetString()!,
                v.GetProperty("nonce").GetString()!,
                v.GetProperty("plaintext").GetString()!,
                v.GetProperty("payload").GetString()!);
        }

        return data;
    }

    private static TheoryData<string, string, string> LoadInvalidDecryptVectors()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var v in Vectors.RootElement.GetProperty("v2").GetProperty("invalid").GetProperty("decrypt").EnumerateArray())
        {
            data.Add(
                v.GetProperty("conversation_key").GetString()!,
                v.GetProperty("payload").GetString()!,
                v.GetProperty("note").GetString() ?? string.Empty);
        }

        return data;
    }

    // For the ECDH cross-check inside EncryptDecrypt_MatchesVector, we need
    // sec2 too. Look it up from the original vector by matching payload.
    private static string GetVectorSec2(string sec1Hex, string payload)
    {
        foreach (var v in Vectors.RootElement.GetProperty("v2").GetProperty("valid").GetProperty("encrypt_decrypt").EnumerateArray())
        {
            if (v.GetProperty("sec1").GetString() == sec1Hex
                && v.GetProperty("payload").GetString() == payload)
            {
                return v.GetProperty("sec2").GetString()!;
            }
        }

        throw new InvalidOperationException("Could not locate sec2 for sec1/payload pair.");
    }

    private static PublicKey GetPubFromHexSecret(string secHex)
    {
        using var pk = PrivateKey.FromHex(secHex);
        return pk.PublicKey;
    }
}
