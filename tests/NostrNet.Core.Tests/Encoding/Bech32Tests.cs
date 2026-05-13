// SPDX-License-Identifier: MIT
//
// Conformance tests for the bech32 encoder/decoder.
//
// Test vectors are drawn from two sources:
//   1. BIP-173 — the appendix of the spec provides valid and invalid strings
//      that exercise the bech32 engine (checksum, mixed case, charset, HRP).
//   2. The Galaxoid Labs Swift Nostr library — provides real Nostr identifier
//      vectors (npub/nsec/note + raw 32-byte payload) that have been verified
//      interoperably. These cross-check the 8↔5 bit conversion path.

using NostrNet.Encoding;

namespace NostrNet.Tests.Encoding;

public class Bech32Tests
{
    // ----- BIP-173 valid strings (round-trip).
    // Source: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki ("Test vectors").
    public static TheoryData<string> Bip173ValidStrings => new()
    {
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
    };

    [Theory]
    [MemberData(nameof(Bip173ValidStrings))]
    public void DecodeSymbols_AcceptsValidBip173Strings(string input)
    {
        // BIP-173 vectors test the bech32 engine (HRP + 5-bit data + checksum).
        // They are not guaranteed to round-trip through 8-bit data conversion,
        // so we validate them at the symbol level.
        Span<char> hrp = stackalloc char[Bech32.MaxHrpLength];
        Span<byte> symbols = stackalloc byte[256];
        bool ok = Bech32.TryDecodeSymbols(input, hrp, symbols, out int hrpLen, out int symbolsLen);
        Assert.True(ok, $"Should accept BIP-173 valid vector: {input}");
        Assert.True(hrpLen >= 1);
        Assert.True(symbolsLen >= 0);
    }

    // ----- BIP-173 invalid strings (must all reject).
    // Source: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki ("Test vectors").
    public static TheoryData<string, string> Bip173InvalidStrings => new()
    {
        { "\x20" + "1nwldj5", "HRP character is space (0x20)" },
        { "\x7f" + "1axkwrx", "HRP character is DEL (0x7F)" },
        { "\x80" + "1eym55h", "HRP character > 0x7F" },
        { "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", "overall max length exceeded" },
        { "pzry9x0s0muk", "no separator character" },
        { "1pzry9x0s0muk", "empty HRP" },
        { "x1b4n0q5v", "invalid data character" },
        { "li1dgmt3", "too short checksum" },
        { "de1lg7wtÿ", "invalid character in checksum (0xFF)" },
        { "A1G7SGD8", "checksum computed with uppercase form of HRP" },
        { "10a06t8", "empty HRP" },
        { "1qzzfhee", "empty HRP" },
    };

    [Theory]
    [MemberData(nameof(Bip173InvalidStrings))]
    public void DecodeSymbols_RejectsInvalidBip173Strings(string input, string reason)
    {
        Span<char> hrp = stackalloc char[Bech32.MaxHrpLength];
        Span<byte> symbols = stackalloc byte[256];
        bool ok = Bech32.TryDecodeSymbols(input, hrp, symbols, out _, out _);
        Assert.False(ok, $"Should reject BIP-173 invalid vector ({reason}): {input}");
    }

    [Theory]
    [InlineData("A1G7SGD8aA")]   // mixed case after the separator
    [InlineData("a1g7sGd8")]     // mixed case in data section
    [InlineData("Abc1FgHiJk")]   // mixed case in HRP
    public void DecodeSymbols_RejectsMixedCase(string input)
    {
        Span<char> hrp = stackalloc char[Bech32.MaxHrpLength];
        Span<byte> symbols = stackalloc byte[256];
        bool ok = Bech32.TryDecodeSymbols(input, hrp, symbols, out _, out _);
        Assert.False(ok);
    }

    // ----- Nostr identifier vectors from Galaxoid Labs Swift Nostr tests.
    // These are 32-byte payloads behind known HRPs; they validate the 8↔5
    // bit regrouping against an interoperably-verified implementation.
    public static TheoryData<string, string, string> NostrEntityVectors => new()
    {
        // npub
        {
            "npub",
            "4b7fef1400aae7011f3121c1cbf63e72ae30ef250e0da169e0fd48427f3fb794",
            "npub1fdl779qq4tnsz8e3y8quha37w2hrpme9pcx6z60ql4yyylelk72qplz85a"
        },
        // nsec
        {
            "nsec",
            "1fb9778c834be7e147f507362cb1c502a14f721570803ccda1eb1729fb8c2507",
            "nsec1r7uh0ryrf0n7z3l4qumzevw9q2s57us4wzqrendpavtjn7uvy5rs9szssa"
        },
        // note
        {
            "note",
            "f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb",
            "note17cp3vms0md4qx20rnxpgpm9dpe2d386l30pq68e9nfqeswk2nhasgvrk8y"
        },
    };

    [Theory]
    [MemberData(nameof(NostrEntityVectors))]
    public void Encode_ProducesExpectedNostrIdentifier(string hrp, string hexPayload, string expected)
    {
        byte[] payload = HexToBytes(hexPayload);
        string encoded = Bech32.Encode(hrp, payload);
        Assert.Equal(expected, encoded);
    }

    [Theory]
    [MemberData(nameof(NostrEntityVectors))]
    public void Decode_RecoversPayloadFromNostrIdentifier(string hrp, string hexPayload, string identifier)
    {
        var decoded = Bech32.Decode(identifier);
        Assert.Equal(hrp, decoded.Hrp);
        Assert.Equal(hexPayload, BytesToHex(decoded.Data));
    }

    // ----- Round-trip property test on random 32-byte payloads (Nostr key shape).
    [Fact]
    public void RoundTrip_RandomNostrShapedPayloads()
    {
        var rng = new Random(12345);
        Span<byte> payload = stackalloc byte[32];
        for (int trial = 0; trial < 256; trial++)
        {
            rng.NextBytes(payload);
            string encoded = Bech32.Encode("npub", payload);
            var decoded = Bech32.Decode(encoded);
            Assert.Equal("npub", decoded.Hrp);
            Assert.Equal(payload.ToArray(), decoded.Data);
        }
    }

    // ----- TryEncode / TryDecode span APIs.
    [Fact]
    public void TryEncode_ReturnsFalseWhenDestinationTooSmall()
    {
        byte[] payload = HexToBytes("4b7fef1400aae7011f3121c1cbf63e72ae30ef250e0da169e0fd48427f3fb794");
        Span<char> dest = stackalloc char[10];
        bool ok = Bech32.TryEncode("npub", payload, dest, out int written);
        Assert.False(ok);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryDecode_ReturnsFalseOnBadChecksum()
    {
        // Flip the final character of a known-good identifier — corrupts checksum.
        const string Good = "npub1fdl779qq4tnsz8e3y8quha37w2hrpme9pcx6z60ql4yyylelk72qplz85a";
        var corrupted = Good[..^1] + (Good[^1] == 'a' ? 'p' : 'a');
        Span<char> hrp = stackalloc char[Bech32.MaxHrpLength];
        Span<byte> data = stackalloc byte[64];
        bool ok = Bech32.TryDecode(corrupted, hrp, data, out _, out _);
        Assert.False(ok);
    }

    [Fact]
    public void GetEncodedLength_MatchesActualEncoding()
    {
        byte[] payload = HexToBytes("4b7fef1400aae7011f3121c1cbf63e72ae30ef250e0da169e0fd48427f3fb794");
        int expected = Bech32.GetEncodedLength("npub".Length, payload.Length);
        string encoded = Bech32.Encode("npub", payload);
        Assert.Equal(expected, encoded.Length);
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0)
        {
            throw new ArgumentException("Hex string must have even length.", nameof(hex));
        }

        return Convert.FromHexString(hex);
    }

    private static string BytesToHex(ReadOnlySpan<byte> bytes)
    {
        return Convert.ToHexStringLower(bytes);
    }
}
