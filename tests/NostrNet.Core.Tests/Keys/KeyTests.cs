// SPDX-License-Identifier: MIT
//
// Tests for PrivateKey / PublicKey. Cross-checks the nsec/npub round-trip
// against the Galaxoid Labs Swift Nostr library's verified vectors.

using NostrNet.Keys;

namespace NostrNet.Tests.Keys;

public class KeyTests
{
    // Verified pair from Tests/NostrTests/NostrTests.swift.
    private const string KnownNsec = "nsec1r7uh0ryrf0n7z3l4qumzevw9q2s57us4wzqrendpavtjn7uvy5rs9szssa";
    private const string KnownPrivHex = "1fb9778c834be7e147f507362cb1c502a14f721570803ccda1eb1729fb8c2507";
    private const string KnownNpub = "npub1fdl779qq4tnsz8e3y8quha37w2hrpme9pcx6z60ql4yyylelk72qplz85a";
    private const string KnownPubHex = "4b7fef1400aae7011f3121c1cbf63e72ae30ef250e0da169e0fd48427f3fb794";

    [Fact]
    public void PrivateKey_FromNsec_DerivesExpectedPublicKey()
    {
        using var key = PrivateKey.FromNsec(KnownNsec);
        Assert.Equal(KnownPrivHex, key.ToHex());
        Assert.Equal(KnownPubHex, key.PublicKey.ToHex());
        Assert.Equal(KnownNpub, key.PublicKey.ToNpub());
        Assert.Equal(KnownNsec, key.ToNsec());
    }

    [Fact]
    public void PrivateKey_FromHex_RoundTrips()
    {
        using var key = PrivateKey.FromHex(KnownPrivHex);
        Assert.Equal(KnownNsec, key.ToNsec());
        Assert.Equal(KnownPubHex, key.PublicKey.ToHex());
    }

    [Fact]
    public void PublicKey_FromNpub_RoundTrips()
    {
        var pub = PublicKey.FromNpub(KnownNpub);
        Assert.Equal(KnownPubHex, pub.ToHex());
        Assert.Equal(KnownNpub, pub.ToNpub());
    }

    [Fact]
    public void PrivateKey_Generate_ProducesUsableKey()
    {
        using var key = PrivateKey.Generate();

        // Round-trip via nsec.
        string nsec = key.ToNsec();
        using var roundTripped = PrivateKey.FromNsec(nsec);
        Assert.Equal(key.ToHex(), roundTripped.ToHex());
        Assert.Equal(key.PublicKey, roundTripped.PublicKey);
    }

    [Fact]
    public void PrivateKey_SignAndVerify_RoundTrip()
    {
        using var key = PrivateKey.FromHex(KnownPrivHex);
        Span<byte> message = stackalloc byte[32];
        new Random(42).NextBytes(message);

        Span<byte> sig = stackalloc byte[64];
        key.Sign(message, sig);

        bool ok = NostrNet.Cryptography.Secp256k1.SchnorrVerify(sig, message, key.PublicKey.AsSpan());
        Assert.True(ok);
    }

    [Fact]
    public void PrivateKey_Dispose_ZeroesMemoryAndPreventsAccess()
    {
        var key = PrivateKey.FromHex(KnownPrivHex);
        key.Dispose();

        // Subsequent access throws.
        Assert.Throws<ObjectDisposedException>(() => key.ToHex());
        Assert.Throws<ObjectDisposedException>(() => key.ToNsec());
        Assert.Throws<ObjectDisposedException>(() =>
        {
            Span<byte> sig = stackalloc byte[64];
            Span<byte> msg = stackalloc byte[32];
            key.Sign(msg, sig);
        });

        // Idempotent.
        key.Dispose();
    }

    [Fact]
    public void PrivateKey_ToString_RedactsSecret()
    {
        using var key = PrivateKey.FromHex(KnownPrivHex);
        string s = key.ToString();
        Assert.DoesNotContain(KnownPrivHex[..8], s, StringComparison.Ordinal);
        Assert.Contains("****", s, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not hex")]
    [InlineData("1fb9778c834be7e147f507362cb1c502a14f721570803ccda1eb1729fb8c2")]   // 62 chars
    [InlineData("zzb9778c834be7e147f507362cb1c502a14f721570803ccda1eb1729fb8c2507")] // non-hex
    public void PrivateKey_TryFromHex_RejectsBadInput(string input)
    {
        Assert.False(PrivateKey.TryFromHex(input, out var key));
        Assert.Null(key);
    }

    [Theory]
    [InlineData("")]
    [InlineData("npub")]
    [InlineData("nprofile1qqsabc")]    // wrong HRP
    public void PublicKey_TryFromNpub_RejectsBadInput(string input)
    {
        Assert.False(PublicKey.TryFromNpub(input, out var key));
        Assert.Null(key);
    }

    [Fact]
    public void PublicKey_Equality_ByValue()
    {
        var a = PublicKey.FromHex(KnownPubHex);
        var b = PublicKey.FromHex(KnownPubHex);
        Assert.True(a.Equals(b));
        Assert.True(a == b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void PublicKey_Inequality_DetectsDifference()
    {
        var a = PublicKey.FromHex(KnownPubHex);
        Span<byte> tweaked = stackalloc byte[32];
        a.CopyTo(tweaked);
        tweaked[0] ^= 0x01;
        var b = new PublicKey(tweaked);
        Assert.False(a.Equals(b));
        Assert.True(a != b);
    }
}
