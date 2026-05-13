// SPDX-License-Identifier: MIT
//
// Tests for NIP-13 proof of work.

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Events;

public class ProofOfWorkTests
{
    [Fact]
    public void CountLeadingZeroBits_SpecExample36Bits()
    {
        // From NIP-13: id "000000000e9d97a1ab09fc381030b346cdd7a142ad57e6df0b46dc9bef6c7e2d"
        // has 36 leading zero bits (4 zero bytes + 4 leading zeros in 0x0e).
        byte[] bytes = Convert.FromHexString("000000000e9d97a1ab09fc381030b346cdd7a142ad57e6df0b46dc9bef6c7e2d");
        Assert.Equal(36, ProofOfWork.CountLeadingZeroBits(bytes));
    }

    [Fact]
    public void CountLeadingZeroBits_SpecPartialNibbleExample()
    {
        // From NIP-13 note about partial nibbles: 0x002f has 10 leading zero
        // bits, not 8 (because 0x2f = 0b00101111 has 2 leading zeros).
        byte[] bytes = { 0x00, 0x2f, 0xff };
        Assert.Equal(10, ProofOfWork.CountLeadingZeroBits(bytes));
    }

    [Theory]
    [InlineData(new byte[] { 0x80, 0x00 }, 0)]   // high bit set immediately
    [InlineData(new byte[] { 0x40, 0x00 }, 1)]   // 0b01000000 → 1 leading zero
    [InlineData(new byte[] { 0x01, 0xff }, 7)]   // 0b00000001 → 7 leading zeros
    [InlineData(new byte[] { 0x00, 0x80 }, 8)]   // 1 zero byte
    [InlineData(new byte[] { 0x00, 0x40 }, 9)]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 32)] // all zeros
    public void CountLeadingZeroBits_KnownPatterns(byte[] bytes, int expected)
    {
        Assert.Equal(expected, ProofOfWork.CountLeadingZeroBits(bytes));
    }

    [Fact]
    public void Mine_AchievesTargetDifficulty()
    {
        using var key = PrivateKey.Generate();
        var template = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "mine me",
        };

        // 8 bits is fast: 1 in 256 ids on average.
        const int Target = 8;
        var mined = ProofOfWork.Mine(template, Target);

        Assert.True(ProofOfWork.Difficulty(mined.ComputeId()) >= Target);
        Assert.Equal(Target, ProofOfWork.CommittedDifficulty(mined));

        // Mined event still signs and verifies normally.
        var signed = mined.Sign(key);
        Assert.True(signed.Verify());
        Assert.True(ProofOfWork.Difficulty(signed) >= Target);
        Assert.True(ProofOfWork.MeetsCommittedDifficulty(signed));
    }

    [Fact]
    public void Mine_ReplacesPreexistingNonceTag()
    {
        using var key = PrivateKey.Generate();
        var template = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "nonce", "0", "100" }, // bogus existing nonce
                new[] { "t", "hashtag" },
            },
            Content = "hi",
        };

        var mined = ProofOfWork.Mine(template, 4);

        // Exactly one nonce tag, and the t tag is preserved.
        int nonceCount = mined.Tags.Count(t => t.Count > 0 && t[0] == "nonce");
        Assert.Equal(1, nonceCount);
        Assert.Contains(mined.Tags, t => t.Count >= 2 && t[0] == "t" && t[1] == "hashtag");
        Assert.Equal(4, ProofOfWork.CommittedDifficulty(mined));
    }

    [Fact]
    public void Mine_HonorsCancellation()
    {
        using var key = PrivateKey.Generate();
        var template = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "x",
        };

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        // 30 bits is hard enough that we won't finish in 50ms.
        Assert.Throws<OperationCanceledException>(() => ProofOfWork.Mine(template, 30, cts.Token));
    }

    [Fact]
    public void CommittedDifficulty_NullWhenNoNonceTag()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "no pow here",
        }.Sign(key);

        Assert.Null(ProofOfWork.CommittedDifficulty(ev));
        Assert.True(ProofOfWork.MeetsCommittedDifficulty(ev), "Events without a nonce tag commit no PoW claim.");
    }

    [Fact]
    public void MeetsCommittedDifficulty_RejectsClaimAboveActual()
    {
        // Build a signed event whose committed target is much higher than the
        // actual difficulty its id achieves.
        using var key = PrivateKey.Generate();

        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "nonce", "0", "200" }, // claim 200 bits — impossible without real mining
            },
            Content = "fraudulent claim",
        }.Sign(key);

        int actual = ProofOfWork.Difficulty(ev);
        Assert.True(actual < 200, "Random id should not have 200 leading zero bits.");
        Assert.False(ProofOfWork.MeetsCommittedDifficulty(ev),
            "Validator must reject committed difficulty larger than actual.");
    }
}
