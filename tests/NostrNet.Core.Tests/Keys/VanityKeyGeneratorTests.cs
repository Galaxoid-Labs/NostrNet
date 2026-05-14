// SPDX-License-Identifier: MIT
//
// Vanity-search tests use deliberately easy patterns (1 char prefix, low PoW)
// so they finish in well under a second on any test machine.

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Keys;

public class VanityKeyGeneratorTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task MinePow_FindsKeyWithRequestedDifficulty()
    {
        using var cts = new CancellationTokenSource(TestTimeout);

        // 8 bits = 1 in 256, finds essentially instantly even on slow hosts.
        using var key = await VanityKeyGenerator.MinePowAsync(
            leadingZeroBits: 8,
            cancellationToken: cts.Token);

        int actualBits = ProofOfWork.CountLeadingZeroBits(key.PublicKey.AsSpan());
        Assert.True(actualBits >= 8, $"Found key has {actualBits} leading zero bits, expected ≥ 8.");
    }

    [Fact]
    public async Task MineNpubPrefix_FindsKeyStartingWithPattern()
    {
        using var cts = new CancellationTokenSource(TestTimeout);

        // Single bech32 char — 1 in 32, finds in <1 second.
        using var key = await VanityKeyGenerator.MineNpubPrefixAsync(
            prefix: "a",
            cancellationToken: cts.Token);

        string npub = key.PublicKey.ToNpub();
        Assert.StartsWith("npub1a", npub, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MineNpubSuffix_FindsKeyEndingWithPattern()
    {
        using var cts = new CancellationTokenSource(TestTimeout);

        using var key = await VanityKeyGenerator.MineNpubSuffixAsync(
            suffix: "a",
            cancellationToken: cts.Token);

        Assert.EndsWith("a", key.PublicKey.ToNpub(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task MineHexPrefix_FindsKeyStartingWithPattern()
    {
        using var cts = new CancellationTokenSource(TestTimeout);

        using var key = await VanityKeyGenerator.MineHexPrefixAsync(
            prefix: "0",
            cancellationToken: cts.Token);

        Assert.StartsWith("0", key.PublicKey.ToHex(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task MineHexSuffix_FindsKeyEndingWithPattern()
    {
        using var cts = new CancellationTokenSource(TestTimeout);

        using var key = await VanityKeyGenerator.MineHexSuffixAsync(
            suffix: "f",
            cancellationToken: cts.Token);

        Assert.EndsWith("f", key.PublicKey.ToHex(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task MineHexPrefix_CaseInsensitive_NormalizesToLower()
    {
        using var cts = new CancellationTokenSource(TestTimeout);

        // Uppercase pattern should match against lowercase output.
        using var key = await VanityKeyGenerator.MineHexPrefixAsync(
            prefix: "A",
            cancellationToken: cts.Token);

        Assert.StartsWith("a", key.PublicKey.ToHex(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("b")]   // not in bech32 alphabet
    [InlineData("i")]
    [InlineData("o")]
    [InlineData("1")]   // separator, not a data char
    [InlineData("alic")]   // 'i' rejected
    public void MineNpubPrefix_RejectsCharactersOutsideBech32(string badPrefix)
    {
        Assert.Throws<ArgumentException>(() =>
            VanityKeyGenerator.MineNpubPrefixAsync(badPrefix).GetAwaiter().GetResult());
    }

    [Theory]
    [InlineData("g")]   // not a hex digit
    [InlineData("z")]
    [InlineData("xyz")]
    public void MineHexPrefix_RejectsNonHexCharacters(string badPrefix)
    {
        Assert.Throws<ArgumentException>(() =>
            VanityKeyGenerator.MineHexPrefixAsync(badPrefix).GetAwaiter().GetResult());
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void MineNpubPrefix_RejectsEmptyPattern(string? pattern)
    {
        // ThrowsAny accepts ArgumentNullException (subtype) for null + ArgumentException for empty.
        Assert.ThrowsAny<ArgumentException>(() =>
            VanityKeyGenerator.MineNpubPrefixAsync(pattern!).GetAwaiter().GetResult());
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(257)]
    public void MinePow_RejectsOutOfRangeDifficulty(int difficulty)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            VanityKeyGenerator.MinePowAsync(difficulty).GetAwaiter().GetResult());
    }

    [Fact]
    public async Task MinePow_HonorsCancellation()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

        // 64 bits is unrealistic to find in 150ms (1 in 1.8e19) — must cancel.
        await Assert.ThrowsAsync<TaskCanceledException>(() =>
            VanityKeyGenerator.MinePowAsync(leadingZeroBits: 64, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task MineNpubPrefix_ReportsProgress()
    {
        using var cts = new CancellationTokenSource(TestTimeout);

        var progressEvents = new List<VanityMiningProgress>();
        var progress = new Progress<VanityMiningProgress>(p => progressEvents.Add(p));

        // Use a pattern that takes a few hundred ms minimum so reporter has
        // time to fire at least once.
        try
        {
            using var key = await VanityKeyGenerator.MineNpubPrefixAsync(
                prefix: "aaa",
                progress: progress,
                cancellationToken: cts.Token);

            // Final progress report should have arrived after the result.
            // Give the synchronization context a beat to flush.
            await Task.Delay(50, cts.Token);

            Assert.NotEmpty(progressEvents);
            Assert.True(progressEvents[^1].Attempts > 0);
        }
        catch (TaskCanceledException)
        {
            // Acceptable on a very slow host — the test environment may not
            // have found "aaa" within the timeout. We still expect progress.
            Assert.NotEmpty(progressEvents);
        }
    }

    [Fact]
    public async Task MineNpubPrefix_RespectsThreadCountOne()
    {
        using var cts = new CancellationTokenSource(TestTimeout);

        // Single-threaded — just verifies the path doesn't deadlock with one worker.
        using var key = await VanityKeyGenerator.MineNpubPrefixAsync(
            prefix: "a",
            threadCount: 1,
            cancellationToken: cts.Token);

        Assert.StartsWith("npub1a", key.PublicKey.ToNpub(), StringComparison.Ordinal);
    }
}
