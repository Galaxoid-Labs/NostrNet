// SPDX-License-Identifier: MIT
//
// Multi-threaded vanity key search. Three matching modes:
//
//   1. Proof-of-work — pubkey has N leading zero bits.
//   2. npub bech32 prefix / suffix — matches characters of the bech32
//      encoding (must use the bech32 alphabet only:
//      qpzry9x8gf2tvdw0s3jn54khce6mua7l).
//   3. Pubkey hex prefix / suffix — matches characters of the lowercase
//      32-byte hex string.
//
// All variants:
//   - Multi-threaded by default (one worker per logical core).
//   - Honor a CancellationToken; cancel any time to stop the search.
//   - Report progress at a steady ~500ms cadence via IProgress so UI
//     bindings don't get flooded.
//   - Validate the pattern up-front; an unreachable pattern (e.g., a
//     character not in the target alphabet) throws ArgumentException
//     instead of looping forever.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using NostrNet.Cryptography;
using NostrNet.Encoding;
using NostrNet.Events;

namespace NostrNet.Keys;

/// <summary>
/// Progress snapshot reported during a vanity search.
/// </summary>
/// <param name="Attempts">Total pubkey derivations attempted across all workers.</param>
/// <param name="Elapsed">Wall-clock time since the search started.</param>
public sealed record VanityMiningProgress(long Attempts, TimeSpan Elapsed)
{
    /// <summary>Average derivations per second over the elapsed window.</summary>
    public double AttemptsPerSecond
        => Elapsed.TotalSeconds > 0 ? Attempts / Elapsed.TotalSeconds : 0;
}

/// <summary>
/// Brute-force search for a private key whose corresponding public key
/// satisfies a vanity criterion (PoW difficulty, npub prefix/suffix, or hex
/// prefix/suffix).
/// </summary>
public static class VanityKeyGenerator
{
    private const int AttemptsPerProgressBatch = 1000;
    private const int ProgressReportIntervalMs = 500;

    // The bech32 alphabet used by NIP-19. The separator '1' is NOT included.
    private const string Bech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /// <summary>
    /// Finds a private key whose 32-byte public key has at least
    /// <paramref name="leadingZeroBits"/> leading zero bits.
    /// </summary>
    /// <param name="leadingZeroBits">Target difficulty in bits (0..256).</param>
    /// <param name="threadCount">Worker count; defaults to <see cref="Environment.ProcessorCount"/>.</param>
    /// <param name="progress">Optional progress callback fired ~every 500ms on the captured SynchronizationContext.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    public static Task<PrivateKey> MinePowAsync(
        int leadingZeroBits,
        int? threadCount = null,
        IProgress<VanityMiningProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (leadingZeroBits < 0 || leadingZeroBits > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(leadingZeroBits), "Must be in [0, 256].");
        }

        int target = leadingZeroBits;
        return SearchAsync(
            stateFactory: () => (object?)null,
            matcher: (_, pubBytes) => ProofOfWork.CountLeadingZeroBits(pubBytes) >= target,
            threadCount,
            progress,
            cancellationToken);
    }

    /// <summary>
    /// Finds a private key whose npub starts with <paramref name="prefix"/>
    /// (matched against the characters following <c>"npub1"</c>).
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="prefix"/> is empty or contains a character outside the bech32 alphabet.</exception>
    public static Task<PrivateKey> MineNpubPrefixAsync(
        string prefix,
        int? threadCount = null,
        IProgress<VanityMiningProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string normalized = ValidateBech32Pattern(prefix, nameof(prefix));
        return SearchAsync(
            stateFactory: () => new char[63],   // npub: "npub1" + 52 data + 6 checksum
            matcher: (buf, pubBytes) =>
            {
                if (!Bech32.TryEncode("npub", pubBytes, buf, out int written))
                {
                    return false;
                }

                // Skip the "npub1" HRP+separator (5 chars).
                return written - 5 >= normalized.Length
                    && new ReadOnlySpan<char>(buf, 5, normalized.Length).SequenceEqual(normalized);
            },
            threadCount,
            progress,
            cancellationToken);
    }

    /// <summary>
    /// Finds a private key whose npub ends with <paramref name="suffix"/>.
    /// </summary>
    /// <remarks>
    /// Note: the trailing 6 characters of an npub are the bech32 checksum,
    /// which is derived from the data. Suffix matching therefore constrains
    /// both the key bytes and the checksum simultaneously — same probability
    /// per character as prefix matching, but a different search space.
    /// </remarks>
    /// <exception cref="ArgumentException"><paramref name="suffix"/> is empty or contains a non-bech32 character.</exception>
    public static Task<PrivateKey> MineNpubSuffixAsync(
        string suffix,
        int? threadCount = null,
        IProgress<VanityMiningProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string normalized = ValidateBech32Pattern(suffix, nameof(suffix));
        return SearchAsync(
            stateFactory: () => new char[63],
            matcher: (buf, pubBytes) =>
            {
                if (!Bech32.TryEncode("npub", pubBytes, buf, out int written) || written < normalized.Length)
                {
                    return false;
                }

                return new ReadOnlySpan<char>(buf, written - normalized.Length, normalized.Length).SequenceEqual(normalized);
            },
            threadCount,
            progress,
            cancellationToken);
    }

    /// <summary>
    /// Finds a private key whose lowercase 64-character hex pubkey starts
    /// with <paramref name="prefix"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="prefix"/> is empty or contains a non-hex character.</exception>
    public static Task<PrivateKey> MineHexPrefixAsync(
        string prefix,
        int? threadCount = null,
        IProgress<VanityMiningProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string normalized = ValidateHexPattern(prefix, nameof(prefix));
        return SearchAsync(
            stateFactory: () => new char[PublicKey.Size * 2],
            matcher: (buf, pubBytes) =>
            {
                WriteHexLower(pubBytes, buf);
                return new ReadOnlySpan<char>(buf, 0, normalized.Length).SequenceEqual(normalized);
            },
            threadCount,
            progress,
            cancellationToken);
    }

    /// <summary>
    /// Finds a private key whose lowercase 64-character hex pubkey ends
    /// with <paramref name="suffix"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="suffix"/> is empty or contains a non-hex character.</exception>
    public static Task<PrivateKey> MineHexSuffixAsync(
        string suffix,
        int? threadCount = null,
        IProgress<VanityMiningProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        string normalized = ValidateHexPattern(suffix, nameof(suffix));
        return SearchAsync(
            stateFactory: () => new char[PublicKey.Size * 2],
            matcher: (buf, pubBytes) =>
            {
                WriteHexLower(pubBytes, buf);
                return new ReadOnlySpan<char>(buf, buf.Length - normalized.Length, normalized.Length).SequenceEqual(normalized);
            },
            threadCount,
            progress,
            cancellationToken);
    }

    // ----- Core search loop ----------------------------------------------------

    private delegate bool VanityMatcher<TState>(TState state, ReadOnlySpan<byte> pubBytes);

    private static async Task<PrivateKey> SearchAsync<TState>(
        Func<TState> stateFactory,
        VanityMatcher<TState> matcher,
        int? threadCount,
        IProgress<VanityMiningProgress>? progress,
        CancellationToken cancellationToken)
    {
        int threads = threadCount ?? Environment.ProcessorCount;
        if (threads < 1)
        {
            threads = 1;
        }

        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        CancellationToken token = linked.Token;

        long totalAttempts = 0;
        var sw = Stopwatch.StartNew();

        var workers = new Task[threads];
        for (int i = 0; i < threads; i++)
        {
            workers[i] = Task.Run(() => Worker(stateFactory, matcher, tcs, ref totalAttempts, token), token);
        }

        Task reporterTask = progress is null
            ? Task.CompletedTask
            : Task.Run(() => ReporterLoop(progress, sw, () => Interlocked.Read(ref totalAttempts), token), CancellationToken.None);

        using (cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken)))
        {
            try
            {
                byte[] privateKeyBytes = await tcs.Task.ConfigureAwait(false);
                linked.Cancel();

                try
                {
                    var key = new PrivateKey(privateKeyBytes);

                    // Final progress update so callers see the terminal count.
                    progress?.Report(new VanityMiningProgress(Interlocked.Read(ref totalAttempts), sw.Elapsed));
                    return key;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(privateKeyBytes);
                }
            }
            finally
            {
                linked.Cancel();
                try { await Task.WhenAll(workers).ConfigureAwait(false); } catch { /* expected on cancel */ }
                try { await reporterTask.ConfigureAwait(false); } catch { /* expected on cancel */ }
            }
        }
    }

    private static void Worker<TState>(
        Func<TState> stateFactory,
        VanityMatcher<TState> matcher,
        TaskCompletionSource<byte[]> tcs,
        ref long totalAttempts,
        CancellationToken token)
    {
        TState state = stateFactory();
        Span<byte> privBytes = stackalloc byte[PrivateKey.Size];
        Span<byte> pubBytes = stackalloc byte[PublicKey.Size];
        int localAttempts = 0;

        while (!token.IsCancellationRequested && !tcs.Task.IsCompleted)
        {
            RandomNumberGenerator.Fill(privBytes);

            try
            {
                Secp256k1.GetXOnlyPublicKey(privBytes, pubBytes);
            }
            catch
            {
                // ~negligible probability of an invalid scalar; try again.
                continue;
            }

            if (matcher(state, pubBytes))
            {
                byte[] copy = privBytes.ToArray();
                if (!tcs.TrySetResult(copy))
                {
                    // Another worker won the race — don't leave our copy in
                    // GC-managed memory with the secret in it.
                    CryptographicOperations.ZeroMemory(copy);
                }

                CryptographicOperations.ZeroMemory(privBytes);
                return;
            }

            if (++localAttempts >= AttemptsPerProgressBatch)
            {
                Interlocked.Add(ref totalAttempts, localAttempts);
                localAttempts = 0;
            }
        }

        // Flush any unaccounted local attempts.
        if (localAttempts > 0)
        {
            Interlocked.Add(ref totalAttempts, localAttempts);
        }

        CryptographicOperations.ZeroMemory(privBytes);
    }

    private static async Task ReporterLoop(
        IProgress<VanityMiningProgress> progress,
        Stopwatch sw,
        Func<long> readTotal,
        CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                await Task.Delay(ProgressReportIntervalMs, token).ConfigureAwait(false);
                progress.Report(new VanityMiningProgress(readTotal(), sw.Elapsed));
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on completion / cancel.
        }
    }

    // ----- Validation ---------------------------------------------------------

    [SuppressMessage("Style", "IDE0046:Convert to conditional expression", Justification = "Clarity")]
    private static string ValidateBech32Pattern(string pattern, string paramName)
    {
        ArgumentException.ThrowIfNullOrEmpty(pattern, paramName);
        string normalized = pattern.ToLowerInvariant();

        foreach (char c in normalized)
        {
            if (Bech32Alphabet.IndexOf(c) < 0)
            {
                throw new ArgumentException(
                    $"Character '{c}' is not in the bech32 alphabet. Allowed: '{Bech32Alphabet}'.",
                    paramName);
            }
        }

        return normalized;
    }

    private static string ValidateHexPattern(string pattern, string paramName)
    {
        ArgumentException.ThrowIfNullOrEmpty(pattern, paramName);
        string normalized = pattern.ToLowerInvariant();

        foreach (char c in normalized)
        {
            bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!isHex)
            {
                throw new ArgumentException(
                    $"Character '{c}' is not a hex digit (0-9, a-f).",
                    paramName);
            }
        }

        return normalized;
    }

    // ----- Hex helper ---------------------------------------------------------

    private static readonly char[] HexLowerLookup =
        { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    private static void WriteHexLower(ReadOnlySpan<byte> source, char[] destination)
    {
        for (int i = 0; i < source.Length; i++)
        {
            byte b = source[i];
            destination[i * 2] = HexLowerLookup[b >> 4];
            destination[(i * 2) + 1] = HexLowerLookup[b & 0x0F];
        }
    }
}
