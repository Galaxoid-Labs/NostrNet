// SPDX-License-Identifier: MIT
//
// NIP-13 proof of work.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/13.md
//
// Difficulty is the number of leading zero bits in the 32-byte event id.
// Miners add a tag of the form
//   ["nonce", "<nonce_value>", "<target_difficulty>"]
// and vary the nonce value until the resulting id has at least
// target_difficulty leading zero bits.
//
// The committed target_difficulty is checked alongside the actual difficulty
// during validation, so a miner cannot claim arbitrary difficulty after the
// fact.

using System.Globalization;
using System.Numerics;
using NostrNet.Keys;

namespace NostrNet.Events;

/// <summary>
/// NIP-13 proof-of-work helpers: counting leading zero bits, mining a target
/// difficulty, and validating committed difficulty against actual difficulty.
/// </summary>
public static class ProofOfWork
{
    /// <summary>The tag name used to commit a nonce and target difficulty.</summary>
    public const string NonceTagName = "nonce";

    /// <summary>
    /// Counts the leading zero bits in <paramref name="bytes"/>.
    /// </summary>
    /// <remarks>
    /// Per NIP-13, this is measured on the binary representation of the event
    /// id. Each fully-zero byte contributes 8 bits; the first non-zero byte
    /// contributes the leading zero bits within that byte.
    /// </remarks>
    public static int CountLeadingZeroBits(ReadOnlySpan<byte> bytes)
    {
        int total = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            if (b == 0)
            {
                total += 8;
                continue;
            }

            // BitOperations.LeadingZeroCount works on a 32-bit value; for a
            // byte the upper 24 bits are zero, so subtract them off.
            total += BitOperations.LeadingZeroCount(b) - 24;
            break;
        }

        return total;
    }

    /// <summary>The number of leading zero bits in <paramref name="id"/>.</summary>
    public static int Difficulty(EventId id)
    {
        ArgumentNullException.ThrowIfNull(id);
        return CountLeadingZeroBits(id.AsSpan());
    }

    /// <summary>The number of leading zero bits in <paramref name="ev"/>'s id.</summary>
    public static int Difficulty(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        return CountLeadingZeroBits(ev.Id.AsSpan());
    }

    /// <summary>
    /// Returns the difficulty committed by the nonce tag, or <c>null</c> if
    /// the event has no well-formed nonce tag.
    /// </summary>
    /// <remarks>
    /// The committed difficulty is the third element of the
    /// <c>["nonce", value, target]</c> tag, parsed as a decimal integer.
    /// </remarks>
    public static int? CommittedDifficulty(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        return ParseCommittedDifficulty(ev.Tags);
    }

    /// <summary>
    /// Returns the difficulty committed by the nonce tag in an unsigned event,
    /// or <c>null</c> if no well-formed nonce tag is present.
    /// </summary>
    public static int? CommittedDifficulty(UnsignedEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        return ParseCommittedDifficulty(ev.Tags);
    }

    /// <summary>
    /// True if the event has no committed PoW (no nonce tag) or the actual
    /// difficulty is at least the committed target.
    /// </summary>
    /// <remarks>
    /// Returns <c>true</c> for events without a nonce tag — they are not
    /// claiming any PoW, so there is nothing to falsify. Callers that require
    /// a minimum difficulty regardless of the committed value should compare
    /// <see cref="Difficulty(NostrEvent)"/> directly.
    /// </remarks>
    public static bool MeetsCommittedDifficulty(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        int? committed = CommittedDifficulty(ev);
        if (committed is null)
        {
            return true;
        }

        return Difficulty(ev) >= committed.Value;
    }

    /// <summary>
    /// Mines <paramref name="template"/> until its computed event id has at
    /// least <paramref name="targetDifficulty"/> leading zero bits. Returns an
    /// <see cref="UnsignedEvent"/> identical to the template except for a
    /// <c>nonce</c> tag committing to the target.
    /// </summary>
    /// <param name="template">The unsigned event to mine. Any existing <c>nonce</c> tag is replaced.</param>
    /// <param name="targetDifficulty">The number of leading zero bits to achieve (0–256).</param>
    /// <param name="cancellationToken">Cancels mining (e.g., to enforce a time budget).</param>
    /// <remarks>
    /// Mining only varies the nonce; <c>created_at</c> is held constant.
    /// Callers wanting timestamp jitter should compose their own outer loop.
    /// </remarks>
    public static UnsignedEvent Mine(
        UnsignedEvent template,
        int targetDifficulty,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(template);
        if (targetDifficulty < 0 || targetDifficulty > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(targetDifficulty), "Target difficulty must be in [0, 256].");
        }

        if (targetDifficulty == 0)
        {
            // Trivially satisfied — but still attach a tag so the committed
            // difficulty is observable, mirroring miner conventions.
            return WithNonceTag(template, "0", "0");
        }

        var baseTags = StripExistingNonceTags(template.Tags);
        string targetStr = targetDifficulty.ToString(CultureInfo.InvariantCulture);

        ulong nonce = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string nonceStr = nonce.ToString(CultureInfo.InvariantCulture);
            var candidateTags = AppendNonceTag(baseTags, nonceStr, targetStr);

            EventId candidateId = EventSerializer.ComputeId(
                template.PubKey,
                template.CreatedAt,
                template.Kind,
                candidateTags,
                template.Content);

            if (CountLeadingZeroBits(candidateId.AsSpan()) >= targetDifficulty)
            {
                return new UnsignedEvent
                {
                    PubKey = template.PubKey,
                    CreatedAt = template.CreatedAt,
                    Kind = template.Kind,
                    Tags = candidateTags,
                    Content = template.Content,
                };
            }

            nonce++;
        }
    }

    private static int? ParseCommittedDifficulty(IReadOnlyList<IReadOnlyList<string>> tags)
    {
        if (tags is null)
        {
            return null;
        }

        for (int i = 0; i < tags.Count; i++)
        {
            var tag = tags[i];
            if (tag.Count >= 3
                && string.Equals(tag[0], NonceTagName, StringComparison.Ordinal)
                && int.TryParse(tag[2], NumberStyles.None, CultureInfo.InvariantCulture, out int target)
                && target >= 0)
            {
                return target;
            }
        }

        return null;
    }

    private static List<IReadOnlyList<string>> StripExistingNonceTags(IReadOnlyList<IReadOnlyList<string>> tags)
    {
        var result = new List<IReadOnlyList<string>>(tags.Count);
        for (int i = 0; i < tags.Count; i++)
        {
            var t = tags[i];
            if (t.Count > 0 && string.Equals(t[0], NonceTagName, StringComparison.Ordinal))
            {
                continue;
            }

            result.Add(t);
        }

        return result;
    }

    private static IReadOnlyList<IReadOnlyList<string>> AppendNonceTag(
        IReadOnlyList<IReadOnlyList<string>> baseTags,
        string nonceValue,
        string targetValue)
    {
        var result = new IReadOnlyList<string>[baseTags.Count + 1];
        for (int i = 0; i < baseTags.Count; i++)
        {
            result[i] = baseTags[i];
        }

        result[baseTags.Count] = new[] { NonceTagName, nonceValue, targetValue };
        return result;
    }

    private static UnsignedEvent WithNonceTag(UnsignedEvent template, string nonceValue, string targetValue)
    {
        var baseTags = StripExistingNonceTags(template.Tags);
        var newTags = AppendNonceTag(baseTags, nonceValue, targetValue);
        return new UnsignedEvent
        {
            PubKey = template.PubKey,
            CreatedAt = template.CreatedAt,
            Kind = template.Kind,
            Tags = newTags,
            Content = template.Content,
        };
    }
}
