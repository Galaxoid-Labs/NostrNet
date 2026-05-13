// SPDX-License-Identifier: MIT
//
// BIP-173 bech32 encoder/decoder.
//
// References:
//   - BIP-173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//   - Reference implementation (Python): the BIP-173 appendix.
//
// This is plain bech32, NOT bech32m (BIP-350). The checksum constant is 1.
// Nostr's NIP-19 uses plain bech32; do not switch to bech32m for that path.

using System.Buffers;

namespace NostrNet.Encoding;

/// <summary>
/// BIP-173 bech32 encoder and decoder.
/// </summary>
/// <remarks>
/// Bech32 is a checksummed base-32 encoding with a human-readable prefix (HRP)
/// separated from the data portion by the literal character <c>1</c>. The data
/// payload accepted by these methods is ordinary 8-bit data; the 8-to-5 bit
/// regrouping required by the format is handled internally.
///
/// <para>
/// This type implements plain bech32 only. It does not implement bech32m
/// (BIP-350); the checksum constant is hard-coded to <c>1</c>. Nostr's NIP-19
/// encoded entities use plain bech32.
/// </para>
///
/// <para>
/// BIP-173 places a 90-character soft cap on bech32 strings for segwit
/// addresses, but NIP-19 explicitly relaxes that cap for entities whose TLV
/// payloads exceed it. This implementation therefore enforces structural
/// constraints (HRP rules, charset, checksum) but does not impose a hard upper
/// bound on total string length. Callers that need one should layer it
/// themselves.
/// </para>
/// </remarks>
public static class Bech32
{
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private const char Separator = '1';
    private const uint ChecksumConstant = 1u; // 1 for bech32, 0x2bc830a3 for bech32m
    private const int ChecksumSymbolCount = 6;

    /// <summary>
    /// The maximum length of the human-readable prefix in characters.
    /// </summary>
    public const int MaxHrpLength = 83;

    /// <summary>
    /// The minimum length of the human-readable prefix in characters.
    /// </summary>
    public const int MinHrpLength = 1;

    // Polymod generator constants (BIP-173 §"Bech32").
    private static readonly uint[] Generator =
    {
        0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u,
    };

    // Inverse of Charset: char -> 5-bit value, or -1 for invalid. Indexed
    // by lowercased ASCII; only entries for the 32 charset characters are set.
    private static readonly sbyte[] CharsetReverse = BuildCharsetReverse();

    private static sbyte[] BuildCharsetReverse()
    {
        var table = new sbyte[128];
        Array.Fill(table, (sbyte)-1);
        for (int i = 0; i < Charset.Length; i++)
        {
            table[Charset[i]] = (sbyte)i;
        }
        return table;
    }

    /// <summary>
    /// Returns the exact number of characters that
    /// <see cref="Encode(string, ReadOnlySpan{byte})"/> will produce for the
    /// given HRP and 8-bit data lengths.
    /// </summary>
    /// <param name="hrpLength">Length of the human-readable prefix in characters.</param>
    /// <param name="dataByteLength">Length of the 8-bit data payload in bytes.</param>
    /// <returns>Total length of the resulting bech32 string.</returns>
    public static int GetEncodedLength(int hrpLength, int dataByteLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(hrpLength);
        ArgumentOutOfRangeException.ThrowIfNegative(dataByteLength);
        // 8-bit -> 5-bit groups with padding: ceil(dataByteLength * 8 / 5).
        int data5BitLength = (dataByteLength * 8 + 4) / 5;
        return hrpLength + 1 /* separator */ + data5BitLength + ChecksumSymbolCount;
    }

    /// <summary>
    /// Encodes a human-readable prefix and an 8-bit data payload into a bech32
    /// string.
    /// </summary>
    /// <param name="hrp">
    /// The human-readable prefix. Must be 1 to 83 characters of ASCII in the
    /// range 33–126. Mixed-case is rejected; the output is lowercase.
    /// </param>
    /// <param name="data">The 8-bit data payload.</param>
    /// <returns>The bech32-encoded string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="hrp"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="hrp"/> is empty, too long, contains out-of-range characters,
    /// or mixes upper- and lower-case letters.
    /// </exception>
    public static string Encode(string hrp, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(hrp);
        int totalLength = GetEncodedLength(hrp.Length, data.Length);

        // Write the bech32 chars to a stack buffer when possible — keeps the
        // hot path (npub/nsec/note: ~63 chars, naddr: ~150 chars) allocation-
        // free other than the final string. Larger NIP-19 payloads fall back
        // to the array pool.
        char[]? rented = null;
        Span<char> destination = totalLength <= 256
            ? stackalloc char[256]
            : (rented = ArrayPool<char>.Shared.Rent(totalLength));

        try
        {
            destination = destination[..totalLength];
            if (!TryEncode(hrp, data, destination, out int written) || written != totalLength)
            {
                throw new ArgumentException("Invalid bech32 input.", nameof(hrp));
            }

            return destination.ToString();
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<char>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Attempts to encode a human-readable prefix and an 8-bit data payload into
    /// the supplied character buffer.
    /// </summary>
    /// <param name="hrp">
    /// The human-readable prefix. Must be 1 to 83 characters of ASCII in the
    /// range 33–126. Mixed-case is rejected.
    /// </param>
    /// <param name="data">The 8-bit data payload.</param>
    /// <param name="destination">Buffer to write the bech32 string into.</param>
    /// <param name="charsWritten">Number of characters written to <paramref name="destination"/>.</param>
    /// <returns>
    /// <c>true</c> on success; <c>false</c> if the HRP is invalid or
    /// <paramref name="destination"/> is too small.
    /// </returns>
    public static bool TryEncode(
        ReadOnlySpan<char> hrp,
        ReadOnlySpan<byte> data,
        Span<char> destination,
        out int charsWritten)
    {
        charsWritten = 0;

        if (!ValidateHrp(hrp))
        {
            return false;
        }

        int total = GetEncodedLength(hrp.Length, data.Length);
        if (destination.Length < total)
        {
            return false;
        }

        // Rent a 5-bit-symbol buffer for the data portion.
        int data5BitLength = (data.Length * 8 + 4) / 5;
        byte[]? rented = null;
        Span<byte> data5Bit = data5BitLength <= 256
            ? stackalloc byte[256]
            : (rented = ArrayPool<byte>.Shared.Rent(data5BitLength));

        try
        {
            data5Bit = data5Bit[..data5BitLength];

            if (!TryConvertBits(data, fromBits: 8, toBits: 5, pad: true, data5Bit, out int actualLen)
                || actualLen != data5BitLength)
            {
                return false;
            }

            // Lowercase HRP into destination at offset 0.
            for (int i = 0; i < hrp.Length; i++)
            {
                destination[i] = ToLowerAscii(hrp[i]);
            }

            destination[hrp.Length] = Separator;

            // Data symbols.
            int cursor = hrp.Length + 1;
            for (int i = 0; i < data5Bit.Length; i++)
            {
                destination[cursor++] = Charset[data5Bit[i]];
            }

            // Checksum is computed over the (lowercased) HRP and the 5-bit data.
            Span<byte> checksum = stackalloc byte[ChecksumSymbolCount];
            ComputeChecksum(destination[..hrp.Length], data5Bit, checksum);
            for (int i = 0; i < ChecksumSymbolCount; i++)
            {
                destination[cursor++] = Charset[checksum[i]];
            }

            charsWritten = total;
            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Decodes a bech32 string into its human-readable prefix and 8-bit data
    /// payload.
    /// </summary>
    /// <param name="source">The bech32-encoded string.</param>
    /// <returns>The decoded HRP and 8-bit data.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="source"/> is null.</exception>
    /// <exception cref="FormatException">
    /// <paramref name="source"/> is not a valid bech32 string. Causes include
    /// missing separator, invalid characters, mixed case, bad checksum, or
    /// invalid padding.
    /// </exception>
    public static Bech32Decoded Decode(string source)
    {
        ArgumentNullException.ThrowIfNull(source);

        // Worst-case output sizes.
        Span<char> hrpBuffer = stackalloc char[MaxHrpLength];
        // 5-bit groups beyond separator and checksum: source.Length - 1 - 6.
        // 8-bit data size: (5-bit count * 5) / 8.
        int maxDataBytes = Math.Max(0, ((source.Length - 1 - ChecksumSymbolCount) * 5) / 8);

        byte[]? rented = null;
        Span<byte> dataBuffer = maxDataBytes <= 256
            ? stackalloc byte[256]
            : (rented = ArrayPool<byte>.Shared.Rent(maxDataBytes));

        try
        {
            if (!TryDecode(source, hrpBuffer, dataBuffer[..maxDataBytes], out int hrpLen, out int dataLen))
            {
                throw new FormatException("Input is not a valid bech32 string.");
            }

            return new Bech32Decoded(
                new string(hrpBuffer[..hrpLen]),
                dataBuffer[..dataLen].ToArray());
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Attempts to decode a bech32 string into its HRP and 8-bit data payload,
    /// writing into caller-provided buffers.
    /// </summary>
    /// <param name="source">The bech32-encoded string.</param>
    /// <param name="hrpDestination">Buffer that receives the lowercased HRP characters.</param>
    /// <param name="dataDestination">Buffer that receives the 8-bit data payload.</param>
    /// <param name="hrpLength">Number of HRP characters written.</param>
    /// <param name="dataLength">Number of data bytes written.</param>
    /// <returns>
    /// <c>true</c> if the input is a valid bech32 string, the 5-bit data
    /// payload converts cleanly to 8-bit bytes (no non-zero padding), and both
    /// buffers were large enough; <c>false</c> otherwise.
    /// </returns>
    /// <remarks>
    /// Some BIP-173 conformance vectors carry 5-bit data that is not a clean
    /// multiple of 8 bits and will fail this method. Use the symbol-level
    /// decoder for spec-conformance checks.
    /// </remarks>
    public static bool TryDecode(
        ReadOnlySpan<char> source,
        Span<char> hrpDestination,
        Span<byte> dataDestination,
        out int hrpLength,
        out int dataLength)
    {
        dataLength = 0;

        // 5-bit symbols (excluding checksum) for the data section.
        // Upper bound = source.Length - 1 (separator) - 6 (checksum).
        int maxSymbols = Math.Max(0, source.Length - 1 - ChecksumSymbolCount);
        byte[]? rented = null;
        Span<byte> symbols = maxSymbols <= 256
            ? stackalloc byte[256]
            : (rented = ArrayPool<byte>.Shared.Rent(maxSymbols));

        try
        {
            symbols = symbols[..maxSymbols];
            if (!TryDecodeSymbols(source, hrpDestination, symbols, out hrpLength, out int symbolsWritten))
            {
                return false;
            }

            // Convert the 5-bit symbol payload (without checksum, already
            // stripped by TryDecodeSymbols) to 8-bit bytes.
            if (!TryConvertBits(symbols[..symbolsWritten], fromBits: 5, toBits: 8, pad: false, dataDestination, out int written))
            {
                hrpLength = 0;
                return false;
            }

            dataLength = written;
            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <summary>
    /// Symbol-level decode: validates a bech32 string and returns the 5-bit
    /// data symbols (with the 6-symbol checksum stripped).
    /// </summary>
    /// <remarks>
    /// This is the BIP-173 "bech32 layer" view, useful for protocols whose
    /// payload is not a clean multiple of 8 bits (e.g., segwit witness
    /// programs) and for spec-conformance tests. NIP-19 callers should use
    /// the 8-bit <see cref="TryDecode"/> instead.
    /// </remarks>
    /// <param name="source">The bech32-encoded string.</param>
    /// <param name="hrpDestination">Buffer that receives the lowercased HRP.</param>
    /// <param name="symbolsDestination">Buffer that receives the 5-bit data symbols (each byte 0–31).</param>
    /// <param name="hrpLength">Number of HRP characters written.</param>
    /// <param name="symbolsLength">Number of data symbols written (does not include the checksum).</param>
    /// <returns><c>true</c> if the string is a valid bech32 string with a passing checksum.</returns>
    internal static bool TryDecodeSymbols(
        ReadOnlySpan<char> source,
        Span<char> hrpDestination,
        Span<byte> symbolsDestination,
        out int hrpLength,
        out int symbolsLength)
    {
        hrpLength = 0;
        symbolsLength = 0;

        // Minimum: 1 HRP char + '1' + 6 checksum chars.
        if (source.Length < MinHrpLength + 1 + ChecksumSymbolCount)
        {
            return false;
        }

        // BIP-173 forbids mixed case. Detect once.
        bool hasLower = false;
        bool hasUpper = false;
        for (int i = 0; i < source.Length; i++)
        {
            char c = source[i];
            if (c < 33 || c > 126)
            {
                return false;
            }

            if (c is >= 'a' and <= 'z')
            {
                hasLower = true;
            }
            else if (c is >= 'A' and <= 'Z')
            {
                hasUpper = true;
            }
        }

        if (hasLower && hasUpper)
        {
            return false;
        }

        // Separator is the LAST '1' (the data charset excludes '1').
        int separatorIndex = source.LastIndexOf(Separator);
        if (separatorIndex < MinHrpLength || separatorIndex > source.Length - 1 - ChecksumSymbolCount)
        {
            return false;
        }

        int hrpLen = separatorIndex;
        if (hrpLen > MaxHrpLength || hrpDestination.Length < hrpLen)
        {
            return false;
        }

        // Lowercase HRP.
        for (int i = 0; i < hrpLen; i++)
        {
            hrpDestination[i] = ToLowerAscii(source[i]);
        }

        int dataSymbolCount = source.Length - separatorIndex - 1;
        int payloadSymbols = dataSymbolCount - ChecksumSymbolCount;
        if (symbolsDestination.Length < payloadSymbols)
        {
            return false;
        }

        // Decode all symbols (payload + checksum) into a contiguous buffer for
        // polymod verification.
        byte[]? rented = null;
        Span<byte> all = dataSymbolCount <= 256
            ? stackalloc byte[256]
            : (rented = ArrayPool<byte>.Shared.Rent(dataSymbolCount));

        try
        {
            all = all[..dataSymbolCount];
            for (int i = 0; i < dataSymbolCount; i++)
            {
                char c = ToLowerAscii(source[separatorIndex + 1 + i]);
                if (c >= CharsetReverse.Length)
                {
                    return false;
                }

                sbyte v = CharsetReverse[c];
                if (v < 0)
                {
                    return false;
                }

                all[i] = (byte)v;
            }

            if (!VerifyChecksum(hrpDestination[..hrpLen], all))
            {
                return false;
            }

            // Strip checksum, copy payload symbols out.
            all[..payloadSymbols].CopyTo(symbolsDestination);
            hrpLength = hrpLen;
            symbolsLength = payloadSymbols;
            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    private static bool ValidateHrp(ReadOnlySpan<char> hrp)
    {
        if (hrp.Length is < MinHrpLength or > MaxHrpLength)
        {
            return false;
        }

        bool hasLower = false;
        bool hasUpper = false;
        for (int i = 0; i < hrp.Length; i++)
        {
            char c = hrp[i];
            if (c < 33 || c > 126)
            {
                return false;
            }

            if (c is >= 'a' and <= 'z')
            {
                hasLower = true;
            }
            else if (c is >= 'A' and <= 'Z')
            {
                hasUpper = true;
            }
        }

        return !(hasLower && hasUpper);
    }

    private static char ToLowerAscii(char c)
        => c is >= 'A' and <= 'Z' ? (char)(c + ('a' - 'A')) : c;

    // Polymod over a 5-bit symbol stream (BIP-173 reference algorithm).
    private static uint Polymod(ReadOnlySpan<byte> symbols)
    {
        uint chk = 1u;
        for (int i = 0; i < symbols.Length; i++)
        {
            uint b = chk >> 25;
            chk = ((chk & 0x1ffffffu) << 5) ^ symbols[i];
            for (int j = 0; j < 5; j++)
            {
                if (((b >> j) & 1) != 0)
                {
                    chk ^= Generator[j];
                }
            }
        }

        return chk;
    }

    private static void ComputeChecksum(
        ReadOnlySpan<char> hrpLower,
        ReadOnlySpan<byte> data5Bit,
        Span<byte> destination)
    {
        // Build [HRP-high-bits || 0 || HRP-low-bits || data || 6 zero symbols].
        int expandedLen = (2 * hrpLower.Length) + 1 + data5Bit.Length + ChecksumSymbolCount;
        Span<byte> values = stackalloc byte[256];
        if (expandedLen > values.Length)
        {
            // Shouldn't happen for reasonable inputs (hrp <= 83, plus 6).
            // Fall back to heap allocation.
            ComputeChecksumHeap(hrpLower, data5Bit, destination);
            return;
        }

        values = values[..expandedLen];
        ExpandHrp(hrpLower, values);
        data5Bit.CopyTo(values.Slice((2 * hrpLower.Length) + 1));
        // last 6 symbols are 0 (the polymod-injection slots), already cleared.

        uint polymod = Polymod(values) ^ ChecksumConstant;
        for (int i = 0; i < ChecksumSymbolCount; i++)
        {
            destination[i] = (byte)((polymod >> (5 * (5 - i))) & 31);
        }
    }

    private static void ComputeChecksumHeap(
        ReadOnlySpan<char> hrpLower,
        ReadOnlySpan<byte> data5Bit,
        Span<byte> destination)
    {
        int expandedLen = (2 * hrpLower.Length) + 1 + data5Bit.Length + ChecksumSymbolCount;
        byte[] rented = ArrayPool<byte>.Shared.Rent(expandedLen);
        try
        {
            Span<byte> values = rented.AsSpan(0, expandedLen);
            values.Clear();
            ExpandHrp(hrpLower, values);
            data5Bit.CopyTo(values.Slice((2 * hrpLower.Length) + 1));

            uint polymod = Polymod(values) ^ ChecksumConstant;
            for (int i = 0; i < ChecksumSymbolCount; i++)
            {
                destination[i] = (byte)((polymod >> (5 * (5 - i))) & 31);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static bool VerifyChecksum(ReadOnlySpan<char> hrpLower, ReadOnlySpan<byte> data5BitWithChecksum)
    {
        int expandedLen = (2 * hrpLower.Length) + 1 + data5BitWithChecksum.Length;
        byte[]? rented = null;
        Span<byte> values = expandedLen <= 256
            ? stackalloc byte[256]
            : (rented = ArrayPool<byte>.Shared.Rent(expandedLen));

        try
        {
            values = values[..expandedLen];
            ExpandHrp(hrpLower, values);
            data5BitWithChecksum.CopyTo(values.Slice((2 * hrpLower.Length) + 1));
            return Polymod(values) == ChecksumConstant;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    // BIP-173 HRP expansion: [high-3-bits of each char] || 0 || [low-5-bits of each char].
    private static void ExpandHrp(ReadOnlySpan<char> hrpLower, Span<byte> destination)
    {
        for (int i = 0; i < hrpLower.Length; i++)
        {
            destination[i] = (byte)(hrpLower[i] >> 5);
        }

        destination[hrpLower.Length] = 0;
        for (int i = 0; i < hrpLower.Length; i++)
        {
            destination[hrpLower.Length + 1 + i] = (byte)(hrpLower[i] & 31);
        }
    }

    // Generic bit-regrouping per the BIP-173 reference. With pad=true (encoding,
    // 8->5), any remaining bits are flushed as a final symbol. With pad=false
    // (decoding, 5->8), trailing bits must be < fromBits and all zero.
    private static bool TryConvertBits(
        ReadOnlySpan<byte> input,
        int fromBits,
        int toBits,
        bool pad,
        Span<byte> output,
        out int written)
    {
        written = 0;
        uint acc = 0;
        int bits = 0;
        uint maxv = (1u << toBits) - 1;
        uint maxAcc = (1u << (fromBits + toBits - 1)) - 1;

        for (int i = 0; i < input.Length; i++)
        {
            uint v = input[i];
            if ((v >> fromBits) != 0)
            {
                return false;
            }

            acc = ((acc << fromBits) | v) & maxAcc;
            bits += fromBits;
            while (bits >= toBits)
            {
                bits -= toBits;
                if (written >= output.Length)
                {
                    return false;
                }

                output[written++] = (byte)((acc >> bits) & maxv);
            }
        }

        if (pad)
        {
            if (bits != 0)
            {
                if (written >= output.Length)
                {
                    return false;
                }

                output[written++] = (byte)((acc << (toBits - bits)) & maxv);
            }
        }
        else
        {
            // No padding: leftover bits must be a sub-byte zero remainder.
            if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0)
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// The decoded components of a bech32 string.
/// </summary>
/// <param name="Hrp">The human-readable prefix, lowercased.</param>
/// <param name="Data">The 8-bit data payload.</param>
public readonly record struct Bech32Decoded(string Hrp, byte[] Data);
