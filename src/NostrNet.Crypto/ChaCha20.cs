// SPDX-License-Identifier: MIT
//
// ChaCha20 stream cipher (RFC 8439).
//
// The .NET BCL exposes ChaCha20-Poly1305 AEAD but not the raw stream cipher
// that NIP-44 v2 requires (NIP-44 uses ChaCha20 + a separate HMAC-SHA256,
// not Poly1305 AEAD). This implementation follows RFC 8439 §2.3–§2.4 line
// by line and is tested against the RFC test vector.

namespace NostrNet.Cryptography;

/// <summary>
/// RFC 8439 ChaCha20 stream cipher.
/// </summary>
internal static class ChaCha20
{
    /// <summary>Key length in bytes.</summary>
    public const int KeySize = 32;

    /// <summary>Nonce length in bytes.</summary>
    public const int NonceSize = 12;

    /// <summary>Block length in bytes.</summary>
    public const int BlockSize = 64;

    // Constants spell "expand 32-byte k" in little-endian.
    private const uint Constant0 = 0x61707865u;
    private const uint Constant1 = 0x3320646eu;
    private const uint Constant2 = 0x79622d32u;
    private const uint Constant3 = 0x6b206574u;

    /// <summary>
    /// Encrypts or decrypts <paramref name="input"/> under the given key and
    /// nonce, writing the XORed output to <paramref name="output"/>.
    /// </summary>
    /// <param name="key">32-byte ChaCha20 key.</param>
    /// <param name="nonce">12-byte ChaCha20 nonce.</param>
    /// <param name="initialCounter">The starting 32-bit block counter.</param>
    /// <param name="input">Input bytes (plaintext or ciphertext).</param>
    /// <param name="output">Output buffer; must be at least as long as <paramref name="input"/>.</param>
    public static void Apply(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        uint initialCounter,
        ReadOnlySpan<byte> input,
        Span<byte> output)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key must be {KeySize} bytes.", nameof(key));
        }

        if (nonce.Length != NonceSize)
        {
            throw new ArgumentException($"Nonce must be {NonceSize} bytes.", nameof(nonce));
        }

        if (output.Length < input.Length)
        {
            throw new ArgumentException("Output buffer is shorter than input.", nameof(output));
        }

        Span<uint> baseState = stackalloc uint[16];
        InitState(baseState, key, nonce, initialCounter);

        Span<uint> workingState = stackalloc uint[16];
        Span<byte> blockBytes = stackalloc byte[BlockSize];

        int position = 0;
        while (position < input.Length)
        {
            baseState.CopyTo(workingState);
            DoTwentyRounds(workingState);
            for (int i = 0; i < 16; i++)
            {
                workingState[i] += baseState[i];
            }

            SerializeState(workingState, blockBytes);

            int chunkLen = Math.Min(BlockSize, input.Length - position);
            for (int i = 0; i < chunkLen; i++)
            {
                output[position + i] = (byte)(input[position + i] ^ blockBytes[i]);
            }

            position += chunkLen;
            baseState[12]++;
        }
    }

    private static void InitState(
        Span<uint> state,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        uint counter)
    {
        state[0] = Constant0;
        state[1] = Constant1;
        state[2] = Constant2;
        state[3] = Constant3;

        for (int i = 0; i < 8; i++)
        {
            state[4 + i] = ReadLeUInt32(key, i * 4);
        }

        state[12] = counter;
        state[13] = ReadLeUInt32(nonce, 0);
        state[14] = ReadLeUInt32(nonce, 4);
        state[15] = ReadLeUInt32(nonce, 8);
    }

    private static void DoTwentyRounds(Span<uint> s)
    {
        // 20 rounds = 10 double rounds (column + diagonal).
        for (int i = 0; i < 10; i++)
        {
            // Column rounds.
            QuarterRound(ref s[0], ref s[4], ref s[8], ref s[12]);
            QuarterRound(ref s[1], ref s[5], ref s[9], ref s[13]);
            QuarterRound(ref s[2], ref s[6], ref s[10], ref s[14]);
            QuarterRound(ref s[3], ref s[7], ref s[11], ref s[15]);

            // Diagonal rounds.
            QuarterRound(ref s[0], ref s[5], ref s[10], ref s[15]);
            QuarterRound(ref s[1], ref s[6], ref s[11], ref s[12]);
            QuarterRound(ref s[2], ref s[7], ref s[8], ref s[13]);
            QuarterRound(ref s[3], ref s[4], ref s[9], ref s[14]);
        }
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b; d ^= a; d = RotateLeft(d, 16);
        c += d; b ^= c; b = RotateLeft(b, 12);
        a += b; d ^= a; d = RotateLeft(d, 8);
        c += d; b ^= c; b = RotateLeft(b, 7);
    }

    private static uint RotateLeft(uint value, int shift) => (value << shift) | (value >> (32 - shift));

    private static uint ReadLeUInt32(ReadOnlySpan<byte> source, int offset)
        => (uint)source[offset]
         | ((uint)source[offset + 1] << 8)
         | ((uint)source[offset + 2] << 16)
         | ((uint)source[offset + 3] << 24);

    private static void SerializeState(ReadOnlySpan<uint> state, Span<byte> output)
    {
        for (int i = 0; i < 16; i++)
        {
            uint v = state[i];
            int offset = i * 4;
            output[offset] = (byte)v;
            output[offset + 1] = (byte)(v >> 8);
            output[offset + 2] = (byte)(v >> 16);
            output[offset + 3] = (byte)(v >> 24);
        }
    }
}
