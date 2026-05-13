// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;
using NostrNet.Encoding;

namespace NostrNet.Keys;

/// <summary>
/// A 32-byte secp256k1 x-only public key (BIP-340).
/// </summary>
/// <remarks>
/// Construction validates the length but does not verify that the bytes
/// correspond to a point on the curve; that check is deferred to the
/// signature-verification path. NIP-19 <c>npub</c> bech32 encoding is provided
/// via <see cref="ToNpub"/> / <see cref="FromNpub"/>.
/// </remarks>
public sealed class PublicKey : IEquatable<PublicKey>
{
    /// <summary>Length of an x-only public key in bytes.</summary>
    public const int Size = 32;

    /// <summary>Human-readable prefix for NIP-19 npub bech32 encoding.</summary>
    public const string NpubHrp = "npub";

    private readonly byte[] _bytes;

    /// <summary>
    /// Creates a public key from a 32-byte buffer.
    /// </summary>
    /// <param name="bytes">Exactly 32 bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is not 32 bytes long.</exception>
    public PublicKey(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Size)
        {
            throw new ArgumentException($"Public key must be {Size} bytes.", nameof(bytes));
        }

        _bytes = bytes.ToArray();
    }

    /// <summary>
    /// Parses a lowercase or uppercase 64-character hex string into a public key.
    /// </summary>
    /// <exception cref="FormatException">The string is not 64 hex characters.</exception>
    public static PublicKey FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if (hex.Length != Size * 2)
        {
            throw new FormatException($"Public key hex must be {Size * 2} characters.");
        }

        return new PublicKey(Convert.FromHexString(hex));
    }

    /// <summary>Attempts to parse a hex public key. Returns <c>false</c> on any failure.</summary>
    public static bool TryFromHex(string? hex, [NotNullWhen(true)] out PublicKey? publicKey)
    {
        publicKey = null;
        if (hex is null || hex.Length != Size * 2)
        {
            return false;
        }

        try
        {
            publicKey = new PublicKey(Convert.FromHexString(hex));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Parses a NIP-19 <c>npub1...</c> bech32 string.
    /// </summary>
    /// <exception cref="FormatException">The input is not a valid <c>npub</c>.</exception>
    public static PublicKey FromNpub(string npub)
    {
        ArgumentNullException.ThrowIfNull(npub);
        var decoded = Bech32.Decode(npub);
        if (!string.Equals(decoded.Hrp, NpubHrp, StringComparison.Ordinal))
        {
            throw new FormatException($"Expected '{NpubHrp}' bech32 prefix.");
        }

        if (decoded.Data.Length != Size)
        {
            throw new FormatException($"npub payload must be {Size} bytes; got {decoded.Data.Length}.");
        }

        return new PublicKey(decoded.Data);
    }

    /// <summary>Attempts to parse an <c>npub</c> bech32 string. Returns <c>false</c> on any failure.</summary>
    public static bool TryFromNpub(string? npub, [NotNullWhen(true)] out PublicKey? publicKey)
    {
        publicKey = null;
        if (npub is null)
        {
            return false;
        }

        try
        {
            publicKey = FromNpub(npub);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>Returns the lowercase 64-character hex encoding.</summary>
    public string ToHex() => Convert.ToHexStringLower(_bytes);

    /// <summary>Returns the NIP-19 <c>npub1...</c> bech32 encoding.</summary>
    public string ToNpub() => Bech32.Encode(NpubHrp, _bytes);

    /// <summary>Copies the 32 raw bytes into <paramref name="destination"/>.</summary>
    /// <exception cref="ArgumentException">Destination is shorter than 32 bytes.</exception>
    public void CopyTo(Span<byte> destination)
    {
        if (destination.Length < Size)
        {
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));
        }

        _bytes.AsSpan().CopyTo(destination);
    }

    /// <summary>Returns a read-only view over the 32 raw bytes.</summary>
    public ReadOnlySpan<byte> AsSpan() => _bytes;

    /// <inheritdoc/>
    public bool Equals(PublicKey? other)
        => other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is PublicKey other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        // Use the first 4 bytes as a hash; collisions are astronomically rare
        // for honest pubkeys, and we accept them on adversarial input.
        return BitConverter.ToInt32(_bytes, 0);
    }

    /// <inheritdoc/>
    public override string ToString() => ToHex();

    /// <summary>Compares two public keys for value equality.</summary>
    public static bool operator ==(PublicKey? left, PublicKey? right)
        => left is null ? right is null : left.Equals(right);

    /// <summary>Compares two public keys for inequality.</summary>
    public static bool operator !=(PublicKey? left, PublicKey? right) => !(left == right);
}
