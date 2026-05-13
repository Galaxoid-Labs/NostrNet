// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using NostrNet.Cryptography;
using NostrNet.Encoding;

namespace NostrNet.Keys;

/// <summary>
/// A 32-byte secp256k1 private key.
/// </summary>
/// <remarks>
/// <para>
/// Construction validates that the bytes form a usable secp256k1 scalar
/// (non-zero, less than the group order). The derived <see cref="PublicKey"/>
/// is computed eagerly and cached.
/// </para>
/// <para>
/// <see cref="PrivateKey"/> implements <see cref="IDisposable"/> and zeroes
/// its in-memory buffer when disposed. <see cref="ToString"/> deliberately
/// returns a redacted placeholder; the secret value never appears in logs or
/// exceptions. Use <see cref="ToHex"/> or <see cref="ToNsec"/> to obtain the
/// secret only when explicitly required.
/// </para>
/// </remarks>
public sealed class PrivateKey : IDisposable, IEquatable<PrivateKey>
{
    /// <summary>Length of a private key in bytes.</summary>
    public const int Size = 32;

    /// <summary>Human-readable prefix for NIP-19 nsec bech32 encoding.</summary>
    public const string NsecHrp = "nsec";

    private readonly byte[] _bytes;
    private readonly PublicKey _publicKey;
    private bool _disposed;

    /// <summary>
    /// Creates a private key from a 32-byte buffer.
    /// </summary>
    /// <param name="bytes">Exactly 32 bytes representing a valid secp256k1 scalar.</param>
    /// <exception cref="ArgumentException">The buffer is the wrong size or not a valid scalar.</exception>
    public PrivateKey(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Size)
        {
            throw new ArgumentException($"Private key must be {Size} bytes.", nameof(bytes));
        }

        _bytes = bytes.ToArray();

        // Validate by deriving the public key. Throws ArgumentException on a
        // bad scalar.
        Span<byte> pub = stackalloc byte[PublicKey.Size];
        try
        {
            Secp256k1.GetXOnlyPublicKey(_bytes, pub);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(_bytes);
            throw;
        }

        _publicKey = new PublicKey(pub);
    }

    /// <summary>
    /// Generates a fresh random private key using the system CSPRNG.
    /// </summary>
    public static PrivateKey Generate()
    {
        Span<byte> buf = stackalloc byte[Size];
        while (true)
        {
            RandomNumberGenerator.Fill(buf);
            try
            {
                return new PrivateKey(buf);
            }
            catch (ArgumentException)
            {
                // Astronomically unlikely (scalar out of range); regenerate.
            }
        }
    }

    /// <summary>
    /// Parses a 64-character hex string into a private key.
    /// </summary>
    /// <exception cref="FormatException">The string is not 64 hex characters.</exception>
    public static PrivateKey FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        if (hex.Length != Size * 2)
        {
            throw new FormatException($"Private key hex must be {Size * 2} characters.");
        }

        byte[]? bytes = null;
        try
        {
            bytes = Convert.FromHexString(hex);
            return new PrivateKey(bytes);
        }
        finally
        {
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    /// <summary>Attempts to parse a hex private key. Returns <c>false</c> on any failure.</summary>
    public static bool TryFromHex(string? hex, [NotNullWhen(true)] out PrivateKey? privateKey)
    {
        privateKey = null;
        if (hex is null || hex.Length != Size * 2)
        {
            return false;
        }

        byte[]? bytes = null;
        try
        {
            bytes = Convert.FromHexString(hex);
            privateKey = new PrivateKey(bytes);
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
        finally
        {
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    /// <summary>
    /// Parses a NIP-19 <c>nsec1...</c> bech32 string.
    /// </summary>
    /// <exception cref="FormatException">The input is not a valid <c>nsec</c>.</exception>
    public static PrivateKey FromNsec(string nsec)
    {
        ArgumentNullException.ThrowIfNull(nsec);
        var decoded = Bech32.Decode(nsec);
        if (!string.Equals(decoded.Hrp, NsecHrp, StringComparison.Ordinal))
        {
            throw new FormatException($"Expected '{NsecHrp}' bech32 prefix.");
        }

        if (decoded.Data.Length != Size)
        {
            throw new FormatException($"nsec payload must be {Size} bytes; got {decoded.Data.Length}.");
        }

        try
        {
            return new PrivateKey(decoded.Data);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decoded.Data);
        }
    }

    /// <summary>Attempts to parse an <c>nsec</c> bech32 string. Returns <c>false</c> on any failure.</summary>
    public static bool TryFromNsec(string? nsec, [NotNullWhen(true)] out PrivateKey? privateKey)
    {
        privateKey = null;
        if (nsec is null)
        {
            return false;
        }

        try
        {
            privateKey = FromNsec(nsec);
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
    /// The x-only public key derived from this private key.
    /// </summary>
    public PublicKey PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    /// <summary>Returns the lowercase 64-character hex encoding of the secret.</summary>
    public string ToHex()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Convert.ToHexStringLower(_bytes);
    }

    /// <summary>Returns the NIP-19 <c>nsec1...</c> bech32 encoding of the secret.</summary>
    public string ToNsec()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Bech32.Encode(NsecHrp, _bytes);
    }

    /// <summary>Copies the 32 raw secret bytes into <paramref name="destination"/>.</summary>
    public void CopyTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < Size)
        {
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));
        }

        _bytes.AsSpan().CopyTo(destination);
    }

    /// <summary>
    /// BIP-340 Schnorr signs a 32-byte message digest.
    /// </summary>
    /// <param name="message32">The 32-byte message to sign (typically a Nostr event id).</param>
    /// <param name="signature64">A 64-byte buffer to receive the signature.</param>
    /// <param name="auxRand">
    /// Either empty (deterministic) or exactly 32 bytes of fresh randomness
    /// (probabilistic, BIP-340 §3.3.1).
    /// </param>
    public void Sign(ReadOnlySpan<byte> message32, Span<byte> signature64, ReadOnlySpan<byte> auxRand = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Secp256k1.SchnorrSign(message32, _bytes, auxRand, signature64);
    }

    /// <inheritdoc/>
    public bool Equals(PrivateKey? other)
    {
        if (other is null || _disposed || other._disposed)
        {
            return false;
        }

        return _bytes.AsSpan().SequenceEqual(other._bytes);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is PrivateKey other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => _disposed ? 0 : BitConverter.ToInt32(_bytes, 0);

    /// <summary>
    /// Returns a redacted placeholder. The secret value never appears here.
    /// Use <see cref="ToHex"/> or <see cref="ToNsec"/> for the actual encoding.
    /// </summary>
    public override string ToString() => "PrivateKey(****)";

    /// <summary>Zeros the in-memory secret and marks this key unusable.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_bytes);
        _disposed = true;
    }
}
