// SPDX-License-Identifier: MIT
//
// MLS GroupSecrets per RFC 9420 §12.4.3.1.
//
//   struct {
//       opaque path_secret<V>;
//   } PathSecret;
//
//   struct {
//       opaque joiner_secret<V>;
//       optional<PathSecret> path_secret;
//       PreSharedKeyID psks<V>;
//   } GroupSecrets;
//
// This is the plaintext that gets HPKE-encrypted to each new member
// inside a Welcome. For the reference provider's group-of-2 case there
// is no UpdatePath (path_secret = absent) and no PSKs (empty psks vector).

using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>
/// The plaintext payload of <c>encrypted_group_secrets</c> in a Welcome.
/// </summary>
/// <param name="JoinerSecret">The joiner_secret — primary input to the new member's key schedule.</param>
/// <param name="PathSecret">Optional path secret. Always <c>null</c> in the reference provider.</param>
internal sealed record GroupSecrets(byte[] JoinerSecret, byte[]? PathSecret = null)
{
    /// <summary>Serializes the GroupSecrets to TLS bytes.</summary>
    public byte[] Encode()
    {
        var buf = new byte[1 << 12];
        var w = new TlsWriter(buf);
        Write(ref w);
        return buf[..w.BytesWritten];
    }

    /// <summary>Writes to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        w.WriteOpaqueVarInt(JoinerSecret);
        if (PathSecret is null)
        {
            w.WriteUInt8(0); // optional<PathSecret> absent
        }
        else
        {
            w.WriteUInt8(1);
            w.WriteOpaqueVarInt(PathSecret);
        }

        // PreSharedKeyID psks<V> — empty vector.
        w.WriteVarInt(0);
    }

    /// <summary>Parses from TLS bytes.</summary>
    public static GroupSecrets Decode(ReadOnlySpan<byte> bytes)
    {
        var r = new TlsReader(bytes);
        return Read(ref r);
    }

    /// <summary>Reads from a TLS stream.</summary>
    public static GroupSecrets Read(ref TlsReader r)
    {
        byte[] joiner = r.ReadOpaqueVarInt().ToArray();
        byte hasPath = r.ReadUInt8();
        byte[]? pathSecret = null;
        if (hasPath == 1)
        {
            pathSecret = r.ReadOpaqueVarInt().ToArray();
        }
        else if (hasPath != 0)
        {
            throw new System.IO.InvalidDataException($"Invalid optional discriminant {hasPath}.");
        }

        // Skip psks vector (must be empty for this provider).
        var psks = r.ReadOpaqueVarInt();
        if (psks.Length != 0)
        {
            throw new NotSupportedException("PSKs are not supported by the reference provider.");
        }

        return new GroupSecrets(joiner, pathSecret);
    }
}
