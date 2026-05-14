// SPDX-License-Identifier: MIT
//
// MLS GroupContext per RFC 9420 §8.1.
//
//   struct {
//       ProtocolVersion version;
//       CipherSuite cipher_suite;
//       opaque group_id<V>;
//       uint64 epoch;
//       opaque tree_hash<V>;
//       opaque confirmed_transcript_hash<V>;
//       Extension extensions<V>;
//   } GroupContext;
//
// The GroupContext bytes are mixed into the MLS key schedule (epoch_secret
// derivation), so any disagreement between members on this struct's
// encoding leads to a divergent epoch_secret and the group splitting.

using NostrNet.Marmot.Mls.Reference.Crypto;
using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>The MLS GroupContext: per-epoch group state mixed into the key schedule.</summary>
internal sealed record GroupContext
{
    /// <summary>Protocol version.</summary>
    public required ProtocolVersion Version { get; init; }

    /// <summary>Ciphersuite identifier.</summary>
    public required Ciphersuite Ciphersuite { get; init; }

    /// <summary>Group id (opaque, chosen by the founder).</summary>
    public required byte[] GroupId { get; init; }

    /// <summary>Epoch counter — starts at 0 and increments per Commit.</summary>
    public required ulong Epoch { get; init; }

    /// <summary>Hash of the ratchet tree at this epoch.</summary>
    public required byte[] TreeHash { get; init; }

    /// <summary>
    /// Hash of the chain of confirmed Commits up to this epoch. For our
    /// minimal scope (no Commit publication, no Update proposals) both
    /// sides use the all-zero hash.
    /// </summary>
    public required byte[] ConfirmedTranscriptHash { get; init; }

    /// <summary>Extensions on the group context.</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = Array.Empty<Extension>();

    /// <summary>Serializes the GroupContext to TLS bytes.</summary>
    public byte[] Encode()
    {
        var buf = new byte[1 << 13];
        var w = new TlsWriter(buf);
        Write(ref w);
        return buf[..w.BytesWritten];
    }

    /// <summary>Writes the GroupContext to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        w.WriteUInt16BigEndian((ushort)Version);
        w.WriteUInt16BigEndian((ushort)Ciphersuite);
        w.WriteOpaqueVarInt(GroupId);
        w.WriteUInt64BigEndian(Epoch);
        w.WriteOpaqueVarInt(TreeHash);
        w.WriteOpaqueVarInt(ConfirmedTranscriptHash);
        Extension.WriteVector(ref w, Extensions);
    }

    /// <summary>Parses a GroupContext from TLS bytes.</summary>
    public static GroupContext Decode(ReadOnlySpan<byte> bytes)
    {
        var r = new TlsReader(bytes);
        return Read(ref r);
    }

    /// <summary>Reads a GroupContext from a TLS stream.</summary>
    public static GroupContext Read(ref TlsReader r)
    {
        var version = (ProtocolVersion)r.ReadUInt16BigEndian();
        var suite = (Ciphersuite)r.ReadUInt16BigEndian();
        byte[] groupId = r.ReadOpaqueVarInt().ToArray();
        ulong epoch = r.ReadUInt64BigEndian();
        byte[] treeHash = r.ReadOpaqueVarInt().ToArray();
        byte[] confHash = r.ReadOpaqueVarInt().ToArray();
        var exts = Extension.ReadVector(ref r);
        return new GroupContext
        {
            Version = version,
            Ciphersuite = suite,
            GroupId = groupId,
            Epoch = epoch,
            TreeHash = treeHash,
            ConfirmedTranscriptHash = confHash,
            Extensions = exts,
        };
    }
}
