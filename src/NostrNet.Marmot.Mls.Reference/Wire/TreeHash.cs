// SPDX-License-Identifier: MIT
//
// Tree hash for a minimal 2-leaf MLS ratchet tree (RFC 9420 §7.8).
//
//   struct {
//       NodeType node_type = leaf;   // 1
//       optional<LeafNode> leaf_node;
//   } LeafNodeHashInput;
//
//   struct {
//       NodeType node_type = parent; // 2
//       optional<ParentNode> parent_node;
//       opaque left_hash<V>;
//       opaque right_hash<V>;
//   } ParentNodeHashInput;
//
// optional<T> = uint8(present?1:0) || (present ? T-bytes : ε)
//
// For a 2-leaf tree at epoch 1 (the founder added one member and the
// Commit had no UpdatePath), the root has no payload — parent_node is
// optional and absent.

using System.Security.Cryptography;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>Tree-hash helpers for a 2-leaf MLS ratchet tree.</summary>
public static class TreeHash
{
    private const byte NodeTypeLeaf = 1;
    private const byte NodeTypeParent = 2;

    /// <summary>Computes the hash of a leaf node.</summary>
    public static byte[] LeafHash(LeafNode leaf)
    {
        byte[] leafBytes = leaf.Encode();
        // LeafNodeHashInput: uint8(1) || uint8(1) || leaf_bytes
        byte[] input = new byte[2 + leafBytes.Length];
        input[0] = NodeTypeLeaf;
        input[1] = 1;
        leafBytes.CopyTo(input, 2);
        return SHA256.HashData(input);
    }

    /// <summary>
    /// Computes the root hash for a 2-leaf tree whose root has no
    /// ParentNode payload (no Commit UpdatePath was applied).
    /// </summary>
    public static byte[] RootHashAtSize2(byte[] leftLeafHash, byte[] rightLeafHash)
    {
        // ParentNodeHashInput with absent parent_node:
        //   uint8(2) || uint8(0) || opaque<V>(left_hash) || opaque<V>(right_hash)
        int size = 2
            + TlsWriter.VarIntLength((ulong)leftLeafHash.Length) + leftLeafHash.Length
            + TlsWriter.VarIntLength((ulong)rightLeafHash.Length) + rightLeafHash.Length;
        byte[] buf = new byte[size];
        var w = new TlsWriter(buf);
        w.WriteUInt8(NodeTypeParent);
        w.WriteUInt8(0); // optional<ParentNode> absent
        w.WriteOpaqueVarInt(leftLeafHash);
        w.WriteOpaqueVarInt(rightLeafHash);
        return SHA256.HashData(buf.AsSpan(0, w.BytesWritten));
    }

    /// <summary>Convenience: full tree hash for a 2-leaf group.</summary>
    public static byte[] HashTwoMemberTree(LeafNode left, LeafNode right)
    {
        byte[] leftHash = LeafHash(left);
        byte[] rightHash = LeafHash(right);
        return RootHashAtSize2(leftHash, rightHash);
    }
}
