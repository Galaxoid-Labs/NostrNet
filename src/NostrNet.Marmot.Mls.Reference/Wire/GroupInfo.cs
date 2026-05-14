// SPDX-License-Identifier: MIT
//
// MLS GroupInfo per RFC 9420 §12.4.3.2.
//
//   struct {
//       GroupContext group_context;
//       Extension extensions<V>;
//       MAC confirmation_tag;       // opaque<V> — HMAC(confirmation_key, confirmed_transcript_hash)
//       uint32 signer;              // leaf_index of the signer
//       opaque signature<V>;         // SignWithLabel(signer's signature key, "GroupInfoTBS", encoded GroupInfoTBS)
//   } GroupInfo;
//
// GroupInfoTBS encodes everything except `signature`.
//
// The reference provider only emits a GroupInfo for the founder's
// initial Welcome (signer is leaf 0 = the founder).

using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>The MLS GroupInfo carried inside a Welcome's <c>encrypted_group_info</c> field.</summary>
public sealed record GroupInfo
{
    /// <summary>Group context for the epoch being joined.</summary>
    public required GroupContext GroupContext { get; init; }

    /// <summary>
    /// Extensions on the group info — for the reference provider this
    /// will carry the <c>ratchet_tree</c> extension (the two leaves
    /// composing the size-2 group).
    /// </summary>
    public required IReadOnlyList<Extension> Extensions { get; init; }

    /// <summary>HMAC tag tying the GroupInfo to the confirmation_key.</summary>
    public required byte[] ConfirmationTag { get; init; }

    /// <summary>Leaf index of the signer (always 0 for our founder-only emit).</summary>
    public required uint Signer { get; init; }

    /// <summary>Signature over GroupInfoTBS, by the signer's Ed25519 key.</summary>
    public required byte[] Signature { get; init; }

    /// <summary>Serializes the full GroupInfo to TLS bytes.</summary>
    public byte[] Encode()
    {
        var buf = new byte[1 << 14];
        var w = new TlsWriter(buf);
        Write(ref w);
        return buf[..w.BytesWritten];
    }

    /// <summary>Writes the full GroupInfo (including signature) to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        WriteUnsigned(ref w);
        w.WriteOpaqueVarInt(Signature);
    }

    /// <summary>Computes GroupInfoTBS (the signed body).</summary>
    public byte[] ComputeTbs()
    {
        var buf = new byte[1 << 14];
        var w = new TlsWriter(buf);
        WriteUnsigned(ref w);
        return buf[..w.BytesWritten];
    }

    /// <summary>Verifies the GroupInfo signature with the signer's Ed25519 public key.</summary>
    public bool VerifySignature(ReadOnlySpan<byte> signerPublicKey)
    {
        byte[] tbs = ComputeTbs();
        byte[] signContent = MlsSignature.BuildSignContent("GroupInfoTBS", tbs);
        return Crypto.Ed25519.Verify(signerPublicKey, signContent, Signature);
    }

    /// <summary>Parses from TLS bytes.</summary>
    public static GroupInfo Decode(ReadOnlySpan<byte> bytes)
    {
        var r = new TlsReader(bytes);
        return Read(ref r);
    }

    /// <summary>Reads from a TLS stream.</summary>
    public static GroupInfo Read(ref TlsReader r)
    {
        var ctx = GroupContext.Read(ref r);
        var exts = Extension.ReadVector(ref r);
        byte[] confirmationTag = r.ReadOpaqueVarInt().ToArray();
        uint signer = r.ReadUInt32BigEndian();
        byte[] signature = r.ReadOpaqueVarInt().ToArray();
        return new GroupInfo
        {
            GroupContext = ctx,
            Extensions = exts,
            ConfirmationTag = confirmationTag,
            Signer = signer,
            Signature = signature,
        };
    }

    /// <summary>
    /// Signs the GroupInfo with <paramref name="signerPrivateKey"/>.
    /// </summary>
    public static GroupInfo Sign(
        GroupContext groupContext,
        IReadOnlyList<Extension> extensions,
        byte[] confirmationTag,
        uint signerLeafIndex,
        byte[] signerPrivateKey)
    {
        var unsigned = new GroupInfo
        {
            GroupContext = groupContext,
            Extensions = extensions,
            ConfirmationTag = confirmationTag,
            Signer = signerLeafIndex,
            Signature = Array.Empty<byte>(),
        };

        byte[] tbs = unsigned.ComputeTbs();
        byte[] signContent = MlsSignature.BuildSignContent("GroupInfoTBS", tbs);
        byte[] sig = Crypto.Ed25519.Sign(signerPrivateKey, signContent);
        return unsigned with { Signature = sig };
    }

    private void WriteUnsigned(ref TlsWriter w)
    {
        GroupContext.Write(ref w);
        Extension.WriteVector(ref w, Extensions);
        w.WriteOpaqueVarInt(ConfirmationTag);
        w.WriteUInt32BigEndian(Signer);
    }
}
