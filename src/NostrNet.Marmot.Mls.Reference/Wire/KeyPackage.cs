// SPDX-License-Identifier: MIT
//
// MLS KeyPackage per RFC 9420 §10.
//
//   struct {
//       ProtocolVersion version;
//       CipherSuite cipher_suite;
//       HPKEPublicKey init_key;
//       LeafNode leaf_node;
//       Extension extensions<V>;
//       opaque signature<V>;  // SignWithLabel(leaf_node.signature_key, "KeyPackageTBS", KeyPackageTBS)
//   } KeyPackage;
//
// The KeyPackage signature is performed by the holder's signature key
// (the same key advertised in the embedded LeafNode), so a recipient can
// verify both bindings (leaf and package) without a separate trust step.

using System.Security.Cryptography;
using NostrNet.Marmot.Mls.Reference.Crypto;
using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>An MLS KeyPackage: a self-signed key bundle published by a prospective member.</summary>
internal sealed record KeyPackage
{
    /// <summary>Protocol version (MLS 1.0 only).</summary>
    public required ProtocolVersion Version { get; init; }

    /// <summary>Ciphersuite identifier.</summary>
    public required Ciphersuite Ciphersuite { get; init; }

    /// <summary>HPKE (X25519) public key for Welcome encryption.</summary>
    public required byte[] InitKey { get; init; }

    /// <summary>The LeafNode this package contributes to the tree.</summary>
    public required LeafNode Leaf { get; init; }

    /// <summary>Package-level extensions (not the leaf's).</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = Array.Empty<Extension>();

    /// <summary>Ed25519 signature over <c>KeyPackageTBS</c>.</summary>
    public required byte[] Signature { get; init; }

    /// <summary>Serializes the KeyPackage to TLS bytes.</summary>
    public byte[] Encode()
    {
        var buf = new byte[1 << 14];
        var w = new TlsWriter(buf);
        Write(ref w);
        return buf[..w.BytesWritten];
    }

    /// <summary>Writes the KeyPackage (with signature) to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        WriteUnsigned(ref w);
        w.WriteOpaqueVarInt(Signature);
    }

    /// <summary>Parses a KeyPackage from TLS bytes.</summary>
    public static KeyPackage Decode(ReadOnlySpan<byte> bytes)
    {
        var r = new TlsReader(bytes);
        return Read(ref r);
    }

    /// <summary>Reads a KeyPackage from a TLS stream.</summary>
    public static KeyPackage Read(ref TlsReader r)
    {
        var version = (ProtocolVersion)r.ReadUInt16BigEndian();
        var suite = (Ciphersuite)r.ReadUInt16BigEndian();
        byte[] initKey = r.ReadOpaqueVarInt().ToArray();
        var leaf = LeafNode.Read(ref r);
        var exts = Extension.ReadVector(ref r);
        byte[] sig = r.ReadOpaqueVarInt().ToArray();

        return new KeyPackage
        {
            Version = version,
            Ciphersuite = suite,
            InitKey = initKey,
            Leaf = leaf,
            Extensions = exts,
            Signature = sig,
        };
    }

    /// <summary>Computes the KeyPackageTBS bytes (everything before the signature).</summary>
    public byte[] ComputeTbs()
    {
        var buf = new byte[1 << 14];
        var w = new TlsWriter(buf);
        WriteUnsigned(ref w);
        return buf[..w.BytesWritten];
    }

    /// <summary>
    /// Verifies both the leaf signature and the KeyPackage signature.
    /// Returns <c>true</c> only if both pass.
    /// </summary>
    public bool Verify()
    {
        if (!Leaf.VerifySignature())
        {
            return false;
        }

        byte[] tbs = ComputeTbs();
        byte[] signContent = MlsSignature.BuildSignContent("KeyPackageTBS", tbs);
        return Crypto.Ed25519.Verify(Leaf.SignatureKey, signContent, Signature);
    }

    /// <summary>
    /// Builds and signs a complete KeyPackage given a freshly-signed LeafNode
    /// and the corresponding signature private key.
    /// </summary>
    public static KeyPackage Sign(
        ProtocolVersion version,
        Ciphersuite suite,
        byte[] initKey,
        LeafNode leaf,
        byte[] signaturePrivateKey,
        IReadOnlyList<Extension>? extensions = null)
    {
        // Sanity-check key length.
        if (initKey.Length != CiphersuiteInfo.Npk)
        {
            throw new ArgumentException(
                $"Init key must be {CiphersuiteInfo.Npk} bytes for X25519.", nameof(initKey));
        }

        byte[] derivedPub = Crypto.Ed25519.DerivePublicKey(signaturePrivateKey);
        if (!CryptographicOperations.FixedTimeEquals(derivedPub, leaf.SignatureKey))
        {
            throw new ArgumentException("signaturePrivateKey does not match leaf.SignatureKey.", nameof(signaturePrivateKey));
        }

        var unsigned = new KeyPackage
        {
            Version = version,
            Ciphersuite = suite,
            InitKey = initKey,
            Leaf = leaf,
            Extensions = extensions ?? Array.Empty<Extension>(),
            Signature = Array.Empty<byte>(),
        };

        byte[] tbs = unsigned.ComputeTbs();
        byte[] signContent = MlsSignature.BuildSignContent("KeyPackageTBS", tbs);
        byte[] sig = Crypto.Ed25519.Sign(signaturePrivateKey, signContent);

        return unsigned with { Signature = sig };
    }

    /// <summary>
    /// Computes the KeyPackage reference per RFC 9420 §5.2 RefHash:
    /// <c>Hash("MLS 1.0 KeyPackage Reference", MLSEncode(KeyPackage))</c>.
    /// </summary>
    public byte[] ComputeReference()
    {
        byte[] encoded = Encode();
        return RefHash("KeyPackage Reference", encoded);
    }

    private static byte[] RefHash(string label, byte[] value)
    {
        byte[] labelBytes = new byte[8 + label.Length];
        System.Text.Encoding.ASCII.GetBytes("MLS 1.0 ", labelBytes);
        System.Text.Encoding.ASCII.GetBytes(label, labelBytes.AsSpan(8));

        int size = TlsWriter.VarIntLength((ulong)labelBytes.Length) + labelBytes.Length
                 + TlsWriter.VarIntLength((ulong)value.Length) + value.Length;
        byte[] buf = new byte[size];
        var w = new TlsWriter(buf);
        w.WriteOpaqueVarInt(labelBytes);
        w.WriteOpaqueVarInt(value);

        return SHA256.HashData(buf.AsSpan(0, w.BytesWritten));
    }

    private void WriteUnsigned(ref TlsWriter w)
    {
        w.WriteUInt16BigEndian((ushort)Version);
        w.WriteUInt16BigEndian((ushort)Ciphersuite);
        w.WriteOpaqueVarInt(InitKey);
        Leaf.Write(ref w);
        Extension.WriteVector(ref w, Extensions);
    }
}
