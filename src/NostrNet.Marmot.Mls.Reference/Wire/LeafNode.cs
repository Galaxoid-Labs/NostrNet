// SPDX-License-Identifier: MIT
//
// MLS LeafNode per RFC 9420 §7.2.
//
// The signature is computed via SignWithLabel(signature_key,
// "LeafNodeTBS", MLSEncode(LeafNodeTBS)) per RFC 9420 §5.1.2.
//
// The TBS form omits the trailing signature field and, for Update/Commit
// origins, appends (group_id, leaf_index). This minimal implementation
// only supports leaf_node_source = KeyPackage, so the TBS suffix is empty.

using System.Security.Cryptography;
using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>
/// A leaf in the MLS ratchet tree. Carries the member's encryption /
/// signature keys, credential, capabilities, and signed metadata.
/// </summary>
internal sealed record LeafNode
{
    /// <summary>X25519 HPKE public key used to receive direct messages in the tree.</summary>
    public required byte[] EncryptionKey { get; init; }

    /// <summary>Ed25519 signature public key for this member.</summary>
    public required byte[] SignatureKey { get; init; }

    /// <summary>BasicCredential — the only credential type supported.</summary>
    public required BasicCredential Credential { get; init; }

    /// <summary>Capabilities declared by this member.</summary>
    public required Capabilities Capabilities { get; init; }

    /// <summary>Origin of this leaf (only <see cref="LeafNodeSource.KeyPackage"/> is supported here).</summary>
    public required LeafNodeSource Source { get; init; }

    /// <summary>Lifetime — present iff <see cref="Source"/> is KeyPackage.</summary>
    public Lifetime? Lifetime { get; init; }

    /// <summary>Extensions attached to this leaf.</summary>
    public IReadOnlyList<Extension> Extensions { get; init; } = Array.Empty<Extension>();

    /// <summary>Ed25519 signature over the LeafNodeTBS form.</summary>
    public required byte[] Signature { get; init; }

    /// <summary>Serializes the LeafNode to TLS bytes.</summary>
    public byte[] Encode()
    {
        var buf = new byte[1 << 13];
        var w = new TlsWriter(buf);
        Write(ref w);
        return buf[..w.BytesWritten];
    }

    /// <summary>Writes the LeafNode (including signature) to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        WriteUnsigned(ref w);
        w.WriteOpaqueVarInt(Signature);
    }

    /// <summary>Parses a LeafNode from TLS bytes.</summary>
    public static LeafNode Decode(ReadOnlySpan<byte> bytes)
    {
        var r = new TlsReader(bytes);
        return Read(ref r);
    }

    /// <summary>Reads a LeafNode from a TLS stream.</summary>
    public static LeafNode Read(ref TlsReader r)
    {
        byte[] encKey = r.ReadOpaqueVarInt().ToArray();
        byte[] sigKey = r.ReadOpaqueVarInt().ToArray();
        var cred = BasicCredential.Read(ref r);
        var caps = Capabilities.Read(ref r);
        var source = (LeafNodeSource)r.ReadUInt8();
        Lifetime? lifetime = source switch
        {
            LeafNodeSource.KeyPackage => Lifetime.Read(ref r),
            LeafNodeSource.Update => null,
            LeafNodeSource.Commit => throw new NotSupportedException("LeafNodeSource.Commit not supported by reference provider."),
            _ => throw new System.IO.InvalidDataException($"Unknown LeafNodeSource {(byte)source}."),
        };

        var exts = Extension.ReadVector(ref r);
        byte[] sig = r.ReadOpaqueVarInt().ToArray();

        return new LeafNode
        {
            EncryptionKey = encKey,
            SignatureKey = sigKey,
            Credential = cred,
            Capabilities = caps,
            Source = source,
            Lifetime = lifetime,
            Extensions = exts,
            Signature = sig,
        };
    }

    /// <summary>
    /// Computes the LeafNodeTBS bytes — the signed input. The TBS form is
    /// everything before <see cref="Signature"/>, plus a source-specific
    /// suffix (empty for KeyPackage-origin).
    /// </summary>
    public byte[] ComputeTbs()
    {
        var buf = new byte[1 << 13];
        var w = new TlsWriter(buf);
        WriteUnsigned(ref w);
        // For LeafNodeSource.KeyPackage, the TBS suffix is empty.
        // Update/Commit would append group_id + leaf_index here.
        return buf[..w.BytesWritten];
    }

    private void WriteUnsigned(ref TlsWriter w)
    {
        w.WriteOpaqueVarInt(EncryptionKey);
        w.WriteOpaqueVarInt(SignatureKey);
        Credential.Write(ref w);
        Capabilities.Write(ref w);
        w.WriteUInt8((byte)Source);
        switch (Source)
        {
            case LeafNodeSource.KeyPackage:
                if (Lifetime is null)
                {
                    throw new InvalidOperationException("KeyPackage-origin LeafNode requires a Lifetime.");
                }

                Lifetime.Write(ref w);
                break;
            case LeafNodeSource.Update:
                break;
            case LeafNodeSource.Commit:
                throw new NotSupportedException("LeafNodeSource.Commit not supported by reference provider.");
            default:
                throw new InvalidOperationException($"Unknown LeafNodeSource {(byte)Source}.");
        }

        Extension.WriteVector(ref w, Extensions);
    }

    /// <summary>
    /// Verifies the leaf's signature with its embedded <see cref="SignatureKey"/>
    /// (which is the member's Ed25519 public key).
    /// </summary>
    public bool VerifySignature()
    {
        byte[] tbs = ComputeTbs();
        byte[] signContent = MlsSignature.BuildSignContent("LeafNodeTBS", tbs);
        return Crypto.Ed25519.Verify(SignatureKey, signContent, Signature);
    }

    /// <summary>
    /// Signs the LeafNode with the given Ed25519 private key (which MUST
    /// match the embedded signature public key).
    /// </summary>
    public static LeafNode Sign(
        byte[] encryptionKey,
        byte[] signatureKey,
        byte[] signaturePrivateKey,
        BasicCredential credential,
        Capabilities capabilities,
        Lifetime lifetime,
        IReadOnlyList<Extension> extensions)
    {
        // Validate the private/public key pair before producing a signature.
        byte[] derivedPub = Crypto.Ed25519.DerivePublicKey(signaturePrivateKey);
        if (!CryptographicOperations.FixedTimeEquals(derivedPub, signatureKey))
        {
            throw new ArgumentException("signaturePrivateKey does not match signatureKey.", nameof(signaturePrivateKey));
        }

        var unsigned = new LeafNode
        {
            EncryptionKey = encryptionKey,
            SignatureKey = signatureKey,
            Credential = credential,
            Capabilities = capabilities,
            Source = LeafNodeSource.KeyPackage,
            Lifetime = lifetime,
            Extensions = extensions,
            Signature = Array.Empty<byte>(),
        };

        byte[] tbs = unsigned.ComputeTbs();
        byte[] signContent = MlsSignature.BuildSignContent("LeafNodeTBS", tbs);
        byte[] sig = Crypto.Ed25519.Sign(signaturePrivateKey, signContent);

        return unsigned with { Signature = sig };
    }
}
