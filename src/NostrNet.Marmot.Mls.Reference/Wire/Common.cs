// SPDX-License-Identifier: MIT
//
// Small shared types and TLS-encoded primitives used across multiple
// MLS structs: ProtocolVersion, Extension, Capabilities, Lifetime,
// HPKECiphertext.
//
// RFC 9420 §6 (encoding), §7.2 (LeafNode), §10 (KeyPackage).

using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>MLS protocol version per RFC 9420 §6. Only <see cref="Mls10"/> is supported.</summary>
public enum ProtocolVersion : ushort
{
    /// <summary>MLS 1.0 (the only version defined).</summary>
    Mls10 = 0x0001,
}

/// <summary>MLS credential type per RFC 9420 §5.3.</summary>
public enum CredentialType : ushort
{
    /// <summary>Reserved.</summary>
    Reserved = 0x0000,

    /// <summary>BasicCredential: a single opaque identity blob.</summary>
    Basic = 0x0001,

    /// <summary>X.509 certificate chain.</summary>
    X509 = 0x0002,
}

/// <summary>LeafNode origin per RFC 9420 §7.2 §"leaf_node_source".</summary>
public enum LeafNodeSource : byte
{
    /// <summary>Leaf came from a KeyPackage (initial join).</summary>
    KeyPackage = 1,

    /// <summary>Leaf was contributed by an Update proposal.</summary>
    Update = 2,

    /// <summary>Leaf was contributed by a Commit's UpdatePath.</summary>
    Commit = 3,
}

/// <summary>A single MLS extension. RFC 9420 §6.5.</summary>
/// <param name="ExtensionType">IANA-assigned extension type.</param>
/// <param name="Data">Raw extension data (opaque to the framing layer).</param>
public sealed record Extension(ushort ExtensionType, byte[] Data)
{
    /// <summary>Writes a single Extension to <paramref name="w"/>.</summary>
    public void Write(ref TlsWriter w)
    {
        w.WriteUInt16BigEndian(ExtensionType);
        w.WriteOpaqueVarInt(Data);
    }

    /// <summary>Reads a single Extension.</summary>
    public static Extension Read(ref TlsReader r)
    {
        ushort type = r.ReadUInt16BigEndian();
        byte[] data = r.ReadOpaqueVarInt().ToArray();
        return new Extension(type, data);
    }

    /// <summary>Writes a length-prefixed vector of extensions.</summary>
    public static void WriteVector(ref TlsWriter w, IReadOnlyList<Extension> exts)
    {
        ulong byteLen = 0;
        for (int i = 0; i < exts.Count; i++)
        {
            byteLen += 2u + (ulong)TlsWriter.VarIntLength((ulong)exts[i].Data.Length) + (ulong)exts[i].Data.Length;
        }

        w.WriteVarInt(byteLen);
        for (int i = 0; i < exts.Count; i++)
        {
            exts[i].Write(ref w);
        }
    }

    /// <summary>Reads a length-prefixed vector of extensions.</summary>
    public static IReadOnlyList<Extension> ReadVector(ref TlsReader r)
    {
        var raw = r.ReadOpaqueVarInt();
        var inner = new TlsReader(raw);
        var list = new List<Extension>();
        while (inner.HasMore)
        {
            list.Add(Read(ref inner));
        }

        return list;
    }
}

/// <summary>Lifetime bounds carried in a KeyPackage-origin LeafNode. RFC 9420 §7.2.</summary>
/// <param name="NotBefore">Unix seconds, inclusive.</param>
/// <param name="NotAfter">Unix seconds, inclusive.</param>
public sealed record Lifetime(ulong NotBefore, ulong NotAfter)
{
    /// <summary>Writes to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        w.WriteUInt64BigEndian(NotBefore);
        w.WriteUInt64BigEndian(NotAfter);
    }

    /// <summary>Reads from a TLS stream.</summary>
    public static Lifetime Read(ref TlsReader r)
        => new(r.ReadUInt64BigEndian(), r.ReadUInt64BigEndian());
}

/// <summary>LeafNode capability advertisement. RFC 9420 §7.2.</summary>
/// <param name="Versions">Supported protocol versions.</param>
/// <param name="CipherSuites">Supported ciphersuites.</param>
/// <param name="ExtensionTypes">Extension types this node understands.</param>
/// <param name="ProposalTypes">Proposal types this node understands.</param>
/// <param name="CredentialTypes">Credential types this node understands.</param>
public sealed record Capabilities(
    IReadOnlyList<ushort> Versions,
    IReadOnlyList<ushort> CipherSuites,
    IReadOnlyList<ushort> ExtensionTypes,
    IReadOnlyList<ushort> ProposalTypes,
    IReadOnlyList<ushort> CredentialTypes)
{
    /// <summary>Writes a Capabilities struct.</summary>
    public void Write(ref TlsWriter w)
    {
        WriteUShortVector(ref w, Versions);
        WriteUShortVector(ref w, CipherSuites);
        WriteUShortVector(ref w, ExtensionTypes);
        WriteUShortVector(ref w, ProposalTypes);
        WriteUShortVector(ref w, CredentialTypes);
    }

    /// <summary>Reads a Capabilities struct.</summary>
    public static Capabilities Read(ref TlsReader r)
        => new(
            ReadUShortVector(ref r),
            ReadUShortVector(ref r),
            ReadUShortVector(ref r),
            ReadUShortVector(ref r),
            ReadUShortVector(ref r));

    private static void WriteUShortVector(ref TlsWriter w, IReadOnlyList<ushort> items)
    {
        w.WriteVarInt((ulong)items.Count * 2);
        for (int i = 0; i < items.Count; i++)
        {
            w.WriteUInt16BigEndian(items[i]);
        }
    }

    private static IReadOnlyList<ushort> ReadUShortVector(ref TlsReader r)
    {
        var raw = r.ReadOpaqueVarInt();
        if (raw.Length % 2 != 0)
        {
            throw new System.IO.InvalidDataException("uint16 vector has odd byte length.");
        }

        var list = new List<ushort>(raw.Length / 2);
        var inner = new TlsReader(raw);
        while (inner.HasMore)
        {
            list.Add(inner.ReadUInt16BigEndian());
        }

        return list;
    }
}

/// <summary>HPKE-encrypted ciphertext per RFC 9420 §6.1.</summary>
/// <param name="KemOutput">The HPKE <c>enc</c> (encapsulated ephemeral public key).</param>
/// <param name="Ciphertext">The AEAD ciphertext with the tag appended.</param>
public sealed record HpkeCiphertext(byte[] KemOutput, byte[] Ciphertext)
{
    /// <summary>Writes to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        w.WriteOpaqueVarInt(KemOutput);
        w.WriteOpaqueVarInt(Ciphertext);
    }

    /// <summary>Reads from a TLS stream.</summary>
    public static HpkeCiphertext Read(ref TlsReader r)
        => new(r.ReadOpaqueVarInt().ToArray(), r.ReadOpaqueVarInt().ToArray());
}
