// SPDX-License-Identifier: MIT
//
// MLS Welcome per RFC 9420 §12.4.3.1.
//
//   struct {
//       opaque[32] new_member;        // KeyPackageRef of the new member
//       HPKECiphertext encrypted_group_secrets;
//   } EncryptedGroupSecrets;
//
//   struct {
//       CipherSuite cipher_suite;
//       EncryptedGroupSecrets secrets<V>;
//       opaque encrypted_group_info<V>;
//   } Welcome;
//
// The reference provider only ever produces single-recipient Welcomes
// (one EncryptedGroupSecrets entry).

using NostrNet.Marmot.Mls.Reference.Crypto;
using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>One per-recipient encrypted-group-secrets entry inside a Welcome.</summary>
/// <param name="NewMember">32-byte KeyPackageRef identifying the recipient.</param>
/// <param name="EncryptedSecrets">HPKE-encrypted GroupSecrets payload.</param>
public sealed record EncryptedGroupSecrets(byte[] NewMember, HpkeCiphertext EncryptedSecrets)
{
    /// <summary>Writes to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        if (NewMember.Length != 32)
        {
            throw new InvalidOperationException("KeyPackageRef must be exactly 32 bytes.");
        }

        w.WriteRaw(NewMember);
        EncryptedSecrets.Write(ref w);
    }

    /// <summary>Reads from a TLS stream.</summary>
    public static EncryptedGroupSecrets Read(ref TlsReader r)
    {
        byte[] newMember = r.ReadRaw(32).ToArray();
        var ct = HpkeCiphertext.Read(ref r);
        return new EncryptedGroupSecrets(newMember, ct);
    }
}

/// <summary>The MLS Welcome message — the bytes that get base64-encoded into a Marmot kind-444 rumor.</summary>
public sealed record Welcome
{
    /// <summary>Ciphersuite identifier.</summary>
    public required Ciphersuite Ciphersuite { get; init; }

    /// <summary>Per-recipient encrypted-group-secrets entries.</summary>
    public required IReadOnlyList<EncryptedGroupSecrets> Secrets { get; init; }

    /// <summary>AEAD ciphertext of the encoded GroupInfo, keyed by welcome_secret.</summary>
    public required byte[] EncryptedGroupInfo { get; init; }

    /// <summary>Serializes to TLS bytes.</summary>
    public byte[] Encode()
    {
        var buf = new byte[1 << 14];
        var w = new TlsWriter(buf);
        Write(ref w);
        return buf[..w.BytesWritten];
    }

    /// <summary>Writes to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        w.WriteUInt16BigEndian((ushort)Ciphersuite);

        // Pre-compute serialized length of the secrets vector so we can write the varint prefix.
        int innerLen = 0;
        for (int i = 0; i < Secrets.Count; i++)
        {
            var s = Secrets[i];
            innerLen += 32; // new_member
            innerLen += TlsWriter.VarIntLength((ulong)s.EncryptedSecrets.KemOutput.Length) + s.EncryptedSecrets.KemOutput.Length;
            innerLen += TlsWriter.VarIntLength((ulong)s.EncryptedSecrets.Ciphertext.Length) + s.EncryptedSecrets.Ciphertext.Length;
        }

        w.WriteVarInt((ulong)innerLen);
        for (int i = 0; i < Secrets.Count; i++)
        {
            Secrets[i].Write(ref w);
        }

        w.WriteOpaqueVarInt(EncryptedGroupInfo);
    }

    /// <summary>Parses from TLS bytes.</summary>
    public static Welcome Decode(ReadOnlySpan<byte> bytes)
    {
        var r = new TlsReader(bytes);
        return Read(ref r);
    }

    /// <summary>Reads from a TLS stream.</summary>
    public static Welcome Read(ref TlsReader r)
    {
        var suite = (Ciphersuite)r.ReadUInt16BigEndian();

        var inner = new TlsReader(r.ReadOpaqueVarInt());
        var list = new List<EncryptedGroupSecrets>();
        while (inner.HasMore)
        {
            list.Add(EncryptedGroupSecrets.Read(ref inner));
        }

        byte[] encryptedGroupInfo = r.ReadOpaqueVarInt().ToArray();

        return new Welcome
        {
            Ciphersuite = suite,
            Secrets = list,
            EncryptedGroupInfo = encryptedGroupInfo,
        };
    }
}
