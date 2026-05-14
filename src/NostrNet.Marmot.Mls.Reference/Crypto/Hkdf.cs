// SPDX-License-Identifier: MIT
//
// Thin wrapper around .NET's HKDF-SHA256, plus the two flavors of
// "labeled" HKDF used by MLS and HPKE.
//
//   HPKE labels (RFC 9180 §4):
//     LabeledExtract(salt, suite_id, label, ikm)
//         labeled_ikm = "HPKE-v1" || suite_id || label || ikm
//         return Extract(salt, labeled_ikm)
//     LabeledExpand(prk, suite_id, label, info, L)
//         labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
//         return Expand(prk, labeled_info, L)
//
//   MLS labels (RFC 9420 §5.2):
//     LabeledExtract(salt, label, ikm)
//         labeled_ikm = "MLS 1.0 " || label || ikm
//         return Extract(salt, labeled_ikm)
//     LabeledExpand(secret, label, context, L)
//         info = struct { uint16 length=L; opaque labeled_label<V>; opaque context<V>; }
//                where labeled_label = "MLS 1.0 " + label
//         return Expand(secret, info, L)
//
// MLS uses the MLS variable-length encoding (QUIC varint) for the
// length-prefixed fields. We reuse NostrNet.Marmot.Encoding.TlsWriter.

using System.Buffers.Binary;
using System.Security.Cryptography;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference.Crypto;

/// <summary>HKDF-SHA256 helpers with the labeled variants used by HPKE and MLS.</summary>
public static class Hkdf
{
    private const string HpkeVersionLabel = "HPKE-v1";
    private const string MlsVersionLabel = "MLS 1.0 ";

    /// <summary>HKDF-SHA256 Extract.</summary>
    public static byte[] Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> ikm)
    {
        byte[] prk = new byte[CiphersuiteInfo.Nh];
        int written = HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, prk);
        if (written != prk.Length)
        {
            throw new InvalidOperationException($"HKDF.Extract produced {written} bytes; expected {prk.Length}.");
        }

        return prk;
    }

    /// <summary>HKDF-SHA256 Expand. <paramref name="length"/> must be &lt;= 255 * 32.</summary>
    public static byte[] Expand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int length)
    {
        byte[] output = new byte[length];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, output, info);
        return output;
    }

    // ─────────────────────────────────────────────────────────────
    // HPKE labeled HKDF (RFC 9180).
    // ─────────────────────────────────────────────────────────────

    /// <summary>HPKE LabeledExtract per RFC 9180 §4.</summary>
    public static byte[] HpkeLabeledExtract(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> suiteId,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> ikm)
    {
        int len = HpkeVersionLabel.Length + suiteId.Length + label.Length + ikm.Length;
        byte[] labeledIkm = new byte[len];
        int p = 0;
        p += WriteAscii(labeledIkm.AsSpan(p), HpkeVersionLabel);
        suiteId.CopyTo(labeledIkm.AsSpan(p));
        p += suiteId.Length;
        label.CopyTo(labeledIkm.AsSpan(p));
        p += label.Length;
        ikm.CopyTo(labeledIkm.AsSpan(p));

        try
        {
            return Extract(salt, labeledIkm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(labeledIkm);
        }
    }

    /// <summary>HPKE LabeledExpand per RFC 9180 §4.</summary>
    public static byte[] HpkeLabeledExpand(
        ReadOnlySpan<byte> prk,
        ReadOnlySpan<byte> suiteId,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> info,
        int length)
    {
        // labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
        int total = 2 + HpkeVersionLabel.Length + suiteId.Length + label.Length + info.Length;
        byte[] labeledInfo = new byte[total];
        BinaryPrimitives.WriteUInt16BigEndian(labeledInfo.AsSpan(0, 2), (ushort)length);
        int p = 2;
        p += WriteAscii(labeledInfo.AsSpan(p), HpkeVersionLabel);
        suiteId.CopyTo(labeledInfo.AsSpan(p));
        p += suiteId.Length;
        label.CopyTo(labeledInfo.AsSpan(p));
        p += label.Length;
        info.CopyTo(labeledInfo.AsSpan(p));

        return Expand(prk, labeledInfo, length);
    }

    // ─────────────────────────────────────────────────────────────
    // MLS labeled HKDF (RFC 9420 §5.2).
    // ─────────────────────────────────────────────────────────────

    /// <summary>MLS LabeledExtract per RFC 9420 §5.2.</summary>
    public static byte[] MlsLabeledExtract(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> ikm)
    {
        // labeled_ikm = "MLS 1.0 " || label || ikm
        int len = MlsVersionLabel.Length + label.Length + ikm.Length;
        byte[] labeledIkm = new byte[len];
        int p = WriteAscii(labeledIkm, MlsVersionLabel);
        label.CopyTo(labeledIkm.AsSpan(p));
        p += label.Length;
        ikm.CopyTo(labeledIkm.AsSpan(p));

        try
        {
            return Extract(salt, labeledIkm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(labeledIkm);
        }
    }

    /// <summary>MLS LabeledExpand per RFC 9420 §5.2.</summary>
    /// <remarks>
    /// info encoding:
    /// <code>
    /// struct {
    ///     uint16 length = L;
    ///     opaque labeled_label&lt;V&gt; = "MLS 1.0 " + label;
    ///     opaque context&lt;V&gt; = context;
    /// }
    /// </code>
    /// </remarks>
    public static byte[] MlsLabeledExpand(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> context,
        int length)
    {
        byte[] labeledLabel = new byte[MlsVersionLabel.Length + label.Length];
        int p = WriteAscii(labeledLabel, MlsVersionLabel);
        label.CopyTo(labeledLabel.AsSpan(p));

        // info: uint16(length) || varint-prefixed labeled_label || varint-prefixed context
        // size = 2 + varintLen(labeled_label.Length) + labeled_label.Length
        //          + varintLen(context.Length) + context.Length
        int infoSize = 2
            + TlsWriter.VarIntLength((ulong)labeledLabel.Length) + labeledLabel.Length
            + TlsWriter.VarIntLength((ulong)context.Length) + context.Length;
        Span<byte> info = stackalloc byte[256];
        byte[]? rented = null;
        Span<byte> dest = infoSize <= info.Length ? info[..infoSize] : (rented = new byte[infoSize]).AsSpan();

        try
        {
            var w = new TlsWriter(dest);
            w.WriteUInt16BigEndian((ushort)length);
            w.WriteOpaqueVarInt(labeledLabel);
            w.WriteOpaqueVarInt(context);

            return Expand(secret, dest[..w.BytesWritten], length);
        }
        finally
        {
            if (rented is not null)
            {
                CryptographicOperations.ZeroMemory(rented);
            }
        }
    }

    /// <summary>
    /// MLS DeriveSecret(Secret, Label) = LabeledExpand(Secret, Label, "", Nh).
    /// Used everywhere in the MLS key schedule.
    /// </summary>
    public static byte[] DeriveSecret(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label)
        => MlsLabeledExpand(secret, label, ReadOnlySpan<byte>.Empty, CiphersuiteInfo.Nh);

    private static int WriteAscii(Span<byte> dest, string ascii)
    {
        return SysEncoding.ASCII.GetBytes(ascii, dest);
    }
}
