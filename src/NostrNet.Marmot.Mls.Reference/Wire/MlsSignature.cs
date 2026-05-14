// SPDX-License-Identifier: MIT
//
// MLS SignWithLabel / VerifyWithLabel helpers (RFC 9420 §5.1.2).
//
//   struct {
//       opaque label<V> = "MLS 1.0 " + Label;
//       opaque content<V> = Content;
//   } SignContent;
//
//   SignWithLabel(K, Label, Content) = Sign(K, MLSEncode(SignContent))

using SysEncoding = System.Text.Encoding;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>MLS labeled-signature helpers (RFC 9420 §5.1.2).</summary>
public static class MlsSignature
{
    private const string LabelPrefix = "MLS 1.0 ";

    /// <summary>
    /// Builds the bytes that get signed under <paramref name="label"/>:
    /// <c>MLSEncode(SignContent{ "MLS 1.0 " + label, content })</c>.
    /// </summary>
    public static byte[] BuildSignContent(string label, ReadOnlySpan<byte> content)
    {
        byte[] labeled = new byte[LabelPrefix.Length + label.Length];
        int p = SysEncoding.ASCII.GetBytes(LabelPrefix, labeled);
        SysEncoding.ASCII.GetBytes(label, labeled.AsSpan(p));

        int size = TlsWriter.VarIntLength((ulong)labeled.Length) + labeled.Length
                 + TlsWriter.VarIntLength((ulong)content.Length) + content.Length;
        byte[] buf = new byte[size];
        var w = new TlsWriter(buf);
        w.WriteOpaqueVarInt(labeled);
        w.WriteOpaqueVarInt(content);
        return buf[..w.BytesWritten];
    }
}
