// SPDX-License-Identifier: MIT
//
// MLS Credential per RFC 9420 §5.3. Only BasicCredential is supported.
//
//   struct {
//       CredentialType credential_type;     // uint16
//       select (Credential.credential_type) {
//           case basic:  opaque identity<V>;
//           case x509:   Certificate certs<V>;
//       };
//   } Credential;

using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>MLS BasicCredential — a single opaque identity blob.</summary>
/// <param name="Identity">
/// Identity bytes. For Marmot usage, this carries the 32-byte Nostr x-only
/// pubkey of the member, but the credential layer treats it as opaque.
/// </param>
public sealed record BasicCredential(byte[] Identity)
{
    /// <summary>Writes the Credential wrapping to a TLS stream.</summary>
    public void Write(ref TlsWriter w)
    {
        w.WriteUInt16BigEndian((ushort)CredentialType.Basic);
        w.WriteOpaqueVarInt(Identity);
    }

    /// <summary>Reads a Credential. Throws if the type is not BasicCredential.</summary>
    public static BasicCredential Read(ref TlsReader r)
    {
        ushort type = r.ReadUInt16BigEndian();
        if (type != (ushort)CredentialType.Basic)
        {
            throw new System.IO.InvalidDataException(
                $"Only BasicCredential is supported; got credential type 0x{type:X4}.");
        }

        return new BasicCredential(r.ReadOpaqueVarInt().ToArray());
    }
}
