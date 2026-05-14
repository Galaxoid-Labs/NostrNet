// SPDX-License-Identifier: MIT
//
// Minimal per-leaf application-message ratchet and a wire format suitable
// for kind-445 content payloads.
//
// This is a SIMPLIFIED subset of RFC 9420 §6.3 (PrivateMessage) + §15
// (Secret Tree). It is NOT interoperable with strict MLS — it
// intentionally omits sender_data encryption, ciphertext_sample binding,
// authenticated_data, reuse_guard, and the full secret-tree shape (we
// only need two leaves).
//
// Wire format (this is OUR encoding, not RFC 9420's):
//
//   struct {
//       uint16 wire_format = 0xFE02;   // private-use: "reference app message"
//       opaque group_id<V>;
//       uint64 epoch;
//       uint32 sender_leaf;
//       uint32 generation;
//       opaque ciphertext<V>;            // AEAD-encrypted application data
//   } ReferenceApplicationMessage;
//
// The header bytes preceding `ciphertext` are bound in as AEAD additional
// data so a flipped header byte fails authentication.
//
// Per-leaf ratchet:
//
//   leaf_app_base_secret = ExpandWithLabel(encryption_secret, "leaf-app", "leaf-{n}", Nh)
//
// Then for each generation g:
//
//   key_g           = ExpandWithLabel(ratchet_g, "key",   "", Nk)
//   nonce_g         = ExpandWithLabel(ratchet_g, "nonce", "", Nn)
//   ratchet_{g+1}   = ExpandWithLabel(ratchet_g, "secret","", Nh)
//
// On the receive side the highest generation seen per peer is tracked;
// messages with generation ≤ that high-water-mark are rejected.

using System.Security.Cryptography;
using NostrNet.Marmot.Mls.Reference.Crypto;
using SysEncoding = System.Text.Encoding;
using TlsReader = NostrNet.Marmot.Encoding.TlsReader;
using TlsWriter = NostrNet.Marmot.Encoding.TlsWriter;

namespace NostrNet.Marmot.Mls.Reference.Wire;

/// <summary>
/// A simple forward-ratcheting symmetric encryption stream keyed off a
/// per-leaf base secret. Each call to <see cref="NextKey"/> consumes one
/// generation and advances the ratchet.
/// </summary>
internal sealed class ApplicationRatchet
{
    private byte[] _ratchet;
    private uint _generation;

    public ApplicationRatchet(byte[] baseSecret, uint startingGeneration = 0)
    {
        if (baseSecret.Length != CiphersuiteInfo.Nh)
        {
            throw new ArgumentException($"baseSecret must be {CiphersuiteInfo.Nh} bytes.", nameof(baseSecret));
        }

        _ratchet = (byte[])baseSecret.Clone();
        _generation = startingGeneration;

        // Wind forward to the starting generation by re-deriving in place.
        for (uint i = 0; i < startingGeneration; i++)
        {
            _ratchet = Hkdf.MlsLabeledExpand(
                secret: _ratchet,
                label: SysEncoding.ASCII.GetBytes("secret"),
                context: ReadOnlySpan<byte>.Empty,
                length: CiphersuiteInfo.Nh);
        }
    }

    /// <summary>The next generation number that <see cref="NextKey"/> will produce.</summary>
    public uint NextGeneration => _generation;

    /// <summary>
    /// Returns the (key, nonce, generation) tuple for the current step
    /// and advances the ratchet. Callers MUST consume the tuple — there
    /// is no rewind.
    /// </summary>
    public (byte[] Key, byte[] Nonce, uint Generation) NextKey()
    {
        byte[] key = Hkdf.MlsLabeledExpand(
            secret: _ratchet,
            label: SysEncoding.ASCII.GetBytes("key"),
            context: ReadOnlySpan<byte>.Empty,
            length: CiphersuiteInfo.Nk);
        byte[] nonce = Hkdf.MlsLabeledExpand(
            secret: _ratchet,
            label: SysEncoding.ASCII.GetBytes("nonce"),
            context: ReadOnlySpan<byte>.Empty,
            length: CiphersuiteInfo.Nn);

        byte[] next = Hkdf.MlsLabeledExpand(
            secret: _ratchet,
            label: SysEncoding.ASCII.GetBytes("secret"),
            context: ReadOnlySpan<byte>.Empty,
            length: CiphersuiteInfo.Nh);
        CryptographicOperations.ZeroMemory(_ratchet);
        _ratchet = next;

        uint g = _generation;
        _generation = checked(_generation + 1);
        return (key, nonce, g);
    }

    /// <summary>
    /// Derives the (key, nonce) for an explicit generation
    /// <paramref name="target"/>. Used on the receive side to decrypt a
    /// message whose generation hasn't been reached yet. Advances the
    /// internal state to <paramref name="target"/> + 1.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The target generation has already been advanced past — re-using a
    /// generation is forbidden (replay protection).
    /// </exception>
    public (byte[] Key, byte[] Nonce) KeyForGeneration(uint target)
    {
        if (target < _generation)
        {
            throw new InvalidOperationException(
                $"Cannot derive a key for generation {target}; ratchet is already at generation {_generation}.");
        }

        while (_generation < target)
        {
            _ratchet = Hkdf.MlsLabeledExpand(
                secret: _ratchet,
                label: SysEncoding.ASCII.GetBytes("secret"),
                context: ReadOnlySpan<byte>.Empty,
                length: CiphersuiteInfo.Nh);
            _generation++;
        }

        var (key, nonce, _) = NextKey();
        return (key, nonce);
    }

    /// <summary>
    /// Derives a per-leaf application base secret from the group's
    /// <paramref name="encryptionSecret"/> for <paramref name="leafIndex"/>.
    /// </summary>
    public static byte[] DeriveLeafBaseSecret(byte[] encryptionSecret, uint leafIndex)
    {
        ArgumentNullException.ThrowIfNull(encryptionSecret);
        return Hkdf.MlsLabeledExpand(
            secret: encryptionSecret,
            label: SysEncoding.ASCII.GetBytes("leaf-app"),
            context: SysEncoding.ASCII.GetBytes($"leaf-{leafIndex}"),
            length: CiphersuiteInfo.Nh);
    }
}

/// <summary>
/// The plaintext view of a reference-format application message.
/// </summary>
internal sealed record ApplicationMessage(
    ushort WireFormat,
    byte[] GroupId,
    ulong Epoch,
    uint SenderLeaf,
    uint Generation,
    byte[] Plaintext);

/// <summary>
/// Codec for the reference application-message wire format. The encoding
/// is intentionally simple — see the file header comment for the struct
/// definition.
/// </summary>
internal static class ApplicationMessageCodec
{
    /// <summary>Wire-format discriminator for this reference codec (private-use range).</summary>
    public const ushort WireFormat = 0xFE02;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with the given AEAD <paramref name="key"/> and
    /// <paramref name="nonce"/>, binding the header bytes as AAD, and returns the full
    /// serialized message.
    /// </summary>
    public static byte[] Encode(
        byte[] groupId, ulong epoch, uint senderLeaf, uint generation,
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(groupId);

        // Write the header (everything up to but not including ciphertext).
        byte[] headerBuf = new byte[2 + TlsWriter.VarIntLength((ulong)groupId.Length) + groupId.Length + 8 + 4 + 4];
        var hw = new TlsWriter(headerBuf);
        hw.WriteUInt16BigEndian(WireFormat);
        hw.WriteOpaqueVarInt(groupId);
        hw.WriteUInt64BigEndian(epoch);
        hw.WriteUInt32BigEndian(senderLeaf);
        hw.WriteUInt32BigEndian(generation);
        ReadOnlySpan<byte> header = headerBuf.AsSpan(0, hw.BytesWritten);

        // AEAD-encrypt plaintext with header as AAD.
        byte[] ciphertext = new byte[plaintext.Length + CiphersuiteInfo.Nt];
        using (var aead = new AesGcm(key, CiphersuiteInfo.Nt))
        {
            aead.Encrypt(
                nonce,
                plaintext,
                ciphertext.AsSpan(0, plaintext.Length),
                ciphertext.AsSpan(plaintext.Length, CiphersuiteInfo.Nt),
                header);
        }

        // Append the ciphertext as an opaque<V> after the header.
        int ctVarIntLen = TlsWriter.VarIntLength((ulong)ciphertext.Length);
        byte[] full = new byte[header.Length + ctVarIntLen + ciphertext.Length];
        header.CopyTo(full);
        var tail = new TlsWriter(full.AsSpan(header.Length));
        tail.WriteOpaqueVarInt(ciphertext);
        return full;
    }

    /// <summary>
    /// Parses + decrypts a wire-format message. The caller supplies the
    /// (key, nonce) derived from the receive-side ratchet at the message's
    /// generation.
    /// </summary>
    public static ApplicationMessage Decode(
        ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        // Parse the header first; we need its bytes intact for AAD.
        var r = new TlsReader(bytes);
        ushort wireFormat = r.ReadUInt16BigEndian();
        if (wireFormat != WireFormat)
        {
            throw new InvalidDataException(
                $"Expected reference application-message wire format 0x{WireFormat:X4}; got 0x{wireFormat:X4}.");
        }

        var gid = r.ReadOpaqueVarInt().ToArray();
        ulong epoch = r.ReadUInt64BigEndian();
        uint senderLeaf = r.ReadUInt32BigEndian();
        uint generation = r.ReadUInt32BigEndian();
        int headerEnd = r.BytesRead;
        ReadOnlySpan<byte> header = bytes[..headerEnd];

        ReadOnlySpan<byte> ciphertext = r.ReadOpaqueVarInt();
        if (ciphertext.Length < CiphersuiteInfo.Nt)
        {
            throw new InvalidDataException("ApplicationMessage ciphertext is shorter than the AEAD tag.");
        }

        int ptLen = ciphertext.Length - CiphersuiteInfo.Nt;
        byte[] plaintext = new byte[ptLen];
        using var aead = new AesGcm(key, CiphersuiteInfo.Nt);
        // Throws AuthenticationTagMismatchException on bad tag — bubble up.
        aead.Decrypt(
            nonce,
            ciphertext[..ptLen],
            ciphertext[ptLen..],
            plaintext,
            header);

        return new ApplicationMessage(wireFormat, gid, epoch, senderLeaf, generation, plaintext);
    }
}
