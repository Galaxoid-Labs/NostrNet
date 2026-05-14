// SPDX-License-Identifier: MIT
//
// IMarmotMlsProvider implementation backed by OpenMLS via the
// nostrnet-marmot-native FFI bridge.
//
// Phase 1: lifecycle + a couple of trivial operations. The full
// IMarmotMlsProvider surface lands in subsequent FFI iterations.

using NostrNet.Keys;
using NostrNet.Marmot.GroupData;
using NostrNet.Marmot.Mls.Native.Interop;

namespace NostrNet.Marmot.Mls.Native;

/// <summary>
/// OpenMLS-backed <see cref="IMarmotMlsProvider"/>. Wire bytes produced
/// by this provider are RFC 9420 compliant and interoperate with any
/// strict Marmot/MLS client (subject to phase-5 cross-implementation
/// verification still being pending).
/// </summary>
public sealed class OpenMlsProvider : IMarmotMlsProvider, IDisposable
{
    private readonly ProviderHandle _handle;
    private bool _disposed;

    /// <summary>Creates a new OpenMLS-backed provider with in-memory state.</summary>
    public OpenMlsProvider()
    {
        _handle = ProviderHandle.CreateNew();
    }

    /// <summary>Returns the FFI ABI version reported by the native library.</summary>
    public static uint NativeAbiVersion() => NativeBindings.AbiVersion();

    // ────────────────────────────────────────────────────────────
    // IMarmotMlsProvider — phase 1 stubs.
    // ────────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public unsafe Task<KeyPackageBundle> BuildKeyPackageAsync(
        PublicKey identityPubkey,
        ushort ciphersuite,
        IReadOnlyList<ushort> extensions,
        IReadOnlyList<ushort> proposals,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(identityPubkey);
        ArgumentNullException.ThrowIfNull(extensions);
        ArgumentNullException.ThrowIfNull(proposals);

        Span<byte> identity = stackalloc byte[32];
        identityPubkey.CopyTo(identity);

        ushort[] extsArr = extensions.ToArray();
        ushort[] propsArr = proposals.ToArray();

        IntPtr bundlePtr = IntPtr.Zero;
        nuint bundleLen = 0;
        IntPtr refPtr = IntPtr.Zero;
        nuint refLen = 0;

        int rc;
        fixed (byte* identityPin = identity)
        fixed (ushort* extsPin = extsArr)
        fixed (ushort* propsPin = propsArr)
        {
            rc = NativeBindings.BuildKeyPackage(
                _handle.DangerousPointer,
                identityPin, (nuint)identity.Length,
                ciphersuite,
                extsPin, (nuint)extsArr.Length,
                propsPin, (nuint)propsArr.Length,
                &bundlePtr, &bundleLen,
                &refPtr, &refLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(BuildKeyPackageAsync));
        }

        byte[] bundle = FfiBuffer.CopyAndFree(bundlePtr, bundleLen);
        byte[] kpRef = FfiBuffer.CopyAndFree(refPtr, refLen);

        return Task.FromResult(new KeyPackageBundle(
            BundleBytes: bundle,
            Ciphersuite: ciphersuite,
            ProtocolVersion: "1.0",
            KeyPackageRef: Convert.ToHexStringLower(kpRef)));
    }

    /// <inheritdoc/>
    public unsafe Task<KeyPackageInfo> ParseKeyPackageAsync(
        ReadOnlyMemory<byte> keyPackageBundleBytes,
        CancellationToken ct = default)
    {
        var span = keyPackageBundleBytes.Span;
        IntPtr identityPtr = IntPtr.Zero;
        nuint identityLen = 0;
        IntPtr refPtr = IntPtr.Zero;
        nuint refLen = 0;
        ushort cs = 0;

        int rc;
        fixed (byte* bundlePin = span)
        {
            rc = NativeBindings.ParseKeyPackage(
                bundlePin, (nuint)span.Length,
                &identityPtr, &identityLen,
                &refPtr, &refLen,
                &cs);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(ParseKeyPackageAsync));
        }

        byte[] identity = FfiBuffer.CopyAndFree(identityPtr, identityLen);
        byte[] kpRef = FfiBuffer.CopyAndFree(refPtr, refLen);

        if (identity.Length != 32)
        {
            throw new InvalidDataException(
                $"BasicCredential identity must be 32 bytes (a Nostr pubkey); got {identity.Length}.");
        }

        return Task.FromResult(new KeyPackageInfo(
            IdentityPubkey: new PublicKey(identity),
            Ciphersuite: cs,
            ProtocolVersion: "1.0",
            Extensions: Array.Empty<ushort>(),
            Proposals: Array.Empty<ushort>(),
            KeyPackageRef: Convert.ToHexStringLower(kpRef)));
    }

    /// <inheritdoc/>
    public unsafe Task<CreateGroupResult> CreateGroupAsync(
        PublicKey creatorPubkey,
        MarmotGroupDataExtension groupData,
        ushort ciphersuite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(creatorPubkey);
        ArgumentNullException.ThrowIfNull(groupData);
        if (groupData.NostrGroupId.Length != 32)
        {
            throw new ArgumentException("nostr_group_id must be 32 bytes.", nameof(groupData));
        }

        Span<byte> identity = stackalloc byte[32];
        creatorPubkey.CopyTo(identity);

        IntPtr exporterPtr = IntPtr.Zero;
        nuint exporterLen = 0;
        int rc;
        fixed (byte* identityPin = identity)
        fixed (byte* gidPin = groupData.NostrGroupId)
        {
            rc = NativeBindings.CreateGroup(
                _handle.DangerousPointer,
                identityPin, (nuint)identity.Length,
                gidPin,
                ciphersuite,
                &exporterPtr, &exporterLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(CreateGroupAsync));
        }

        byte[] exporter = FfiBuffer.CopyAndFree(exporterPtr, exporterLen);
        return Task.FromResult(new CreateGroupResult(
            NostrGroupId: (byte[])groupData.NostrGroupId.Clone(),
            InitialExporterSecret: exporter));
    }

    /// <inheritdoc/>
    public unsafe Task<AddMembersResult> AddMembersAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        IReadOnlyList<ReadOnlyMemory<byte>> keyPackageBundles,
        CancellationToken ct = default)
    {
        if (nostrGroupId.Length != 32)
        {
            throw new ArgumentException("nostr_group_id must be 32 bytes.", nameof(nostrGroupId));
        }

        if (keyPackageBundles.Count == 0)
        {
            throw new ArgumentException("must add at least one member", nameof(keyPackageBundles));
        }

        // Encode the length-prefixed blob: [u32 BE count] [u32 BE len_0] [bytes_0] ...
        int blobSize = 4;
        foreach (var b in keyPackageBundles)
        {
            blobSize += 4 + b.Length;
        }

        byte[] blob = new byte[blobSize];
        int p = 0;
        WriteUInt32BigEndian(blob, p, (uint)keyPackageBundles.Count); p += 4;
        foreach (var b in keyPackageBundles)
        {
            WriteUInt32BigEndian(blob, p, (uint)b.Length); p += 4;
            b.Span.CopyTo(blob.AsSpan(p, b.Length)); p += b.Length;
        }

        IntPtr commitPtr = IntPtr.Zero; nuint commitLen = 0;
        IntPtr welcomePtr = IntPtr.Zero; nuint welcomeLen = 0;
        IntPtr recipientsPtr = IntPtr.Zero; nuint recipientsLen = 0;
        IntPtr exporterPtr = IntPtr.Zero; nuint exporterLen = 0;

        int rc;
        fixed (byte* gidPin = nostrGroupId.Span)
        fixed (byte* blobPin = blob)
        {
            rc = NativeBindings.AddMembers(
                _handle.DangerousPointer,
                gidPin,
                blobPin, (nuint)blob.Length,
                &commitPtr, &commitLen,
                &welcomePtr, &welcomeLen,
                &recipientsPtr, &recipientsLen,
                &exporterPtr, &exporterLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(AddMembersAsync));
        }

        byte[] commit = FfiBuffer.CopyAndFree(commitPtr, commitLen);
        byte[] welcome = FfiBuffer.CopyAndFree(welcomePtr, welcomeLen);
        byte[] recipientsBlob = FfiBuffer.CopyAndFree(recipientsPtr, recipientsLen);
        byte[] exporter = FfiBuffer.CopyAndFree(exporterPtr, exporterLen);

        // Decode recipients: [u32 BE count] [32 bytes id_0] ...
        if (recipientsBlob.Length < 4)
        {
            throw new InvalidDataException("recipients blob too short");
        }

        uint recipientCount = ReadUInt32BigEndian(recipientsBlob, 0);
        if (recipientsBlob.Length != 4 + 32 * recipientCount)
        {
            throw new InvalidDataException(
                $"recipients blob has unexpected length {recipientsBlob.Length} for count {recipientCount}");
        }

        var welcomes = new WelcomeToSend[recipientCount];
        for (int i = 0; i < recipientCount; i++)
        {
            byte[] id = new byte[32];
            Array.Copy(recipientsBlob, 4 + 32 * i, id, 0, 32);
            // For a single Add+Commit, the SAME Welcome bytes carry
            // EncryptedGroupSecrets for every new member. Each WelcomeToSend
            // points at the same bytes; the recipient-specific routing
            // happens at the NIP-59 gift-wrap layer.
            welcomes[i] = new WelcomeToSend(
                RecipientPubkey: new PublicKey(id),
                WelcomeMlsMessageBytes: welcome);
        }

        return Task.FromResult(new AddMembersResult(
            CommitMlsMessageBytes: commit,
            Welcomes: welcomes,
            NewExporterSecret: exporter));
    }

    private static void WriteUInt32BigEndian(byte[] buf, int offset, uint value)
    {
        buf[offset + 0] = (byte)(value >> 24);
        buf[offset + 1] = (byte)(value >> 16);
        buf[offset + 2] = (byte)(value >> 8);
        buf[offset + 3] = (byte)value;
    }

    private static uint ReadUInt32BigEndian(byte[] buf, int offset)
    {
        return ((uint)buf[offset + 0] << 24)
             | ((uint)buf[offset + 1] << 16)
             | ((uint)buf[offset + 2] << 8)
             | buf[offset + 3];
    }

    /// <inheritdoc/>
    public unsafe Task<JoinedGroupResult> JoinGroupFromWelcomeAsync(
        ReadOnlyMemory<byte> mlsWelcomeBytes,
        CancellationToken ct = default)
    {
        var span = mlsWelcomeBytes.Span;
        IntPtr gidPtr = IntPtr.Zero; nuint gidLen = 0;
        IntPtr exporterPtr = IntPtr.Zero; nuint exporterLen = 0;

        int rc;
        fixed (byte* pin = span)
        {
            rc = NativeBindings.JoinFromWelcome(
                _handle.DangerousPointer,
                pin, (nuint)span.Length,
                &gidPtr, &gidLen,
                &exporterPtr, &exporterLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(JoinGroupFromWelcomeAsync));
        }

        byte[] gid = FfiBuffer.CopyAndFree(gidPtr, gidLen);
        byte[] exporter = FfiBuffer.CopyAndFree(exporterPtr, exporterLen);

        // We don't yet propagate the MarmotGroupDataExtension across the
        // MLS-to-Marmot envelope boundary (Marmot carries it in the
        // group's kind-445 `h` tag), so synthesize a minimal one here.
        var groupData = new MarmotGroupDataExtension
        {
            NostrGroupId = gid,
            AdminPubkeys = Array.Empty<PublicKey>(),
            Relays = Array.Empty<string>(),
        };

        return Task.FromResult(new JoinedGroupResult(
            NostrGroupId: gid,
            GroupData: groupData,
            CurrentExporterSecret: exporter));
    }

    /// <inheritdoc/>
    public unsafe Task<RemoveMembersResult> RemoveMembersAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        IReadOnlyList<PublicKey> peerPubkeys,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(peerPubkeys);
        if (nostrGroupId.Length != 32)
        {
            throw new ArgumentException("nostr_group_id must be 32 bytes.", nameof(nostrGroupId));
        }

        if (peerPubkeys.Count == 0)
        {
            throw new ArgumentException("must remove at least one member", nameof(peerPubkeys));
        }

        // Encode [u32 BE count] [32 bytes pubkey_0] ...
        byte[] blob = new byte[4 + 32 * peerPubkeys.Count];
        WriteUInt32BigEndian(blob, 0, (uint)peerPubkeys.Count);
        for (int i = 0; i < peerPubkeys.Count; i++)
        {
            peerPubkeys[i].CopyTo(blob.AsSpan(4 + 32 * i, 32));
        }

        IntPtr commitPtr = IntPtr.Zero; nuint commitLen = 0;
        IntPtr expPtr = IntPtr.Zero; nuint expLen = 0;
        int rc;
        fixed (byte* gidPin = nostrGroupId.Span)
        fixed (byte* blobPin = blob)
        {
            rc = NativeBindings.RemoveMembers(
                _handle.DangerousPointer,
                gidPin,
                blobPin, (nuint)blob.Length,
                &commitPtr, &commitLen,
                &expPtr, &expLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(RemoveMembersAsync));
        }

        return Task.FromResult(new RemoveMembersResult(
            CommitMlsMessageBytes: FfiBuffer.CopyAndFree(commitPtr, commitLen),
            NewExporterSecret: FfiBuffer.CopyAndFree(expPtr, expLen)));
    }

    /// <inheritdoc/>
    public unsafe Task<SelfUpdateResult> SelfUpdateAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default)
    {
        if (nostrGroupId.Length != 32)
        {
            throw new ArgumentException("nostr_group_id must be 32 bytes.", nameof(nostrGroupId));
        }

        IntPtr commitPtr = IntPtr.Zero; nuint commitLen = 0;
        IntPtr expPtr = IntPtr.Zero; nuint expLen = 0;
        int rc;
        fixed (byte* gidPin = nostrGroupId.Span)
        {
            rc = NativeBindings.SelfUpdate(
                _handle.DangerousPointer,
                gidPin,
                &commitPtr, &commitLen,
                &expPtr, &expLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(SelfUpdateAsync));
        }

        return Task.FromResult(new SelfUpdateResult(
            CommitMlsMessageBytes: FfiBuffer.CopyAndFree(commitPtr, commitLen),
            NewExporterSecret: FfiBuffer.CopyAndFree(expPtr, expLen)));
    }

    /// <inheritdoc/>
    public Task<byte[]> BuildSelfRemoveProposalAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default)
        => throw new NotImplementedException("BuildSelfRemoveProposalAsync lands in the next FFI iteration.");

    /// <inheritdoc/>
    public unsafe Task<byte[]> EncryptApplicationMessageAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken ct = default)
    {
        if (nostrGroupId.Length != 32)
        {
            throw new ArgumentException("nostr_group_id must be 32 bytes.", nameof(nostrGroupId));
        }

        IntPtr msgPtr = IntPtr.Zero;
        nuint msgLen = 0;
        int rc;
        fixed (byte* gidPin = nostrGroupId.Span)
        fixed (byte* ptPin = plaintext.Span)
        {
            rc = NativeBindings.EncryptApplicationMessage(
                _handle.DangerousPointer,
                gidPin,
                ptPin, (nuint)plaintext.Length,
                &msgPtr, &msgLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(EncryptApplicationMessageAsync));
        }

        return Task.FromResult(FfiBuffer.CopyAndFree(msgPtr, msgLen));
    }

    /// <inheritdoc/>
    public unsafe Task<ProcessedMlsMessage> ProcessIncomingMlsMessageAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        ReadOnlyMemory<byte> mlsMessageBytes,
        CancellationToken ct = default)
    {
        if (nostrGroupId.Length != 32)
        {
            throw new ArgumentException("nostr_group_id must be 32 bytes.", nameof(nostrGroupId));
        }

        int kind = 0;
        IntPtr payloadPtr = IntPtr.Zero;
        nuint payloadLen = 0;
        byte epochAdvanced = 0;
        IntPtr newExpPtr = IntPtr.Zero;
        nuint newExpLen = 0;

        int rc;
        fixed (byte* gidPin = nostrGroupId.Span)
        fixed (byte* msgPin = mlsMessageBytes.Span)
        {
            rc = NativeBindings.ProcessIncomingMessage(
                _handle.DangerousPointer,
                gidPin,
                msgPin, (nuint)mlsMessageBytes.Length,
                &kind,
                &payloadPtr, &payloadLen,
                &epochAdvanced,
                &newExpPtr, &newExpLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(ProcessIncomingMlsMessageAsync));
        }

        byte[] payload = FfiBuffer.CopyAndFree(payloadPtr, payloadLen);
        byte[]? newExporter = epochAdvanced != 0 ? FfiBuffer.CopyAndFree(newExpPtr, newExpLen) : null;

        var mlsKind = kind switch
        {
            0 => MlsMessageKind.Application,
            1 => MlsMessageKind.Proposal,
            2 => MlsMessageKind.Commit,
            _ => throw new InvalidDataException($"unknown MLS message kind {kind}"),
        };

        return Task.FromResult(new ProcessedMlsMessage(
            Kind: mlsKind,
            ApplicationPayload: payload,
            EpochAdvanced: epochAdvanced != 0,
            NewExporterSecret: newExporter));
    }

    /// <inheritdoc/>
    public unsafe Task<byte[]> CurrentExporterSecretAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default)
    {
        if (nostrGroupId.Length != 32)
        {
            throw new ArgumentException("nostr_group_id must be 32 bytes.", nameof(nostrGroupId));
        }

        IntPtr exporterPtr = IntPtr.Zero;
        nuint exporterLen = 0;
        int rc;
        fixed (byte* gidPin = nostrGroupId.Span)
        {
            rc = NativeBindings.CurrentExporter(
                _handle.DangerousPointer,
                gidPin,
                &exporterPtr, &exporterLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(CurrentExporterSecretAsync));
        }

        return Task.FromResult(FfiBuffer.CopyAndFree(exporterPtr, exporterLen));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _handle.Dispose();
    }
}
