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

        if (keyPackageBundles.Count != 1)
        {
            throw new NotSupportedException(
                $"Phase 1 supports adding exactly one member; got {keyPackageBundles.Count}.");
        }

        var kp = keyPackageBundles[0].Span;

        IntPtr commitPtr = IntPtr.Zero; nuint commitLen = 0;
        IntPtr welcomePtr = IntPtr.Zero; nuint welcomeLen = 0;
        IntPtr recipientPtr = IntPtr.Zero; nuint recipientLen = 0;
        IntPtr exporterPtr = IntPtr.Zero; nuint exporterLen = 0;

        int rc;
        fixed (byte* gidPin = nostrGroupId.Span)
        fixed (byte* kpPin = kp)
        {
            rc = NativeBindings.AddMember(
                _handle.DangerousPointer,
                gidPin,
                kpPin, (nuint)kp.Length,
                &commitPtr, &commitLen,
                &welcomePtr, &welcomeLen,
                &recipientPtr, &recipientLen,
                &exporterPtr, &exporterLen);
        }

        if (rc != 0)
        {
            Errors.Throw(rc, nameof(AddMembersAsync));
        }

        byte[] commit = FfiBuffer.CopyAndFree(commitPtr, commitLen);
        byte[] welcome = FfiBuffer.CopyAndFree(welcomePtr, welcomeLen);
        byte[] recipient = FfiBuffer.CopyAndFree(recipientPtr, recipientLen);
        byte[] exporter = FfiBuffer.CopyAndFree(exporterPtr, exporterLen);

        if (recipient.Length != 32)
        {
            throw new InvalidDataException(
                $"recipient identity must be 32 bytes; got {recipient.Length}.");
        }

        return Task.FromResult(new AddMembersResult(
            CommitMlsMessageBytes: commit,
            Welcomes: new[]
            {
                new WelcomeToSend(
                    RecipientPubkey: new PublicKey(recipient),
                    WelcomeMlsMessageBytes: welcome),
            },
            NewExporterSecret: exporter));
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
    public Task<byte[]> BuildSelfRemoveProposalAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default)
        => throw new NotImplementedException("BuildSelfRemoveProposalAsync lands in the next FFI iteration.");

    /// <inheritdoc/>
    public Task<byte[]> EncryptApplicationMessageAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken ct = default)
        => throw new NotImplementedException("EncryptApplicationMessageAsync lands in the next FFI iteration.");

    /// <inheritdoc/>
    public Task<ProcessedMlsMessage> ProcessIncomingMlsMessageAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        ReadOnlyMemory<byte> mlsMessageBytes,
        CancellationToken ct = default)
        => throw new NotImplementedException("ProcessIncomingMlsMessageAsync lands in the next FFI iteration.");

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
