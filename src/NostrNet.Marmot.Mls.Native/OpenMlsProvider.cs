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
    public Task<CreateGroupResult> CreateGroupAsync(
        PublicKey creatorPubkey,
        MarmotGroupDataExtension groupData,
        ushort ciphersuite,
        CancellationToken ct = default)
        => throw new NotImplementedException("CreateGroupAsync lands in the next FFI iteration.");

    /// <inheritdoc/>
    public Task<AddMembersResult> AddMembersAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        IReadOnlyList<ReadOnlyMemory<byte>> keyPackageBundles,
        CancellationToken ct = default)
        => throw new NotImplementedException("AddMembersAsync lands in the next FFI iteration.");

    /// <inheritdoc/>
    public Task<JoinedGroupResult> JoinGroupFromWelcomeAsync(
        ReadOnlyMemory<byte> mlsWelcomeBytes,
        CancellationToken ct = default)
        => throw new NotImplementedException("JoinGroupFromWelcomeAsync lands in the next FFI iteration.");

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
    public Task<byte[]> CurrentExporterSecretAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default)
        => throw new NotImplementedException("CurrentExporterSecretAsync lands in the next FFI iteration.");

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
