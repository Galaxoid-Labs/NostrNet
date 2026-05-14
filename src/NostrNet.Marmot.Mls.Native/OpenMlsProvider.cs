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
    public Task<KeyPackageBundle> BuildKeyPackageAsync(
        PublicKey identityPubkey,
        ushort ciphersuite,
        IReadOnlyList<ushort> extensions,
        IReadOnlyList<ushort> proposals,
        CancellationToken ct = default)
        => throw new NotImplementedException("BuildKeyPackageAsync lands in the next FFI iteration.");

    /// <inheritdoc/>
    public Task<KeyPackageInfo> ParseKeyPackageAsync(
        ReadOnlyMemory<byte> keyPackageBundleBytes,
        CancellationToken ct = default)
        => throw new NotImplementedException("ParseKeyPackageAsync lands in the next FFI iteration.");

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
