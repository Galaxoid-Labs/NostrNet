// SPDX-License-Identifier: MIT
//
// LibraryImport-based P/Invoke surface for nostrnet-marmot-native.
//
// We use `LibraryImport` (source-generated stubs) instead of `DllImport`
// (reflection-based) so the resulting code is AOT- and trim-safe.
//
// Buffer ownership convention (mirroring the Rust side):
//   - Functions returning bytes to managed take two out-parameters:
//       out IntPtr buffer
//       out nuint length
//     The Rust side allocates a Box<[u8]>, transfers ownership to us.
//   - Managed code copies the bytes into a byte[], then calls
//     `marmot_buffer_free(ptr, length)` to release the Rust allocation.
//   - If a function returns non-zero (failure), the out-params are left
//     unwritten.
//
// All entry points are `internal` — consumers use the public
// `OpenMlsProvider` class which wraps these.

using System.Runtime.InteropServices;

namespace NostrNet.Marmot.Mls.Native.Interop;

internal static partial class NativeBindings
{
    /// <summary>Library file name (resolved per-platform by the .NET runtime).</summary>
    public const string Library = "nostrnet_marmot_native";

    [LibraryImport(Library, EntryPoint = "marmot_provider_new")]
    public static partial IntPtr ProviderNew();

    [LibraryImport(Library, EntryPoint = "marmot_provider_open_at_path", StringMarshalling = StringMarshalling.Utf8)]
    public static partial IntPtr ProviderOpenAtPath(string path);

    [LibraryImport(Library, EntryPoint = "marmot_provider_free")]
    public static partial void ProviderFree(IntPtr handle);

    [LibraryImport(Library, EntryPoint = "marmot_buffer_free")]
    public static partial void BufferFree(IntPtr ptr, nuint len);

    [LibraryImport(Library, EntryPoint = "marmot_last_error_message")]
    public static partial IntPtr LastErrorMessage();

    [LibraryImport(Library, EntryPoint = "marmot_abi_version")]
    public static partial uint AbiVersion();

    // ────────────────────────────────────────────────────────────
    // KeyPackage build / parse.
    // ────────────────────────────────────────────────────────────

    [LibraryImport(Library, EntryPoint = "marmot_build_keypackage")]
    public static unsafe partial int BuildKeyPackage(
        IntPtr provider,
        byte* identityPtr, nuint identityLen,
        ushort ciphersuite,
        ushort* extensionsPtr, nuint extensionsLen,
        ushort* proposalsPtr, nuint proposalsLen,
        IntPtr* outBundlePtr, nuint* outBundleLen,
        IntPtr* outKpRefPtr, nuint* outKpRefLen);

    [LibraryImport(Library, EntryPoint = "marmot_parse_keypackage")]
    public static unsafe partial int ParseKeyPackage(
        byte* bundlePtr, nuint bundleLen,
        IntPtr* outIdentityPtr, nuint* outIdentityLen,
        IntPtr* outKpRefPtr, nuint* outKpRefLen,
        ushort* outCiphersuite);

    // ────────────────────────────────────────────────────────────
    // Group lifecycle.
    // ────────────────────────────────────────────────────────────

    [LibraryImport(Library, EntryPoint = "marmot_create_group")]
    public static unsafe partial int CreateGroup(
        IntPtr provider,
        byte* creatorIdentityPtr, nuint creatorIdentityLen,
        byte* nostrGroupIdPtr,
        ushort ciphersuite,
        IntPtr* outExporterPtr, nuint* outExporterLen);

    [LibraryImport(Library, EntryPoint = "marmot_add_members")]
    public static unsafe partial int AddMembers(
        IntPtr provider,
        byte* nostrGroupIdPtr,
        byte* keypackageBlobPtr, nuint keypackageBlobLen,
        IntPtr* outCommitPtr, nuint* outCommitLen,
        IntPtr* outWelcomePtr, nuint* outWelcomeLen,
        IntPtr* outRecipientsPtr, nuint* outRecipientsLen,
        IntPtr* outExporterPtr, nuint* outExporterLen);

    [LibraryImport(Library, EntryPoint = "marmot_join_from_welcome")]
    public static unsafe partial int JoinFromWelcome(
        IntPtr provider,
        byte* welcomeBytesPtr, nuint welcomeBytesLen,
        IntPtr* outGroupIdPtr, nuint* outGroupIdLen,
        IntPtr* outExporterPtr, nuint* outExporterLen);

    [LibraryImport(Library, EntryPoint = "marmot_remove_members")]
    public static unsafe partial int RemoveMembers(
        IntPtr provider,
        byte* nostrGroupIdPtr,
        byte* pubkeysBlobPtr, nuint pubkeysBlobLen,
        IntPtr* outCommitPtr, nuint* outCommitLen,
        IntPtr* outExporterPtr, nuint* outExporterLen);

    [LibraryImport(Library, EntryPoint = "marmot_self_update")]
    public static unsafe partial int SelfUpdate(
        IntPtr provider,
        byte* nostrGroupIdPtr,
        IntPtr* outCommitPtr, nuint* outCommitLen,
        IntPtr* outExporterPtr, nuint* outExporterLen);

    [LibraryImport(Library, EntryPoint = "marmot_current_exporter")]
    public static unsafe partial int CurrentExporter(
        IntPtr provider,
        byte* nostrGroupIdPtr,
        IntPtr* outExporterPtr, nuint* outExporterLen);

    // ────────────────────────────────────────────────────────────
    // Application messages.
    // ────────────────────────────────────────────────────────────

    [LibraryImport(Library, EntryPoint = "marmot_encrypt_application_message")]
    public static unsafe partial int EncryptApplicationMessage(
        IntPtr provider,
        byte* nostrGroupIdPtr,
        byte* plaintextPtr, nuint plaintextLen,
        IntPtr* outMsgPtr, nuint* outMsgLen);

    [LibraryImport(Library, EntryPoint = "marmot_process_incoming_message")]
    public static unsafe partial int ProcessIncomingMessage(
        IntPtr provider,
        byte* nostrGroupIdPtr,
        byte* msgPtr, nuint msgLen,
        int* outKind,
        IntPtr* outPayloadPtr, nuint* outPayloadLen,
        byte* outEpochAdvanced,
        IntPtr* outNewExporterPtr, nuint* outNewExporterLen,
        IntPtr* outSenderPtr, nuint* outSenderLen);
}
