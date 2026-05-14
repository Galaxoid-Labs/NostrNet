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

    [LibraryImport(Library, EntryPoint = "marmot_provider_free")]
    public static partial void ProviderFree(IntPtr handle);

    [LibraryImport(Library, EntryPoint = "marmot_buffer_free")]
    public static partial void BufferFree(IntPtr ptr, nuint len);

    [LibraryImport(Library, EntryPoint = "marmot_last_error_message")]
    public static partial IntPtr LastErrorMessage();

    [LibraryImport(Library, EntryPoint = "marmot_abi_version")]
    public static partial uint AbiVersion();
}
