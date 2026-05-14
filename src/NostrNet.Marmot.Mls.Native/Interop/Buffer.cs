// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace NostrNet.Marmot.Mls.Native.Interop;

/// <summary>
/// Helpers for the Rust-allocated-buffer ownership convention used by
/// the FFI: Rust hands us (IntPtr, nuint); we copy into managed memory
/// and call <c>marmot_buffer_free</c>.
/// </summary>
internal static class FfiBuffer
{
    public static byte[] CopyAndFree(IntPtr ptr, nuint len)
    {
        if (ptr == IntPtr.Zero || len == 0)
        {
            return Array.Empty<byte>();
        }

        byte[] buf = new byte[(int)len];
        Marshal.Copy(ptr, buf, 0, (int)len);
        NativeBindings.BufferFree(ptr, len);
        return buf;
    }
}
