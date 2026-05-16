// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace NostrNet.Marmot.Mls.Native.Interop;

internal static class Errors
{
    /// <summary>
    /// Throws an exception that matches the FFI error code, using the
    /// per-thread last-error message from the Rust side.
    /// </summary>
    public static void Throw(int code, string operation)
    {
        string message = ReadLastErrorMessage() ?? "unknown error";
        throw code switch
        {
            -1 => new ArgumentException($"{operation}: null argument ({message})"),
            -2 => new ArgumentException($"{operation}: invalid argument ({message})"),
            -3 => new NotSupportedException($"{operation}: unsupported ({message})"),
            -4 => new InvalidOperationException($"{operation}: unknown group id ({message})"),
            -5 => new System.IO.InvalidDataException($"{operation}: invalid wire format ({message})"),
            -6 => new System.Security.Cryptography.CryptographicException($"{operation}: crypto failure ({message})"),
            -7 => new System.IO.InvalidDataException($"{operation}: serialization failure ({message})"),
            -8 => new InvalidOperationException($"{operation}: storage failure ({message})"),
            -10 => new InvalidOperationException($"{operation}: openmls failure ({message})"),
            -11 => new InvalidMlsKeyException($"{operation}: invalid MLS state key ({message})"),
            _ => new InvalidOperationException($"{operation}: unknown error code {code} ({message})"),
        };
    }

    private static string? ReadLastErrorMessage()
    {
        IntPtr ptr = NativeBindings.LastErrorMessage();
        return ptr == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(ptr);
    }
}
