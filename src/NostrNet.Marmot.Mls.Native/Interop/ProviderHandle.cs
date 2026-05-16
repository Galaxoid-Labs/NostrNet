// SPDX-License-Identifier: MIT
//
// Safe handle wrapping the opaque *mut Provider returned by
// marmot_provider_new(). Disposing frees the Rust allocation via
// marmot_provider_free().

using System.Runtime.InteropServices;

namespace NostrNet.Marmot.Mls.Native.Interop;

/// <summary>
/// Safe-handle wrapping a Rust-side <c>*mut Provider</c>. Disposing it
/// calls <c>marmot_provider_free</c>.
/// </summary>
internal sealed class ProviderHandle : SafeHandle
{
    public ProviderHandle()
        : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    public static ProviderHandle CreateNew()
    {
        var h = new ProviderHandle();
        IntPtr raw = NativeBindings.ProviderNew();
        if (raw == IntPtr.Zero)
        {
            throw new InvalidOperationException("marmot_provider_new returned null.");
        }

        h.SetHandle(raw);
        return h;
    }

    public static ProviderHandle OpenAtPath(string path, ReadOnlySpan<byte> rawKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        if (rawKey.Length != 32)
        {
            throw new ArgumentException(
                $"MLS state key must be exactly 32 bytes; got {rawKey.Length}.", nameof(rawKey));
        }

        var h = new ProviderHandle();
        IntPtr raw;
        unsafe
        {
            fixed (byte* keyPtr = rawKey)
            {
                raw = NativeBindings.ProviderOpenAtPath(path, keyPtr, (nuint)rawKey.Length);
            }
        }

        if (raw == IntPtr.Zero)
        {
            // Surface the precise FFI error code so wrong-key vs. generic
            // storage failure produce distinct exception types.
            int code = NativeBindings.LastErrorCode();
            Errors.Throw(code, $"OpenAtPath({path})");
        }

        h.SetHandle(raw);
        return h;
    }

    /// <summary>The raw pointer for use in P/Invoke calls. Must NOT be freed by the caller.</summary>
    public IntPtr DangerousPointer => handle;

    protected override bool ReleaseHandle()
    {
        NativeBindings.ProviderFree(handle);
        return true;
    }
}
