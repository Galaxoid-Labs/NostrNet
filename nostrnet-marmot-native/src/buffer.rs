// SPDX-License-Identifier: MIT
//
// FFI buffer ownership convention:
//
//   - Functions returning bytes to .NET take two out-parameters:
//       out_ptr: *mut *mut u8
//       out_len: *mut usize
//     The Rust side allocates a Box<[u8]>, leaks it, and writes the
//     pointer + length to the out-params.
//   - The .NET caller copies the bytes into a managed array, then
//     calls `marmot_buffer_free(ptr, len)` to release the allocation.
//   - If a function fails, the out-params remain unwritten.

use std::ptr;

/// Writes a Rust Vec<u8> through the (out_ptr, out_len) FFI convention,
/// transferring ownership to the caller (who must release via
/// marmot_buffer_free).
///
/// # Safety
/// `out_ptr` and `out_len` must be valid, writable, non-null pointers
/// owned by the caller's stack/heap.
pub unsafe fn return_ffi_buffer(buf: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    let boxed = buf.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    unsafe {
        ptr::write(out_ptr, ptr);
        ptr::write(out_len, len);
    }
}

/// Releases a buffer previously handed to the caller via
/// `return_ffi_buffer`.
///
/// # Safety
/// `ptr` and `len` must be the exact pair previously returned by the
/// library. Calling with mismatched values is UB.
pub unsafe fn free_ffi_buffer(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: ptr+len came from a Box::into_raw(Vec::into_boxed_slice).
    unsafe {
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len));
    }
}

/// Materializes a borrowed byte slice from FFI input. Returns None if
/// the pointer is null and length is non-zero (caller bug).
///
/// # Safety
/// `ptr` and `len` together must describe a valid readable region for
/// the duration of the borrow.
pub unsafe fn input_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }

    if ptr.is_null() {
        return None;
    }

    // SAFETY: caller asserts ptr+len is a valid readable region.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}
