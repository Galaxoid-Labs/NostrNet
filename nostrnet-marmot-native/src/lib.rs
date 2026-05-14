// SPDX-License-Identifier: MIT
//
// nostrnet-marmot-native — C ABI exposing the OpenMLS subset that
// NostrNet.Marmot.Mls.Native needs to implement IMarmotMlsProvider.
//
// Conventions:
//   - All entry points return i32. 0 = success, negative = error.
//     The most recent error message (per-thread) is available via
//     marmot_last_error_message().
//   - Output buffers are Rust-allocated as Box<[u8]>, returned to .NET
//     via out-parameter (*mut *mut u8, *mut usize). .NET copies the
//     bytes into managed memory, then calls marmot_buffer_free(ptr, len)
//     to release the Rust allocation.
//   - Slices passed FROM .NET are read-only: (*const u8, usize). No
//     ownership transfer.
//   - The ProviderHandle is an opaque pointer (*mut Provider). It owns
//     OpenMLS's crypto/storage backend and per-group state.
//
// Threading: callers MUST NOT share a single ProviderHandle across
// threads concurrently. Each thread should own its own provider, or
// the caller must serialize calls externally. (We can add a Mutex
// inside the provider in phase 6 if needed.)

#![allow(clippy::missing_safety_doc)]

mod buffer;
mod errors;
mod keypackage;
mod provider;

use std::ffi::c_char;

pub use buffer::*;
pub use errors::*;
pub use keypackage::*;
pub use provider::*;

// ──────────────────────────────────────────────────────────────────────
// Provider lifecycle.
// ──────────────────────────────────────────────────────────────────────

/// Creates a new provider instance. Returns a non-null pointer on
/// success or null on allocation failure (extremely unlikely).
#[unsafe(no_mangle)]
pub extern "C" fn marmot_provider_new() -> *mut Provider {
    errors::clear_last_error();
    let provider = Box::new(Provider::new());
    Box::into_raw(provider)
}

/// Frees a provider created via `marmot_provider_new`. Calling with a
/// null pointer is a no-op.
///
/// # Safety
/// `handle` must have been produced by `marmot_provider_new` and not
/// already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_provider_free(handle: *mut Provider) {
    if handle.is_null() {
        return;
    }

    // SAFETY: handle came from Box::into_raw; reconstitute and drop.
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Returns the per-thread last error message as a UTF-8 null-terminated
/// C string. The pointer is owned by the library and remains valid
/// until the next FFI call on the same thread.
///
/// Returns null if no error has been recorded.
#[unsafe(no_mangle)]
pub extern "C" fn marmot_last_error_message() -> *const c_char {
    errors::last_error_ptr()
}

/// Frees an output buffer previously returned to the caller via an
/// out-parameter (e.g. from marmot_build_keypackage). After this call,
/// `ptr` is invalid.
///
/// # Safety
/// `ptr` and `len` must be the exact pair returned by a previous FFI
/// call. Passing a different `len` is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_buffer_free(ptr: *mut u8, len: usize) {
    unsafe { buffer::free_ffi_buffer(ptr, len) }
}

/// Returns the ABI version of this library. .NET callers should bump
/// in lockstep when the FFI surface changes. Useful for diagnosing
/// mismatched binaries.
#[unsafe(no_mangle)]
pub extern "C" fn marmot_abi_version() -> u32 {
    1
}

// ──────────────────────────────────────────────────────────────────────
// KeyPackage operations.
// ──────────────────────────────────────────────────────────────────────

/// Builds a fresh KeyPackage. See `keypackage::build_keypackage`.
///
/// # Safety
/// See `keypackage::build_keypackage`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn marmot_build_keypackage(
    provider: *mut Provider,
    identity_ptr: *const u8,
    identity_len: usize,
    ciphersuite: u16,
    extensions_ptr: *const u16,
    extensions_len: usize,
    proposals_ptr: *const u16,
    proposals_len: usize,
    out_bundle_ptr: *mut *mut u8,
    out_bundle_len: *mut usize,
    out_kp_ref_ptr: *mut *mut u8,
    out_kp_ref_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    unsafe {
        keypackage::build_keypackage(
            provider,
            identity_ptr,
            identity_len,
            ciphersuite,
            extensions_ptr,
            extensions_len,
            proposals_ptr,
            proposals_len,
            out_bundle_ptr,
            out_bundle_len,
            out_kp_ref_ptr,
            out_kp_ref_len,
        )
    }
}

/// Parses a KeyPackage bundle. See `keypackage::parse_keypackage`.
///
/// # Safety
/// See `keypackage::parse_keypackage`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_parse_keypackage(
    bundle_ptr: *const u8,
    bundle_len: usize,
    out_identity_ptr: *mut *mut u8,
    out_identity_len: *mut usize,
    out_kp_ref_ptr: *mut *mut u8,
    out_kp_ref_len: *mut usize,
    out_ciphersuite: *mut u16,
) -> i32 {
    errors::clear_last_error();
    unsafe {
        keypackage::parse_keypackage(
            bundle_ptr,
            bundle_len,
            out_identity_ptr,
            out_identity_len,
            out_kp_ref_ptr,
            out_kp_ref_len,
            out_ciphersuite,
        )
    }
}
