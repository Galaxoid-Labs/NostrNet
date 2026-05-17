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
mod group;
mod group_map;
mod keypackage;
mod messages;
mod provider;

use std::ffi::c_char;

pub use buffer::*;
pub use errors::*;
pub use group::*;
pub use keypackage::*;
pub use messages::*;
pub use provider::*;

// ──────────────────────────────────────────────────────────────────────
// Provider lifecycle.
// ──────────────────────────────────────────────────────────────────────

/// Creates a new provider instance backed by in-memory SQLite (no
/// persistence). Returns a non-null pointer on success.
#[unsafe(no_mangle)]
pub extern "C" fn marmot_provider_new() -> *mut Provider {
    errors::clear_last_error();
    let provider = Box::new(Provider::new());
    Box::into_raw(provider)
}

/// Creates a new provider instance backed by a SQLCipher-encrypted
/// SQLite file at `path` (UTF-8 NUL-terminated). The file is encrypted
/// with the supplied 32-byte raw key (AES-256). State persists across
/// process restarts: re-opening the same file with the same key
/// restores all groups, signature keys, and HPKE init keys.
///
/// Returns null on failure. On a wrong-key open, last-error code is
/// `InvalidMlsKey` so callers can distinguish "user typed wrong
/// passphrase" from a generic storage failure and prompt accordingly.
///
/// # Safety
/// `path_ptr` must point at a NUL-terminated UTF-8 string.
/// `key_ptr` must point at exactly `key_len` (= 32) bytes of readable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_provider_open_at_path(
    path_ptr: *const c_char,
    key_ptr: *const u8,
    key_len: usize,
) -> *mut Provider {
    errors::clear_last_error();
    if path_ptr.is_null() {
        errors::set_last_error(errors::ErrorCode::NullArgument, "path pointer is null");
        return std::ptr::null_mut();
    }
    if key_ptr.is_null() {
        errors::set_last_error(errors::ErrorCode::NullArgument, "key pointer is null");
        return std::ptr::null_mut();
    }
    if key_len != 32 {
        errors::set_last_error(
            errors::ErrorCode::InvalidArgument,
            format!("MLS state key must be exactly 32 bytes, got {key_len}"),
        );
        return std::ptr::null_mut();
    }

    let path_str = unsafe { std::ffi::CStr::from_ptr(path_ptr) };
    let path = match path_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            errors::set_last_error(
                errors::ErrorCode::InvalidArgument,
                format!("path is not valid UTF-8: {e:?}"),
            );
            return std::ptr::null_mut();
        }
    };

    let key = unsafe { std::slice::from_raw_parts(key_ptr, key_len) };

    match Provider::open_at_path(std::path::Path::new(path), key) {
        Ok(p) => Box::into_raw(Box::new(p)),
        Err(provider::OpenError::InvalidKey(msg)) => {
            errors::set_last_error(errors::ErrorCode::InvalidMlsKey, msg);
            std::ptr::null_mut()
        }
        Err(provider::OpenError::Other(msg)) => {
            errors::set_last_error(errors::ErrorCode::StorageFailure, msg);
            std::ptr::null_mut()
        }
    }
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

/// Returns the per-thread last-error code, or 0 if no error has been
/// recorded since the last clear. Used by pointer-returning entry points
/// (e.g. marmot_provider_open_at_path) to surface a typed code after a
/// null return — managed callers can distinguish `InvalidMlsKey` (-11)
/// from `StorageFailure` (-8) and throw the right exception.
#[unsafe(no_mangle)]
pub extern "C" fn marmot_last_error_code() -> i32 {
    errors::last_error_code()
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
    7
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
    let _g = unsafe { provider::lock_ffi(provider) };
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

// ──────────────────────────────────────────────────────────────────────
// Group lifecycle.
// ──────────────────────────────────────────────────────────────────────

/// # Safety
/// See `group::create_group`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn marmot_create_group(
    provider: *mut Provider,
    creator_identity_ptr: *const u8,
    creator_identity_len: usize,
    nostr_group_id_ptr: *const u8,
    ciphersuite: u16,
    group_data_ptr: *const u8,
    group_data_len: usize,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        group::create_group(
            provider,
            creator_identity_ptr,
            creator_identity_len,
            nostr_group_id_ptr,
            ciphersuite,
            group_data_ptr,
            group_data_len,
            out_exporter_ptr,
            out_exporter_len,
        )
    }
}

/// Delete local state for a single group. See `group::delete_group`.
///
/// # Safety
/// Standard FFI safety. `nostr_group_id_ptr` must point at 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_delete_group(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe { group::delete_group(provider, nostr_group_id_ptr) }
}

/// Run SQLite VACUUM to reclaim freed pages. See `group::vacuum`.
///
/// # Safety
/// Standard FFI safety.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_vacuum(provider: *mut Provider) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe { group::vacuum(provider) }
}

/// Enumerate every group currently in storage.
///
/// Output blob layout: `[u32 BE count]
///   { [32 bytes nostr_group_id] [u32 BE member_count] [member_count * 32 bytes member_identity] }*`
///
/// # Safety
/// Standard FFI safety.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_list_groups(
    provider: *mut Provider,
    out_blob_ptr: *mut *mut u8,
    out_blob_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe { group::list_groups(provider, out_blob_ptr, out_blob_len) }
}

/// # Safety
/// See `group::add_members`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn marmot_add_members(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    keypackage_blob_ptr: *const u8,
    keypackage_blob_len: usize,
    out_commit_ptr: *mut *mut u8,
    out_commit_len: *mut usize,
    out_welcome_ptr: *mut *mut u8,
    out_welcome_len: *mut usize,
    out_recipients_ptr: *mut *mut u8,
    out_recipients_len: *mut usize,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        group::add_members(
            provider,
            nostr_group_id_ptr,
            keypackage_blob_ptr,
            keypackage_blob_len,
            out_commit_ptr,
            out_commit_len,
            out_welcome_ptr,
            out_welcome_len,
            out_recipients_ptr,
            out_recipients_len,
            out_exporter_ptr,
            out_exporter_len,
        )
    }
}

/// # Safety
/// See `group::join_from_welcome`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_join_from_welcome(
    provider: *mut Provider,
    welcome_bytes_ptr: *const u8,
    welcome_bytes_len: usize,
    out_group_id_ptr: *mut *mut u8,
    out_group_id_len: *mut usize,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        group::join_from_welcome(
            provider,
            welcome_bytes_ptr,
            welcome_bytes_len,
            out_group_id_ptr,
            out_group_id_len,
            out_exporter_ptr,
            out_exporter_len,
        )
    }
}

/// Non-destructively probe whether the provider can join the given
/// Welcome (i.e., has a stored KeyPackage matching one of its recipient
/// refs). Writes 1/0 to `*out_can_join`. See `group::welcome_join_state`.
///
/// # Safety
/// Standard FFI safety.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_welcome_join_state(
    provider: *mut Provider,
    welcome_bytes_ptr: *const u8,
    welcome_bytes_len: usize,
    out_can_join: *mut u8,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        group::welcome_join_state(provider, welcome_bytes_ptr, welcome_bytes_len, out_can_join)
    }
}

/// # Safety
/// See `group::remove_members`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn marmot_remove_members(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    pubkeys_blob_ptr: *const u8,
    pubkeys_blob_len: usize,
    out_commit_ptr: *mut *mut u8,
    out_commit_len: *mut usize,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        group::remove_members(
            provider,
            nostr_group_id_ptr,
            pubkeys_blob_ptr,
            pubkeys_blob_len,
            out_commit_ptr,
            out_commit_len,
            out_exporter_ptr,
            out_exporter_len,
        )
    }
}

/// # Safety
/// See `group::self_update`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_self_update(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    out_commit_ptr: *mut *mut u8,
    out_commit_len: *mut usize,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        group::self_update(
            provider,
            nostr_group_id_ptr,
            out_commit_ptr,
            out_commit_len,
            out_exporter_ptr,
            out_exporter_len,
        )
    }
}

/// # Safety
/// See `group::current_exporter`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_current_exporter(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        group::current_exporter(
            provider,
            nostr_group_id_ptr,
            out_exporter_ptr,
            out_exporter_len,
        )
    }
}

// ──────────────────────────────────────────────────────────────────────
// Application messages.
// ──────────────────────────────────────────────────────────────────────

/// # Safety
/// See `messages::encrypt_application_message`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_encrypt_application_message(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    out_msg_ptr: *mut *mut u8,
    out_msg_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        messages::encrypt_application_message(
            provider,
            nostr_group_id_ptr,
            plaintext_ptr,
            plaintext_len,
            out_msg_ptr,
            out_msg_len,
        )
    }
}

/// # Safety
/// See `messages::process_incoming_message`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn marmot_process_incoming_message(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    out_kind: *mut i32,
    out_payload_ptr: *mut *mut u8,
    out_payload_len: *mut usize,
    out_epoch_advanced: *mut u8,
    out_new_exporter_ptr: *mut *mut u8,
    out_new_exporter_len: *mut usize,
    out_sender_ptr: *mut *mut u8,
    out_sender_len: *mut usize,
) -> i32 {
    errors::clear_last_error();
    let _g = unsafe { provider::lock_ffi(provider) };
    unsafe {
        messages::process_incoming_message(
            provider,
            nostr_group_id_ptr,
            msg_ptr,
            msg_len,
            out_kind,
            out_payload_ptr,
            out_payload_len,
            out_epoch_advanced,
            out_new_exporter_ptr,
            out_new_exporter_len,
            out_sender_ptr,
            out_sender_len,
        )
    }
}
