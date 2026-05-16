// SPDX-License-Identifier: MIT
//
// Per-thread last-error message storage, accessed via
// `marmot_last_error_message()`. Same idea as errno.

use std::cell::{Cell, RefCell};
use std::ffi::{CString, c_char};
use std::ptr;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
    static LAST_CODE: Cell<i32> = const { Cell::new(0) };
}

/// Negative i32 error codes returned by FFI entry points.
#[repr(i32)]
#[derive(Debug, Copy, Clone)]
pub enum ErrorCode {
    Success = 0,
    NullArgument = -1,
    InvalidArgument = -2,
    Unsupported = -3,
    UnknownGroupId = -4,
    InvalidWireFormat = -5,
    CryptoFailure = -6,
    SerializationFailure = -7,
    StorageFailure = -8,
    InternalError = -9,
    OpenMlsFailure = -10,
    /// The supplied key did not decrypt the SQLCipher MLS state file
    /// (SQLite reports SQLITE_NOTADB on first read). Apps should treat
    /// this as a wrong-passphrase case and prompt accordingly, distinct
    /// from a generic StorageFailure.
    InvalidMlsKey = -11,
}

/// Sets the per-thread last-error message and code, returning the code.
pub fn set_last_error(code: ErrorCode, message: impl Into<String>) -> i32 {
    let msg = message.into();
    let c_msg = CString::new(msg).unwrap_or_else(|_| CString::new("invalid error message").unwrap());
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(c_msg);
    });
    let c = code as i32;
    LAST_CODE.with(|cell| cell.set(c));
    c
}

/// Clears the per-thread last-error message and code.
pub fn clear_last_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
    LAST_CODE.with(|cell| cell.set(0));
}

/// Returns the per-thread last-error code, or 0 when no error is stored.
/// Pointer-returning FFI entry points use this so callers can distinguish
/// e.g. wrong-key from generic storage failures after a null return.
pub fn last_error_code() -> i32 {
    LAST_CODE.with(|cell| cell.get())
}

/// Returns a pointer to the current last-error message C string, or
/// null if none. The pointer remains valid until the next call that
/// modifies the last error on this thread.
pub fn last_error_ptr() -> *const c_char {
    LAST_ERROR.with(|cell| match cell.borrow().as_ref() {
        Some(msg) => msg.as_ptr(),
        None => ptr::null(),
    })
}

/// Helper: convert a std::result::Result<T, E> into either Ok(T) or
/// the error returned via `set_last_error`. Used at the boundary of
/// each FFI function.
pub fn fail<E: std::fmt::Display>(code: ErrorCode, err: E) -> i32 {
    set_last_error(code, err.to_string())
}
