// SPDX-License-Identifier: MIT
//
// Per-instance state owned by the .NET side via an opaque
// ProviderHandle (*mut Provider).
//
// The provider holds an OpenMLS-compatible crypto+storage backend.
// Crypto is openmls_rust_crypto::RustCrypto (RustCrypto primitives).
// Storage is SQLite-backed via openmls_sqlite_storage:
//
//   - marmot_provider_new()           -> in-memory SQLite (":memory:")
//   - marmot_provider_open_at_path()  -> file-backed SQLite
//
// All MLS state (group state, signature keypairs, HPKE init keys)
// lives in the SQLite storage. We do not maintain any redundant
// in-memory state.

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// A serde_json-based Codec for the SQLite storage backend.
#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// Marmot's OpenMLS provider: RustCrypto + SQLite storage.
pub struct MarmotCryptoProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl OpenMlsProvider for MarmotCryptoProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

pub struct Provider {
    pub(crate) crypto: MarmotCryptoProvider,
    /// Marmot-specific metadata that doesn't fit OpenMLS's storage trait.
    /// Currently: a (nostr_group_id, mls_group_id) mapping so we can
    /// look up OpenMLS groups by the 32-byte Nostr group id even when
    /// the inviter used a different-length MLS GroupId (e.g. mdk-core
    /// and White Noise use 16 bytes).
    pub(crate) marmot_meta: std::sync::Mutex<rusqlite::Connection>,
    /// Serializes every FFI entry that touches the OpenMLS storage.
    /// `openmls_sqlite_storage::Connection` is wrapped in a `RefCell`
    /// internally and is **not** `Sync`; concurrent FFI calls from
    /// different .NET / app threads would otherwise hit
    /// "RefCell already borrowed" and abort the process via Rust's
    /// no-unwind across the FFI boundary. The lock is coarse-grained
    /// (one per Provider) — fine, because MLS ops are sub-millisecond
    /// and the contention surface is tiny.
    pub(crate) ffi_lock: std::sync::Mutex<()>,
    /// Path the provider was opened from, or `None` for in-memory.
    /// Used by VACUUM to open an exclusive connection for the rewrite.
    pub(crate) path: Option<PathBuf>,
}

impl Provider {
    /// Open an in-memory provider (no persistence).
    pub fn new() -> Self {
        let openmls_conn =
            Connection::open_in_memory().expect("rusqlite open_in_memory (openmls)");
        let meta_conn =
            rusqlite::Connection::open_in_memory().expect("rusqlite open_in_memory (meta)");
        Self::open(openmls_conn, meta_conn, None)
    }

    /// Open a provider with state persisted at the given filesystem path.
    /// Returns an error if the path cannot be opened or the schema
    /// migrations fail.
    pub fn open_at_path(path: &Path) -> Result<Self, String> {
        let openmls_conn = Connection::open(path)
            .map_err(|e| format!("open SQLite at {}: {e} (openmls)", path.display()))?;
        let meta_conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("open SQLite at {}: {e} (marmot meta)", path.display()))?;
        Ok(Self::open(openmls_conn, meta_conn, Some(path.to_path_buf())))
    }

    fn open(
        openmls_conn: Connection,
        meta_conn: rusqlite::Connection,
        path: Option<PathBuf>,
    ) -> Self {
        let mut storage = SqliteStorageProvider::<JsonCodec, Connection>::new(openmls_conn);
        storage
            .run_migrations()
            .expect("SqliteStorageProvider::run_migrations (schema)");

        // Marmot metadata tables. Currently just the group-id mapping;
        // future entries (e.g. cached NostrGroupData) can join this table.
        meta_conn
            .execute(
                "CREATE TABLE IF NOT EXISTS marmot_group_map (
                    nostr_group_id BLOB PRIMARY KEY,
                    mls_group_id   BLOB NOT NULL
                )",
                [],
            )
            .expect("marmot_meta: create table");

        Self {
            crypto: MarmotCryptoProvider {
                crypto: RustCrypto::default(),
                storage,
            },
            marmot_meta: std::sync::Mutex::new(meta_conn),
            ffi_lock: std::sync::Mutex::new(()),
            path,
        }
    }
}

/// Guard helper used at every FFI export that takes a `*mut Provider`.
/// Locks the per-provider FFI mutex for the duration of the caller's
/// scope. Returns `None` when the pointer is null so the caller can
/// fall through to its own null-pointer error reporting.
///
/// Mutex-poisoned state is recovered (`into_inner`) so a previous
/// panic-mid-call doesn't permanently brick the provider — though in
/// practice we panic with `panic = "abort"` so this only matters for
/// tests.
pub(crate) unsafe fn lock_ffi(
    provider: *mut Provider,
) -> Option<std::sync::MutexGuard<'static, ()>> {
    if provider.is_null() {
        return None;
    }
    // SAFETY: caller asserts `provider` is a live ProviderHandle.
    let p: &Provider = unsafe { &*provider };
    let guard = match p.ffi_lock.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Erase the lifetime — the guard is dropped before the caller
    // returns to .NET, and `Provider` outlives every FFI call.
    Some(unsafe { std::mem::transmute::<
        std::sync::MutexGuard<'_, ()>,
        std::sync::MutexGuard<'static, ()>,
    >(guard) })
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}
