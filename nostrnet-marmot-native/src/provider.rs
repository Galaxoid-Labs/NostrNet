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
    /// Cached SQLCipher key for fresh connections (e.g. VACUUM). `None`
    /// for in-memory providers. SQLCipher already holds the same bytes
    /// in the pager's memory for our long-lived connections, so this
    /// second copy doesn't broaden the exposure; it's zeroed on drop.
    pub(crate) mls_key: Option<Vec<u8>>,
}

impl Drop for Provider {
    fn drop(&mut self) {
        if let Some(key) = self.mls_key.as_mut() {
            // Best-effort zeroize. Compiler can't optimize this away
            // because Vec::fill writes through a pointer the destructor
            // doesn't observe to be dead.
            for b in key.iter_mut() {
                *b = 0;
            }
        }
    }
}

impl Provider {
    /// Open an in-memory provider (no persistence).
    pub fn new() -> Self {
        let openmls_conn =
            Connection::open_in_memory().expect("rusqlite open_in_memory (openmls)");
        let meta_conn =
            rusqlite::Connection::open_in_memory().expect("rusqlite open_in_memory (meta)");
        Self::open(openmls_conn, meta_conn, None, None)
    }

    /// Open a provider with state persisted at the given filesystem path,
    /// SQLCipher-encrypted with the supplied 32-byte raw key. Returns:
    /// - `Ok(provider)` on success (new or correctly-keyed existing file)
    /// - `Err(OpenError::InvalidKey(..))` when the file exists but the
    ///   key doesn't decrypt it (SQLite reports SQLITE_NOTADB)
    /// - `Err(OpenError::Other(..))` for any other open / migration error
    ///
    /// The key must be exactly 32 bytes (256-bit AES key for SQLCipher).
    /// Use HKDF-SHA256 or equivalent at the caller layer to derive it
    /// from a user passphrase or nsec; the library doesn't run a KDF.
    pub fn open_at_path(path: &Path, key: &[u8]) -> Result<Self, OpenError> {
        if key.len() != 32 {
            return Err(OpenError::Other(format!(
                "MLS state key must be exactly 32 bytes, got {}",
                key.len()
            )));
        }

        let openmls_conn = Connection::open(path)
            .map_err(|e| OpenError::Other(format!("open SQLite at {}: {e} (openmls)", path.display())))?;
        apply_key_and_probe(&openmls_conn, key)
            .map_err(|e| classify_open_error(e, path, "openmls"))?;

        let meta_conn = rusqlite::Connection::open(path)
            .map_err(|e| OpenError::Other(format!("open SQLite at {}: {e} (marmot meta)", path.display())))?;
        apply_key_and_probe(&meta_conn, key)
            .map_err(|e| classify_open_error(e, path, "marmot meta"))?;

        Ok(Self::open(openmls_conn, meta_conn, Some(path.to_path_buf()), Some(key.to_vec())))
    }

    fn open(
        openmls_conn: Connection,
        meta_conn: rusqlite::Connection,
        path: Option<PathBuf>,
        mls_key: Option<Vec<u8>>,
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
            mls_key,
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

/// Distinguishes a wrong-key failure (so the FFI layer can map it to
/// `ErrorCode::InvalidMlsKey` and the C# side to `InvalidMlsKeyException`)
/// from any other open / migration error.
pub enum OpenError {
    InvalidKey(String),
    Other(String),
}

/// Apply `PRAGMA key = "x'<hex>'"` to a fresh rusqlite Connection so
/// it can read SQLCipher-encrypted pages. Caller-visible from inside
/// the crate so one-shot helpers (e.g. VACUUM) that open their own
/// short-lived connection can re-apply the key from the cached copy
/// on Provider without duplicating the hex-formatting logic.
pub(crate) fn apply_key_for_fresh_connection(
    conn: &rusqlite::Connection,
    key: &[u8],
) -> Result<(), rusqlite::Error> {
    apply_key_and_probe(conn, key)
}

/// Apply `PRAGMA key = "x'<hex>'"` to set the SQLCipher decryption key,
/// then probe the schema to detect a wrong-key case immediately
/// (SQLite returns SQLITE_NOTADB on the first read with a mismatched key).
/// On a brand-new file the probe returns 0 rows and succeeds — same as
/// any correctly-keyed existing file.
fn apply_key_and_probe(conn: &rusqlite::Connection, key: &[u8]) -> Result<(), rusqlite::Error> {
    // Hex-encode the 32-byte key into the SQLCipher raw-key blob literal
    // form. PRAGMA cannot use bound parameters, so we format the SQL
    // directly — the key bytes are fully under caller control, no
    // user-supplied string ever reaches this path.
    let mut hex = String::with_capacity(key.len() * 2);
    for b in key {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", b);
    }
    let pragma = format!("PRAGMA key = \"x'{hex}'\";");
    conn.execute_batch(&pragma)?;

    // Probe — SELECT count(*) FROM sqlite_master forces the first page
    // read which decrypts (or fails) under SQLCipher. New databases
    // succeed too (empty sqlite_master = count 0).
    let _: i64 = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
    Ok(())
}

fn classify_open_error(err: rusqlite::Error, path: &Path, label: &str) -> OpenError {
    // SQLITE_NOTADB (code 26) is SQLCipher's wrong-key signal on the
    // first decrypt attempt. Any other error path (I/O, permission,
    // schema migration) falls through to Other.
    if let rusqlite::Error::SqliteFailure(e, _) = &err {
        if e.code == rusqlite::ErrorCode::NotADatabase {
            return OpenError::InvalidKey(format!(
                "wrong key for SQLCipher MLS state file at {} ({label})",
                path.display()
            ));
        }
    }
    OpenError::Other(format!("open SQLite at {} ({label}): {err}", path.display()))
}
