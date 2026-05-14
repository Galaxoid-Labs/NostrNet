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
use std::path::Path;

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
}

impl Provider {
    /// Open an in-memory provider (no persistence).
    pub fn new() -> Self {
        Self::open(Connection::open_in_memory().expect("rusqlite open_in_memory"))
    }

    /// Open a provider with state persisted at the given filesystem path.
    /// Returns an error if the path cannot be opened or the schema
    /// migrations fail.
    pub fn open_at_path(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path)
            .map_err(|e| format!("open SQLite at {}: {e}", path.display()))?;
        Ok(Self::open(conn))
    }

    fn open(conn: Connection) -> Self {
        let mut storage = SqliteStorageProvider::<JsonCodec, Connection>::new(conn);
        storage
            .run_migrations()
            .expect("SqliteStorageProvider::run_migrations (schema)");
        Self {
            crypto: MarmotCryptoProvider {
                crypto: RustCrypto::default(),
                storage,
            },
        }
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}
