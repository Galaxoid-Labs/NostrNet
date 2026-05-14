// SPDX-License-Identifier: MIT
//
// Marmot has two distinct group identifiers:
//
//   - **nostr_group_id** (32 bytes): the `h`-tag value on kind-445
//     events used for relay routing. Carried inside the NostrGroupData
//     MLS GroupContextExtension (MIP-01). Always 32 bytes.
//
//   - **MLS GroupId** (opaque, variable length): chosen by the group
//     creator. OpenMLS uses this for internal lookups. mdk-core uses
//     a 16-byte random id; we historically used the 32-byte
//     nostr_group_id, but we cannot assume that for groups we join
//     from other Marmot clients.
//
// The .NET layer only ever sees nostr_group_id. This module maintains
// the mapping so all FFI ops that take a nostr_group_id can translate
// to the right MLS GroupId before hitting OpenMLS storage.

use crate::provider::Provider;
use rusqlite::params;

/// Insert (or overwrite) the mapping `nostr_group_id → mls_group_id`.
pub(crate) fn register(provider: &Provider, nostr_group_id: &[u8], mls_group_id: &[u8]) -> Result<(), String> {
    let conn = provider
        .marmot_meta
        .lock()
        .map_err(|e| format!("marmot_meta lock: {e}"))?;
    conn.execute(
        "INSERT OR REPLACE INTO marmot_group_map (nostr_group_id, mls_group_id) VALUES (?1, ?2)",
        params![nostr_group_id, mls_group_id],
    )
    .map(|_| ())
    .map_err(|e| format!("marmot_group_map insert: {e}"))
}

/// Resolve the MLS GroupId for the given 32-byte `nostr_group_id`.
///
/// As a fallback, when no row exists we return the input unchanged.
/// That keeps state DBs created by older NostrNet builds (where the
/// nostr_group_id WAS the MLS GroupId) working without a migration.
pub(crate) fn lookup_mls(provider: &Provider, nostr_group_id: &[u8]) -> Result<Vec<u8>, String> {
    let conn = provider
        .marmot_meta
        .lock()
        .map_err(|e| format!("marmot_meta lock: {e}"))?;
    let mls: Option<Vec<u8>> = conn
        .query_row(
            "SELECT mls_group_id FROM marmot_group_map WHERE nostr_group_id = ?1",
            params![nostr_group_id],
            |row| row.get(0),
        )
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|e| format!("marmot_group_map select: {e}"))?
        .map(Some)
        .unwrap_or(None);

    Ok(mls.unwrap_or_else(|| nostr_group_id.to_vec()))
}

/// Drop the mapping for the given nostr_group_id. Currently unused;
/// reserved for future RemoveGroup / leave-group plumbing.
#[allow(dead_code)]
pub(crate) fn forget(provider: &Provider, nostr_group_id: &[u8]) -> Result<(), String> {
    let conn = provider
        .marmot_meta
        .lock()
        .map_err(|e| format!("marmot_meta lock: {e}"))?;
    conn.execute(
        "DELETE FROM marmot_group_map WHERE nostr_group_id = ?1",
        params![nostr_group_id],
    )
    .map(|_| ())
    .map_err(|e| format!("marmot_group_map delete: {e}"))
}
