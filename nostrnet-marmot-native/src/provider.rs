// SPDX-License-Identifier: MIT
//
// Per-instance state owned by the .NET side via an opaque
// ProviderHandle (*mut Provider). Wraps OpenMLS's crypto/storage
// backend (OpenMlsRustCrypto) and a map of MlsGroup objects keyed by
// nostr_group_id.

use openmls_rust_crypto::OpenMlsRustCrypto;
use std::collections::HashMap;

/// The handle owned by .NET. Holds:
///   - the OpenMLS crypto+storage backend (in-memory for phase 1)
///   - per-group MlsGroup state keyed by 32-byte nostr_group_id
///   - the local member's signature keypair indexed by KeyPackageRef
///
/// We can't store openmls::group::MlsGroup directly here yet because
/// openmls's group APIs require the provider+credentials at every
/// call. We instead store the SerializedMlsGroup bytes and rehydrate
/// per call — slower but simpler. Phase 6 (perf) can revisit.
// Fields are populated in subsequent FFI iterations (KeyPackage build,
// group create/add/join, etc.). Allowing dead_code here keeps the
// build clean for phase 1 (lifecycle-only) checkpoints.
#[allow(dead_code)]
pub struct Provider {
    pub(crate) crypto: OpenMlsRustCrypto,
    pub(crate) groups: HashMap<[u8; 32], GroupState>,
    pub(crate) keypackages: HashMap<Vec<u8>, KeyPackageState>,
}

pub struct GroupState {
    /// The serialized MlsGroup state. Hydrated and re-stored on each op.
    pub serialized: Vec<u8>,
    /// The 32-byte Marmot group id (= MLS group id in our design).
    pub group_id: [u8; 32],
}

pub struct KeyPackageState {
    /// Serialized SignaturePrivateKey + SignaturePublicKey pair we
    /// generated when building this KeyPackage. Needed at join time.
    pub signature_keypair_bytes: Vec<u8>,
    /// The KeyPackageRef (32 bytes) for lookup.
    pub key_package_ref: Vec<u8>,
}

impl Provider {
    pub fn new() -> Self {
        Self {
            crypto: OpenMlsRustCrypto::default(),
            groups: HashMap::new(),
            keypackages: HashMap::new(),
        }
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}
