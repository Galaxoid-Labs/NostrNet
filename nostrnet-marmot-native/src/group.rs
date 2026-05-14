// SPDX-License-Identifier: MIT
//
// Group lifecycle FFI: create, add_member, join_from_welcome, exporter.

use crate::buffer::{input_slice, return_ffi_buffer};
use crate::errors::{ErrorCode, fail};
use crate::keypackage::ciphersuite_from_u16;
use crate::provider::Provider;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use crate::provider::MarmotCryptoProvider;
use openmls_traits::types::SignatureScheme;
use tls_codec::{Deserialize, Serialize};

/// Loads an MlsGroup by id from storage, returning a uniform error if absent.
pub(crate) fn load_group(
    crypto: &MarmotCryptoProvider,
    group_id: &[u8; 32],
) -> Result<MlsGroup, (ErrorCode, String)> {
    let group_id_obj = GroupId::from_slice(group_id);
    match MlsGroup::load(crypto.storage(), &group_id_obj) {
        Ok(Some(g)) => Ok(g),
        Ok(None) => Err((ErrorCode::UnknownGroupId, "group not in storage".into())),
        Err(e) => Err((ErrorCode::StorageFailure, format!("MlsGroup::load: {e:?}"))),
    }
}

/// Loads the local member's SignatureKeyPair for a given group by
/// looking up the own-leaf signature pubkey in OpenMLS storage.
pub(crate) fn load_own_signature_keys(
    crypto: &MarmotCryptoProvider,
    group: &MlsGroup,
) -> Result<SignatureKeyPair, (ErrorCode, String)> {
    let own_leaf = group
        .own_leaf()
        .ok_or((ErrorCode::InternalError, "group has no own leaf".to_string()))?;
    let pubkey = own_leaf.signature_key().as_slice();
    let scheme: SignatureScheme = group.ciphersuite().signature_algorithm();
    SignatureKeyPair::read(crypto.storage(), pubkey, scheme).ok_or((
        ErrorCode::StorageFailure,
        "own signature keypair not in storage (was this member built on a different provider instance?)"
            .into(),
    ))
}

/// Marmot exporter label, per MIP-03.
const EXPORTER_LABEL: &str = "marmot";
/// Marmot exporter context, per MIP-03.
const EXPORTER_CONTEXT: &[u8] = b"group-event";
/// Marmot exporter output length.
const EXPORTER_LENGTH: usize = 32;

/// Reads the 32-byte nostr_group_id out of a raw pointer. Returns
/// an error string on null. Exported for use by the messages module.
pub(crate) unsafe fn read_group_id_safe(ptr: *const u8) -> Result<[u8; 32], &'static str> {
    unsafe { read_group_id(ptr) }
}

/// Reads the 32-byte nostr_group_id out of a raw pointer. Returns
/// an error string on null.
unsafe fn read_group_id(ptr: *const u8) -> Result<[u8; 32], &'static str> {
    if ptr.is_null() {
        return Err("nostr_group_id pointer is null");
    }
    // SAFETY: caller passes a 32-byte buffer.
    let slice = unsafe { std::slice::from_raw_parts(ptr, 32) };
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Builds a CredentialWithKey + SignatureKeyPair for a member identified
/// by `identity` and the given ciphersuite. The keys are persisted in
/// the OpenMLS storage before returning.
fn build_member_credential(
    crypto: &MarmotCryptoProvider,
    identity: &[u8],
    ciphersuite: Ciphersuite,
) -> Result<(CredentialWithKey, SignatureKeyPair), (ErrorCode, String)> {
    let scheme: SignatureScheme = ciphersuite.signature_algorithm();
    let signature_keys = SignatureKeyPair::new(scheme)
        .map_err(|e| (ErrorCode::CryptoFailure, format!("SignatureKeyPair::new: {e:?}")))?;
    signature_keys
        .store(crypto.storage())
        .map_err(|e| (ErrorCode::StorageFailure, format!("store signature keys: {e:?}")))?;

    let credential = BasicCredential::new(identity.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };
    Ok((credential_with_key, signature_keys))
}

/// Create a new MLS group with the founder as the only member.
///
/// `group_data_ptr` / `group_data_len` carry the TLS-serialized Marmot
/// Group Data extension (MIP-01) payload, which becomes a 0xF2EE
/// `GroupContextExtension` and is also listed in the group's
/// `required_capabilities` so non-Marmot clients reject membership.
///
/// # Safety
/// Standard FFI safety. `nostr_group_id_ptr` must point at a 32-byte buffer.
#[allow(clippy::too_many_arguments)]
pub unsafe fn create_group(
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
    use crate::keypackage::{
        NOSTR_GROUP_DATA_EXTENSION_TYPE, marmot_capabilities,
    };
    use openmls::extensions::{
        Extension, ExtensionType, Extensions, RequiredCapabilitiesExtension, UnknownExtension,
    };

    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }
    let provider = unsafe { &mut *provider };

    let identity = match unsafe { input_slice(creator_identity_ptr, creator_identity_len) } {
        Some(s) => s.to_vec(),
        None => return fail(ErrorCode::NullArgument, "creator identity is null"),
    };
    let group_id = match unsafe { read_group_id(nostr_group_id_ptr) } {
        Ok(g) => g,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };
    let group_data = match unsafe { input_slice(group_data_ptr, group_data_len) } {
        Some(s) => s.to_vec(),
        None => return fail(ErrorCode::NullArgument, "group_data pointer is null"),
    };
    let suite = match ciphersuite_from_u16(ciphersuite) {
        Some(s) => s,
        None => {
            return fail(
                ErrorCode::Unsupported,
                format!("unsupported ciphersuite 0x{ciphersuite:04X}"),
            );
        }
    };

    let (credential_with_key, signature_keys) =
        match build_member_credential(&provider.crypto, &identity, suite) {
            Ok(v) => v,
            Err((code, msg)) => return fail(code, msg),
        };

    // Build the Marmot group-context extensions: the NostrGroupData blob
    // plus a RequiredCapabilities entry that forces every future member
    // to declare support for 0xF2EE. This mirrors mdk-core exactly.
    let nostr_group_data_extension = Extension::Unknown(
        NOSTR_GROUP_DATA_EXTENSION_TYPE,
        UnknownExtension(group_data),
    );
    let required_capabilities = Extension::RequiredCapabilities(
        RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE)],
            &[],
            &[],
        ),
    );
    let context_extensions = match Extensions::from_vec(vec![
        nostr_group_data_extension,
        required_capabilities,
    ]) {
        Ok(e) => e,
        Err(e) => {
            return fail(
                ErrorCode::OpenMlsFailure,
                format!("Extensions::from_vec: {e:?}"),
            );
        }
    };

    let capabilities = marmot_capabilities(provider.crypto.rand(), suite);

    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities)
        .with_group_context_extensions(context_extensions)
        .build();

    let group_id_obj = GroupId::from_slice(&group_id);

    let group = match MlsGroup::new_with_group_id(
        &provider.crypto,
        &signature_keys,
        &group_config,
        group_id_obj,
        credential_with_key,
    ) {
        Ok(g) => g,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("MlsGroup::new_with_group_id: {e:?}")),
    };

    // Compute the exporter secret for the bootstrap epoch.
    let exporter = match group.export_secret(provider.crypto.crypto(), EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_LENGTH) {
        Ok(s) => s,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("export_secret: {e:?}")),
    };

    // The signature keys were already persisted in OpenMLS storage by
    // build_member_credential; the group state is persisted by
    // MlsGroup::new_with_group_id. No extra bookkeeping needed.
    let _ = (signature_keys, group);  // suppress unused warnings; values are bound for clarity

    unsafe {
        return_ffi_buffer(exporter, out_exporter_ptr, out_exporter_len);
    }
    ErrorCode::Success as i32
}

/// Add one or more members to the group, producing a single Welcome
/// blob (carrying EncryptedGroupSecrets for each new member) and a
/// single Commit MLSMessage.
///
/// Input format for `keypackage_blob`: `[u32 BE count] [u32 BE len_0] [bytes_0] ...`
/// Output `recipients` format: `[u32 BE count] [32 bytes id_0] ...`
///
/// # Safety
/// Standard FFI safety.
#[allow(clippy::too_many_arguments)]
pub unsafe fn add_members(
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
    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }
    let provider = unsafe { &mut *provider };

    let group_id = match unsafe { read_group_id(nostr_group_id_ptr) } {
        Ok(g) => g,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };

    let blob = match unsafe { input_slice(keypackage_blob_ptr, keypackage_blob_len) } {
        Some(s) => s,
        None => return fail(ErrorCode::NullArgument, "keypackage blob pointer is null"),
    };

    // Decode the inbound KeyPackage blob.
    let (key_packages, recipient_identities) = match decode_keypackage_blob(blob, &provider.crypto) {
        Ok(v) => v,
        Err((code, msg)) => return fail(code, msg),
    };

    if key_packages.is_empty() {
        return fail(ErrorCode::InvalidArgument, "must add at least one member");
    }

    let mut group = match load_group(&provider.crypto, &group_id) {
        Ok(g) => g,
        Err((c, m)) => return fail(c, m),
    };
    let signature_keys = match load_own_signature_keys(&provider.crypto, &group) {
        Ok(k) => k,
        Err((c, m)) => return fail(c, m),
    };

    // Issue the Add proposals + Commit.
    let (commit_msg, welcome_msg, _group_info) = match group.add_members(
        &provider.crypto,
        &signature_keys,
        &key_packages,
    ) {
        Ok(t) => t,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("add_members: {e:?}")),
    };

    // Apply our own Commit locally to advance our epoch.
    if let Err(e) = group.merge_pending_commit(&provider.crypto) {
        return fail(ErrorCode::OpenMlsFailure, format!("merge_pending_commit: {e:?}"));
    }

    // Recompute the exporter for the new epoch.
    let exporter = match group.export_secret(provider.crypto.crypto(), EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_LENGTH) {
        Ok(s) => s,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("export_secret: {e:?}")),
    };

    // Encode recipients: u32 BE count + N * 32-byte identities.
    let mut recipient_identity = Vec::with_capacity(4 + 32 * recipient_identities.len());
    recipient_identity.extend_from_slice(&(recipient_identities.len() as u32).to_be_bytes());
    for id in &recipient_identities {
        if id.len() != 32 {
            return fail(
                ErrorCode::Unsupported,
                format!("recipient identity must be 32 bytes (got {})", id.len()),
            );
        }
        recipient_identity.extend_from_slice(id);
    }

    let commit_bytes = match commit_msg.tls_serialize_detached() {
        Ok(b) => b,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("serialize Commit: {e:?}")),
    };
    let welcome_bytes = match welcome_msg.tls_serialize_detached() {
        Ok(b) => b,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("serialize Welcome: {e:?}")),
    };

    unsafe {
        return_ffi_buffer(commit_bytes, out_commit_ptr, out_commit_len);
        return_ffi_buffer(welcome_bytes, out_welcome_ptr, out_welcome_len);
        return_ffi_buffer(recipient_identity, out_recipients_ptr, out_recipients_len);
        return_ffi_buffer(exporter, out_exporter_ptr, out_exporter_len);
    }
    ErrorCode::Success as i32
}

/// Remove one or more members from the group by their Nostr pubkeys.
/// Produces a Commit MLSMessage that existing members process to apply
/// the removal and advance the epoch.
///
/// Input `pubkeys_blob` format: `[u32 BE count] [32 bytes pubkey_0] ...`
///
/// # Safety
/// Standard FFI safety.
#[allow(clippy::too_many_arguments)]
pub unsafe fn remove_members(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    pubkeys_blob_ptr: *const u8,
    pubkeys_blob_len: usize,
    out_commit_ptr: *mut *mut u8,
    out_commit_len: *mut usize,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }
    let provider = unsafe { &mut *provider };

    let group_id = match unsafe { read_group_id(nostr_group_id_ptr) } {
        Ok(g) => g,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };

    let blob = match unsafe { input_slice(pubkeys_blob_ptr, pubkeys_blob_len) } {
        Some(s) => s,
        None => return fail(ErrorCode::NullArgument, "pubkeys blob pointer is null"),
    };

    if blob.len() < 4 {
        return fail(ErrorCode::InvalidArgument, "pubkeys blob too short");
    }
    let count = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let expected_len = 4 + 32 * count;
    if blob.len() != expected_len {
        return fail(
            ErrorCode::InvalidArgument,
            format!("pubkeys blob length {} != expected {expected_len}", blob.len()),
        );
    }

    if count == 0 {
        return fail(ErrorCode::InvalidArgument, "must remove at least one member");
    }

    let mut group = match load_group(&provider.crypto, &group_id) {
        Ok(g) => g,
        Err((c, m)) => return fail(c, m),
    };
    let signature_keys = match load_own_signature_keys(&provider.crypto, &group) {
        Ok(k) => k,
        Err((c, m)) => return fail(c, m),
    };

    // Map each pubkey to a LeafNodeIndex via the group's member list.
    let mut leaf_indices = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + 32 * i;
        let pubkey = &blob[off..off + 32];

        let found = group.members().find(|m| {
            BasicCredential::try_from(m.credential.clone())
                .map(|b| b.identity() == pubkey)
                .unwrap_or(false)
        });

        match found {
            Some(member) => leaf_indices.push(member.index),
            None => {
                return fail(
                    ErrorCode::InvalidArgument,
                    format!("member with pubkey #{i} not found in group"),
                );
            }
        }
    }

    let (commit_msg, _welcome_opt, _group_info) = match group.remove_members(
        &provider.crypto,
        &signature_keys,
        &leaf_indices,
    ) {
        Ok(t) => t,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("remove_members: {e:?}")),
    };

    if let Err(e) = group.merge_pending_commit(&provider.crypto) {
        return fail(ErrorCode::OpenMlsFailure, format!("merge_pending_commit: {e:?}"));
    }

    let exporter = match group.export_secret(provider.crypto.crypto(), EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_LENGTH) {
        Ok(s) => s,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("export_secret: {e:?}")),
    };

    let commit_bytes = match commit_msg.tls_serialize_detached() {
        Ok(b) => b,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("serialize Commit: {e:?}")),
    };

    unsafe {
        return_ffi_buffer(commit_bytes, out_commit_ptr, out_commit_len);
        return_ffi_buffer(exporter, out_exporter_ptr, out_exporter_len);
    }
    ErrorCode::Success as i32
}

/// Rotates the calling member's leaf keys via OpenMLS `self_update`.
/// Produces a Commit MLSMessage that all existing members process to
/// advance the epoch.
///
/// # Safety
/// Standard FFI safety.
pub unsafe fn self_update(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    out_commit_ptr: *mut *mut u8,
    out_commit_len: *mut usize,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }
    let provider = unsafe { &mut *provider };

    let group_id = match unsafe { read_group_id(nostr_group_id_ptr) } {
        Ok(g) => g,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };

    let mut group = match load_group(&provider.crypto, &group_id) {
        Ok(g) => g,
        Err((c, m)) => return fail(c, m),
    };
    let signature_keys = match load_own_signature_keys(&provider.crypto, &group) {
        Ok(k) => k,
        Err((c, m)) => return fail(c, m),
    };

    let commit_bundle = match group.self_update(
        &provider.crypto,
        &signature_keys,
        LeafNodeParameters::default(),
    ) {
        Ok(b) => b,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("self_update: {e:?}")),
    };

    if let Err(e) = group.merge_pending_commit(&provider.crypto) {
        return fail(ErrorCode::OpenMlsFailure, format!("merge_pending_commit: {e:?}"));
    }

    let exporter = match group.export_secret(provider.crypto.crypto(), EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_LENGTH) {
        Ok(s) => s,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("export_secret: {e:?}")),
    };

    let commit_bytes = match commit_bundle.commit().tls_serialize_detached() {
        Ok(b) => b,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("serialize Commit: {e:?}")),
    };

    unsafe {
        return_ffi_buffer(commit_bytes, out_commit_ptr, out_commit_len);
        return_ffi_buffer(exporter, out_exporter_ptr, out_exporter_len);
    }
    ErrorCode::Success as i32
}

/// Decode the length-prefixed blob format `[u32 BE count] [u32 BE len_0]
/// [bytes_0] ...` into a Vec<KeyPackage>, validating each. Also returns
/// the parallel list of recipient identity bytes.
fn decode_keypackage_blob(
    blob: &[u8],
    crypto: &MarmotCryptoProvider,
) -> Result<(Vec<KeyPackage>, Vec<Vec<u8>>), (ErrorCode, String)> {
    if blob.len() < 4 {
        return Err((ErrorCode::InvalidArgument, "keypackage blob too short".into()));
    }
    let count = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let mut cursor = 4usize;
    let mut kps = Vec::with_capacity(count);
    let mut identities = Vec::with_capacity(count);

    for i in 0..count {
        if cursor + 4 > blob.len() {
            return Err((ErrorCode::InvalidArgument, format!("blob truncated at entry {i} length")));
        }
        let len = u32::from_be_bytes([blob[cursor], blob[cursor + 1], blob[cursor + 2], blob[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + len > blob.len() {
            return Err((ErrorCode::InvalidArgument, format!("blob truncated at entry {i} body")));
        }
        let kp_bytes = &blob[cursor..cursor + len];
        cursor += len;

        let mut c = kp_bytes;
        // Marmot MIP-00: wire form is a raw KeyPackage (matches mdk-core /
        // White Noise), not an MLSMessage(KeyPackage) frame.
        let kp_in = KeyPackageIn::tls_deserialize(&mut c)
            .map_err(|e| (ErrorCode::SerializationFailure, format!("deserialize KeyPackage #{i}: {e:?}")))?;
        let kp = kp_in
            .validate(crypto.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| (ErrorCode::CryptoFailure, format!("KeyPackage #{i} validation: {e:?}")))?;

        let credential = kp.leaf_node().credential().clone();
        let identity = match BasicCredential::try_from(credential) {
            Ok(b) => b.identity().to_vec(),
            Err(e) => return Err((ErrorCode::SerializationFailure, format!("decode BasicCredential #{i}: {e:?}"))),
        };

        kps.push(kp);
        identities.push(identity);
    }

    Ok((kps, identities))
}

/// Process an inbound Welcome and join the group.
///
/// # Safety
/// Standard FFI safety.
pub unsafe fn join_from_welcome(
    provider: *mut Provider,
    welcome_bytes_ptr: *const u8,
    welcome_bytes_len: usize,
    out_group_id_ptr: *mut *mut u8,
    out_group_id_len: *mut usize,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }
    let provider = unsafe { &mut *provider };

    let welcome_bytes = match unsafe { input_slice(welcome_bytes_ptr, welcome_bytes_len) } {
        Some(s) => s,
        None => return fail(ErrorCode::NullArgument, "welcome bytes pointer is null"),
    };

    let mut cursor = welcome_bytes;
    let message = match MlsMessageIn::tls_deserialize(&mut cursor) {
        Ok(m) => m,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("deserialize MLSMessage(Welcome): {e:?}")),
    };
    let welcome = match message.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return fail(ErrorCode::InvalidWireFormat, "expected MLSMessage(Welcome)"),
    };

    let join_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let staged = match StagedWelcome::new_from_welcome(
        &provider.crypto,
        &join_config,
        welcome,
        None,
    ) {
        Ok(s) => s,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("StagedWelcome::new_from_welcome: {e:?}")),
    };

    let group = match staged.into_group(&provider.crypto) {
        Ok(g) => g,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("StagedWelcome::into_group: {e:?}")),
    };

    // The joiner's signature keys were already persisted when their
    // KeyPackage was built. The MlsGroup state has been written to
    // storage by StagedWelcome::into_group. No further bookkeeping needed.
    let group_id_slice = group.group_id().as_slice();
    let mut group_id = [0u8; 32];
    if group_id_slice.len() != 32 {
        return fail(
            ErrorCode::InvalidArgument,
            format!("group_id is not 32 bytes (got {})", group_id_slice.len()),
        );
    }
    group_id.copy_from_slice(group_id_slice);

    // Sanity-check that our own-leaf signature keypair is reachable
    // from storage by pubkey — if not, future state changes will fail.
    if load_own_signature_keys(&provider.crypto, &group).is_err() {
        return fail(
            ErrorCode::InternalError,
            "joined leaf signature keys missing from storage (was this provider used to build the KeyPackage?)",
        );
    }

    let exporter = match group.export_secret(provider.crypto.crypto(), EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_LENGTH) {
        Ok(s) => s,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("export_secret: {e:?}")),
    };

    unsafe {
        return_ffi_buffer(group_id.to_vec(), out_group_id_ptr, out_group_id_len);
        return_ffi_buffer(exporter, out_exporter_ptr, out_exporter_len);
    }
    ErrorCode::Success as i32
}

/// Returns the current epoch's Marmot exporter secret for the given group.
///
/// # Safety
/// Standard FFI safety. `nostr_group_id_ptr` must point at 32 bytes.
pub unsafe fn current_exporter(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    out_exporter_ptr: *mut *mut u8,
    out_exporter_len: *mut usize,
) -> i32 {
    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }
    let provider = unsafe { &*provider };

    let group_id = match unsafe { read_group_id(nostr_group_id_ptr) } {
        Ok(g) => g,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };

    let group = match load_group(&provider.crypto, &group_id) {
        Ok(g) => g,
        Err((c, m)) => return fail(c, m),
    };

    let exporter = match group.export_secret(provider.crypto.crypto(), EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_LENGTH) {
        Ok(s) => s,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("export_secret: {e:?}")),
    };

    unsafe {
        return_ffi_buffer(exporter, out_exporter_ptr, out_exporter_len);
    }
    ErrorCode::Success as i32
}
