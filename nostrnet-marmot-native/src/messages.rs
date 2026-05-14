// SPDX-License-Identifier: MIT
//
// Application-message FFI: encrypt a plaintext into an
// MLSMessage(PrivateMessage), and process an inbound MLSMessage of
// any content type.

use crate::buffer::{input_slice, return_ffi_buffer};
use crate::errors::{ErrorCode, fail};
use crate::provider::Provider;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::{Deserialize, Serialize};

const EXPORTER_LABEL: &str = "marmot";
const EXPORTER_CONTEXT: &[u8] = b"group-event";
const EXPORTER_LENGTH: usize = 32;

/// Discriminant returned via the FFI's `out_kind` parameter on
/// process_incoming_mls_message.
#[repr(i32)]
pub enum MessageKind {
    Application = 0,
    Proposal = 1,
    Commit = 2,
}

/// # Safety
/// Standard FFI safety.
pub unsafe fn encrypt_application_message(
    provider: *mut Provider,
    nostr_group_id_ptr: *const u8,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    out_msg_ptr: *mut *mut u8,
    out_msg_len: *mut usize,
) -> i32 {
    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }
    let provider = unsafe { &mut *provider };

    let group_id = match unsafe { crate::group::read_group_id_safe(nostr_group_id_ptr) } {
        Ok(g) => g,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };
    let plaintext = match unsafe { input_slice(plaintext_ptr, plaintext_len) } {
        Some(s) => s,
        None => return fail(ErrorCode::NullArgument, "plaintext pointer is null"),
    };

    let group_state = match provider.groups.get(&group_id) {
        Some(s) => s,
        None => return fail(ErrorCode::UnknownGroupId, "no such group"),
    };

    let mut sig_bytes = group_state.serialized.as_slice();
    let signature_keys = match SignatureKeyPair::tls_deserialize(&mut sig_bytes) {
        Ok(k) => k,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("deserialize SignatureKeyPair: {e:?}")),
    };

    let group_id_obj = GroupId::from_slice(&group_id);
    let mut group = match MlsGroup::load(provider.crypto.storage(), &group_id_obj) {
        Ok(Some(g)) => g,
        Ok(None) => return fail(ErrorCode::UnknownGroupId, "group not in storage"),
        Err(e) => return fail(ErrorCode::StorageFailure, format!("MlsGroup::load: {e:?}")),
    };

    let mls_message = match group.create_message(&provider.crypto, &signature_keys, plaintext) {
        Ok(m) => m,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("create_message: {e:?}")),
    };

    let bytes = match mls_message.tls_serialize_detached() {
        Ok(b) => b,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("serialize MLSMessage: {e:?}")),
    };

    unsafe {
        return_ffi_buffer(bytes, out_msg_ptr, out_msg_len);
    }
    ErrorCode::Success as i32
}

/// # Safety
/// Standard FFI safety.
#[allow(clippy::too_many_arguments)]
pub unsafe fn process_incoming_message(
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
) -> i32 {
    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }
    let provider = unsafe { &mut *provider };

    let group_id = match unsafe { crate::group::read_group_id_safe(nostr_group_id_ptr) } {
        Ok(g) => g,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };
    let bytes = match unsafe { input_slice(msg_ptr, msg_len) } {
        Some(s) => s,
        None => return fail(ErrorCode::NullArgument, "message pointer is null"),
    };

    let group_id_obj = GroupId::from_slice(&group_id);
    let mut group = match MlsGroup::load(provider.crypto.storage(), &group_id_obj) {
        Ok(Some(g)) => g,
        Ok(None) => return fail(ErrorCode::UnknownGroupId, "group not in storage"),
        Err(e) => return fail(ErrorCode::StorageFailure, format!("MlsGroup::load: {e:?}")),
    };

    let mut cursor = bytes;
    let mls_message = match MlsMessageIn::tls_deserialize(&mut cursor) {
        Ok(m) => m,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("deserialize MLSMessage: {e:?}")),
    };

    let protocol_message: ProtocolMessage = match mls_message.extract() {
        MlsMessageBodyIn::PrivateMessage(m) => m.into(),
        MlsMessageBodyIn::PublicMessage(m) => m.into(),
        _ => return fail(ErrorCode::InvalidWireFormat, "expected Public/PrivateMessage"),
    };

    let processed = match group.process_message(&provider.crypto, protocol_message) {
        Ok(p) => p,
        Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("process_message: {e:?}")),
    };

    let (kind, payload, advanced) = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            (MessageKind::Application, app_msg.into_bytes(), false)
        }
        ProcessedMessageContent::ProposalMessage(_) => {
            (MessageKind::Proposal, Vec::new(), false)
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            if let Err(e) = group.merge_staged_commit(&provider.crypto, *staged) {
                return fail(ErrorCode::OpenMlsFailure, format!("merge_staged_commit: {e:?}"));
            }
            (MessageKind::Commit, Vec::new(), true)
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
            return fail(ErrorCode::Unsupported, "external join proposals not supported");
        }
    };

    let new_exporter = if advanced {
        match group.export_secret(provider.crypto.crypto(), EXPORTER_LABEL, EXPORTER_CONTEXT, EXPORTER_LENGTH) {
            Ok(s) => Some(s),
            Err(e) => return fail(ErrorCode::OpenMlsFailure, format!("export_secret: {e:?}")),
        }
    } else {
        None
    };

    unsafe {
        std::ptr::write(out_kind, kind as i32);
        return_ffi_buffer(payload, out_payload_ptr, out_payload_len);
        std::ptr::write(out_epoch_advanced, if advanced { 1 } else { 0 });
        match new_exporter {
            Some(exp) => return_ffi_buffer(exp, out_new_exporter_ptr, out_new_exporter_len),
            None => {
                std::ptr::write(out_new_exporter_ptr, std::ptr::null_mut());
                std::ptr::write(out_new_exporter_len, 0);
            }
        }
    }
    ErrorCode::Success as i32
}
