// SPDX-License-Identifier: MIT
//
// KeyPackage FFI: build + parse via OpenMLS.

use crate::buffer::{input_slice, return_ffi_buffer};
use crate::errors::{ErrorCode, fail, set_last_error};
use crate::provider::Provider;

use crate::provider::MarmotCryptoProvider;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

/// Resolves a ciphersuite identifier (u16) into an OpenMLS Ciphersuite.
pub(crate) fn ciphersuite_from_u16(v: u16) -> Option<Ciphersuite> {
    match v {
        0x0001 => Some(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
        0x0002 => Some(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
        0x0003 => Some(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
        // Phase 1: stick to widely-supported suites; expand later.
        _ => None,
    }
}

/// Build a KeyPackage and return its MLSMessage-wrapped wire bytes plus
/// the KeyPackageRef (32-byte hash).
///
/// # Safety
/// All pointer arguments must satisfy the standard FFI safety rules.
/// `provider` must be a live ProviderHandle from `marmot_provider_new`.
pub unsafe fn build_keypackage(
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
    if provider.is_null() {
        return fail(ErrorCode::NullArgument, "provider handle is null");
    }

    let provider = unsafe { &mut *provider };
    let identity = match unsafe { input_slice(identity_ptr, identity_len) } {
        Some(s) => s,
        None => return fail(ErrorCode::NullArgument, "identity pointer is null"),
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

    // Parse the extension / proposal type lists.
    let exts = match unsafe { read_u16_slice(extensions_ptr, extensions_len) } {
        Ok(v) => v,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };
    let props = match unsafe { read_u16_slice(proposals_ptr, proposals_len) } {
        Ok(v) => v,
        Err(msg) => return fail(ErrorCode::NullArgument, msg),
    };

    match build_keypackage_inner(&provider.crypto, identity, suite, &exts, &props) {
        Ok((bundle_bytes, kp_ref_bytes)) => {
            // The signature keypair was already persisted into OpenMLS
            // storage by build_member_credential — no separate state to track here.
            unsafe {
                return_ffi_buffer(bundle_bytes, out_bundle_ptr, out_bundle_len);
                return_ffi_buffer(kp_ref_bytes, out_kp_ref_ptr, out_kp_ref_len);
            }
            ErrorCode::Success as i32
        }
        Err((code, msg)) => fail(code, msg),
    }
}

fn build_keypackage_inner(
    provider: &MarmotCryptoProvider,
    identity: &[u8],
    ciphersuite: Ciphersuite,
    _extensions: &[u16],
    _proposals: &[u16],
) -> Result<(Vec<u8>, Vec<u8>), (ErrorCode, String)> {
    use openmls_traits::OpenMlsProvider;
    use openmls_traits::types::SignatureScheme;

    let signature_scheme: SignatureScheme = ciphersuite.signature_algorithm();
    let signature_keys = SignatureKeyPair::new(signature_scheme)
        .map_err(|e| (ErrorCode::CryptoFailure, format!("signature keypair generation: {e:?}")))?;

    // Persist the signature keypair in OpenMLS storage so we can look
    // it up later (by pubkey) when this member joins a group.
    signature_keys
        .store(provider.storage())
        .map_err(|e| (ErrorCode::StorageFailure, format!("store signature keys: {e:?}")))?;

    let credential = BasicCredential::new(identity.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };

    let key_package_bundle = KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            credential_with_key,
        )
        .map_err(|e| (ErrorCode::OpenMlsFailure, format!("KeyPackage::builder().build(): {e:?}")))?;

    let kp = key_package_bundle.key_package();

    let mls_message: MlsMessageOut = kp.clone().into();
    let bundle_bytes = mls_message
        .tls_serialize_detached()
        .map_err(|e| (ErrorCode::SerializationFailure, format!("serialize MLSMessage(KeyPackage): {e:?}")))?;

    let kp_ref = kp
        .hash_ref(provider.crypto())
        .map_err(|e| (ErrorCode::CryptoFailure, format!("hash_ref: {e:?}")))?;

    Ok((bundle_bytes, kp_ref.as_slice().to_vec()))
}

/// Parse a KeyPackage bundle (MLSMessage-wrapped) and return its
/// identity, ciphersuite, and KeyPackageRef.
///
/// # Safety
/// All pointer arguments must satisfy the standard FFI safety rules.
pub unsafe fn parse_keypackage(
    bundle_ptr: *const u8,
    bundle_len: usize,
    out_identity_ptr: *mut *mut u8,
    out_identity_len: *mut usize,
    out_kp_ref_ptr: *mut *mut u8,
    out_kp_ref_len: *mut usize,
    out_ciphersuite: *mut u16,
) -> i32 {
    let bytes = match unsafe { input_slice(bundle_ptr, bundle_len) } {
        Some(s) => s,
        None => return fail(ErrorCode::NullArgument, "bundle pointer is null"),
    };

    if out_ciphersuite.is_null() {
        return fail(ErrorCode::NullArgument, "out_ciphersuite is null");
    }

    let mut cursor = bytes;
    let mls_message = match MlsMessageIn::tls_deserialize(&mut cursor) {
        Ok(m) => m,
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("deserialize MLSMessage: {e:?}")),
    };

    let kp = match mls_message.extract() {
        MlsMessageBodyIn::KeyPackage(kp) => kp,
        other => {
            return fail(
                ErrorCode::InvalidWireFormat,
                format!("expected MLSMessage(KeyPackage); got {:?}", std::mem::discriminant(&other)),
            );
        }
    };

    // OpenMLS handed us a KeyPackageIn — verify and convert to KeyPackage.
    let backend = OpenMlsRustCrypto::default();
    let kp = match kp.validate(backend.crypto(), ProtocolVersion::Mls10) {
        Ok(kp) => kp,
        Err(e) => return set_last_error(ErrorCode::CryptoFailure, format!("KeyPackage validation: {e:?}")),
    };

    let credential = kp.leaf_node().credential();
    if credential.credential_type() != CredentialType::Basic {
        return fail(ErrorCode::Unsupported, "only BasicCredential is supported");
    }
    let identity = match BasicCredential::try_from(credential.clone()) {
        Ok(b) => b.identity().to_vec(),
        Err(e) => return fail(ErrorCode::SerializationFailure, format!("decode BasicCredential: {e:?}")),
    };

    let ciphersuite = kp.ciphersuite();
    let ciphersuite_u16 = u16::from(ciphersuite);

    let kp_ref = match kp.hash_ref(backend.crypto()) {
        Ok(r) => r.as_slice().to_vec(),
        Err(e) => return fail(ErrorCode::CryptoFailure, format!("hash_ref: {e:?}")),
    };

    unsafe {
        *out_ciphersuite = ciphersuite_u16;
        return_ffi_buffer(identity, out_identity_ptr, out_identity_len);
        return_ffi_buffer(kp_ref, out_kp_ref_ptr, out_kp_ref_len);
    }
    ErrorCode::Success as i32
}

/// Reads a u16 slice from FFI input. Empty (len=0) returns an empty Vec.
unsafe fn read_u16_slice(ptr: *const u16, len: usize) -> Result<Vec<u16>, &'static str> {
    if len == 0 {
        return Ok(Vec::new());
    }

    if ptr.is_null() {
        return Err("u16 slice pointer is null");
    }

    // SAFETY: caller asserts ptr+len is a valid readable region.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(slice.to_vec())
}

use openmls_traits::OpenMlsProvider;
