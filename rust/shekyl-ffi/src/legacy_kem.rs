// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! KEM, address, seed-derive, blob encode FFI.

use std::os::raw::c_char;

use super::legacy_types::*;
use super::legacy_util::*;

// ─── FCMP++: KEM Operations ─────────────────────────────────────────────────

/// Generate a hybrid X25519 + ML-KEM-768 keypair.
#[no_mangle]
pub extern "C" fn shekyl_kem_keypair_generate() -> ShekylPqcKeypair {
    use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};

    let fail = ShekylPqcKeypair {
        public_key: ShekylBuffer::null(),
        secret_key: ShekylBuffer::null(),
        success: false,
    };

    let kem = HybridX25519MlKem;
    match kem.keypair_generate() {
        Ok((pk, sk)) => {
            let mut pk_bytes = Vec::new();
            pk_bytes.extend_from_slice(&pk.x25519);
            pk_bytes.extend_from_slice(&pk.ml_kem);

            let mut sk_bytes = Vec::new();
            sk_bytes.extend_from_slice(&sk.x25519);
            sk_bytes.extend_from_slice(&sk.ml_kem);

            ShekylPqcKeypair {
                public_key: ShekylBuffer::from_vec(pk_bytes),
                secret_key: ShekylBuffer::from_vec(sk_bytes),
                success: true,
            }
        }
        Err(_) => fail,
    }
}

/// Convert an Ed25519 view public key to its X25519 (Montgomery u-coordinate)
/// equivalent. The caller provides a 32-byte Ed25519 public key and receives
/// the 32-byte X25519 public key. Returns false on rejection (identity point,
/// non-canonical encoding).
///
/// # Safety
/// Both pointers must point to valid 32-byte buffers.
#[no_mangle]
pub unsafe extern "C" fn shekyl_view_pub_to_x25519_pub(
    ed_pub_ptr: *const u8,
    x25519_out_ptr: *mut u8,
) -> bool {
    use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;

    if ed_pub_ptr.is_null() || x25519_out_ptr.is_null() {
        return false;
    }

    let ed_pub: &[u8; 32] = unsafe { &*(ed_pub_ptr as *const [u8; 32]) };

    match ed25519_pk_to_x25519_pk(ed_pub) {
        Ok(x25519_pk) => {
            unsafe { std::ptr::copy_nonoverlapping(x25519_pk.as_ptr(), x25519_out_ptr, 32) };
            true
        }
        Err(_) => false,
    }
}

/// Encapsulate to a hybrid public key. Returns ciphertext in the buffer.
/// Combined shared secret is written to `ss_out_ptr` (64 bytes).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_kem_encapsulate(
    pk_x25519_ptr: *const u8,
    pk_ml_kem_ptr: *const u8,
    pk_ml_kem_len: usize,
    ct_out: *mut ShekylBuffer,
    ss_out_ptr: *mut u8,
) -> bool {
    use shekyl_crypto_pq::kem::{HybridKemPublicKey, HybridX25519MlKem, KeyEncapsulation};

    if pk_x25519_ptr.is_null()
        || pk_ml_kem_ptr.is_null()
        || ct_out.is_null()
        || ss_out_ptr.is_null()
    {
        return false;
    }

    let x25519: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(pk_x25519_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let Some(ml_kem) = (unsafe { slice_from_ptr(pk_ml_kem_ptr, pk_ml_kem_len) }) else {
        return false;
    };

    let pk = HybridKemPublicKey {
        x25519,
        ml_kem: ml_kem.to_vec(),
    };
    let kem = HybridX25519MlKem;

    match kem.encapsulate(&pk) {
        Ok((ss, ct)) => {
            let mut ct_bytes = Vec::new();
            ct_bytes.extend_from_slice(&ct.x25519);
            ct_bytes.extend_from_slice(&ct.ml_kem);

            *ct_out = ShekylBuffer::from_vec(ct_bytes);
            std::ptr::copy_nonoverlapping(ss.0.as_ptr(), ss_out_ptr, 64);
            true
        }
        Err(_) => false,
    }
}

/// Decapsulate a hybrid ciphertext. Writes combined shared secret to `ss_out_ptr` (64 bytes).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_kem_decapsulate(
    sk_x25519_ptr: *const u8,
    sk_ml_kem_ptr: *const u8,
    sk_ml_kem_len: usize,
    ct_x25519_ptr: *const u8,
    ct_ml_kem_ptr: *const u8,
    ct_ml_kem_len: usize,
    ss_out_ptr: *mut u8,
) -> bool {
    use shekyl_crypto_pq::kem::{
        HybridCiphertext, HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation,
    };

    if sk_x25519_ptr.is_null()
        || sk_ml_kem_ptr.is_null()
        || ct_x25519_ptr.is_null()
        || ct_ml_kem_ptr.is_null()
        || ss_out_ptr.is_null()
    {
        return false;
    }

    let sk_x25519: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(sk_x25519_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let Some(sk_ml_kem) = (unsafe { slice_from_ptr(sk_ml_kem_ptr, sk_ml_kem_len) }) else {
        return false;
    };
    let ct_x25519: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(ct_x25519_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let Some(ct_ml_kem) = (unsafe { slice_from_ptr(ct_ml_kem_ptr, ct_ml_kem_len) }) else {
        return false;
    };

    let sk = HybridKemSecretKey {
        x25519: sk_x25519,
        ml_kem: sk_ml_kem.to_vec(),
    };
    let ct = HybridCiphertext {
        x25519: ct_x25519,
        ml_kem: ct_ml_kem.to_vec(),
    };
    let kem = HybridX25519MlKem;

    match kem.decapsulate(&sk, &ct) {
        Ok(ss) => {
            std::ptr::copy_nonoverlapping(ss.0.as_ptr(), ss_out_ptr, 64);
            true
        }
        Err(_) => false,
    }
}

// ─── Bech32m Address Encoding ────────────────────────────────────────────────

/// Encode a Shekyl Bech32m address from raw key material.
///
/// `network`: 0=mainnet, 1=testnet, 2=stagenet.
/// `spend_key_ptr`: 32 bytes. `view_key_ptr`: 32 bytes.
/// `msg_sign_pk_ptr`: 48 bytes (SLH-DSA-192s message-signing public key —
/// the fourth classical field since the fork-(ii) layout). **Required**:
/// a null pointer returns a null buffer, because no valid address can be
/// assembled without it. C++ callers that only hold an
/// `account_public_address` (which carries no msg_sign_pk) cannot use
/// this function any more; live daemon paths carry the original address
/// string instead of re-encoding.
/// `ml_kem_ek_ptr`: 1184 bytes (ML-KEM-768 encapsulation key).
///
/// Returns a ShekylBuffer containing the UTF-8 encoded address string.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_address_encode(
    network: u8,
    spend_key_ptr: *const u8,
    view_key_ptr: *const u8,
    msg_sign_pk_ptr: *const u8,
    ml_kem_ek_ptr: *const u8,
    ml_kem_ek_len: usize,
) -> ShekylBuffer {
    if ml_kem_ek_len > 0 && ml_kem_ek_ptr.is_null() {
        return ShekylBuffer::null();
    }

    let Some(net) = shekyl_address::Network::from_u8(network) else {
        return ShekylBuffer::null();
    };

    // Every fixed-size boundary read goes through `array_from_ptr`
    // (rule 40): one audited construction owns the null / zero-length /
    // isize::MAX preconditions, and the type parameter *is* the layout
    // length so a wrong count cannot silently truncate. What NO
    // boundary code can check is the caller's allocation size — a
    // non-null undersized buffer is UB under any read idiom; that
    // precondition is the `# Safety` contract above, as everywhere on
    // this surface.
    let Some(spend_key) = (unsafe { array_from_ptr::<32>(spend_key_ptr) }) else {
        return ShekylBuffer::null();
    };
    let Some(view_key) = (unsafe { array_from_ptr::<32>(view_key_ptr) }) else {
        return ShekylBuffer::null();
    };
    let Some(msg_sign_pk) =
        (unsafe { array_from_ptr::<{ shekyl_address::MSG_SIGN_PK_LEN }>(msg_sign_pk_ptr) })
    else {
        return ShekylBuffer::null();
    };
    let ml_kem_ek = if ml_kem_ek_len == 0 {
        Vec::new()
    } else {
        let Some(slice) = (unsafe { slice_from_ptr(ml_kem_ek_ptr, ml_kem_ek_len) }) else {
            return ShekylBuffer::null();
        };
        slice.to_vec()
    };

    let addr = shekyl_address::ShekylAddress::new(net, spend_key, view_key, msg_sign_pk, ml_kem_ek);

    match addr.encode() {
        Ok(s) => ShekylBuffer::from_vec(s.into_bytes()),
        Err(_) => ShekylBuffer::null(),
    }
}

/// Decode a Bech32m-encoded Shekyl address.
///
/// `encoded_ptr`: null-terminated UTF-8 string.
/// `network_out`: receives network discriminant (0=mainnet, 1=testnet, 2=stagenet).
/// Writes: 32 bytes to `spend_key_out`, 32 bytes to `view_key_out`.
/// Returns ML-KEM encapsulation key in a ShekylBuffer (1184 bytes, or 0 if classical-only).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_address_decode(
    encoded_ptr: *const c_char,
    network_out: *mut u8,
    spend_key_out: *mut u8,
    view_key_out: *mut u8,
) -> ShekylBuffer {
    if encoded_ptr.is_null()
        || network_out.is_null()
        || spend_key_out.is_null()
        || view_key_out.is_null()
    {
        return ShekylBuffer::null();
    }

    let c_str = std::ffi::CStr::from_ptr(encoded_ptr);
    let Ok(encoded) = c_str.to_str() else {
        return ShekylBuffer::null();
    };

    match shekyl_address::ShekylAddress::decode(encoded) {
        Ok(addr) => {
            *network_out = addr.network.as_u8();
            std::ptr::copy_nonoverlapping(addr.spend_key.as_ptr(), spend_key_out, 32);
            std::ptr::copy_nonoverlapping(addr.view_key.as_ptr(), view_key_out, 32);
            ShekylBuffer::from_vec(addr.ml_kem_encap_key)
        }
        Err(_) => ShekylBuffer::null(),
    }
}

// ─── Bech32m Blob Encoding ──────────────────────────────────────────────────

/// Encode arbitrary binary data as a Bech32m string with the given HRP.
///
/// `hrp_ptr` / `hrp_len`: UTF-8 HRP string (not null-terminated).
/// `data_ptr` / `data_len`: raw binary payload.
///
/// Returns a ShekylBuffer containing the UTF-8 encoded Bech32m string,
/// or a null buffer on failure.
#[no_mangle]
pub extern "C" fn shekyl_encode_blob(
    hrp_ptr: *const u8,
    hrp_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> ShekylBuffer {
    let Some(hrp_bytes) = (unsafe { slice_from_ptr(hrp_ptr, hrp_len) }) else {
        return ShekylBuffer::null();
    };
    let Ok(hrp) = std::str::from_utf8(hrp_bytes) else {
        return ShekylBuffer::null();
    };
    let Some(data) = (unsafe { slice_from_ptr(data_ptr, data_len) }) else {
        return ShekylBuffer::null();
    };

    match shekyl_encoding::encode_blob(hrp, data) {
        Ok(s) => ShekylBuffer::from_vec(s.into_bytes()),
        Err(_) => ShekylBuffer::null(),
    }
}

/// Decode a Bech32m string, writing the HRP and payload to caller-owned buffers.
///
/// `encoded_ptr`: null-terminated UTF-8 Bech32m string.
/// `hrp_out` / `hrp_out_cap`: buffer for the decoded HRP (UTF-8, not null-terminated).
/// `hrp_len_out`: receives the actual HRP byte length.
/// `data_out` / `data_out_cap`: buffer for the decoded payload.
/// `data_len_out`: receives the actual payload byte length.
///
/// Returns true on success. If a buffer is too small, writes nothing and returns false.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_decode_blob(
    encoded_ptr: *const c_char,
    hrp_out: *mut u8,
    hrp_out_cap: usize,
    hrp_len_out: *mut usize,
    data_out: *mut u8,
    data_out_cap: usize,
    data_len_out: *mut usize,
) -> bool {
    if encoded_ptr.is_null()
        || hrp_out.is_null()
        || hrp_len_out.is_null()
        || data_out.is_null()
        || data_len_out.is_null()
    {
        return false;
    }

    let c_str = std::ffi::CStr::from_ptr(encoded_ptr);
    let Ok(encoded) = c_str.to_str() else {
        return false;
    };

    let Ok((hrp, data)) = shekyl_encoding::decode_blob(encoded) else {
        return false;
    };

    let hrp_bytes = hrp.as_bytes();
    if hrp_bytes.len() > hrp_out_cap || data.len() > data_out_cap {
        return false;
    }

    std::ptr::copy_nonoverlapping(hrp_bytes.as_ptr(), hrp_out, hrp_bytes.len());
    *hrp_len_out = hrp_bytes.len();
    std::ptr::copy_nonoverlapping(data.as_ptr(), data_out, data.len());
    *data_len_out = data.len();
    true
}

// ─── FCMP++: Seed Derivation ────────────────────────────────────────────────

/// Derive Ed25519 spend secret key from master seed.
/// `seed_ptr`: 32 bytes. Writes 32 bytes to `out_ptr`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seed_derive_spend(seed_ptr: *const u8, out_ptr: *mut u8) -> bool {
    if seed_ptr.is_null() || out_ptr.is_null() {
        return false;
    }
    let seed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(seed_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let key = shekyl_crypto_pq::kem::SeedDerivation::derive_ed25519_spend(&seed);
    std::ptr::copy_nonoverlapping(key.as_ptr(), out_ptr, 32);
    true
}

/// Derive Ed25519 view secret key from master seed.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seed_derive_view(seed_ptr: *const u8, out_ptr: *mut u8) -> bool {
    if seed_ptr.is_null() || out_ptr.is_null() {
        return false;
    }
    let seed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(seed_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let key = shekyl_crypto_pq::kem::SeedDerivation::derive_ed25519_view(&seed);
    std::ptr::copy_nonoverlapping(key.as_ptr(), out_ptr, 32);
    true
}

/// Derive ML-KEM-768 seed material from master seed.
/// Writes 64 bytes to `out_ptr`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seed_derive_ml_kem(seed_ptr: *const u8, out_ptr: *mut u8) -> bool {
    if seed_ptr.is_null() || out_ptr.is_null() {
        return false;
    }
    let seed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(seed_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let material = shekyl_crypto_pq::kem::SeedDerivation::derive_ml_kem_seed(&seed);
    std::ptr::copy_nonoverlapping(material.as_ptr(), out_ptr, 64);
    true
}
