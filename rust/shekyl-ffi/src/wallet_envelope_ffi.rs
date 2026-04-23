// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the wallet-file envelope (WALLET_FILE_FORMAT_V1).
//!
//! This module exposes six entry points mirroring `shekyl_crypto_pq::
//! wallet_envelope`:
//! - `shekyl_wallet_keys_inspect` — parse AAD-readable header only
//! - `shekyl_wallet_keys_seal` — create a fresh `.wallet.keys`
//! - `shekyl_wallet_keys_open` — decrypt `.wallet.keys`
//! - `shekyl_wallet_keys_rewrap_password` — rotate the wrapping password
//! - `shekyl_wallet_state_seal` — seal `.wallet` state bytes
//! - `shekyl_wallet_state_open` — open `.wallet` state bytes
//!
//! # Discipline
//!
//! * **Typed out-struct for fixed-size metadata** (`ShekylKeysFileHeaderView`,
//!   `ShekylOpenedKeysInfo`) — C++ fills named fields instead of decoding
//!   byte offsets in user code.
//! * **Two-call sizing for variable-length byte outputs.** Every function
//!   with a `Vec<u8>` on the Rust side takes `out_buf` + `out_cap` + a
//!   `*mut size_t out_len_required`. On *any* return (success, error,
//!   buffer-too-small), the function writes the size it *would* need into
//!   `out_len_required`. On buffer-too-small, `out_error` is set to
//!   `SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL`; the caller retries with a
//!   larger buffer. This gives the C++ side a uniform "probe, allocate,
//!   call" loop without any hidden allocations in Rust.
//! * **Zeroize-on-failure.** If the function would have produced secret
//!   output but is failing (wrong password, tampering, etc.), the out
//!   buffers passed by the caller are overwritten with zeros before
//!   `false` is returned. The caller sees the same write pattern on every
//!   path.
//! * **Narrow error taxonomy** via `SHEKYL_WALLET_ERR_*` constants so the
//!   C++ side can render precise user messages (e.g. "requires multisig
//!   build" vs "wrong password") without string matching.

use shekyl_crypto_pq::wallet_envelope::{
    self, CapabilityContent, KdfParams, WalletEnvelopeError,
};
use shekyl_crypto_pq::kem::{ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN};

// ---------------------------------------------------------------------------
// Constants mirrored by the C++ header (shekyl_ffi.h)
// ---------------------------------------------------------------------------

pub const SHEKYL_WALLET_KEYS_WRAP_SALT_BYTES: usize = 16;
pub const SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES: usize =
    wallet_envelope::EXPECTED_CLASSICAL_ADDRESS_BYTES;
pub const SHEKYL_WALLET_SEED_BLOCK_TAG_BYTES: usize = 16;

pub const SHEKYL_WALLET_CAPABILITY_FULL: u8 = wallet_envelope::CAPABILITY_FULL;
pub const SHEKYL_WALLET_CAPABILITY_VIEW_ONLY: u8 = wallet_envelope::CAPABILITY_VIEW_ONLY;
pub const SHEKYL_WALLET_CAPABILITY_HARDWARE_OFFLOAD: u8 =
    wallet_envelope::CAPABILITY_HARDWARE_OFFLOAD;
pub const SHEKYL_WALLET_CAPABILITY_RESERVED_MULTISIG: u8 =
    wallet_envelope::CAPABILITY_RESERVED_MULTISIG;

pub const SHEKYL_WALLET_FORMAT_VERSION: u8 = wallet_envelope::WALLET_FILE_FORMAT_VERSION;
pub const SHEKYL_STATE_FORMAT_VERSION: u8 = wallet_envelope::STATE_FILE_FORMAT_VERSION;
pub const SHEKYL_KDF_ALGO_ARGON2ID: u8 = wallet_envelope::KDF_ALGO_ARGON2ID;
pub const SHEKYL_KDF_DEFAULT_M_LOG2: u8 = wallet_envelope::DEFAULT_KDF_M_LOG2;
pub const SHEKYL_KDF_DEFAULT_T: u8 = wallet_envelope::DEFAULT_KDF_T;
pub const SHEKYL_KDF_DEFAULT_P: u8 = wallet_envelope::DEFAULT_KDF_P;

pub const SHEKYL_WALLET_ML_KEM_768_EK_BYTES: usize = ML_KEM_768_EK_LEN;
pub const SHEKYL_WALLET_ML_KEM_768_DK_BYTES: usize = ML_KEM_768_DK_LEN;

// --- error codes (stable wire values) --------------------------------------

pub const SHEKYL_WALLET_ERR_OK: u32 = 0;
pub const SHEKYL_WALLET_ERR_TOO_SHORT: u32 = 1;
pub const SHEKYL_WALLET_ERR_BAD_MAGIC: u32 = 2;
pub const SHEKYL_WALLET_ERR_VERSION_TOO_NEW: u32 = 3;
pub const SHEKYL_WALLET_ERR_UNSUPPORTED_KDF_ALGO: u32 = 4;
pub const SHEKYL_WALLET_ERR_KDF_PARAMS_OUT_OF_RANGE: u32 = 5;
pub const SHEKYL_WALLET_ERR_UNSUPPORTED_WRAP_COUNT: u32 = 6;
pub const SHEKYL_WALLET_ERR_CAP_CONTENT_LEN_MISMATCH: u32 = 7;
pub const SHEKYL_WALLET_ERR_UNKNOWN_CAPABILITY_MODE: u32 = 8;
pub const SHEKYL_WALLET_ERR_REQUIRES_MULTISIG: u32 = 9;
pub const SHEKYL_WALLET_ERR_INVALID_PASSWORD_OR_CORRUPT: u32 = 10;
pub const SHEKYL_WALLET_ERR_STATE_SEED_BLOCK_MISMATCH: u32 = 11;
pub const SHEKYL_WALLET_ERR_INTERNAL: u32 = 12;
pub const SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL: u32 = 13;
pub const SHEKYL_WALLET_ERR_NULL_POINTER: u32 = 14;

fn map_err(e: &WalletEnvelopeError) -> u32 {
    match e {
        WalletEnvelopeError::TooShort => SHEKYL_WALLET_ERR_TOO_SHORT,
        WalletEnvelopeError::BadMagic => SHEKYL_WALLET_ERR_BAD_MAGIC,
        WalletEnvelopeError::FormatVersionTooNew { .. } => SHEKYL_WALLET_ERR_VERSION_TOO_NEW,
        WalletEnvelopeError::UnsupportedKdfAlgo(_) => SHEKYL_WALLET_ERR_UNSUPPORTED_KDF_ALGO,
        WalletEnvelopeError::KdfParamsOutOfRange { .. } => {
            SHEKYL_WALLET_ERR_KDF_PARAMS_OUT_OF_RANGE
        }
        WalletEnvelopeError::UnsupportedWrapCount(_) => SHEKYL_WALLET_ERR_UNSUPPORTED_WRAP_COUNT,
        WalletEnvelopeError::CapContentLenMismatch { .. } => {
            SHEKYL_WALLET_ERR_CAP_CONTENT_LEN_MISMATCH
        }
        WalletEnvelopeError::UnknownCapabilityMode(_) => SHEKYL_WALLET_ERR_UNKNOWN_CAPABILITY_MODE,
        WalletEnvelopeError::RequiresMultisigSupport => SHEKYL_WALLET_ERR_REQUIRES_MULTISIG,
        WalletEnvelopeError::InvalidPasswordOrCorrupt => {
            SHEKYL_WALLET_ERR_INVALID_PASSWORD_OR_CORRUPT
        }
        WalletEnvelopeError::StateSeedBlockMismatch => SHEKYL_WALLET_ERR_STATE_SEED_BLOCK_MISMATCH,
        WalletEnvelopeError::Internal(_) => SHEKYL_WALLET_ERR_INTERNAL,
    }
}

// ---------------------------------------------------------------------------
// C-ABI structs
// ---------------------------------------------------------------------------

/// AAD-readable header view returned by [`shekyl_wallet_keys_inspect`].
#[repr(C)]
pub struct ShekylKeysFileHeaderView {
    pub format_version: u8,
    pub kdf_algo: u8,
    pub kdf_m_log2: u8,
    pub kdf_t: u8,
    pub kdf_p: u8,
    pub wrap_count: u8,
    pub _reserved: [u8; 2],
    pub wrap_salt: [u8; SHEKYL_WALLET_KEYS_WRAP_SALT_BYTES],
}

/// Full post-decryption view returned by [`shekyl_wallet_keys_open`]. The
/// actual `cap_content` bytes are written by the caller-provided
/// `cap_content_buf`; this struct carries the fixed-size metadata and the
/// length of the bytes written.
#[repr(C)]
pub struct ShekylOpenedKeysInfo {
    pub format_version: u8,
    pub capability_mode: u8,
    pub network: u8,
    pub seed_format: u8,
    pub _reserved: [u8; 4],
    pub expected_classical_address: [u8; SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES],
    pub creation_timestamp: u64,
    pub restore_height_hint: u32,
    pub cap_content_len: u32,
    pub seed_block_tag: [u8; SHEKYL_WALLET_SEED_BLOCK_TAG_BYTES],
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Safely reconstruct a byte slice from an FFI (ptr, len). Returns `None`
/// on null-with-nonzero-len combinations; zero-length with either ptr
/// returns an empty slice (never dereferences the pointer).
unsafe fn make_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

/// Zero `len` bytes at `ptr` if non-null. Used on every failure path that
/// would otherwise leave junk in a caller-visible secret buffer.
unsafe fn zero_out(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    std::ptr::write_bytes(ptr, 0u8, len);
}

unsafe fn set_err(out: *mut u32, code: u32) {
    if !out.is_null() {
        *out = code;
    }
}

unsafe fn set_len(out: *mut usize, v: usize) {
    if !out.is_null() {
        *out = v;
    }
}

/// Write `bytes` into `(out_buf, out_cap)`, setting `out_len_required` to
/// the actual length. If the buffer is too small, sets the
/// `BUFFER_TOO_SMALL` error and returns `false` without touching
/// `out_buf`.
unsafe fn write_variable_out(
    out_buf: *mut u8,
    out_cap: usize,
    out_len_required: *mut usize,
    out_error: *mut u32,
    bytes: &[u8],
) -> bool {
    set_len(out_len_required, bytes.len());
    if out_buf.is_null() || out_cap < bytes.len() {
        set_err(out_error, SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL);
        return false;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    set_err(out_error, SHEKYL_WALLET_ERR_OK);
    true
}

// ---------------------------------------------------------------------------
// shekyl_wallet_keys_inspect
// ---------------------------------------------------------------------------

/// Parse only the AAD-readable header of a `.wallet.keys` file (no
/// password required, no decryption attempted).
///
/// On success, populates `*out_view` and returns `true`.
/// On failure, zeroes `*out_view` and returns `false`; `*out_error` gives
/// a precise code (see `SHEKYL_WALLET_ERR_*`).
#[no_mangle]
pub unsafe extern "C" fn shekyl_wallet_keys_inspect(
    bytes_ptr: *const u8,
    bytes_len: usize,
    out_view: *mut ShekylKeysFileHeaderView,
    out_error: *mut u32,
) -> bool {
    if out_view.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    std::ptr::write_bytes(out_view, 0u8, 1);
    let bytes = match make_slice(bytes_ptr, bytes_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    match wallet_envelope::inspect_keys_file(bytes) {
        Ok(view) => {
            (*out_view).format_version = view.format_version;
            (*out_view).kdf_algo = SHEKYL_KDF_ALGO_ARGON2ID;
            (*out_view).kdf_m_log2 = view.kdf.m_log2;
            (*out_view).kdf_t = view.kdf.t;
            (*out_view).kdf_p = view.kdf.p;
            (*out_view).wrap_count = view.wrap_count;
            (*out_view).wrap_salt = view.wrap_salt;
            set_err(out_error, SHEKYL_WALLET_ERR_OK);
            true
        }
        Err(e) => {
            set_err(out_error, map_err(&e));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// shekyl_wallet_keys_seal
// ---------------------------------------------------------------------------

/// Seal a fresh `.wallet.keys` file.
///
/// Variable-length output: probe once with `out_buf = null` (or too small
/// `out_cap`) to discover the required size in `*out_len_required`, then
/// call again with a buffer of at least that size.
///
/// `cap_content_bytes` contains the capability-mode-specific secret
/// material, its layout dictated by `capability_mode`:
///   FULL              : 64 bytes master_seed
///   VIEW_ONLY         : 32 view_sk || 2400 ml_kem_dk || 32 spend_pk
///   HARDWARE_OFFLOAD  : 32 view_sk || 2400 ml_kem_dk || 32 spend_pk
///                       || 2 u16-LE dev_desc_len || dev_desc_bytes
///
/// On any error path, `out_buf` (up to the bytes that would have been
/// written) is zeroed so observers see a uniform write pattern.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_wallet_keys_seal(
    password_ptr: *const u8,
    password_len: usize,
    network: u8,
    seed_format: u8,
    capability_mode: u8,
    cap_content_ptr: *const u8,
    cap_content_len: usize,
    creation_timestamp: u64,
    restore_height_hint: u32,
    expected_classical_address_ptr: *const u8,
    kdf_m_log2: u8,
    kdf_t: u8,
    kdf_p: u8,
    out_buf: *mut u8,
    out_cap: usize,
    out_len_required: *mut usize,
    out_error: *mut u32,
) -> bool {
    set_len(out_len_required, 0);
    // Pre-zero the caller's output buffer up to out_cap so that partial
    // writes on the failure path cannot leak state.
    zero_out(out_buf, out_cap);

    let password = match make_slice(password_ptr, password_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let cap_content = match make_slice(cap_content_ptr, cap_content_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    if expected_classical_address_ptr.is_null() {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    let expected_addr: &[u8; SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES] =
        &*(expected_classical_address_ptr
            as *const [u8; SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES]);

    // Reconstruct a typed CapabilityContent. Layout errors here surface as
    // CapContentLenMismatch.
    let Some(cap) = parse_cap_content(capability_mode, cap_content) else {
        set_err(out_error, SHEKYL_WALLET_ERR_CAP_CONTENT_LEN_MISMATCH);
        return false;
    };

    let kdf = KdfParams { m_log2: kdf_m_log2, t: kdf_t, p: kdf_p };

    match wallet_envelope::seal_keys_file(
        password,
        network,
        seed_format,
        &cap,
        creation_timestamp,
        restore_height_hint,
        expected_addr,
        kdf,
    ) {
        Ok(bytes) => write_variable_out(out_buf, out_cap, out_len_required, out_error, &bytes),
        Err(e) => {
            set_err(out_error, map_err(&e));
            false
        }
    }
}

fn parse_cap_content(mode: u8, bytes: &[u8]) -> Option<CapabilityContent<'_>> {
    match mode {
        wallet_envelope::CAPABILITY_FULL => {
            if bytes.len() != 64 {
                return None;
            }
            let seed: &[u8; 64] = bytes.try_into().ok()?;
            Some(CapabilityContent::Full { master_seed_64: seed })
        }
        wallet_envelope::CAPABILITY_VIEW_ONLY => {
            let need = 32 + ML_KEM_768_DK_LEN + 32;
            if bytes.len() != need {
                return None;
            }
            let view_sk: &[u8; 32] = bytes[..32].try_into().ok()?;
            let dk: &[u8; ML_KEM_768_DK_LEN] =
                bytes[32..32 + ML_KEM_768_DK_LEN].try_into().ok()?;
            let spend_pk: &[u8; 32] = bytes[32 + ML_KEM_768_DK_LEN..].try_into().ok()?;
            Some(CapabilityContent::ViewOnly { view_sk, ml_kem_dk: dk, spend_pk })
        }
        wallet_envelope::CAPABILITY_HARDWARE_OFFLOAD => {
            let head = 32 + ML_KEM_768_DK_LEN + 32;
            if bytes.len() < head + 2 {
                return None;
            }
            let view_sk: &[u8; 32] = bytes[..32].try_into().ok()?;
            let dk: &[u8; ML_KEM_768_DK_LEN] =
                bytes[32..32 + ML_KEM_768_DK_LEN].try_into().ok()?;
            let spend_pk: &[u8; 32] = bytes[32 + ML_KEM_768_DK_LEN..head].try_into().ok()?;
            let dev_len =
                u16::from_le_bytes([bytes[head], bytes[head + 1]]) as usize;
            if bytes.len() != head + 2 + dev_len {
                return None;
            }
            let dev = &bytes[head + 2..];
            Some(CapabilityContent::HardwareOffload {
                view_sk,
                ml_kem_dk: dk,
                spend_pk,
                device_desc: dev,
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// shekyl_wallet_keys_open
// ---------------------------------------------------------------------------

/// Decrypt a `.wallet.keys` file.
///
/// `cap_content_buf` + `cap_content_cap` receive the capability-mode bytes;
/// `out_info.cap_content_len` reports the actual length. The two-call
/// sizing pattern applies: pass a null / too-small buffer first to probe
/// `cap_content_len`, then retry.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_wallet_keys_open(
    password_ptr: *const u8,
    password_len: usize,
    bytes_ptr: *const u8,
    bytes_len: usize,
    out_info: *mut ShekylOpenedKeysInfo,
    cap_content_buf: *mut u8,
    cap_content_cap: usize,
    out_error: *mut u32,
) -> bool {
    if out_info.is_null() {
        zero_out(cap_content_buf, cap_content_cap);
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    }
    std::ptr::write_bytes(out_info, 0u8, 1);
    zero_out(cap_content_buf, cap_content_cap);

    let password = match make_slice(password_ptr, password_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };
    let bytes = match make_slice(bytes_ptr, bytes_len) {
        Some(s) => s,
        None => {
            set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
            return false;
        }
    };

    match wallet_envelope::open_keys_file(password, bytes) {
        Ok(opened) => {
            let cap_len = opened.cap_content.len();
            (*out_info).format_version = SHEKYL_WALLET_FORMAT_VERSION;
            (*out_info).capability_mode = opened.capability_mode;
            (*out_info).network = opened.network;
            (*out_info).seed_format = opened.seed_format;
            (*out_info).expected_classical_address = opened.expected_classical_address;
            (*out_info).creation_timestamp = opened.creation_timestamp;
            (*out_info).restore_height_hint = opened.restore_height_hint;
            (*out_info).cap_content_len = u32::try_from(cap_len).unwrap_or(u32::MAX);
            (*out_info).seed_block_tag = opened.seed_block_tag;
            if cap_content_buf.is_null() || cap_content_cap < cap_len {
                set_err(out_error, SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL);
                return false;
            }
            std::ptr::copy_nonoverlapping(opened.cap_content.as_ptr(), cap_content_buf, cap_len);
            set_err(out_error, SHEKYL_WALLET_ERR_OK);
            true
        }
        Err(e) => {
            set_err(out_error, map_err(&e));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// shekyl_wallet_keys_rewrap_password
// ---------------------------------------------------------------------------

/// Rewrite a `.wallet.keys` file under a new password. The output has the
/// same byte length as the input; two-call sizing is still offered for
/// uniformity with the other variable-output entry points. Pass
/// `new_kdf_present = 0` to preserve the existing KDF parameters.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_wallet_keys_rewrap_password(
    old_password_ptr: *const u8,
    old_password_len: usize,
    new_password_ptr: *const u8,
    new_password_len: usize,
    bytes_ptr: *const u8,
    bytes_len: usize,
    new_kdf_present: u8,
    new_kdf_m_log2: u8,
    new_kdf_t: u8,
    new_kdf_p: u8,
    out_buf: *mut u8,
    out_cap: usize,
    out_len_required: *mut usize,
    out_error: *mut u32,
) -> bool {
    set_len(out_len_required, 0);
    zero_out(out_buf, out_cap);

    let Some(old_pw) = make_slice(old_password_ptr, old_password_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };
    let Some(new_pw) = make_slice(new_password_ptr, new_password_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };
    let Some(bytes) = make_slice(bytes_ptr, bytes_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };

    let new_kdf = if new_kdf_present != 0 {
        Some(KdfParams { m_log2: new_kdf_m_log2, t: new_kdf_t, p: new_kdf_p })
    } else {
        None
    };

    match wallet_envelope::rewrap_keys_file_password(old_pw, new_pw, bytes, new_kdf) {
        Ok(out) => write_variable_out(out_buf, out_cap, out_len_required, out_error, &out),
        Err(e) => {
            set_err(out_error, map_err(&e));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// shekyl_wallet_state_seal / open
// ---------------------------------------------------------------------------

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_wallet_state_seal(
    password_ptr: *const u8,
    password_len: usize,
    keys_file_ptr: *const u8,
    keys_file_len: usize,
    state_plain_ptr: *const u8,
    state_plain_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len_required: *mut usize,
    out_error: *mut u32,
) -> bool {
    set_len(out_len_required, 0);
    zero_out(out_buf, out_cap);

    let Some(pw) = make_slice(password_ptr, password_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };
    let Some(keys) = make_slice(keys_file_ptr, keys_file_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };
    let Some(state) = make_slice(state_plain_ptr, state_plain_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };

    match wallet_envelope::seal_state_file(pw, keys, state) {
        Ok(out) => write_variable_out(out_buf, out_cap, out_len_required, out_error, &out),
        Err(e) => {
            set_err(out_error, map_err(&e));
            false
        }
    }
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_wallet_state_open(
    password_ptr: *const u8,
    password_len: usize,
    keys_file_ptr: *const u8,
    keys_file_len: usize,
    state_file_ptr: *const u8,
    state_file_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len_required: *mut usize,
    out_error: *mut u32,
) -> bool {
    set_len(out_len_required, 0);
    zero_out(out_buf, out_cap);

    let Some(pw) = make_slice(password_ptr, password_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };
    let Some(keys) = make_slice(keys_file_ptr, keys_file_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };
    let Some(state) = make_slice(state_file_ptr, state_file_len) else {
        set_err(out_error, SHEKYL_WALLET_ERR_NULL_POINTER);
        return false;
    };

    match wallet_envelope::open_state_file(pw, keys, state) {
        Ok(plain) => write_variable_out(out_buf, out_cap, out_len_required, out_error, &plain),
        Err(e) => {
            set_err(out_error, map_err(&e));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    fn kat_kdf() -> (u8, u8, u8) {
        (8, 1, 1)
    }

    fn addr() -> [u8; SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES] {
        let mut a = [0u8; SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES];
        for (i, b) in a.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap();
        }
        a
    }

    #[test]
    fn seal_then_open_roundtrip_full_mode() {
        let pw = b"pw";
        let seed = [0x11u8; 64];
        let a = addr();
        let (m, t, p) = kat_kdf();

        // Probe size.
        let mut required: usize = 0;
        let mut err: u32 = 0;
        let ok = unsafe {
            shekyl_wallet_keys_seal(
                pw.as_ptr(),
                pw.len(),
                0,
                0,
                SHEKYL_WALLET_CAPABILITY_FULL,
                seed.as_ptr(),
                seed.len(),
                0,
                0,
                a.as_ptr(),
                m,
                t,
                p,
                ptr::null_mut(),
                0,
                &raw mut required,
                &raw mut err,
            )
        };
        assert!(!ok);
        assert_eq!(err, SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL);
        assert!(required > 0);

        // Actual seal.
        let mut out = vec![0u8; required];
        let mut required2: usize = 0;
        let ok = unsafe {
            shekyl_wallet_keys_seal(
                pw.as_ptr(),
                pw.len(),
                0,
                0,
                SHEKYL_WALLET_CAPABILITY_FULL,
                seed.as_ptr(),
                seed.len(),
                0,
                0,
                a.as_ptr(),
                m,
                t,
                p,
                out.as_mut_ptr(),
                out.len(),
                &raw mut required2,
                &raw mut err,
            )
        };
        assert!(ok);
        assert_eq!(err, SHEKYL_WALLET_ERR_OK);
        assert_eq!(required2, required);

        // Inspect.
        let mut view = unsafe { std::mem::zeroed::<ShekylKeysFileHeaderView>() };
        let ok = unsafe {
            shekyl_wallet_keys_inspect(
                out.as_ptr(),
                out.len(),
                &raw mut view,
                &raw mut err,
            )
        };
        assert!(ok);
        assert_eq!(view.format_version, SHEKYL_WALLET_FORMAT_VERSION);
        assert_eq!(view.kdf_algo, SHEKYL_KDF_ALGO_ARGON2ID);
        assert_eq!(view.kdf_m_log2, m);
        assert_eq!(view.kdf_t, t);
        assert_eq!(view.kdf_p, p);

        // Open probe → real open.
        let mut info = unsafe { std::mem::zeroed::<ShekylOpenedKeysInfo>() };
        let ok = unsafe {
            shekyl_wallet_keys_open(
                pw.as_ptr(),
                pw.len(),
                out.as_ptr(),
                out.len(),
                &raw mut info,
                ptr::null_mut(),
                0,
                &raw mut err,
            )
        };
        assert!(!ok);
        assert_eq!(err, SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL);
        assert_eq!(info.cap_content_len, 64);

        let mut cap = vec![0u8; info.cap_content_len as usize];
        let ok = unsafe {
            shekyl_wallet_keys_open(
                pw.as_ptr(),
                pw.len(),
                out.as_ptr(),
                out.len(),
                &raw mut info,
                cap.as_mut_ptr(),
                cap.len(),
                &raw mut err,
            )
        };
        assert!(ok);
        assert_eq!(err, SHEKYL_WALLET_ERR_OK);
        assert_eq!(info.capability_mode, SHEKYL_WALLET_CAPABILITY_FULL);
        assert_eq!(cap.as_slice(), &seed);
    }

    #[test]
    fn bad_magic_on_inspect() {
        let mut view = unsafe { std::mem::zeroed::<ShekylKeysFileHeaderView>() };
        let mut err: u32 = 0;
        let fake = [0u8; 200];
        let ok = unsafe {
            shekyl_wallet_keys_inspect(
                fake.as_ptr(),
                fake.len(),
                &raw mut view,
                &raw mut err,
            )
        };
        assert!(!ok);
        assert_eq!(err, SHEKYL_WALLET_ERR_BAD_MAGIC);
    }

    #[test]
    fn wrong_password_maps_to_invalid_code() {
        let pw = b"right";
        let seed = [0u8; 64];
        let a = addr();
        let (m, t, p) = kat_kdf();
        let mut required: usize = 0;
        let mut err: u32 = 0;
        unsafe {
            shekyl_wallet_keys_seal(
                pw.as_ptr(),
                pw.len(),
                0,
                0,
                SHEKYL_WALLET_CAPABILITY_FULL,
                seed.as_ptr(),
                seed.len(),
                0,
                0,
                a.as_ptr(),
                m,
                t,
                p,
                ptr::null_mut(),
                0,
                &raw mut required,
                &raw mut err,
            );
        }
        let mut out = vec![0u8; required];
        let _ = unsafe {
            shekyl_wallet_keys_seal(
                pw.as_ptr(),
                pw.len(),
                0,
                0,
                SHEKYL_WALLET_CAPABILITY_FULL,
                seed.as_ptr(),
                seed.len(),
                0,
                0,
                a.as_ptr(),
                m,
                t,
                p,
                out.as_mut_ptr(),
                out.len(),
                &raw mut required,
                &raw mut err,
            )
        };

        let mut info = unsafe { std::mem::zeroed::<ShekylOpenedKeysInfo>() };
        let mut cap = vec![0u8; 64];
        let ok = unsafe {
            shekyl_wallet_keys_open(
                b"wrong".as_ptr(),
                5,
                out.as_ptr(),
                out.len(),
                &raw mut info,
                cap.as_mut_ptr(),
                cap.len(),
                &raw mut err,
            )
        };
        assert!(!ok);
        assert_eq!(err, SHEKYL_WALLET_ERR_INVALID_PASSWORD_OR_CORRUPT);
    }
}
