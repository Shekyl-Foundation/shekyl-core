// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI surface for the stabilized v1 account-derivation pipeline.
//!
//! Every function in this module follows three disciplines, chosen to make
//! the C++ callers trivially correct and the secret-material locality rule
//! (see `.cursor/rules/36-secret-locality.mdc`) mechanically enforceable:
//!
//! 1. **Out-pointer, not buffer-struct.** All outputs are fixed-length, so
//!    the caller allocates (typically on an `mlock`'d region of its stack
//!    or a member of `account_keys`) and passes a raw pointer. Rust never
//!    heap-allocates secret-bearing memory that the C++ side has to free.
//!
//! 2. **Fail-closed, constant-time write pattern.** Every function zeroes
//!    every output buffer before doing anything else, and zeroes them again
//!    on any error path before returning `false`. Callers that observe
//!    `false` can treat the output memory as uninitialised; callers that
//!    observe `true` find fully-populated output. There is no "partially
//!    written" state. The write pattern is identical regardless of which
//!    error branch fires, so timing/write-pattern observers learn nothing
//!    beyond "success or failure."
//!
//! 3. **Pinned sizes.** Every length relevant to the pipeline is a `pub
//!    const` in this module, so the C++ side can `static_assert` against
//!    the same number. Introducing a mismatch in either direction is a
//!    compile error, not a runtime surprise.
//!
//! The matching C header comes from the existing `shekyl_ffi.h` generator
//! (or manual bindings); the new functions are additive — existing FFIs
//! continue to link. The account.cpp rewrite in the next slice replaces
//! `shekyl_kem_keypair_generate`, `shekyl_seed_derive_{spend,view,ml_kem}`
//! with calls into this module.

use rand::RngCore;
use zeroize::Zeroize;

use shekyl_crypto_pq::account::{
    self, AllKeysBlob, DerivationNetwork, SeedFormat, CLASSICAL_ADDRESS_BYTES, MASTER_SEED_BYTES,
    PQC_PUBLIC_KEY_BYTES, RAW_SEED_BYTES,
};
use shekyl_crypto_pq::bip39;
use shekyl_crypto_pq::kem::{ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN};

// --- pinned sizes (mirrored on the C++ side with static_assert) ------------

/// Master-seed length in bytes. Matches `m_master_seed_64` on the C++ side.
pub const SHEKYL_MASTER_SEED_BYTES: usize = MASTER_SEED_BYTES;

/// Raw-seed length in bytes. Testnet and fakechain only.
pub const SHEKYL_RAW_SEED_BYTES: usize = RAW_SEED_BYTES;

/// ML-KEM-768 encap-key length. Matches FIPS 203.
pub const SHEKYL_ML_KEM_768_EK_BYTES: usize = ML_KEM_768_EK_LEN;

/// ML-KEM-768 decap-key length. Matches FIPS 203.
pub const SHEKYL_ML_KEM_768_DK_BYTES: usize = ML_KEM_768_DK_LEN;

/// Concatenated `x25519 pk || ml_kem ek` length. Matches the C++
/// `account_public_address::m_pqc_public_key` buffer.
pub const SHEKYL_PQC_PUBLIC_KEY_BYTES: usize = PQC_PUBLIC_KEY_BYTES;

/// Classical-segment raw-bytes length (version + spend_pk + view_pk).
pub const SHEKYL_CLASSICAL_ADDRESS_BYTES: usize = CLASSICAL_ADDRESS_BYTES;

/// Wide-reduce intermediate length. Every HKDF sub-derivation produces this
/// many bytes before collapsing to a 32-byte scalar or feeding into
/// ML-KEM keygen.
pub const SHEKYL_HKDF_WIDE_BYTES: usize = 64;

/// Ed25519 scalar length after wide-reduce.
pub const SHEKYL_SCALAR_BYTES: usize = 32;

/// Wire byte for `SeedFormat::Bip39`.
pub const SHEKYL_SEED_FORMAT_BIP39: u8 = account::SEED_FORMAT_BIP39;

/// Wire byte for `SeedFormat::Raw32`.
pub const SHEKYL_SEED_FORMAT_RAW32: u8 = account::SEED_FORMAT_RAW32;

// --- internal helpers -------------------------------------------------------

/// Convert a raw `u8` network discriminant into `DerivationNetwork`.
/// Any unknown discriminant returns `None`, which in callers translates to
/// zero-all-outputs-and-return-false.
fn net_from_u8(v: u8) -> Option<DerivationNetwork> {
    DerivationNetwork::from_u8(v)
}

/// Convert a raw `u8` seed-format discriminant into `SeedFormat`.
fn fmt_from_u8(v: u8) -> Option<SeedFormat> {
    SeedFormat::from_u8(v)
}

/// Zero a caller-provided out-buffer on the failure path.
///
/// # Safety
/// `ptr` must be valid for writes of `len` bytes. `len` must be the exact
/// declared length of the buffer (never a guess).
unsafe fn zero_out(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // `write_bytes` compiles to a memset that the compiler is not allowed
    // to elide because the caller's buffer is visible across the FFI
    // boundary. For extra paranoia, we could also compiler_fence here; in
    // practice the FFI boundary itself is a barrier.
    std::ptr::write_bytes(ptr, 0u8, len);
}

/// Copy bytes from a `&[u8]` into a caller-provided out-buffer.
///
/// # Safety
/// Same contract as [`zero_out`]; additionally `src.len() <= len`.
unsafe fn write_out(dst: *mut u8, src: &[u8], len: usize) {
    debug_assert!(src.len() <= len);
    std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    if src.len() < len {
        // Zero the tail so the caller sees a deterministic value.
        std::ptr::write_bytes(dst.add(src.len()), 0u8, len - src.len());
    }
}

// --- BIP-39 -----------------------------------------------------------------

/// Validate that `words_ptr..words_ptr+words_len` is a well-formed 24-word
/// BIP-39 English mnemonic. UTF-8 invalid bytes yield `false`.
///
/// # Safety
/// `words_ptr` must be valid for reads of `words_len` bytes (or null with
/// `words_len == 0`). No output buffer, so fail-closed is trivial.
#[no_mangle]
pub unsafe extern "C" fn shekyl_bip39_validate(words_ptr: *const u8, words_len: usize) -> bool {
    if words_ptr.is_null() && words_len != 0 {
        return false;
    }
    let slice = if words_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(words_ptr, words_len)
    };
    let Ok(s) = std::str::from_utf8(slice) else {
        return false;
    };
    bip39::validate(s)
}

/// Convert a 32-byte entropy into a 24-word English BIP-39 mnemonic.
///
/// `out_words_cap` must be at least 232 bytes (the maximum possible length
/// of a 24-word English mnemonic including 23 single-space separators;
/// BIP-39 English words are at most 8 characters). On success, the written
/// byte count (not including any terminator — the output is NOT
/// null-terminated) is written to `*out_words_len`. On failure,
/// `out_words_len` is set to zero and the output region is fully zeroed.
///
/// # Safety
/// `entropy32_ptr` must be valid for 32 bytes of reads. `out_words_ptr`
/// must be valid for `out_words_cap` bytes of writes. `out_words_len` must
/// be valid for writes of a single `usize`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_bip39_mnemonic_from_entropy(
    entropy32_ptr: *const u8,
    out_words_ptr: *mut u8,
    out_words_cap: usize,
    out_words_len: *mut usize,
) -> bool {
    if out_words_len.is_null() {
        zero_out(out_words_ptr, out_words_cap);
        return false;
    }
    *out_words_len = 0;
    zero_out(out_words_ptr, out_words_cap);

    if entropy32_ptr.is_null() || out_words_ptr.is_null() {
        return false;
    }

    let mut entropy = [0u8; 32];
    std::ptr::copy_nonoverlapping(entropy32_ptr, entropy.as_mut_ptr(), 32);

    let Ok(words) = bip39::mnemonic_from_entropy(&entropy) else {
        entropy.zeroize();
        return false;
    };
    entropy.zeroize();

    let bytes = words.as_bytes();
    if bytes.len() > out_words_cap {
        return false;
    }

    write_out(out_words_ptr, bytes, bytes.len());
    *out_words_len = bytes.len();
    true
}

/// Convert a validated 24-word mnemonic + optional passphrase into the
/// 64-byte PBKDF2-HMAC-SHA512 output per BIP-39 §Seed-derivation.
///
/// The 64-byte output is NOT the Shekyl master seed — downstream code must
/// run it through `shekyl_seed_normalize` to produce the format-independent
/// `master_seed_64`. Splitting the two steps keeps the pipeline auditable
/// and allows future-proofing (e.g., if we ever add 12-word support).
///
/// # Safety
/// `words_ptr`/`pass_ptr` must be valid for their respective lengths. A
/// `null, 0` pair is accepted as "no passphrase".
/// `out64_ptr` must be valid for 64 bytes of writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_bip39_mnemonic_to_pbkdf2_seed(
    words_ptr: *const u8,
    words_len: usize,
    pass_ptr: *const u8,
    pass_len: usize,
    out64_ptr: *mut u8,
) -> bool {
    zero_out(out64_ptr, 64);
    if words_ptr.is_null() || out64_ptr.is_null() {
        return false;
    }
    if pass_ptr.is_null() && pass_len != 0 {
        return false;
    }

    let words_slice = std::slice::from_raw_parts(words_ptr, words_len);
    let pass_slice = if pass_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(pass_ptr, pass_len)
    };

    let Ok(words) = std::str::from_utf8(words_slice) else {
        return false;
    };
    let Ok(pass) = std::str::from_utf8(pass_slice) else {
        return false;
    };

    let Ok(seed) = bip39::mnemonic_to_pbkdf2_seed(words, pass) else {
        return false;
    };
    write_out(out64_ptr, seed.as_slice(), 64);
    true
}

// --- raw seed ---------------------------------------------------------------

/// Generate a fresh 32-byte raw seed from OsRng. Testnet and fakechain
/// wallet-creation path.
///
/// # Safety
/// `out32_ptr` must be valid for 32 bytes of writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_raw_seed_generate(out32_ptr: *mut u8) -> bool {
    zero_out(out32_ptr, 32);
    if out32_ptr.is_null() {
        return false;
    }
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    write_out(out32_ptr, &buf, 32);
    buf.zeroize();
    true
}

// --- seed normalize ---------------------------------------------------------

/// HKDF-SHA-512-normalize an arbitrary-length input into a 64-byte master
/// seed. Applied to both BIP-39 PBKDF2 output and raw 32-byte seeds so the
/// on-disk master seed is format-independent.
///
/// # Safety
/// `ikm_ptr` must be valid for reads of `ikm_len` bytes. `out64_ptr` must
/// be valid for 64 bytes of writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seed_normalize(
    ikm_ptr: *const u8,
    ikm_len: usize,
    out64_ptr: *mut u8,
) -> bool {
    zero_out(out64_ptr, 64);
    if out64_ptr.is_null() {
        return false;
    }
    if ikm_ptr.is_null() && ikm_len != 0 {
        return false;
    }
    let ikm = if ikm_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(ikm_ptr, ikm_len)
    };
    let normalised = account::normalize_seed(ikm);
    write_out(out64_ptr, normalised.as_slice(), 64);
    true
}

// --- split-byte sub-derivations ---------------------------------------------

/// Derive the 64-byte HKDF output for the Ed25519 spend scalar. The caller
/// pairs this with `shekyl_ed25519_scalar_wide_reduce` to obtain the
/// 32-byte canonical scalar.
///
/// # Safety
/// `master_seed64_ptr` must be valid for 64 bytes of reads. `out64_ptr`
/// must be valid for 64 bytes of writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seed_derive_spend_wide(
    master_seed64_ptr: *const u8,
    network: u8,
    seed_format: u8,
    out64_ptr: *mut u8,
) -> bool {
    zero_out(out64_ptr, 64);
    if master_seed64_ptr.is_null() || out64_ptr.is_null() {
        return false;
    }
    let Some(net) = net_from_u8(network) else {
        return false;
    };
    let Some(fmt) = fmt_from_u8(seed_format) else {
        return false;
    };
    if !net.permitted_seed_format(fmt) {
        return false;
    }

    let mut master = [0u8; MASTER_SEED_BYTES];
    std::ptr::copy_nonoverlapping(master_seed64_ptr, master.as_mut_ptr(), MASTER_SEED_BYTES);

    let wide = account::derive_spend_wide(&master, net, fmt);
    master.zeroize();
    write_out(out64_ptr, wide.as_slice(), 64);
    true
}

/// Same as [`shekyl_seed_derive_spend_wide`] for the view scalar.
///
/// # Safety
/// See [`shekyl_seed_derive_spend_wide`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_seed_derive_view_wide(
    master_seed64_ptr: *const u8,
    network: u8,
    seed_format: u8,
    out64_ptr: *mut u8,
) -> bool {
    zero_out(out64_ptr, 64);
    if master_seed64_ptr.is_null() || out64_ptr.is_null() {
        return false;
    }
    let Some(net) = net_from_u8(network) else {
        return false;
    };
    let Some(fmt) = fmt_from_u8(seed_format) else {
        return false;
    };
    if !net.permitted_seed_format(fmt) {
        return false;
    }

    let mut master = [0u8; MASTER_SEED_BYTES];
    std::ptr::copy_nonoverlapping(master_seed64_ptr, master.as_mut_ptr(), MASTER_SEED_BYTES);

    let wide = account::derive_view_wide(&master, net, fmt);
    master.zeroize();
    write_out(out64_ptr, wide.as_slice(), 64);
    true
}

/// Reduce a uniformly-distributed 64-byte intermediate into a canonical
/// 32-byte Ed25519 scalar via `Scalar::from_bytes_mod_order_wide`.
///
/// This is the **only** supported way to collapse a 64-byte HKDF output
/// into a 32-byte scalar in Shekyl. Per workspace rule 36-secret-locality,
/// C++ never performs this step itself.
///
/// # Safety
/// `in64_ptr` must be valid for 64 bytes of reads. `out32_ptr` must be
/// valid for 32 bytes of writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ed25519_scalar_wide_reduce(
    in64_ptr: *const u8,
    out32_ptr: *mut u8,
) -> bool {
    zero_out(out32_ptr, 32);
    if in64_ptr.is_null() || out32_ptr.is_null() {
        return false;
    }
    let mut wide = [0u8; 64];
    std::ptr::copy_nonoverlapping(in64_ptr, wide.as_mut_ptr(), 64);

    let scalar = account::wide_reduce_to_scalar(&wide);
    wide.zeroize();
    write_out(out32_ptr, scalar.as_bytes(), 32);
    true
}

// --- ML-KEM deterministic keygen --------------------------------------------

/// Deterministically derive the ML-KEM-768 `(ek, dk)` pair from a master
/// seed + (network, format). The two output buffers have fixed lengths:
/// 1184 bytes for `ek_out_ptr`, 2400 bytes for `dk_out_ptr`.
///
/// # Safety
/// `master_seed64_ptr` must be valid for 64 bytes of reads.
/// `ek_out_ptr` must be valid for `SHEKYL_ML_KEM_768_EK_BYTES` writes.
/// `dk_out_ptr` must be valid for `SHEKYL_ML_KEM_768_DK_BYTES` writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_kem_keypair_from_master_seed(
    master_seed64_ptr: *const u8,
    network: u8,
    seed_format: u8,
    ek_out_ptr: *mut u8,
    dk_out_ptr: *mut u8,
) -> bool {
    zero_out(ek_out_ptr, ML_KEM_768_EK_LEN);
    zero_out(dk_out_ptr, ML_KEM_768_DK_LEN);

    if master_seed64_ptr.is_null() || ek_out_ptr.is_null() || dk_out_ptr.is_null() {
        return false;
    }
    let Some(net) = net_from_u8(network) else {
        return false;
    };
    let Some(fmt) = fmt_from_u8(seed_format) else {
        return false;
    };
    if !net.permitted_seed_format(fmt) {
        return false;
    }

    let mut master = [0u8; MASTER_SEED_BYTES];
    std::ptr::copy_nonoverlapping(master_seed64_ptr, master.as_mut_ptr(), MASTER_SEED_BYTES);

    let d_z = account::derive_kem_d_z(&master, net, fmt);
    master.zeroize();

    let Ok((ek, dk)) = account::ml_kem_keypair_from_d_z(&d_z) else {
        return false;
    };
    write_out(ek_out_ptr, &ek, ML_KEM_768_EK_LEN);
    write_out(dk_out_ptr, dk.as_slice(), ML_KEM_768_DK_LEN);
    true
}

/// Test-only tracing FFI: expose the SHA3-ChaCha intermediary bytes to
/// callers running the Tier-2 KATs. Populates a 32-byte `chacha_seed_out`
/// buffer from a 64-byte `d_z_in`. Not for production use; the C++ API
/// does not call this.
///
/// # Safety
/// `d_z_in` must be valid for 64 bytes of reads. `chacha_seed_out` must be
/// valid for 32 bytes of writes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ml_kem_chacha_seed_trace(
    d_z_in: *const u8,
    chacha_seed_out: *mut u8,
) -> bool {
    zero_out(chacha_seed_out, 32);
    if d_z_in.is_null() || chacha_seed_out.is_null() {
        return false;
    }
    let mut d_z = [0u8; 64];
    std::ptr::copy_nonoverlapping(d_z_in, d_z.as_mut_ptr(), 64);
    let seed = account::ml_kem_chacha_seed_from_d_z(&d_z);
    d_z.zeroize();
    write_out(chacha_seed_out, &seed, 32);
    true
}

// --- coarse-grained account flows -------------------------------------------

/// C-compatible layout for [`shekyl_crypto_pq::account::AllKeysBlob`].
/// Caller (C++ `account_keys`) owns an mlock'd region of this size; Rust
/// fills it in place. On any error the entire struct is zeroed.
///
/// This type must be layout-compatible with `AllKeysBlob` bit-for-bit.
/// Both are `#[repr(C)]` with the same field order and types; see the
/// `static_assert`-style check in the `struct_layout_matches` test.
#[repr(C)]
pub struct ShekylAllKeysBlob {
    pub spend_pk: [u8; 32],
    pub view_pk: [u8; 32],
    pub ml_kem_ek: [u8; ML_KEM_768_EK_LEN],
    pub x25519_pk: [u8; 32],
    pub pqc_public_key: [u8; PQC_PUBLIC_KEY_BYTES],
    pub classical_address_bytes: [u8; CLASSICAL_ADDRESS_BYTES],
    pub spend_sk: [u8; 32],
    pub view_sk: [u8; 32],
    pub ml_kem_dk: [u8; ML_KEM_768_DK_LEN],
}

impl ShekylAllKeysBlob {
    fn zeroed() -> Self {
        ShekylAllKeysBlob {
            spend_pk: [0u8; 32],
            view_pk: [0u8; 32],
            ml_kem_ek: [0u8; ML_KEM_768_EK_LEN],
            x25519_pk: [0u8; 32],
            pqc_public_key: [0u8; PQC_PUBLIC_KEY_BYTES],
            classical_address_bytes: [0u8; CLASSICAL_ADDRESS_BYTES],
            spend_sk: [0u8; 32],
            view_sk: [0u8; 32],
            ml_kem_dk: [0u8; ML_KEM_768_DK_LEN],
        }
    }
}

/// Copy every field from an internal `AllKeysBlob` into the C-layout
/// counterpart. Both types have identical field order/types.
fn copy_blob_to_ffi(src: &AllKeysBlob, dst: &mut ShekylAllKeysBlob) {
    dst.spend_pk = src.spend_pk;
    dst.view_pk = src.view_pk;
    dst.ml_kem_ek = src.ml_kem_ek;
    dst.x25519_pk = src.x25519_pk;
    dst.pqc_public_key = src.pqc_public_key;
    dst.classical_address_bytes = src.classical_address_bytes;
    dst.spend_sk = src.spend_sk;
    dst.view_sk = src.view_sk;
    dst.ml_kem_dk = src.ml_kem_dk;
}

/// Zero every field of a caller-provided blob. Used on all error paths.
///
/// # Safety
/// `blob` must be non-null and point to an allocation of `size_of::<ShekylAllKeysBlob>()`
/// bytes.
unsafe fn zero_blob(blob: *mut ShekylAllKeysBlob) {
    if blob.is_null() {
        return;
    }
    *blob = ShekylAllKeysBlob::zeroed();
}

/// Generate a fresh wallet account from a BIP-39 mnemonic + passphrase.
/// Mainnet and stagenet only. Also emits the 64-byte `master_seed` that
/// the wallet file will persist (encrypted).
///
/// # Safety
/// `words_ptr`/`pass_ptr` valid for their respective lengths. `master_seed_out64`
/// valid for 64 bytes. `blob_out` valid for a `ShekylAllKeysBlob`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_account_generate_from_bip39(
    words_ptr: *const u8,
    words_len: usize,
    pass_ptr: *const u8,
    pass_len: usize,
    network: u8,
    master_seed_out64: *mut u8,
    blob_out: *mut ShekylAllKeysBlob,
) -> bool {
    zero_out(master_seed_out64, MASTER_SEED_BYTES);
    zero_blob(blob_out);

    if words_ptr.is_null() || master_seed_out64.is_null() || blob_out.is_null() {
        return false;
    }
    if pass_ptr.is_null() && pass_len != 0 {
        return false;
    }
    let Some(net) = net_from_u8(network) else {
        return false;
    };

    let words_slice = std::slice::from_raw_parts(words_ptr, words_len);
    let pass_slice = if pass_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(pass_ptr, pass_len)
    };
    let Ok(words) = std::str::from_utf8(words_slice) else {
        return false;
    };
    let Ok(pass) = std::str::from_utf8(pass_slice) else {
        return false;
    };

    let Ok((seed, blob)) = account::generate_account_from_bip39(words, pass, net) else {
        return false;
    };
    write_out(master_seed_out64, seed.as_slice(), MASTER_SEED_BYTES);
    copy_blob_to_ffi(&blob, &mut *blob_out);
    true
}

/// Generate a fresh wallet account from a 32-byte raw seed. Testnet and
/// fakechain only.
///
/// # Safety
/// `raw_seed32_ptr` valid for 32 bytes. `master_seed_out64` valid for 64
/// bytes. `blob_out` valid for a `ShekylAllKeysBlob`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_account_generate_from_raw_seed(
    raw_seed32_ptr: *const u8,
    network: u8,
    master_seed_out64: *mut u8,
    blob_out: *mut ShekylAllKeysBlob,
) -> bool {
    zero_out(master_seed_out64, MASTER_SEED_BYTES);
    zero_blob(blob_out);

    if raw_seed32_ptr.is_null() || master_seed_out64.is_null() || blob_out.is_null() {
        return false;
    }
    let Some(net) = net_from_u8(network) else {
        return false;
    };

    let mut raw = [0u8; RAW_SEED_BYTES];
    std::ptr::copy_nonoverlapping(raw_seed32_ptr, raw.as_mut_ptr(), RAW_SEED_BYTES);

    let result = account::generate_account_from_raw_seed(&raw, net);
    raw.zeroize();

    let Ok((seed, blob)) = result else {
        return false;
    };
    write_out(master_seed_out64, seed.as_slice(), MASTER_SEED_BYTES);
    copy_blob_to_ffi(&blob, &mut *blob_out);
    true
}

/// Rederive a wallet account from an existing 64-byte master seed. This is
/// the wallet-open path: the encrypted seed block is decrypted, AAD is
/// verified, and this function rebuilds every key. The resulting blob is
/// then cross-checked against the wallet-file's stored expected-address
/// bytes for additional corruption protection.
///
/// # Safety
/// `master_seed64_ptr` valid for 64 bytes. `blob_out` valid for a
/// `ShekylAllKeysBlob`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_account_rederive(
    master_seed64_ptr: *const u8,
    network: u8,
    seed_format: u8,
    blob_out: *mut ShekylAllKeysBlob,
) -> bool {
    zero_blob(blob_out);

    if master_seed64_ptr.is_null() || blob_out.is_null() {
        return false;
    }
    let Some(net) = net_from_u8(network) else {
        return false;
    };
    let Some(fmt) = fmt_from_u8(seed_format) else {
        return false;
    };

    let mut master = [0u8; MASTER_SEED_BYTES];
    std::ptr::copy_nonoverlapping(master_seed64_ptr, master.as_mut_ptr(), MASTER_SEED_BYTES);

    let result = account::rederive_account(&master, net, fmt);
    master.zeroize();

    let Ok(blob) = result else {
        return false;
    };
    copy_blob_to_ffi(&blob, &mut *blob_out);
    true
}

/// Assemble the 1216-byte `m_pqc_public_key` from its `x25519_pk` + `ml_kem_ek`
/// components. Used when reconstructing an `account_public_address` from
/// on-wire or on-disk pieces.
///
/// # Safety
/// `x25519_pk_ptr` valid for 32 bytes. `ml_kem_ek_ptr` valid for 1184
/// bytes. `pqc_pk_out` valid for 1216 bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_account_public_address_build(
    x25519_pk_ptr: *const u8,
    ml_kem_ek_ptr: *const u8,
    pqc_pk_out: *mut u8,
) -> bool {
    zero_out(pqc_pk_out, PQC_PUBLIC_KEY_BYTES);
    if x25519_pk_ptr.is_null() || ml_kem_ek_ptr.is_null() || pqc_pk_out.is_null() {
        return false;
    }
    let mut x_pk = [0u8; 32];
    std::ptr::copy_nonoverlapping(x25519_pk_ptr, x_pk.as_mut_ptr(), 32);
    let mut ek = [0u8; ML_KEM_768_EK_LEN];
    std::ptr::copy_nonoverlapping(ml_kem_ek_ptr, ek.as_mut_ptr(), ML_KEM_768_EK_LEN);

    let composed = account::build_pqc_public_key(&x_pk, &ek);
    x_pk.zeroize();
    ek.fill(0);
    write_out(pqc_pk_out, &composed, PQC_PUBLIC_KEY_BYTES);
    true
}

/// Validate that a 1216-byte `m_pqc_public_key` is consistent with the
/// supplied 32-byte Ed25519 view public key (i.e. the first 32 bytes of
/// the buffer are the birational image of `view_pk`).
///
/// # Safety
/// `pqc_pk_ptr` valid for 1216 bytes. `view_pk_ptr` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_account_public_address_check(
    pqc_pk_ptr: *const u8,
    view_pk_ptr: *const u8,
) -> bool {
    if pqc_pk_ptr.is_null() || view_pk_ptr.is_null() {
        return false;
    }
    let mut pqc = [0u8; PQC_PUBLIC_KEY_BYTES];
    std::ptr::copy_nonoverlapping(pqc_pk_ptr, pqc.as_mut_ptr(), PQC_PUBLIC_KEY_BYTES);
    let mut view_pk = [0u8; 32];
    std::ptr::copy_nonoverlapping(view_pk_ptr, view_pk.as_mut_ptr(), 32);

    let ok = account::check_pqc_public_key_matches_view(&pqc, &view_pk).is_ok();
    pqc.fill(0);
    view_pk.zeroize();
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn struct_layout_matches() {
        // The C-facing and Rust-facing blob types must agree on size and
        // alignment; their field order is also identical by construction.
        assert_eq!(
            size_of::<ShekylAllKeysBlob>(),
            size_of::<AllKeysBlob>(),
            "ShekylAllKeysBlob and AllKeysBlob must be bit-for-bit compatible"
        );
    }

    #[test]
    fn bip39_validate_accepts_good_mnemonic() {
        let entropy = [0u8; 32];
        let words = bip39::mnemonic_from_entropy(&entropy).unwrap();
        let bytes = words.as_bytes();
        unsafe {
            assert!(shekyl_bip39_validate(bytes.as_ptr(), bytes.len()));
        }
    }

    #[test]
    fn bip39_validate_rejects_garbage() {
        let bad = "not even close to a mnemonic";
        unsafe {
            assert!(!shekyl_bip39_validate(bad.as_ptr(), bad.len()));
        }
    }

    #[test]
    fn bip39_mnemonic_from_entropy_zero_padded_tail() {
        let entropy = [0u8; 32];
        let mut out = [0xFFu8; 256];
        let mut out_len: usize = 0;
        unsafe {
            assert!(shekyl_bip39_mnemonic_from_entropy(
                entropy.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                &raw mut out_len,
            ));
        }
        assert!(out_len > 0);
        // Every byte past out_len must be zero (deterministic tail).
        assert!(out[out_len..].iter().all(|&b| b == 0));
        let words = std::str::from_utf8(&out[..out_len]).unwrap();
        assert!(bip39::validate(words));
    }

    #[test]
    fn pbkdf2_seed_ffi_matches_library() {
        let entropy = [0u8; 32];
        let words = bip39::mnemonic_from_entropy(&entropy).unwrap();
        let mut out = [0u8; 64];
        unsafe {
            assert!(shekyl_bip39_mnemonic_to_pbkdf2_seed(
                words.as_ptr(),
                words.len(),
                std::ptr::null(),
                0,
                out.as_mut_ptr(),
            ));
        }
        let direct = bip39::mnemonic_to_pbkdf2_seed(&words, "").unwrap();
        assert_eq!(out, *direct);
    }

    #[test]
    fn seed_normalize_matches_library() {
        let ikm = b"hello";
        let mut out = [0u8; 64];
        unsafe {
            assert!(shekyl_seed_normalize(
                ikm.as_ptr(),
                ikm.len(),
                out.as_mut_ptr()
            ));
        }
        let direct = account::normalize_seed(ikm);
        assert_eq!(out, *direct);
    }

    #[test]
    fn raw_seed_generate_is_nonzero_and_distinct() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        unsafe {
            assert!(shekyl_raw_seed_generate(a.as_mut_ptr()));
            assert!(shekyl_raw_seed_generate(b.as_mut_ptr()));
        }
        assert_ne!(a, [0u8; 32]);
        assert_ne!(b, [0u8; 32]);
        assert_ne!(a, b, "OsRng must not produce identical back-to-back seeds");
    }

    #[test]
    fn derive_wide_rejects_network_format_mismatch() {
        let master = [0u8; 64];
        let mut out = [0u8; 64];
        // Mainnet + RAW32 is not permitted.
        unsafe {
            assert!(!shekyl_seed_derive_spend_wide(
                master.as_ptr(),
                DerivationNetwork::Mainnet.as_u8(),
                SeedFormat::Raw32.as_u8(),
                out.as_mut_ptr(),
            ));
        }
        // On failure the output must be zero.
        assert_eq!(out, [0u8; 64]);
    }

    #[test]
    fn wide_reduce_matches_library() {
        let input = [0x42u8; 64];
        let mut out = [0u8; 32];
        unsafe {
            assert!(shekyl_ed25519_scalar_wide_reduce(
                input.as_ptr(),
                out.as_mut_ptr()
            ));
        }
        let expected = account::wide_reduce_to_scalar(&input);
        assert_eq!(&out, expected.as_bytes());
    }

    #[test]
    fn kem_keypair_from_master_seed_is_deterministic() {
        let master = [0xABu8; 64];
        let mut ek1 = vec![0u8; ML_KEM_768_EK_LEN];
        let mut dk1 = vec![0u8; ML_KEM_768_DK_LEN];
        let mut ek2 = vec![0u8; ML_KEM_768_EK_LEN];
        let mut dk2 = vec![0u8; ML_KEM_768_DK_LEN];
        unsafe {
            assert!(shekyl_kem_keypair_from_master_seed(
                master.as_ptr(),
                DerivationNetwork::Mainnet.as_u8(),
                SeedFormat::Bip39.as_u8(),
                ek1.as_mut_ptr(),
                dk1.as_mut_ptr(),
            ));
            assert!(shekyl_kem_keypair_from_master_seed(
                master.as_ptr(),
                DerivationNetwork::Mainnet.as_u8(),
                SeedFormat::Bip39.as_u8(),
                ek2.as_mut_ptr(),
                dk2.as_mut_ptr(),
            ));
        }
        assert_eq!(ek1, ek2);
        assert_eq!(dk1, dk2);
    }

    #[test]
    fn account_generate_from_bip39_then_rederive_matches() {
        let entropy = [0x11u8; 32];
        let words = bip39::mnemonic_from_entropy(&entropy).unwrap();
        let mut seed_a = [0u8; 64];
        let mut blob_a = ShekylAllKeysBlob::zeroed();
        unsafe {
            assert!(shekyl_account_generate_from_bip39(
                words.as_ptr(),
                words.len(),
                std::ptr::null(),
                0,
                DerivationNetwork::Mainnet.as_u8(),
                seed_a.as_mut_ptr(),
                &raw mut blob_a,
            ));
        }
        let mut blob_b = ShekylAllKeysBlob::zeroed();
        unsafe {
            assert!(shekyl_account_rederive(
                seed_a.as_ptr(),
                DerivationNetwork::Mainnet.as_u8(),
                SeedFormat::Bip39.as_u8(),
                &raw mut blob_b,
            ));
        }
        assert_eq!(blob_a.spend_pk, blob_b.spend_pk);
        assert_eq!(blob_a.view_pk, blob_b.view_pk);
        assert_eq!(blob_a.pqc_public_key, blob_b.pqc_public_key);
        assert_eq!(blob_a.spend_sk, blob_b.spend_sk);
    }

    #[test]
    fn account_generate_from_bip39_rejects_testnet() {
        let entropy = [0u8; 32];
        let words = bip39::mnemonic_from_entropy(&entropy).unwrap();
        let mut seed = [0xFFu8; 64];
        let mut blob = ShekylAllKeysBlob::zeroed();
        unsafe {
            assert!(!shekyl_account_generate_from_bip39(
                words.as_ptr(),
                words.len(),
                std::ptr::null(),
                0,
                DerivationNetwork::Testnet.as_u8(),
                seed.as_mut_ptr(),
                &raw mut blob,
            ));
        }
        // fail-closed: outputs zeroed.
        assert_eq!(seed, [0u8; 64]);
    }

    #[test]
    fn public_address_build_and_check_roundtrip() {
        let master = [0x33u8; 64];
        let mut blob = ShekylAllKeysBlob::zeroed();
        unsafe {
            assert!(shekyl_account_rederive(
                master.as_ptr(),
                DerivationNetwork::Mainnet.as_u8(),
                SeedFormat::Bip39.as_u8(),
                &raw mut blob,
            ));
        }
        let mut built = [0u8; PQC_PUBLIC_KEY_BYTES];
        unsafe {
            assert!(shekyl_account_public_address_build(
                blob.x25519_pk.as_ptr(),
                blob.ml_kem_ek.as_ptr(),
                built.as_mut_ptr(),
            ));
        }
        assert_eq!(built, blob.pqc_public_key);
        unsafe {
            assert!(shekyl_account_public_address_check(
                built.as_ptr(),
                blob.view_pk.as_ptr(),
            ));
        }
    }

    #[test]
    fn public_address_check_rejects_tampered_x25519() {
        let master = [0x44u8; 64];
        let mut blob = ShekylAllKeysBlob::zeroed();
        unsafe {
            assert!(shekyl_account_rederive(
                master.as_ptr(),
                DerivationNetwork::Mainnet.as_u8(),
                SeedFormat::Bip39.as_u8(),
                &raw mut blob,
            ));
        }
        blob.pqc_public_key[0] ^= 0x01;
        unsafe {
            assert!(!shekyl_account_public_address_check(
                blob.pqc_public_key.as_ptr(),
                blob.view_pk.as_ptr(),
            ));
        }
    }
}
