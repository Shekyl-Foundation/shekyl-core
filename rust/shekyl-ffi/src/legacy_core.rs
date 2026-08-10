// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Init, buffer, PQC sign/verify, economics, secure memory.

use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme as _,
    SCHEME_DOMAIN_PQC_AUTH_TX, SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG,
};
use std::os::raw::c_char;
use std::sync::Mutex;

use super::legacy_types::*;
use super::legacy_util::*;

static CONSENSUS_REGISTRY: Mutex<Option<shekyl_consensus::ConsensusRegistry>> = Mutex::new(None);

// ─── Version / Init ─────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn shekyl_rust_version() -> *const c_char {
    static VERSION: &[u8] = b"2.0.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Initialize the Rust subsystem. Registers built-in consensus modules.
#[no_mangle]
pub extern "C" fn shekyl_rust_init() -> bool {
    let mut registry = shekyl_consensus::ConsensusRegistry::new();
    let randomx = shekyl_consensus::RandomXProof::new(120, 720);
    if registry.register(Box::new(randomx)).is_err() {
        return false;
    }
    if let Ok(mut guard) = CONSENSUS_REGISTRY.lock() {
        *guard = Some(registry);
    }
    true
}

/// Get the name of the active consensus module. Returns null-terminated C string.
#[no_mangle]
pub extern "C" fn shekyl_active_consensus_module() -> *const c_char {
    static RANDOMX: &[u8] = b"RandomX\0";
    static NONE: &[u8] = b"none\0";
    if let Ok(guard) = CONSENSUS_REGISTRY.lock() {
        if let Some(ref reg) = *guard {
            if reg.active().is_some() {
                return RANDOMX.as_ptr() as *const c_char;
            }
        }
    }
    NONE.as_ptr() as *const c_char
}

// ─── XChaCha20 Stream Cipher ─────────────────────────────────────────────────

/// Apply XChaCha20 keystream: reads `length` bytes from `data`, XORs with
/// the keystream derived from `key` (32 bytes) and `nonce` (24 bytes), and
/// writes the result to `cipher`.  `data` and `cipher` may alias (in-place).
///
/// # Safety
/// - `data` must point to at least `length` readable bytes.
/// - `key` must point to 32 bytes.
/// - `nonce` must point to 24 bytes.
/// - `cipher` must point to at least `length` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn xchacha20(
    data: *const u8,
    length: usize,
    key: *const u8,
    nonce: *const u8,
    cipher: *mut u8,
) {
    if length == 0 {
        return;
    }
    debug_assert!(!data.is_null());
    debug_assert!(!key.is_null());
    debug_assert!(!nonce.is_null());
    debug_assert!(!cipher.is_null());

    let key_arr: &[u8; 32] = &*(key as *const [u8; 32]);
    let nonce_arr: &[u8; 24] = &*(nonce as *const [u8; 24]);
    let src = std::slice::from_raw_parts(data, length);
    let dst = std::slice::from_raw_parts_mut(cipher, length);

    shekyl_chacha::xchacha20_apply_copy(key_arr, nonce_arr, src, dst);
}

// ─── PQC: Hybrid Signatures ─────────────────────────────────────────────────

/// Generate a hybrid Ed25519 + ML-DSA-65 keypair.
///
/// Returns canonical-encoded public and secret key buffers. Caller owns the
/// buffers and must release them via `shekyl_buffer_free`.
/// **Test-support only** (F-7): generates a fresh, *non-derived* hybrid keypair.
/// Real wallets derive their keys (`generate_pqc_key_material`); this export
/// exists solely for the C++ FFI test suite (`fcmp.cpp`) and has no production
/// caller. It is not gated out of the shared archive because the C++ tests link
/// the same archive as production; the structural gate (a separate test-only
/// Rust archive) is tracked in FOLLOWUPS. Do not call from production C++.
#[no_mangle]
pub extern "C" fn shekyl_pqc_keypair_generate() -> ShekylPqcKeypair {
    let scheme = HybridEd25519MlDsa;
    match scheme.generate_ephemeral_keypair_for_tests() {
        Ok((pk, sk)) => {
            let public_key = pk.to_canonical_bytes().map(ShekylBuffer::from_vec);
            let secret_key = sk.to_canonical_bytes().map(ShekylBuffer::from_vec);
            match (public_key, secret_key) {
                (Ok(public_key), Ok(secret_key)) => ShekylPqcKeypair {
                    public_key,
                    secret_key,
                    success: true,
                },
                _ => ShekylPqcKeypair {
                    public_key: ShekylBuffer::null(),
                    secret_key: ShekylBuffer::null(),
                    success: false,
                },
            }
        }
        Err(_) => ShekylPqcKeypair {
            public_key: ShekylBuffer::null(),
            secret_key: ShekylBuffer::null(),
            success: false,
        },
    }
}

/// Sign a message using a canonical-encoded hybrid secret key.
///
/// Returns a canonical-encoded hybrid signature buffer. Caller owns the buffer
/// and must release it via `shekyl_buffer_free`.
#[no_mangle]
pub extern "C" fn shekyl_pqc_sign(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> ShekylPqcSignatureResult {
    let Some(secret_key_bytes) = (unsafe { slice_from_ptr(secret_key_ptr, secret_key_len) }) else {
        return ShekylPqcSignatureResult {
            signature: ShekylBuffer::null(),
            success: false,
        };
    };
    let Some(message) = (unsafe { slice_from_ptr(message_ptr, message_len) }) else {
        return ShekylPqcSignatureResult {
            signature: ShekylBuffer::null(),
            success: false,
        };
    };

    let scheme = HybridEd25519MlDsa;
    let Ok(secret_key) = HybridSecretKey::from_canonical_bytes(secret_key_bytes) else {
        return ShekylPqcSignatureResult {
            signature: ShekylBuffer::null(),
            success: false,
        };
    };

    // The scheme-level domain is Rust-owned (SA-R-2): this export serves the
    // tx per-input PQC auth surface, so C++ never carries a domain string.
    match scheme
        .sign(&secret_key, SCHEME_DOMAIN_PQC_AUTH_TX, message)
        .and_then(|sig| sig.to_canonical_bytes())
    {
        Ok(signature) => ShekylPqcSignatureResult {
            signature: ShekylBuffer::from_vec(signature),
            success: true,
        },
        Err(_) => ShekylPqcSignatureResult {
            signature: ShekylBuffer::null(),
            success: false,
        },
    }
}

/// Sign a message as a **multisig participant** (scheme 2), under the
/// multisig-specific domain (SA-R-5). A participant signature is NOT
/// interchangeable with a single-signer signature (`shekyl_pqc_sign`) over the
/// same message: this applies `SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG`, which is
/// what `verify_multisig` (scheme_id=2) checks.
///
/// **Test-support only** (F-7): production multisig participant signing is
/// unbuilt; this export exists so the C++ FFI test suite can assemble genuine
/// multisig containers instead of faking participant sigs through the
/// single-signer FFI. The domain is Rust-owned — C++ carries no domain string.
/// Do not call from production C++. Free the buffer via `shekyl_buffer_free`.
#[no_mangle]
pub extern "C" fn shekyl_pqc_sign_multisig_participant(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> ShekylPqcSignatureResult {
    let fail = ShekylPqcSignatureResult {
        signature: ShekylBuffer::null(),
        success: false,
    };
    let Some(secret_key_bytes) = (unsafe { slice_from_ptr(secret_key_ptr, secret_key_len) }) else {
        return fail;
    };
    let Some(message) = (unsafe { slice_from_ptr(message_ptr, message_len) }) else {
        return fail;
    };
    let scheme = HybridEd25519MlDsa;
    let Ok(secret_key) = HybridSecretKey::from_canonical_bytes(secret_key_bytes) else {
        return fail;
    };
    match scheme
        .sign(&secret_key, SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG, message)
        .and_then(|sig| sig.to_canonical_bytes())
    {
        Ok(signature) => ShekylPqcSignatureResult {
            signature: ShekylBuffer::from_vec(signature),
            success: true,
        },
        Err(_) => fail,
    }
}

/// Return the canonical PQC multisig wire lengths (see `ShekylPqcCanonicalLens`).
#[no_mangle]
pub extern "C" fn shekyl_pqc_canonical_lens() -> ShekylPqcCanonicalLens {
    use shekyl_crypto_pq::multisig::{
        MAX_MULTISIG_PARTICIPANTS, PQC_MAX_PUBLIC_KEY_BLOB, PQC_MAX_SIGNATURE_BLOB,
        SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN, SPEND_AUTH_PUBKEY_LEN,
    };
    ShekylPqcCanonicalLens {
        single_key_len: SINGLE_KEY_CANONICAL_LEN,
        single_sig_len: SINGLE_SIG_CANONICAL_LEN,
        spend_auth_pubkey_len: SPEND_AUTH_PUBKEY_LEN,
        max_multisig_participants: MAX_MULTISIG_PARTICIPANTS as usize,
        max_public_key_blob: PQC_MAX_PUBLIC_KEY_BLOB,
        max_signature_blob: PQC_MAX_SIGNATURE_BLOB,
    }
}

/// Verify a PQC-authenticated message.
///
/// Returns 0 on success, or a nonzero `PqcVerifyError` discriminant on failure:
///   1=SchemeMismatch, 2=ParameterBounds, 3=KeyBlobLength, 4=SigBlobLength,
///   5=ThresholdMismatch, 6=IndexOutOfRange, 7=IndicesNotAscending, 8=DuplicateKeys,
///   10=CryptoVerifyFailed, 11=DeserializationFailed
///   (code 9 is retired — the group_id check was removed under E′.)
///
/// `scheme_id = 1`: single-signer hybrid Ed25519 + ML-DSA-65.
/// `scheme_id = 2`: M-of-N multisig over hybrid keys.
///
/// For scheme_id 1, `pubkey_blob` and `sig_blob` are single canonical encodings.
/// For scheme_id 2, `pubkey_blob` is a MultisigKeyContainer and `sig_blob` is a
/// MultisigSigContainer in canonical encoding. Group ID is **not** checked: under
/// E′ the group's identity is the address fingerprint (`shekyl-address`), not a
/// per-output container hash, so there is nothing sound for the daemon to compare.
#[no_mangle]
pub extern "C" fn shekyl_pqc_verify(
    scheme_id: u8,
    pubkey_blob: *const u8,
    pubkey_len: usize,
    sig_blob: *const u8,
    sig_len: usize,
    message: *const u8,
    message_len: usize,
) -> u8 {
    let Some(pk_bytes) = (unsafe { slice_from_ptr(pubkey_blob, pubkey_len) }) else {
        return 11; // DeserializationFailed
    };
    let Some(msg) = (unsafe { slice_from_ptr(message, message_len) }) else {
        return 11;
    };
    let Some(sig_bytes) = (unsafe { slice_from_ptr(sig_blob, sig_len) }) else {
        return 11;
    };

    match scheme_id {
        1 => {
            let scheme = HybridEd25519MlDsa;
            let Ok(pk) = HybridPublicKey::from_canonical_bytes(pk_bytes) else {
                return 11;
            };
            let Ok(sig) = HybridSignature::from_canonical_bytes(sig_bytes) else {
                return 11;
            };
            // Rust-owned tx-auth domain (SA-R-2); C++ passes no domain.
            match scheme.verify(&pk, SCHEME_DOMAIN_PQC_AUTH_TX, msg, &sig) {
                Ok(()) => 0,
                Err(_) => 10, // CryptoVerifyFailed
            }
        }
        2 => {
            use shekyl_crypto_pq::multisig::verify_multisig;
            match verify_multisig(scheme_id, pk_bytes, sig_bytes, msg) {
                Ok(true) => 0,
                Ok(false) => 10, // CryptoVerifyFailed
                Err(e) => e as u8,
            }
        }
        _ => 1, // SchemeMismatch
    }
}

// ─── Crypto: Hash Functions ──────────────────────────────────────────────────

/// Compute Keccak-256 (cn_fast_hash) of `data_len` bytes at `data_ptr`.
/// Result is written to `out_ptr` which must point to 32 writable bytes.
/// Returns true on success, false if pointers are null.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_cn_fast_hash(
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let Some(data) = (unsafe { slice_from_ptr(data_ptr, data_len) }) else {
        return false;
    };
    let hash = shekyl_crypto_hash::cn_fast_hash(data);
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, 32);
    true
}

/// Compute Merkle tree root hash from an array of 32-byte hashes.
/// `hashes_ptr` points to `count * 32` contiguous bytes.
/// Result is written to `out_ptr` (32 bytes).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_tree_hash(
    hashes_ptr: *const u8,
    count: usize,
    out_ptr: *mut u8,
) -> bool {
    if out_ptr.is_null() || (count > 0 && hashes_ptr.is_null()) {
        return false;
    }
    let hashes: Vec<shekyl_crypto_hash::Hash> = if count == 0 {
        vec![]
    } else {
        let Some(byte_len) = count.checked_mul(32) else {
            return false;
        };
        let raw = std::slice::from_raw_parts(hashes_ptr, byte_len);
        raw.chunks_exact(32)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect()
    };
    let root = shekyl_crypto_hash::tree_hash(&hashes);
    std::ptr::copy_nonoverlapping(root.as_ptr(), out_ptr, 32);
    true
}

// ─── Economics: Release Rate ────────────────────────────────────────────────

/// Calculate the release multiplier from transaction volume.
///
/// Returns fixed-point value (SCALE=1_000_000). 1_000_000 = 1.0x.
#[no_mangle]
pub extern "C" fn shekyl_calc_release_multiplier(
    tx_volume_avg: u64,
    tx_volume_baseline: u64,
    release_min: u64,
    release_max: u64,
) -> u64 {
    shekyl_economics::release::calc_release_multiplier(
        tx_volume_avg,
        tx_volume_baseline,
        release_min,
        release_max,
    )
}

/// Apply a release multiplier to a base reward.
///
/// Returns: base_reward * multiplier / SCALE
#[no_mangle]
pub extern "C" fn shekyl_apply_release_multiplier(base_reward: u64, multiplier: u64) -> u64 {
    shekyl_economics::release::apply_release_multiplier(base_reward, multiplier)
}

// ─── Economics: Fee Burn ────────────────────────────────────────────────────

/// Calculate the burn percentage from chain state.
///
/// Returns fixed-point burn percentage (SCALE=1_000_000). 400_000 = 40%.
#[no_mangle]
pub extern "C" fn shekyl_calc_burn_pct(
    tx_volume: u64,
    tx_baseline: u64,
    circulating_supply: u64,
    total_supply: u64,
    burn_base_rate: u64,
    burn_cap: u64,
) -> u64 {
    shekyl_economics::burn::calc_burn_pct(
        tx_volume,
        tx_baseline,
        circulating_supply,
        total_supply,
        burn_base_rate,
        burn_cap,
    )
}

/// Pack a Rust [`BurnSplit`] for the C ABI — single packing site for both
/// burn-split exports so field order cannot drift between them.
fn burn_split_to_c(split: shekyl_economics::BurnSplit) -> ShekylBurnSplit {
    ShekylBurnSplit {
        miner_fee_income: split.miner_fee_income,
        staker_pool_amount: split.staker_pool_amount,
        actually_destroyed: split.actually_destroyed,
    }
}

/// Compute the three-way fee split for a block, with a caller-supplied flat
/// share.
///
/// Consensus C++ no longer calls this (Stage 3b routes every burn split
/// through [`shekyl_compute_burn_split_escalated`]); it is retained as the
/// differential oracle for the genesis-neutrality pin. It holds no share
/// constant of its own (the share is an argument), so keeping it duplicates no
/// fact.
#[no_mangle]
pub extern "C" fn shekyl_compute_burn_split(
    total_fees: u64,
    burn_pct: u64,
    staker_pool_share: u64,
) -> ShekylBurnSplit {
    use shekyl_economics::{compute_burn_split, ScaledShare};
    burn_split_to_c(compute_burn_split(
        total_fees,
        burn_pct,
        ScaledShare::from_raw(staker_pool_share),
    ))
}

/// Compute the three-way fee split with the **D2-escalated** staker share.
///
/// Thin FFI over the canonical Rust entry
/// [`shekyl_economics::compute_burn_split_at`]. `frozen_segment_count` is the
/// burden operand `n`, read **at parent-block state** (M3-1 cached-counter
/// drift class). Numerics stay in shipped `EconomicParams`.
///
/// **The share cannot reach `miner_fee_income`** (§12.11.1 Leg 1). At the
/// genesis-neutral parameterization this is bit-identical to
/// [`shekyl_compute_burn_split`] with the flat constant, for every `n`.
#[no_mangle]
pub extern "C" fn shekyl_compute_burn_split_escalated(
    total_fees: u64,
    burn_pct: u64,
    frozen_segment_count: u64,
) -> ShekylBurnSplit {
    use shekyl_economics::{compute_burn_split_at, EconomicParams, FrozenSegmentCount};
    burn_split_to_c(compute_burn_split_at(
        total_fees,
        burn_pct,
        FrozenSegmentCount::new(frozen_segment_count),
        &EconomicParams::default(),
    ))
}

/// The D2-escalated staker share at `frozen_segment_count`, fixed-point `SCALE`.
///
/// Observability / callers that need the share without a split. Same
/// parent-state read-point obligation as [`shekyl_compute_burn_split_escalated`].
#[no_mangle]
pub extern "C" fn shekyl_staker_pool_share_at(frozen_segment_count: u64) -> u64 {
    use shekyl_economics::{staker_pool_share_at, EconomicParams, FrozenSegmentCount};
    staker_pool_share_at(
        FrozenSegmentCount::new(frozen_segment_count),
        &EconomicParams::default().escalation(),
    )
    .to_raw()
}

/// Base block subsidy before weight penalty and release multiplier (0h KAT export).
///
/// Saturating at `money_supply`: past full emission the base curve yields the
/// tail floor, so clamping the input keeps `base_block_reward` in range and this
/// `extern "C"` export cannot panic (or unwind) across the FFI boundary. The
/// consensus connect path already caps `already_generated_coins` at
/// `MONEY_SUPPLY`, so the clamp is only reached by out-of-range callers.
#[no_mangle]
pub extern "C" fn shekyl_base_block_reward(already_generated_coins: u64) -> u64 {
    let params = shekyl_economics::params::EconomicParams::default();
    let clamped = already_generated_coins.min(params.money_supply);
    // After clamping `clamped <= money_supply`, so the only residual error is a
    // tail-subsidy overflow that canonical params never trigger; fall back to 0
    // deterministically rather than panicking.
    shekyl_economics::base_block_reward(clamped, &params).unwrap_or(0)
}

// ─── Emission Share (Component 4) ───────────────────────────────────────────

/// Calculate the effective staker emission share at a given block height.
///
/// Returns fixed-point SCALE value (e.g., 150_000 = 15%).
#[no_mangle]
pub extern "C" fn shekyl_calc_emission_share(
    current_height: u64,
    genesis_height: u64,
    initial_share: u64,
    annual_decay: u64,
    blocks_per_year: u64,
) -> u64 {
    shekyl_economics::emission_share::calc_effective_emission_share(
        current_height,
        genesis_height,
        initial_share,
        annual_decay,
        blocks_per_year,
    )
}

#[no_mangle]
pub extern "C" fn shekyl_split_block_emission(
    block_emission: u64,
    effective_share: u64,
) -> ShekylEmissionSplit {
    let (miner, staker) =
        shekyl_economics::emission_share::split_block_emission(block_emission, effective_share);
    ShekylEmissionSplit {
        miner_emission: miner,
        staker_emission: staker,
    }
}

// ─── SSL Certificate Generation ─────────────────────────────────────────────

/// Generate a self-signed ECDSA P-256 TLS certificate.
///
/// Writes PEM-encoded private key to `key_pem_out` and PEM-encoded certificate
/// to `cert_pem_out`. Caller owns both buffers and must free them with
/// `shekyl_buffer_free`. Certificate validity follows rcgen defaults (~1 year).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generate_ssl_certificate(
    key_pem_out: *mut ShekylBuffer,
    cert_pem_out: *mut ShekylBuffer,
) -> bool {
    if key_pem_out.is_null() || cert_pem_out.is_null() {
        return false;
    }

    let Ok(key_pair) = rcgen::KeyPair::generate() else {
        return false;
    };

    let Ok(cert) = rcgen::CertificateParams::default().self_signed(&key_pair) else {
        return false;
    };

    let key_pem_str = key_pair.serialize_pem();
    let cert_pem_str = cert.pem();

    *key_pem_out = ShekylBuffer::from_vec(key_pem_str.into_bytes());
    *cert_pem_out = ShekylBuffer::from_vec(cert_pem_str.into_bytes());
    true
}

// ─── Secure Memory ──────────────────────────────────────────────────────────

/// Securely wipe memory at `ptr` for `len` bytes.
///
/// Uses `zeroize` to guarantee the write is not optimized away.
/// C signature: `void shekyl_memwipe(void *ptr, size_t len)`
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_memwipe(ptr: *mut libc::c_void, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    use zeroize::Zeroize;
    std::slice::from_raw_parts_mut(ptr as *mut u8, len).zeroize();
}

/// Lock memory pages containing `[ptr, ptr+len)` into RAM.
///
/// Returns 0 on success, -1 on failure (mirrors POSIX mlock).
/// C signature: `int shekyl_mlock(const void *ptr, size_t len)`
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_mlock(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(unix)]
    {
        libc::mlock(ptr, len)
    }
    #[cfg(windows)]
    {
        extern "system" {
            fn VirtualLock(lpAddress: *const libc::c_void, dwSize: usize) -> i32;
        }
        let ret = VirtualLock(ptr, len);
        if ret != 0 {
            0
        } else {
            -1
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        -1
    }
}

/// Unlock previously locked memory pages.
///
/// Returns 0 on success, -1 on failure (mirrors POSIX munlock).
/// C signature: `int shekyl_munlock(const void *ptr, size_t len)`
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_munlock(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(unix)]
    {
        libc::munlock(ptr, len)
    }
    #[cfg(windows)]
    {
        extern "system" {
            fn VirtualUnlock(lpAddress: *const libc::c_void, dwSize: usize) -> i32;
        }
        let ret = VirtualUnlock(ptr, len);
        if ret != 0 {
            0
        } else {
            -1
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        -1
    }
}

/// Advise the kernel to exclude `[ptr, ptr+len)` from core dumps.
///
/// Uses `madvise(MADV_DONTDUMP)` on Linux. No-op on other platforms.
/// Returns 0 on success, -1 on failure.
/// C signature: `int shekyl_madvise_dontdump(const void *ptr, size_t len)`
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_madvise_dontdump(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(target_os = "linux")]
    {
        libc::madvise(ptr.cast_mut(), len, libc::MADV_DONTDUMP)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ptr, len);
        0
    }
}

/// Return the system page size in bytes.
///
/// Returns 0 on failure.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_page_size() -> usize {
    #[cfg(unix)]
    {
        let ret = libc::sysconf(libc::_SC_PAGESIZE);
        if ret <= 0 {
            0
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                ret as usize
            }
        }
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct SystemInfo {
            _pad: [u8; 4],
            page_size: u32,
            _rest: [u8; 52],
        }
        extern "system" {
            fn GetSystemInfo(info: *mut SystemInfo);
        }
        let mut info = SystemInfo {
            _pad: [0; 4],
            page_size: 0,
            _rest: [0; 52],
        };
        GetSystemInfo(&mut info);
        info.page_size as usize
    }
    #[cfg(not(any(unix, windows)))]
    {
        0
    }
}
