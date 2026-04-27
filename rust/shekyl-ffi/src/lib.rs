//! FFI bridge between the C++ core and Rust modules.
//!
//! Exposes Rust functionality to C++ through a C-compatible ABI.
//! All public functions use `extern "C"` with `#[no_mangle]`.

// FFI boundary code has structural patterns that trigger clippy lints:
// - extern "C" functions take raw pointers (not_unsafe_ptr_arg_deref)
// - C-compatible APIs require specific cast patterns
// - Mathematical variable names follow cryptographic notation (non_snake_case)
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    clippy::missing_safety_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::manual_let_else,
    clippy::ptr_as_ptr,
    non_snake_case
)]

// ---------------------------------------------------------------------------
// 64-bit-only gate — Chore #3, v3.1.0-alpha.5 (Tripwire B —
// structural-not-observable).
//
// This tripwire is DUPLICATED BY DESIGN. In the current workspace shape,
// `shekyl-ffi` always depends (transitively) on `shekyl-crypto-pq` whose
// Tripwire A would already fire; this gate is NOT expected to be the one
// that "catches" a 32-bit build in practice. Its job is different:
//
//   1. Preserve the refusal under a future refactor that might split
//      the FFI boundary from the PQC crate.
//   2. Make the refusal legible at the FFI seam, where downstream C++
//      consumers discover what Rust will and will not link against.
//
// Do NOT delete this gate on the grounds that it "never fires". Its
// value is structural, not observable. See Tripwire A in
// rust/shekyl-crypto-pq/src/lib.rs for the primary CT argument; Tripwire C
// in rust/shekyl-tx-builder/src/lib.rs for the fips204 transaction-signing
// gate; and Tripwire D at the top of CMakeLists.txt for the C++-side
// configure-time refusal.
// ---------------------------------------------------------------------------
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "shekyl-ffi refuses to build on non-64-bit targets. This is \
     Tripwire B (structural-not-observable): duplicated by design to \
     preserve the 64-bit refusal at the FFI seam under future refactors \
     that might split this crate from shekyl-crypto-pq. See Tripwire A \
     in shekyl-crypto-pq for the primary ML-KEM/ML-DSA constant-time \
     argument; see docs/CHANGELOG.md 'Retired 32-bit build targets' \
     before attempting to revert this gate."
);

use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme,
};
use std::os::raw::c_char;
use std::sync::Mutex;

// Stabilized v1 account-derivation FFI surface. See `account_ffi.rs` for
// per-function docs and the fail-closed / out-pointer / pinned-size
// disciplines. The legacy `shekyl_kem_keypair_generate` and
// `shekyl_seed_derive_{spend,view,ml_kem}` FFIs in this file remain for
// the duration of the wallet-account-rewire slice; they are replaced by
// `shekyl_account_*` callers and removed once C++ no longer references
// them.
pub mod account_ffi;

// Engine-file envelope (WALLET_FILE_FORMAT_V1) FFI surface. Six entry points
// matching `shekyl_crypto_pq::wallet_envelope`:
//   - shekyl_wallet_keys_inspect    (AAD-only header view)
//   - shekyl_wallet_keys_seal       (create .wallet.keys)
//   - shekyl_wallet_keys_open       (decrypt .wallet.keys)
//   - shekyl_wallet_keys_rewrap_password (rotate wrapping password)
//   - shekyl_engine_state_seal      (seal .wallet)
//   - shekyl_engine_state_open      (open .wallet)
// Each function follows the two-call sizing + zeroize-on-failure + narrow
// error-code discipline documented in the module header. Consumed by
// wallet2.cpp in the commit 2 slice.
pub mod wallet_envelope_ffi;

// Opaque high-level `ShekylWallet` handle wrapping `WalletFile` and
// the loaded `WalletLedger`. Where `wallet_envelope_ffi` exposes the raw
// envelope primitives so C++ can compose its own orchestration, this
// module exposes a single lifecycle surface (create / open / save /
// rotate / free) plus a non-secret metadata getter and a postcard ledger
// export. Consumed by wallet2.cpp in the 2k/2l rewire slices.
pub mod engine_file_ffi;

static CONSENSUS_REGISTRY: Mutex<Option<shekyl_consensus::ConsensusRegistry>> = Mutex::new(None);

/// Fixed-size witness header per input in the FCMP++ prove/verify FFI.
/// Layout: [O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]
///   x, y = SAL spend secrets (O = xG + yT)
///   z    = Pedersen commitment mask (C = zG + amount*H)
///   a    = pseudo-out blinding factor (r_c = a - z)
pub const SHEKYL_PROVE_WITNESS_HEADER_BYTES: usize = 256;

/// Typed struct for passing FCMP++ prover inputs across FFI.
/// C++ fills named fields instead of writing at hand-counted byte offsets.
#[repr(C)]
pub struct ProveInputFields {
    pub output_key: [u8; 32],
    pub key_image_gen: [u8; 32],
    pub commitment: [u8; 32],
    pub h_pqc: [u8; 32],
    pub spend_key_x: [u8; 32],
    pub spend_key_y: [u8; 32],
    pub commitment_mask: [u8; 32],
    pub pseudo_out_blind: [u8; 32],
}

/// Result struct for construct_output FFI.
#[repr(C)]
pub struct ShekylOutputData {
    pub output_key: [u8; 32],
    pub commitment: [u8; 32],
    pub enc_amount: [u8; 8],
    pub amount_tag: u8,
    pub view_tag_x25519: u8,
    pub kem_ciphertext_x25519: [u8; 32],
    pub kem_ciphertext_ml_kem: ShekylBuffer,
    pub pqc_public_key: ShekylBuffer,
    pub h_pqc: [u8; 32],
    pub y: [u8; 32],
    pub z: [u8; 32],
    pub k_amount: [u8; 32],
    pub success: bool,
}

/// Result struct for scan_output FFI.
#[repr(C)]
pub struct ShekylScannedOutput {
    pub y: [u8; 32],
    pub z: [u8; 32],
    pub k_amount: [u8; 32],
    pub amount: u64,
    pub amount_tag: u8,
    pub pqc_public_key: ShekylBuffer,
    pub pqc_secret_key: ShekylBuffer,
    pub h_pqc: [u8; 32],
    pub success: bool,
}

/// Result struct for sign_pqc_auth FFI.
#[repr(C)]
pub struct ShekylPqcAuthResult {
    pub hybrid_public_key: ShekylBuffer,
    pub signature: ShekylBuffer,
    pub success: bool,
}

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

// ─── Generic Buffer Helpers ──────────────────────────────────────────────────

#[repr(C)]
pub struct ShekylBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl ShekylBuffer {
    fn from_vec(mut data: Vec<u8>) -> Self {
        let buffer = ShekylBuffer {
            ptr: data.as_mut_ptr(),
            len: data.len(),
        };
        std::mem::forget(data);
        buffer
    }

    fn null() -> Self {
        ShekylBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

/// Free a buffer originally allocated by a Rust FFI export.
///
/// # Safety
/// `len` **must** equal the buffer length from the paired Rust export (i.e.,
/// the `len` field of the `ShekylBuffer` that was returned). Passing a
/// different `len` is undefined behavior — it reconstructs a `Vec` with
/// mismatched capacity.
#[no_mangle]
pub unsafe extern "C" fn shekyl_buffer_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        use zeroize::Zeroize;
        std::slice::from_raw_parts_mut(ptr, len).zeroize();
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

/// # Safety
///
/// The caller must ensure that `ptr` points to a valid allocation of at
/// least `len` bytes, and that the returned reference does not outlive the
/// allocation. This is the standard FFI raw-pointer-to-slice contract —
/// the function is `unsafe` because safe Rust cannot verify these
/// preconditions.
unsafe fn slice_from_ptr<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
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

#[repr(C)]
pub struct ShekylPqcKeypair {
    pub public_key: ShekylBuffer,
    pub secret_key: ShekylBuffer,
    pub success: bool,
}

#[repr(C)]
pub struct ShekylPqcSignatureResult {
    pub signature: ShekylBuffer,
    pub success: bool,
}

/// Generate a hybrid Ed25519 + ML-DSA-65 keypair.
///
/// Returns canonical-encoded public and secret key buffers. Caller owns the
/// buffers and must release them via `shekyl_buffer_free`.
#[no_mangle]
pub extern "C" fn shekyl_pqc_keypair_generate() -> ShekylPqcKeypair {
    let scheme = HybridEd25519MlDsa;
    match scheme.keypair_generate() {
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

    match scheme
        .sign(&secret_key, message)
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

/// Verify a PQC-authenticated message.
///
/// Returns 0 on success, or a nonzero `PqcVerifyError` discriminant (1-11) on failure:
///   1=SchemeMismatch, 2=ParameterBounds, 3=KeyBlobLength, 4=SigBlobLength,
///   5=ThresholdMismatch, 6=IndexOutOfRange, 7=IndicesNotAscending, 8=DuplicateKeys,
///   9=GroupIdMismatch, 10=CryptoVerifyFailed, 11=DeserializationFailed
///
/// `scheme_id = 1`: single-signer hybrid Ed25519 + ML-DSA-65.
/// `scheme_id = 2`: M-of-N multisig over hybrid keys.
///
/// For scheme_id 1, `pubkey_blob` and `sig_blob` are single canonical encodings.
/// For scheme_id 2, `pubkey_blob` is a MultisigKeyContainer and `sig_blob` is a
/// MultisigSigContainer in canonical encoding. Group ID is not checked here;
/// callers performing consensus verification should compute it separately via
/// `shekyl_pqc_multisig_group_id` and compare against the expected value.
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
            match scheme.verify(&pk, msg, &sig) {
                Ok(true) => 0,
                Ok(false) | Err(_) => 10, // CryptoVerifyFailed
            }
        }
        2 => {
            use shekyl_crypto_pq::multisig::verify_multisig;
            match verify_multisig(scheme_id, pk_bytes, sig_bytes, msg, None) {
                Ok(true) => 0,
                Ok(false) => 10, // CryptoVerifyFailed
                Err(e) => e as u8,
            }
        }
        _ => 1, // SchemeMismatch
    }
}

/// Verify a PQC-authenticated message with optional group ID binding.
///
/// Same error codes as `shekyl_pqc_verify` (0=success, 1-11=PqcVerifyError).
/// For `scheme_id = 2`, passes `expected_group_id` to `verify_multisig` for
/// defense-in-depth group binding (PQC_MULTISIG.md SS16.3).
///
/// `expected_group_id_ptr`: pointer to 32 bytes of expected group ID, or null to skip.
#[no_mangle]
pub extern "C" fn shekyl_pqc_verify_with_group_id(
    scheme_id: u8,
    pubkey_blob: *const u8,
    pubkey_len: usize,
    sig_blob: *const u8,
    sig_len: usize,
    message: *const u8,
    message_len: usize,
    expected_group_id_ptr: *const u8,
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
            match scheme.verify(&pk, msg, &sig) {
                Ok(true) => 0,
                Ok(false) | Err(_) => 10, // CryptoVerifyFailed
            }
        }
        2 => {
            use shekyl_crypto_pq::multisig::verify_multisig;
            let group_id: Option<&[u8; 32]> = if expected_group_id_ptr.is_null() {
                None
            } else {
                unsafe { slice_from_ptr(expected_group_id_ptr, 32) }
                    .and_then(|s| <&[u8; 32]>::try_from(s).ok())
            };
            match verify_multisig(scheme_id, pk_bytes, sig_bytes, msg, group_id) {
                Ok(true) => 0,
                Ok(false) => 10, // CryptoVerifyFailed
                Err(e) => e as u8,
            }
        }
        _ => 1, // SchemeMismatch
    }
}

/// Compute the deterministic group_id for a MultisigKeyContainer blob.
///
/// Writes 32 bytes to `out_ptr`. Returns true on success.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pqc_multisig_group_id(
    keys_ptr: *const u8,
    keys_len: usize,
    out_ptr: *mut u8,
) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let Some(keys_bytes) = (unsafe { slice_from_ptr(keys_ptr, keys_len) }) else {
        return false;
    };

    use shekyl_crypto_pq::multisig::{multisig_group_id, MultisigKeyContainer};

    let Ok(container) = MultisigKeyContainer::from_canonical_bytes(keys_bytes) else {
        return false;
    };

    match multisig_group_id(&container) {
        Ok(id) => {
            std::ptr::copy_nonoverlapping(id.as_ptr(), out_ptr, 32);
            true
        }
        Err(_) => false,
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
    stake_ratio: u64,
    burn_base_rate: u64,
    burn_cap: u64,
) -> u64 {
    shekyl_economics::burn::calc_burn_pct(
        tx_volume,
        tx_baseline,
        circulating_supply,
        total_supply,
        stake_ratio,
        burn_base_rate,
        burn_cap,
    )
}

/// Opaque result struct for the fee burn split, readable from C++.
#[repr(C)]
pub struct ShekylBurnSplit {
    pub miner_fee_income: u64,
    pub staker_pool_amount: u64,
    pub actually_destroyed: u64,
}

/// Compute the three-way fee split for a block.
#[no_mangle]
pub extern "C" fn shekyl_compute_burn_split(
    total_fees: u64,
    burn_pct: u64,
    staker_pool_share: u64,
) -> ShekylBurnSplit {
    let split = shekyl_economics::burn::compute_burn_split(total_fees, burn_pct, staker_pool_share);
    ShekylBurnSplit {
        miner_fee_income: split.miner_fee_income,
        staker_pool_amount: split.staker_pool_amount,
        actually_destroyed: split.actually_destroyed,
    }
}

// ─── Staking ────────────────────────────────────────────────────────────────

/// Compute the weighted stake for a single entry.
///
/// Returns: amount * yield_multiplier / SCALE
#[no_mangle]
pub extern "C" fn shekyl_stake_weight(amount: u64, tier_id: u8) -> u64 {
    use shekyl_staking::tiers::tier_by_id;
    let Some(tier) = tier_by_id(tier_id) else {
        return 0;
    };
    #[allow(clippy::cast_possible_truncation)]
    {
        ((u128::from(amount) * u128::from(tier.yield_multiplier))
            / u128::from(shekyl_economics::params::SCALE)) as u64
    }
}

/// Get lock duration in blocks for a given tier.
///
/// Returns 0 if tier_id is invalid.
#[no_mangle]
pub extern "C" fn shekyl_stake_lock_blocks(tier_id: u8) -> u64 {
    use shekyl_staking::tiers::tier_by_id;
    match tier_by_id(tier_id) {
        Some(t) => t.lock_blocks,
        None => 0,
    }
}

/// Get the yield multiplier for a given tier (fixed-point SCALE).
///
/// Returns 0 if tier_id is invalid.
#[no_mangle]
pub extern "C" fn shekyl_stake_yield_multiplier(tier_id: u8) -> u64 {
    use shekyl_staking::tiers::tier_by_id;
    match tier_by_id(tier_id) {
        Some(t) => t.yield_multiplier,
        None => 0,
    }
}

/// Per-block share of the staker pool for one weighted stake entry:
/// `(total_reward_at_height * stake_weight) / total_weighted_stake` using `u128` math.
///
/// `total_weighted_stake` is passed as a 128-bit value split into lo/hi u64 halves.
/// If `total_weighted_stake == 0`, returns `0`.
/// If the quotient does not fit in `u64`, returns `0` and sets `*overflow_out` to `1` when
/// `overflow_out` is non-null.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_calc_per_block_staker_reward(
    total_reward_at_height: u64,
    stake_weight: u64,
    total_weighted_stake_lo: u64,
    total_weighted_stake_hi: u64,
    overflow_out: *mut u8,
) -> u64 {
    if !overflow_out.is_null() {
        *overflow_out = 0;
    }
    let total_weighted_stake =
        u128::from(total_weighted_stake_hi) << 64 | u128::from(total_weighted_stake_lo);
    if total_weighted_stake == 0 {
        return 0;
    }
    let num = u128::from(total_reward_at_height) * u128::from(stake_weight);
    let q = num / total_weighted_stake;
    if q > u128::from(u64::MAX) {
        if !overflow_out.is_null() {
            *overflow_out = 1;
        }
        return 0;
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        q as u64
    }
}

/// Number of staking lock tiers (length of `TIERS`).
#[no_mangle]
pub extern "C" fn shekyl_stake_tier_count() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        shekyl_staking::tiers::TIERS.len() as u32
    }
}

/// UTF-8 tier display name, null-terminated. Returns null for invalid `tier_id`.
#[no_mangle]
pub extern "C" fn shekyl_stake_tier_name(tier_id: u8) -> *const c_char {
    match tier_id {
        0 => c"Short".as_ptr(),
        1 => c"Medium".as_ptr(),
        2 => c"Long".as_ptr(),
        _ => std::ptr::null(),
    }
}

/// Maximum `to_height - from_height` allowed for a stake claim (from economics config).
#[no_mangle]
pub extern "C" fn shekyl_stake_max_claim_range() -> u64 {
    shekyl_staking::MAX_CLAIM_RANGE
}

/// Compute stake_ratio = total_staked / circulating_supply (fixed-point SCALE).
#[no_mangle]
pub extern "C" fn shekyl_calc_stake_ratio(total_staked: u64, circulating_supply: u64) -> u64 {
    if circulating_supply == 0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        (u128::from(total_staked) * u128::from(shekyl_economics::params::SCALE)
            / u128::from(circulating_supply)) as u64
    }
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

/// Split block emission between miner and staker pool.
#[repr(C)]
pub struct ShekylEmissionSplit {
    pub miner_emission: u64,
    pub staker_emission: u64,
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

// ─── FCMP++: Generators ─────────────────────────────────────────────────────

/// Write the compressed Ed25519 bytes of generator T to `out_ptr` (32 bytes).
///
/// T = hash_to_point(keccak256("Monero Generator T")) — the generator used
/// to blind the key-image commitment in two-component output keys: O = xG + yT.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generator_T(out_ptr: *mut u8) {
    use ciphersuite::group::GroupEncoding;
    if out_ptr.is_null() {
        return;
    }
    let t_bytes: [u8; 32] = shekyl_generators::T.to_bytes();
    std::ptr::copy_nonoverlapping(t_bytes.as_ptr(), out_ptr, 32);
}

// ─── FCMP++: Proof and Tree Operations ──────────────────────────────────────

/// Compute H(pqc_pk) leaf scalar for a PQC public key.
///
/// Writes 32 bytes to `out_ptr`. Returns true on success.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_pqc_leaf_hash(
    pqc_pk_ptr: *const u8,
    pqc_pk_len: usize,
    out_ptr: *mut u8,
) -> bool {
    let Some(pk_bytes) = (unsafe { slice_from_ptr(pqc_pk_ptr, pqc_pk_len) }) else {
        return false;
    };
    if out_ptr.is_null() {
        return false;
    }
    let hash = shekyl_crypto_pq::derivation::hash_pqc_public_key(pk_bytes);
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, 32);
    true
}

/// Derive `h_pqc = H(hybrid_public_key)` from combined shared secret and output
/// index. Secret key is derived internally, used for public key derivation only,
/// and zeroized immediately. No secret material crosses this boundary.
///
/// # Safety
/// - `combined_ss_ptr` must point to 64 bytes.
/// - `h_pqc_out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_pqc_leaf_hash(
    combined_ss_ptr: *const u8,
    output_index: u64,
    h_pqc_out: *mut u8,
) -> bool {
    if combined_ss_ptr.is_null() || h_pqc_out.is_null() {
        return false;
    }
    let mut ss = [0u8; 64];
    std::ptr::copy_nonoverlapping(combined_ss_ptr, ss.as_mut_ptr(), 64);

    match shekyl_crypto_pq::derivation::derive_pqc_leaf_hash(&ss, output_index) {
        Ok(hash) => {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), h_pqc_out, 32);
            true
        }
        Err(_) => false,
    }
}

/// Derive the canonical hybrid public key bytes from combined shared secret and
/// output index. No secret material crosses this boundary.
///
/// # Safety
/// - `combined_ss_ptr` must point to 64 bytes.
/// - Returns a heap-allocated ShekylBuffer that must be freed with `shekyl_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_pqc_public_key(
    combined_ss_ptr: *const u8,
    output_index: u64,
) -> ShekylBuffer {
    if combined_ss_ptr.is_null() {
        return ShekylBuffer::null();
    }
    let mut ss = [0u8; 64];
    std::ptr::copy_nonoverlapping(combined_ss_ptr, ss.as_mut_ptr(), 64);

    match shekyl_crypto_pq::derivation::derive_pqc_public_key(&ss, output_index) {
        Ok(pk) => ShekylBuffer::from_vec(pk),
        Err(_) => ShekylBuffer::null(),
    }
}

/// Derive all per-output secrets from the combined KEM shared secret.
///
/// Writes to 7 output pointers: ho(32), y(32), z(32), k_amount(32),
/// view_tag_combined(1), amount_tag(1), ml_dsa_seed(32). All pointers must be
/// non-null and point to writable memory of the stated size.
///
/// Returns true on success, false if any pointer is null.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_output_secrets(
    combined_ss_ptr: *const u8,
    combined_ss_len: u32,
    output_index: u64,
    out_ho: *mut u8,
    out_y: *mut u8,
    out_z: *mut u8,
    out_k_amount: *mut u8,
    out_view_tag_combined: *mut u8,
    out_amount_tag: *mut u8,
    out_ml_dsa_seed: *mut u8,
) -> bool {
    if combined_ss_ptr.is_null()
        || out_ho.is_null()
        || out_y.is_null()
        || out_z.is_null()
        || out_k_amount.is_null()
        || out_view_tag_combined.is_null()
        || out_amount_tag.is_null()
        || out_ml_dsa_seed.is_null()
    {
        return false;
    }

    let ss = std::slice::from_raw_parts(combined_ss_ptr, combined_ss_len as usize);

    let secrets = shekyl_crypto_pq::derivation::derive_output_secrets(ss, output_index);

    std::ptr::copy_nonoverlapping(secrets.ho.as_ptr(), out_ho, 32);
    std::ptr::copy_nonoverlapping(secrets.y.as_ptr(), out_y, 32);
    std::ptr::copy_nonoverlapping(secrets.z.as_ptr(), out_z, 32);
    std::ptr::copy_nonoverlapping(secrets.k_amount.as_ptr(), out_k_amount, 32);
    *out_view_tag_combined = secrets.view_tag_combined;
    *out_amount_tag = secrets.amount_tag;
    std::ptr::copy_nonoverlapping(secrets.ml_dsa_seed.as_ptr(), out_ml_dsa_seed, 32);

    true
}

/// Derive the X25519-only view tag for scanner pre-filtering.
///
/// `x25519_ss_ptr` must point to exactly 32 bytes. Returns the 1-byte tag.
/// Returns 0 if the pointer is null (callers should check for null separately).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_view_tag_x25519(
    x25519_ss_ptr: *const u8,
    output_index: u64,
) -> u8 {
    if x25519_ss_ptr.is_null() {
        return 0;
    }
    let ss: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(x25519_ss_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    shekyl_crypto_pq::derivation::derive_view_tag_x25519(&ss, output_index)
}

/// Compute the expected FCMP++ proof size given input count and tree depth.
#[no_mangle]
pub extern "C" fn shekyl_fcmp_proof_len(num_inputs: u32, tree_depth: u8) -> usize {
    shekyl_fcmp::tree::proof_size(num_inputs as usize, tree_depth as usize)
}

/// FCMP++ proof construction result.
#[repr(C)]
pub struct ShekylFcmpProveResult {
    pub proof: ShekylBuffer,
    pub pseudo_outs: ShekylBuffer,
    pub success: bool,
}

/// Construct an FCMP++ proof from a variable-length witness blob.
///
/// `witness_ptr` / `witness_len`: the complete serialized witness for all inputs.
///
/// Wire format (all multi-byte integers are little-endian):
///
/// ```text
/// For each of `num_inputs` inputs, sequentially:
///   Fixed header (224 bytes):
///     [O:32][I:32][C:32][h_pqc:32][spend_x:32][spend_y:32][pseudo_out_blind:32]
///     O, I, C are compressed Ed25519 output points.
///     pseudo_out_blind is the desired blinding factor a_i for this input's
///     pseudo-out commitment (r_c = a_i - spend_y).
///   Leaf chunk (variable):
///     leaf_chunk_count: u32
///     For each entry (128 bytes):
///       [O:32][I:32][C:32][h_pqc:32]  (compressed Ed25519 points + PQC hash)
///   C1 (Selene) branch layers (variable):
///     c1_layer_count: u32
///     For each layer:
///       sibling_count: u32
///       siblings: sibling_count * 32 bytes (Selene scalars)
///   C2 (Helios) branch layers (variable):
///     c2_layer_count: u32
///     For each layer:
///       sibling_count: u32
///       siblings: sibling_count * 32 bytes (Helios scalars)
/// ```
///
/// `tree_root_ptr`: 32-byte curve tree root.
/// `signable_tx_hash_ptr`: 32-byte transaction binding hash.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_prove(
    witness_ptr: *const u8,
    witness_len: usize,
    num_inputs: u32,
    tree_root_ptr: *const u8,
    tree_depth: u8,
    signable_tx_hash_ptr: *const u8,
) -> ShekylFcmpProveResult {
    let fail = ShekylFcmpProveResult {
        proof: ShekylBuffer::null(),
        pseudo_outs: ShekylBuffer::null(),
        success: false,
    };

    if witness_ptr.is_null() || tree_root_ptr.is_null() || signable_tx_hash_ptr.is_null() {
        return fail;
    }

    let n = num_inputs as usize;
    if n == 0 || n > shekyl_fcmp::MAX_INPUTS {
        return fail;
    }

    let Some(witness) = (unsafe { slice_from_ptr(witness_ptr, witness_len) }) else {
        return fail;
    };
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let signable_tx_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(signable_tx_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let Some(inputs) = parse_prove_witness(witness, n) else {
        return fail;
    };

    // The `tree_depth` parameter is the upstream library's `layers` count:
    // the total number of tree layers including the leaf layer. C++ callers
    // are responsible for converting LMDB depth to layers (depth + 1) before
    // calling this function. See FCMP_PLUS_PLUS.md §FFI Invariants.
    //
    //   layers 1 = single Selene root (degenerate, root IS the leaf hash).
    //   layers 2 = Selene leaves → Helios root.
    //   layers 3 = Selene leaves → Helios → Selene root.
    //
    //   Root curve parity: layers % 2 == 1 → C1 (Selene), == 0 → C2 (Helios).

    match shekyl_fcmp::proof::prove(&inputs, &tree_root, tree_depth, signable_tx_hash) {
        Ok(result) => {
            let mut po_flat = Vec::with_capacity(n * 32);
            for po in &result.pseudo_outs {
                po_flat.extend_from_slice(po);
            }
            ShekylFcmpProveResult {
                proof: ShekylBuffer::from_vec(result.proof.data),
                pseudo_outs: ShekylBuffer::from_vec(po_flat),
                success: true,
            }
        }
        Err(_) => fail,
    }
}

fn parse_prove_witness(
    data: &[u8],
    num_inputs: usize,
) -> Option<Vec<shekyl_fcmp::proof::ProveInput>> {
    let mut offset = 0usize;
    let mut inputs = Vec::with_capacity(num_inputs);

    for _ in 0..num_inputs {
        if offset + SHEKYL_PROVE_WITNESS_HEADER_BYTES > data.len() {
            return None;
        }

        let mut output_key = [0u8; 32];
        let mut key_image_gen = [0u8; 32];
        let mut commitment = [0u8; 32];
        let mut h_pqc = [0u8; 32];
        let mut spend_key_x = [0u8; 32];
        let mut spend_key_y = [0u8; 32];
        let mut commitment_mask = [0u8; 32];
        let mut pseudo_out_blind = [0u8; 32];

        output_key.copy_from_slice(&data[offset..offset + 32]);
        key_image_gen.copy_from_slice(&data[offset + 32..offset + 64]);
        commitment.copy_from_slice(&data[offset + 64..offset + 96]);
        h_pqc.copy_from_slice(&data[offset + 96..offset + 128]);
        spend_key_x.copy_from_slice(&data[offset + 128..offset + 160]);
        spend_key_y.copy_from_slice(&data[offset + 160..offset + 192]);
        commitment_mask.copy_from_slice(&data[offset + 192..offset + 224]);
        pseudo_out_blind
            .copy_from_slice(&data[offset + 224..offset + SHEKYL_PROVE_WITNESS_HEADER_BYTES]);
        offset += SHEKYL_PROVE_WITNESS_HEADER_BYTES;

        // Leaf chunk
        if offset + 4 > data.len() {
            return None;
        }
        let chunk_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut leaf_chunk_outputs = Vec::with_capacity(chunk_count);
        let mut leaf_chunk_h_pqc = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            if offset + 128 > data.len() {
                return None;
            }
            let mut lo = [0u8; 32];
            let mut li = [0u8; 32];
            let mut lc = [0u8; 32];
            let mut lh = [0u8; 32];
            lo.copy_from_slice(&data[offset..offset + 32]);
            li.copy_from_slice(&data[offset + 32..offset + 64]);
            lc.copy_from_slice(&data[offset + 64..offset + 96]);
            lh.copy_from_slice(&data[offset + 96..offset + 128]);
            leaf_chunk_outputs.push((lo, li, lc));
            leaf_chunk_h_pqc.push(lh);
            offset += 128;
        }

        // C1 (Selene) branch layers
        if offset + 4 > data.len() {
            return None;
        }
        let c1_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut c1_branch_layers = Vec::with_capacity(c1_count);
        for _ in 0..c1_count {
            if offset + 4 > data.len() {
                return None;
            }
            let sib_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
            offset += 4;
            let needed = sib_count * 32;
            if offset + needed > data.len() {
                return None;
            }
            let mut siblings = Vec::with_capacity(sib_count);
            for s in 0..sib_count {
                let mut scalar = [0u8; 32];
                scalar.copy_from_slice(&data[offset + s * 32..offset + (s + 1) * 32]);
                siblings.push(scalar);
            }
            offset += needed;
            c1_branch_layers.push(shekyl_fcmp::proof::BranchLayer { siblings });
        }

        // C2 (Helios) branch layers
        if offset + 4 > data.len() {
            return None;
        }
        let c2_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut c2_branch_layers = Vec::with_capacity(c2_count);
        for _ in 0..c2_count {
            if offset + 4 > data.len() {
                return None;
            }
            let sib_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
            offset += 4;
            let needed = sib_count * 32;
            if offset + needed > data.len() {
                return None;
            }
            let mut siblings = Vec::with_capacity(sib_count);
            for s in 0..sib_count {
                let mut scalar = [0u8; 32];
                scalar.copy_from_slice(&data[offset + s * 32..offset + (s + 1) * 32]);
                siblings.push(scalar);
            }
            offset += needed;
            c2_branch_layers.push(shekyl_fcmp::proof::BranchLayer { siblings });
        }

        inputs.push(shekyl_fcmp::proof::ProveInput {
            output_key,
            key_image_gen,
            commitment,
            h_pqc: shekyl_fcmp::leaf::PqcLeafScalar(h_pqc),
            spend_key_x,
            spend_key_y,
            commitment_mask,
            pseudo_out_blind,
            leaf_chunk_outputs,
            leaf_chunk_h_pqc,
            c1_branch_layers,
            c2_branch_layers,
        });
    }

    Some(inputs)
}

/// Verify an FCMP++ proof with batch verification.
///
/// Returns 0 on success, or a nonzero `VerifyError` discriminant (1-7) on failure:
///   1=DeserializationFailed, 2=InvalidTreeRoot, 3=PqcCommitmentMismatch,
///   4=KeyImageCountMismatch, 5=UpstreamError, 6=BatchVerificationFailed,
///   7=TreeDepthTooLarge
///
/// `signable_tx_hash_ptr`: 32-byte hash that binds the proof to the transaction.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_verify(
    proof_ptr: *const u8,
    proof_len: usize,
    key_images_ptr: *const u8,
    ki_count: usize,
    pseudo_outs_ptr: *const u8,
    po_count: usize,
    pqc_pk_hashes_ptr: *const u8,
    pqc_hash_count: usize,
    tree_root_ptr: *const u8,
    tree_depth: u8,
    signable_tx_hash_ptr: *const u8,
) -> u8 {
    let Some(proof_bytes) = (unsafe { slice_from_ptr(proof_ptr, proof_len) }) else {
        return 1; // DeserializationFailed
    };
    let Some(ki_bytes) = (unsafe { slice_from_ptr(key_images_ptr, ki_count * 32) }) else {
        return 1;
    };
    let Some(po_bytes) = (unsafe { slice_from_ptr(pseudo_outs_ptr, po_count * 32) }) else {
        return 1;
    };
    let Some(ph_bytes) = (unsafe { slice_from_ptr(pqc_pk_hashes_ptr, pqc_hash_count * 32) }) else {
        return 1;
    };
    if tree_root_ptr.is_null()
        || signable_tx_hash_ptr.is_null()
        || ki_count != po_count
        || ki_count != pqc_hash_count
    {
        return 1; // DeserializationFailed (invalid parameters)
    }
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let signable_tx_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(signable_tx_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    // The `tree_depth` parameter is the upstream library's `layers` count.
    // C++ callers convert LMDB depth to layers (depth + 1) before calling.
    // See convention comment in shekyl_fcmp_prove.

    let proof = shekyl_fcmp::proof::ShekylFcmpProof {
        data: proof_bytes.to_vec(),
        #[allow(clippy::cast_possible_truncation)]
        num_inputs: ki_count as u32,
        tree_depth,
    };

    let mut key_images = Vec::with_capacity(ki_count);
    let mut pseudo_outs = Vec::with_capacity(po_count);
    let mut pqc_hashes = Vec::with_capacity(pqc_hash_count);

    for i in 0..ki_count {
        let mut ki = [0u8; 32];
        ki.copy_from_slice(&ki_bytes[i * 32..(i + 1) * 32]);
        key_images.push(ki);

        let mut po = [0u8; 32];
        po.copy_from_slice(&po_bytes[i * 32..(i + 1) * 32]);
        pseudo_outs.push(po);

        let mut ph = [0u8; 32];
        ph.copy_from_slice(&ph_bytes[i * 32..(i + 1) * 32]);
        pqc_hashes.push(shekyl_fcmp::leaf::PqcLeafScalar(ph));
    }

    match shekyl_fcmp::proof::verify(
        &proof,
        &key_images,
        &pseudo_outs,
        &pqc_hashes,
        &tree_root,
        tree_depth,
        signable_tx_hash,
    ) {
        Ok(true) => 0,
        Ok(false) => 6, // BatchVerificationFailed
        Err(e) => {
            tracing::debug!(error = ?e, tree_depth, "verify error");
            e.discriminant()
        }
    }
}

/// Convert raw output data into serialized 4-scalar leaves.
///
/// `outputs_ptr`: packed tuples of `{O.x[32], I.x[32], C.x[32], pqc_pk_hash[32]}`,
/// each 128 bytes. `count` = number of outputs.
///
/// Returns a ShekylBuffer containing the serialized leaves (same format, but validated).
#[no_mangle]
pub extern "C" fn shekyl_fcmp_outputs_to_leaves(
    outputs_ptr: *const u8,
    count: usize,
) -> ShekylBuffer {
    let total = count * 128;
    let Some(bytes) = (unsafe { slice_from_ptr(outputs_ptr, total) }) else {
        return ShekylBuffer::null();
    };

    let mut leaves = Vec::with_capacity(count);
    for i in 0..count {
        let chunk: &[u8; 128] = bytes[i * 128..(i + 1) * 128].try_into().unwrap();
        leaves.push(shekyl_fcmp::leaf::ShekylLeaf::from_bytes(chunk));
    }

    let serialized = shekyl_fcmp::tree::leaves_to_bytes(&leaves);
    ShekylBuffer::from_vec(serialized)
}

// ─── FCMP++: FROST SAL Multisig ─────────────────────────────────────────────

#[cfg(feature = "multisig")]
/// Opaque handle for a FROST SAL session (one per input).
/// Created by `shekyl_frost_sal_session_new`, freed by `_session_free`.
pub struct ShekylFrostSalSession(shekyl_fcmp::frost_sal::FrostSalSession);

#[cfg(feature = "multisig")]
/// Create a new FROST SAL session for one input.
///
/// `output_key_ptr`, `key_image_gen_ptr`, `commitment_ptr`: 32-byte compressed
/// Ed25519 points. `spend_key_x_ptr`, `signable_tx_hash_ptr`: 32 bytes each.
///
/// Returns an opaque session handle, or null on failure.
/// The returned pseudo-out (32 bytes) is written to `pseudo_out_ptr`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_sal_session_new(
    output_key_ptr: *const u8,
    key_image_gen_ptr: *const u8,
    commitment_ptr: *const u8,
    spend_key_x_ptr: *const u8,
    signable_tx_hash_ptr: *const u8,
    pseudo_out_ptr: *mut u8,
) -> *mut ShekylFrostSalSession {
    if output_key_ptr.is_null()
        || key_image_gen_ptr.is_null()
        || commitment_ptr.is_null()
        || spend_key_x_ptr.is_null()
        || signable_tx_hash_ptr.is_null()
        || pseudo_out_ptr.is_null()
    {
        return std::ptr::null_mut();
    }

    let read32 = |ptr: *const u8| -> [u8; 32] {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let input_data = shekyl_fcmp::frost_sal::FrostSalInput {
        output_key: read32(output_key_ptr),
        key_image_gen: read32(key_image_gen_ptr),
        commitment: read32(commitment_ptr),
        spend_key_x: read32(spend_key_x_ptr),
        signable_tx_hash: read32(signable_tx_hash_ptr),
    };

    match shekyl_fcmp::frost_sal::FrostSalSession::new(&input_data) {
        Ok(session) => {
            std::ptr::copy_nonoverlapping(session.pseudo_out().as_ptr(), pseudo_out_ptr, 32);
            Box::into_raw(Box::new(ShekylFrostSalSession(session)))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(feature = "multisig")]
/// Get the serialized `RerandomizedOutput` from a FROST SAL session.
///
/// Returns a buffer that can be deserialized by peers to reconstruct
/// the rerandomized tuple for signing. The caller must free the buffer.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_sal_get_rerand(
    session: *const ShekylFrostSalSession,
) -> ShekylBuffer {
    if session.is_null() {
        return ShekylBuffer::null();
    }
    let session = &*session;
    let mut data = Vec::new();
    if session.0.rerandomized_output().write(&mut data).is_err() {
        return ShekylBuffer::null();
    }
    ShekylBuffer::from_vec(data)
}

// ─── FROST Signing Coordinator FFI ───────────────────────────────────────────

#[cfg(feature = "multisig")]
/// Opaque handle for the FROST signing coordinator.
pub struct ShekylFrostCoordinator(shekyl_fcmp::frost_sal::FrostSigningCoordinator);

#[cfg(feature = "multisig")]
/// Create a FROST signing coordinator for `num_inputs` inputs.
///
/// `included_ptr`: array of `num_included` u16 participant indices.
/// Returns an opaque handle, or null on failure.
///
/// # Safety
/// `included_ptr` must point to `num_included` valid u16 values.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_new(
    num_inputs: u32,
    included_ptr: *const u16,
    num_included: u32,
) -> *mut ShekylFrostCoordinator {
    if included_ptr.is_null() || num_included == 0 || num_inputs == 0 {
        return std::ptr::null_mut();
    }

    let included: Vec<modular_frost::Participant> = (0..num_included as usize)
        .filter_map(|i| {
            let idx = *included_ptr.add(i);
            modular_frost::Participant::new(idx)
        })
        .collect();

    if included.len() != num_included as usize {
        return std::ptr::null_mut();
    }

    match shekyl_fcmp::frost_sal::FrostSigningCoordinator::new_for_sal(
        num_inputs as usize,
        included,
    ) {
        Ok(c) => Box::into_raw(Box::new(ShekylFrostCoordinator(c))),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(feature = "multisig")]
/// Feed one participant's nonce commitments to the coordinator.
///
/// `participant`: 1-based participant index.
/// `data_ptr`: `num_inputs` contiguous 32-byte compressed point commitments.
/// Returns true on success.
///
/// # Safety
/// `coord` must be a valid handle. `data_ptr` must point to `num_inputs * 32` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_add_preprocesses(
    coord: *mut ShekylFrostCoordinator,
    participant: u16,
    data_ptr: *const u8,
    num_inputs: u32,
) -> bool {
    if coord.is_null() || data_ptr.is_null() {
        return false;
    }
    let Some(p) = modular_frost::Participant::new(participant) else {
        return false;
    };
    let coord = &mut *coord;
    let n = num_inputs as usize;

    let mut preprocesses = Vec::with_capacity(n);
    for i in 0..n {
        let offset = i * 32;
        let slice = std::slice::from_raw_parts(data_ptr.add(offset), 32);
        preprocesses.push(shekyl_fcmp::frost_sal::FrostPreprocessResult {
            nonce_commitments: slice.to_vec(),
            addendum: Vec::new(),
        });
    }

    coord.0.collect_preprocesses(p, preprocesses).is_ok()
}

#[cfg(feature = "multisig")]
/// Get aggregated nonce sums from the coordinator.
///
/// Returns a `ShekylBuffer` with `num_inputs * 32` bytes (one 32-byte nonce sum per input).
/// Caller must free via `shekyl_buffer_free`.
///
/// # Safety
/// `coord` must be a valid handle with all preprocesses collected.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_nonce_sums(
    coord: *mut ShekylFrostCoordinator,
) -> ShekylBuffer {
    if coord.is_null() {
        return ShekylBuffer::null();
    }
    let coord = &mut *coord;
    match coord.0.nonce_sums_bytes() {
        Ok(per_input) => {
            let mut flat = Vec::new();
            for bytes in per_input {
                flat.extend_from_slice(&bytes);
            }
            ShekylBuffer::from_vec(flat)
        }
        Err(_) => ShekylBuffer::null(),
    }
}

#[cfg(feature = "multisig")]
/// Feed one participant's partial shares to the coordinator.
///
/// `data_ptr`: `num_inputs` contiguous 32-byte scalar shares.
///
/// # Safety
/// `coord` must be a valid handle. `data_ptr` must point to `num_inputs * 32` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_add_shares(
    coord: *mut ShekylFrostCoordinator,
    participant: u16,
    data_ptr: *const u8,
    num_inputs: u32,
) -> bool {
    if coord.is_null() || data_ptr.is_null() {
        return false;
    }
    let Some(p) = modular_frost::Participant::new(participant) else {
        return false;
    };
    let coord = &mut *coord;
    let n = num_inputs as usize;

    let mut shares = Vec::with_capacity(n);
    for i in 0..n {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(data_ptr.add(i * 32), buf.as_mut_ptr(), 32);
        shares.push(shekyl_fcmp::frost_sal::FrostSignShareResult { share: buf });
    }

    coord.0.collect_shares(p, shares).is_ok()
}

#[cfg(feature = "multisig")]
/// Aggregate all inputs: consume sessions + coordinator, produce FCMP++ proof.
///
/// `session_ptrs`: `num_inputs` session handles. Consumed on success.
/// `group_key_ptr`: 32-byte Ed25519T group public key.
/// `witness_ptr/witness_len`: full witness blob for `prove_with_sal`.
/// `tree_depth`: curve tree depth.
///
/// # Safety
/// All sessions and the coordinator are consumed on success and must not be used after.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_aggregate_and_prove(
    coord: *mut ShekylFrostCoordinator,
    session_ptrs: *const *mut ShekylFrostSalSession,
    num_inputs: u32,
    group_key_ptr: *const u8,
    witness_ptr: *const u8,
    witness_len: usize,
    tree_root_ptr: *const u8,
    tree_depth: u8,
) -> ShekylFcmpProveResult {
    let fail = ShekylFcmpProveResult {
        proof: ShekylBuffer::null(),
        pseudo_outs: ShekylBuffer::null(),
        success: false,
    };

    if coord.is_null()
        || session_ptrs.is_null()
        || group_key_ptr.is_null()
        || witness_ptr.is_null()
        || tree_root_ptr.is_null()
    {
        return fail;
    }

    let n = num_inputs as usize;
    if n == 0 || n > shekyl_fcmp::MAX_INPUTS {
        return fail;
    }

    let read32 = |ptr: *const u8| -> [u8; 32] {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let group_key_bytes = read32(group_key_ptr);
    let Some(witness) = (unsafe { slice_from_ptr(witness_ptr, witness_len) }) else {
        return fail;
    };

    use ciphersuite::group::GroupEncoding;
    let gk_ct =
        <dalek_ff_group::EdwardsPoint as GroupEncoding>::from_bytes(&group_key_bytes.into());
    if bool::from(gk_ct.is_none()) {
        return fail;
    }
    let group_key: dalek_ff_group::EdwardsPoint = gk_ct.unwrap();

    let Some(prove_inputs) = parse_prove_witness(witness, n) else {
        return fail;
    };

    let mut coord_box = Box::from_raw(coord);

    let mut sessions: Vec<shekyl_fcmp::frost_sal::FrostSalSession> = Vec::with_capacity(n);
    for i in 0..n {
        let ptr = *session_ptrs.add(i);
        if ptr.is_null() {
            return fail;
        }
        sessions.push(unsafe { Box::from_raw(ptr) }.0);
    }

    let original_outputs: Vec<_> = sessions.iter().map(|s| *s.original_output()).collect();
    let rerands: Vec<_> = sessions
        .iter()
        .map(|s| s.rerandomized_output().clone())
        .collect();
    let pseudo_outs_flat: Vec<u8> = sessions
        .iter()
        .flat_map(|s| s.pseudo_out().iter().copied())
        .collect();

    let leaf_chunks: Vec<_> = prove_inputs
        .iter()
        .map(|pi| shekyl_fcmp::proof::ProveInputLeafChunk {
            output_h_pqc: pi.h_pqc.clone(),
            leaf_outputs: pi.leaf_chunk_outputs.clone(),
            leaf_h_pqc: pi.leaf_chunk_h_pqc.clone(),
            c1_branch_layers: pi.c1_branch_layers.clone(),
            c2_branch_layers: pi.c2_branch_layers.clone(),
        })
        .collect();

    let Ok(sal_pairs) = coord_box.0.aggregate_all(sessions, group_key) else {
        return fail;
    };

    match shekyl_fcmp::proof::prove_with_sal(
        sal_pairs,
        &original_outputs,
        &rerands,
        &leaf_chunks,
        tree_depth,
    ) {
        Ok(result) => ShekylFcmpProveResult {
            proof: ShekylBuffer::from_vec(result.proof.data),
            pseudo_outs: ShekylBuffer::from_vec(pseudo_outs_flat),
            success: true,
        },
        Err(_) => fail,
    }
}

#[cfg(feature = "multisig")]
/// Free a FROST signing coordinator handle.
///
/// # Safety
/// `coord` must be a valid handle or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_coordinator_free(coord: *mut ShekylFrostCoordinator) {
    if !coord.is_null() {
        drop(Box::from_raw(coord));
    }
}

// ─── FROST Signer FFI ───────────────────────────────────────────────────────

#[cfg(feature = "multisig")]
/// Signer-side: preprocess a session to generate nonce commitments.
///
/// `session`: a FROST SAL session handle.
/// `keys_handle`: threshold keys handle.
///
/// Returns nonce commitments (32 bytes for SalAlgorithm) as a `ShekylBuffer`.
///
/// # Safety
/// Both handles must be valid.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_signer_preprocess(
    session: *mut ShekylFrostSalSession,
    keys_handle: *const ShekylFrostThresholdKeys,
) -> ShekylBuffer {
    if session.is_null() || keys_handle.is_null() {
        return ShekylBuffer::null();
    }
    let session = &mut *session;
    let keys_handle = &*keys_handle;

    let Ok(keys) = keys_handle.0.deserialize() else {
        return ShekylBuffer::null();
    };

    match session.0.preprocess(&keys) {
        Ok(result) => ShekylBuffer::from_vec(result.nonce_commitments),
        Err(_) => ShekylBuffer::null(),
    }
}

#[cfg(feature = "multisig")]
/// Signer-side: produce a partial signature share for one input.
///
/// `session`: FROST SAL session (must have been preprocessed).
/// `keys_handle`: threshold keys.
/// `included_ptr`: array of participant indices in the signing set.
/// `num_included`: number of participants.
/// `nonce_sums_ptr`: 32 bytes of aggregated nonce sums for this input.
///
/// Returns 32-byte partial share as a `ShekylBuffer`.
///
/// # Safety
/// All pointers must be valid. `included_ptr` must have `num_included` u16 values.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_signer_sign(
    session: *mut ShekylFrostSalSession,
    keys_handle: *const ShekylFrostThresholdKeys,
    included_ptr: *const u16,
    num_included: u32,
    nonce_sums_ptr: *const u8,
) -> ShekylBuffer {
    if session.is_null()
        || keys_handle.is_null()
        || included_ptr.is_null()
        || nonce_sums_ptr.is_null()
    {
        return ShekylBuffer::null();
    }

    let session = &mut *session;
    let keys_handle = &*keys_handle;

    let Ok(keys) = keys_handle.0.deserialize() else {
        return ShekylBuffer::null();
    };

    let included: Vec<modular_frost::Participant> = (0..num_included as usize)
        .filter_map(|i| {
            let idx = *included_ptr.add(i);
            modular_frost::Participant::new(idx)
        })
        .collect();

    let view = keys.view(included).unwrap();

    let mut nonce_sum_bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(nonce_sums_ptr, nonce_sum_bytes.as_mut_ptr(), 32);

    use ciphersuite::group::GroupEncoding;
    let nonce_sum_ct =
        <dalek_ff_group::EdwardsPoint as GroupEncoding>::from_bytes(&nonce_sum_bytes.into());
    if bool::from(nonce_sum_ct.is_none()) {
        return ShekylBuffer::null();
    }
    let nonce_sums = vec![vec![nonce_sum_ct.unwrap()]];

    match session.0.sign_share(&view, &nonce_sums) {
        Ok(result) => ShekylBuffer::from_vec(result.share.to_vec()),
        Err(_) => ShekylBuffer::null(),
    }
}

#[cfg(feature = "multisig")]
/// Free a FROST SAL session handle.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_sal_session_free(session: *mut ShekylFrostSalSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

// ─── FCMP++: FROST DKG Key Management ───────────────────────────────────────

#[cfg(feature = "multisig")]
/// Opaque handle for stored FROST threshold keys.
pub struct ShekylFrostThresholdKeys(shekyl_fcmp::frost_dkg::SerializedThresholdKeys);

#[cfg(feature = "multisig")]
/// Import FROST threshold keys from a serialized blob.
/// Returns an opaque handle, or NULL if deserialization fails.
/// The caller must later free the handle with `shekyl_frost_keys_free`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_import(
    data_ptr: *const u8,
    data_len: usize,
) -> *mut ShekylFrostThresholdKeys {
    if data_ptr.is_null() || data_len == 0 {
        return std::ptr::null_mut();
    }
    let data = std::slice::from_raw_parts(data_ptr, data_len);
    let serialized = shekyl_fcmp::frost_dkg::SerializedThresholdKeys::from_bytes(data);
    if serialized.deserialize().is_err() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(ShekylFrostThresholdKeys(serialized)))
}

#[cfg(feature = "multisig")]
/// Export FROST threshold keys as a serialized blob.
/// Returns a ShekylBuffer with the serialized data, or empty on failure.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_export(
    handle: *const ShekylFrostThresholdKeys,
) -> ShekylBuffer {
    let fail = ShekylBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
    };
    if handle.is_null() {
        return fail;
    }
    let keys = &*handle;
    let bytes = keys.0.as_bytes().to_vec();
    let len = bytes.len();
    let ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8;
    ShekylBuffer { ptr, len }
}

#[cfg(feature = "multisig")]
/// Get the 32-byte group public key from threshold keys.
/// Writes 32 bytes to `out_ptr`. Returns true on success.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_group_key(
    handle: *const ShekylFrostThresholdKeys,
    out_ptr: *mut u8,
) -> bool {
    if handle.is_null() || out_ptr.is_null() {
        return false;
    }
    let keys_handle = &*handle;
    match keys_handle.0.deserialize() {
        Ok(keys) => {
            let gk = shekyl_fcmp::frost_dkg::group_key_bytes(&keys);
            std::ptr::copy_nonoverlapping(gk.as_ptr(), out_ptr, 32);
            true
        }
        Err(_) => false,
    }
}

#[cfg(feature = "multisig")]
/// Validate that threshold keys match expected M-of-N parameters.
/// Returns true if valid.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_validate(
    handle: *const ShekylFrostThresholdKeys,
    expected_m: u16,
    expected_n: u16,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let keys_handle = &*handle;
    match keys_handle.0.deserialize() {
        Ok(keys) => shekyl_fcmp::frost_dkg::validate_keys(&keys, expected_m, expected_n).is_ok(),
        Err(_) => false,
    }
}

#[cfg(feature = "multisig")]
/// Free a FROST threshold keys handle.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_frost_keys_free(handle: *mut ShekylFrostThresholdKeys) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

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
    ml_kem_ek_ptr: *const u8,
    ml_kem_ek_len: usize,
) -> ShekylBuffer {
    if spend_key_ptr.is_null() || view_key_ptr.is_null() {
        return ShekylBuffer::null();
    }
    if ml_kem_ek_len > 0 && ml_kem_ek_ptr.is_null() {
        return ShekylBuffer::null();
    }

    let Some(net) = shekyl_address::Network::from_u8(network) else {
        return ShekylBuffer::null();
    };

    let spend_key: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(spend_key_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let view_key: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(view_key_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let ml_kem_ek = if ml_kem_ek_len == 0 {
        Vec::new()
    } else {
        let Some(slice) = (unsafe { slice_from_ptr(ml_kem_ek_ptr, ml_kem_ek_len) }) else {
            return ShekylBuffer::null();
        };
        slice.to_vec()
    };

    let addr = shekyl_address::ShekylAddress::new(net, spend_key, view_key, ml_kem_ek);

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

// ─── FCMP++: Curve Tree Hash Operations ─────────────────────────────────────

/// Incrementally grow a Selene-layer chunk hash with new children.
///
/// Used for the leaf layer (layer 0) and even-numbered internal layers.
///
/// - `existing_hash_ptr`: 32 bytes, current Selene point (use hash_init for new chunk)
/// - `offset`: position in chunk where new children start
/// - `existing_child_at_offset_ptr`: 32 bytes, old Selene scalar at offset (zero for fresh)
/// - `new_children_ptr`: `num_children * 32` bytes, new Selene scalars
/// - `out_hash_ptr`: 32 bytes output buffer for the new Selene point
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_hash_grow_selene(
    existing_hash_ptr: *const u8,
    offset: u64,
    existing_child_at_offset_ptr: *const u8,
    new_children_ptr: *const u8,
    num_children: u64,
    out_hash_ptr: *mut u8,
) -> bool {
    if existing_hash_ptr.is_null()
        || existing_child_at_offset_ptr.is_null()
        || out_hash_ptr.is_null()
        || (num_children > 0 && new_children_ptr.is_null())
    {
        return false;
    }

    let existing_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let existing_child: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_child_at_offset_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let n = usize::try_from(num_children).unwrap_or(0);
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(new_children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_grow_selene(
        &existing_hash,
        usize::try_from(offset).unwrap_or(0),
        &existing_child,
        &children,
    ) {
        Some(result) => {
            std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32);
            true
        }
        None => false,
    }
}

/// Incrementally grow a Helios-layer chunk hash with new children.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_hash_grow_helios(
    existing_hash_ptr: *const u8,
    offset: u64,
    existing_child_at_offset_ptr: *const u8,
    new_children_ptr: *const u8,
    num_children: u64,
    out_hash_ptr: *mut u8,
) -> bool {
    if existing_hash_ptr.is_null()
        || existing_child_at_offset_ptr.is_null()
        || out_hash_ptr.is_null()
        || (num_children > 0 && new_children_ptr.is_null())
    {
        return false;
    }

    let existing_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let existing_child: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_child_at_offset_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let n = usize::try_from(num_children).unwrap_or(0);
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(new_children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_grow_helios(
        &existing_hash,
        usize::try_from(offset).unwrap_or(0),
        &existing_child,
        &children,
    ) {
        Some(result) => {
            std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32);
            true
        }
        None => false,
    }
}

/// Trim children from a Selene-layer chunk hash.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_hash_trim_selene(
    existing_hash_ptr: *const u8,
    offset: u64,
    children_ptr: *const u8,
    num_children: u64,
    child_to_grow_back_ptr: *const u8,
    out_hash_ptr: *mut u8,
) -> bool {
    if existing_hash_ptr.is_null()
        || child_to_grow_back_ptr.is_null()
        || out_hash_ptr.is_null()
        || (num_children > 0 && children_ptr.is_null())
    {
        return false;
    }

    let existing_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let grow_back: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(child_to_grow_back_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let n = usize::try_from(num_children).unwrap_or(0);
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_trim_selene(
        &existing_hash,
        usize::try_from(offset).unwrap_or(0),
        &children,
        &grow_back,
    ) {
        Some(result) => {
            std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32);
            true
        }
        None => false,
    }
}

/// Trim children from a Helios-layer chunk hash.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_hash_trim_helios(
    existing_hash_ptr: *const u8,
    offset: u64,
    children_ptr: *const u8,
    num_children: u64,
    child_to_grow_back_ptr: *const u8,
    out_hash_ptr: *mut u8,
) -> bool {
    if existing_hash_ptr.is_null()
        || child_to_grow_back_ptr.is_null()
        || out_hash_ptr.is_null()
        || (num_children > 0 && children_ptr.is_null())
    {
        return false;
    }

    let existing_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let grow_back: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(child_to_grow_back_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let n = usize::try_from(num_children).unwrap_or(0);
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_trim_helios(
        &existing_hash,
        usize::try_from(offset).unwrap_or(0),
        &children,
        &grow_back,
    ) {
        Some(result) => {
            std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32);
            true
        }
        None => false,
    }
}

/// Convert a Selene point to a Helios scalar (x-coordinate extraction).
///
/// Used when propagating Selene layer hashes up to the next Helios layer.
/// Writes 32 bytes to `out_scalar_ptr`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_selene_to_helios_scalar(
    selene_point_ptr: *const u8,
    out_scalar_ptr: *mut u8,
) -> bool {
    if selene_point_ptr.is_null() || out_scalar_ptr.is_null() {
        return false;
    }
    let point: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(selene_point_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    match shekyl_fcmp::tree::selene_point_to_helios_scalar(&point) {
        Some(scalar) => {
            std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32);
            true
        }
        None => false,
    }
}

/// Convert a Helios point to a Selene scalar (x-coordinate extraction).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_helios_to_selene_scalar(
    helios_point_ptr: *const u8,
    out_scalar_ptr: *mut u8,
) -> bool {
    if helios_point_ptr.is_null() || out_scalar_ptr.is_null() {
        return false;
    }
    let point: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(helios_point_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    match shekyl_fcmp::tree::helios_point_to_selene_scalar(&point) {
        Some(scalar) => {
            std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32);
            true
        }
        None => false,
    }
}

/// Get the Selene hash initialization point (32 bytes).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_selene_hash_init(out_ptr: *mut u8) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let init = shekyl_fcmp::tree::selene_hash_init();
    std::ptr::copy_nonoverlapping(init.as_ptr(), out_ptr, 32);
    true
}

/// Get the Helios hash initialization point (32 bytes).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_helios_hash_init(out_ptr: *mut u8) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let init = shekyl_fcmp::tree::helios_hash_init();
    std::ptr::copy_nonoverlapping(init.as_ptr(), out_ptr, 32);
    true
}

/// Return the number of scalars per leaf (4 for Shekyl: O.x, I.x, C.x, H(pqc_pk)).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_scalars_per_leaf() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        shekyl_fcmp::SCALARS_PER_LEAF as u32
    }
}

/// Return the Selene-layer chunk width (branching factor = LAYER_ONE_LEN = 38).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_selene_chunk_width() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        shekyl_fcmp::SELENE_CHUNK_WIDTH as u32
    }
}

/// Return the Helios-layer chunk width (branching factor = LAYER_TWO_LEN = 18).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_helios_chunk_width() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        shekyl_fcmp::HELIOS_CHUNK_WIDTH as u32
    }
}

// ─── FCMP++: Ed25519 → Selene scalar conversion ────────────────────────────

/// Convert a compressed Ed25519 point (32 bytes) to a Selene scalar
/// (Wei25519 x-coordinate, 32 bytes).
///
/// Returns true on success (writes 32 bytes to `out_scalar_ptr`).
/// Returns false if the point cannot be decompressed or is the identity.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ed25519_to_selene_scalar(
    compressed_ptr: *const u8,
    out_scalar_ptr: *mut u8,
) -> bool {
    if compressed_ptr.is_null() || out_scalar_ptr.is_null() {
        return false;
    }

    let compressed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(compressed_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    match shekyl_fcmp::tree::ed25519_point_to_selene_scalar(&compressed) {
        Some(scalar) => {
            std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32);
            true
        }
        None => false,
    }
}

// ─── FCMP++: Leaf construction ──────────────────────────────────────────────

/// Construct a 128-byte curve tree leaf from an output public key and commitment.
///
/// - `output_key_ptr`: 32 bytes, compressed Ed25519 output public key (O)
/// - `commitment_ptr`: 32 bytes, compressed Ed25519 amount commitment (C)
/// - `h_pqc_ptr`: 32 bytes, H(pqc_pk) scalar (or 32 zero bytes if unavailable)
/// - `leaf_out_ptr`: 128 bytes output buffer for {O.x, I.x, C.x, H(pqc_pk)}
///
/// Internally computes I = Hp(O) via Monero's biased hash-to-point, then
/// extracts Wei25519 x-coordinates for O, Hp(O), C. The 4th scalar comes
/// from `h_pqc_ptr`.
///
/// Returns true on success, false on decompression failure.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_construct_curve_tree_leaf(
    output_key_ptr: *const u8,
    commitment_ptr: *const u8,
    h_pqc_ptr: *const u8,
    leaf_out_ptr: *mut u8,
) -> bool {
    if output_key_ptr.is_null()
        || commitment_ptr.is_null()
        || h_pqc_ptr.is_null()
        || leaf_out_ptr.is_null()
    {
        return false;
    }

    let output_key: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(output_key_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let commitment: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(commitment_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let h_pqc: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(h_pqc_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    match shekyl_fcmp::tree::construct_leaf(&output_key, &commitment, &h_pqc) {
        Some(leaf) => {
            std::ptr::copy_nonoverlapping(leaf.as_ptr(), leaf_out_ptr, 128);
            true
        }
        None => false,
    }
}

// ─── Transaction Builder (shekyl-tx-builder) ────────────────────────────────

/// Result of `shekyl_sign_transaction`.
///
/// On success, `success` is true and `proofs_json` contains a JSON-encoded
/// `SignedProofs` (BP+, FCMP++, ECDH, pseudo-outs, tree metadata).
/// On failure, `success` is false, `error_code` classifies the error, and
/// `error_message` contains a human-readable description.
///
/// The caller must free `proofs_json` and `error_message` via `shekyl_buffer_free`.
#[repr(C)]
pub struct ShekylSignResult {
    pub proofs_json: ShekylBuffer,
    pub success: bool,
    pub error_code: i32,
    pub error_message: ShekylBuffer,
}

impl ShekylSignResult {
    fn ok(json: Vec<u8>) -> Self {
        ShekylSignResult {
            proofs_json: ShekylBuffer::from_vec(json),
            success: true,
            error_code: 0,
            error_message: ShekylBuffer::null(),
        }
    }

    fn err(code: i32, message: String) -> Self {
        ShekylSignResult {
            proofs_json: ShekylBuffer::null(),
            success: false,
            error_code: code,
            error_message: ShekylBuffer::from_vec(message.into_bytes()),
        }
    }
}

/// Generate FCMP++ transaction proofs in a single call (BP+, FCMP++, ECDH,
/// pseudo-outs).
///
/// This replaces the old C++ → Rust → C++ → Rust round-trip through
/// `genRctFcmpPlusPlus` + `shekyl_fcmp_prove` + `shekyl_pqc_sign` with a
/// single FFI entry point.
///
/// # Parameters
///
/// - `tx_prefix_hash_ptr`: Pointer to exactly 32 bytes — the Keccak-256 hash
///   of the serialized transaction prefix.
/// - `inputs_json_ptr` / `inputs_json_len`: JSON-encoded array of `SpendInput`.
/// - `outputs_json_ptr` / `outputs_json_len`: JSON-encoded array of `OutputInfo`.
/// - `fee`: Transaction fee in atomic units.
/// - `reference_block_ptr`: Pointer to exactly 32 bytes — block hash.
/// - `tree_root_ptr`: Pointer to exactly 32 bytes — Selene curve tree root.
///   **This is NOT the block hash.** Passing the block hash produces invalid proofs.
/// - `tree_depth`: Number of tree layers (must be >= 1).
///
/// # Return value
///
/// [`ShekylSignResult`] with JSON-encoded `SignedProofs` on success, or a
/// structured error code and message on failure.
///
/// # Error codes
///
/// - `-1`: Null pointer argument
/// - `-2`: JSON parse error
/// - `-10` through `-29`: `TxBuilderError` variant (message has details)
///
/// # Memory
///
/// The caller owns both `proofs_json` and `error_message` buffers and must
/// free them via `shekyl_buffer_free`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_sign_transaction(
    tx_prefix_hash_ptr: *const u8,
    inputs_json_ptr: *const u8,
    inputs_json_len: usize,
    outputs_json_ptr: *const u8,
    outputs_json_len: usize,
    fee: u64,
    reference_block_ptr: *const u8,
    tree_root_ptr: *const u8,
    tree_depth: u8,
) -> ShekylSignResult {
    // Null checks
    if tx_prefix_hash_ptr.is_null()
        || inputs_json_ptr.is_null()
        || outputs_json_ptr.is_null()
        || reference_block_ptr.is_null()
        || tree_root_ptr.is_null()
    {
        return ShekylSignResult::err(-1, "null pointer argument".into());
    }

    let tx_prefix_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tx_prefix_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let reference_block: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(reference_block_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let Some(inputs_json) = (unsafe { slice_from_ptr(inputs_json_ptr, inputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid inputs_json pointer".into());
    };
    let Some(outputs_json) = (unsafe { slice_from_ptr(outputs_json_ptr, outputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid outputs_json pointer".into());
    };

    let inputs: Vec<shekyl_tx_builder::SpendInput> = match serde_json::from_slice(inputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("inputs JSON parse error: {e}")),
    };
    let outputs: Vec<shekyl_tx_builder::OutputInfo> = match serde_json::from_slice(outputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("outputs JSON parse error: {e}")),
    };

    let tree = shekyl_tx_builder::TreeContext {
        reference_block,
        tree_root,
        tree_depth,
    };

    match shekyl_tx_builder::sign_transaction(tx_prefix_hash, &inputs, &outputs, fee, &tree) {
        Ok(proofs) => match serde_json::to_vec(&proofs) {
            Ok(json) => ShekylSignResult::ok(json),
            Err(e) => ShekylSignResult::err(-3, format!("result serialization error: {e}")),
        },
        Err(e) => {
            let code = tx_builder_error_code(&e);
            ShekylSignResult::err(code, e.to_string())
        }
    }
}

fn tx_builder_error_code(e: &shekyl_tx_builder::TxBuilderError) -> i32 {
    use shekyl_tx_builder::TxBuilderError;
    match e {
        TxBuilderError::NoInputs => -10,
        TxBuilderError::TooManyInputs(_) => -11,
        TxBuilderError::NoOutputs => -12,
        TxBuilderError::TooManyOutputs(_) => -13,
        TxBuilderError::ZeroInputAmount { .. } => -14,
        TxBuilderError::ZeroOutputAmount { .. } => -15,
        TxBuilderError::InputAmountOverflow => -16,
        TxBuilderError::OutputAmountOverflow => -17,
        TxBuilderError::InsufficientFunds { .. } => -18,
        TxBuilderError::EmptyLeafChunk { .. } => -19,
        TxBuilderError::LeafChunkTooLarge { .. } => -20,
        TxBuilderError::ZeroTreeDepth => -21,
        TxBuilderError::BranchLayerMismatch { .. } => -22,
        TxBuilderError::InvalidCombinedSsLength { .. } => -23,
        TxBuilderError::BulletproofError(_) => -24,
        TxBuilderError::FcmpProveError(_) => -25,
        TxBuilderError::PqcSignError { .. } => -26,
        TxBuilderError::TreeDepthTooLarge(_) => -27,
    }
}

// ─── Collapsed FCMP++ Signing (PR-wallet Phase 1b) ───────────────────────────

/// Input struct for collapsed signing. C++ passes `combined_ss` + `output_index`
/// instead of `spend_key_x` / `spend_key_y`. Rust derives those internally.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FcmpSignInput {
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    ki: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_blob")]
    combined_ss: Vec<u8>,
    output_index: u64,
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    #[allow(non_snake_case)]
    hp_of_O: [u8; 32],
    amount: u64,
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    commitment_mask: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    commitment: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    output_key: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    h_pqc: [u8; 32],
    leaf_chunk: Vec<shekyl_tx_builder::LeafEntry>,
    #[serde(with = "shekyl_tx_builder::types::hex_layers")]
    c1_layers: Vec<Vec<[u8; 32]>>,
    #[serde(with = "shekyl_tx_builder::types::hex_layers")]
    c2_layers: Vec<Vec<[u8; 32]>>,
}

impl Drop for FcmpSignInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.combined_ss.zeroize();
        self.commitment_mask.zeroize();
    }
}

/// Collapsed FCMP++ signing: Rust owns all witness assembly.
///
/// C++ passes the wallet master spend key `b` (one value) plus per-input data
/// that includes `combined_ss` + `output_index`. Rust derives `ho` from HKDF,
/// computes `x = ho + b` and `y` internally, then builds `SpendInput` and
/// calls `sign_transaction`. C++ never touches `x`.
///
/// # Safety
/// - `spend_secret_ptr`, `tx_prefix_hash_ptr`: 32 bytes each.
/// - `reference_block_ptr`, `tree_root_ptr`: 32 bytes each.
/// - JSON pointers: valid for their documented lengths.
#[no_mangle]
pub unsafe extern "C" fn shekyl_sign_fcmp_transaction(
    spend_secret_ptr: *const u8,
    tx_prefix_hash_ptr: *const u8,
    inputs_json_ptr: *const u8,
    inputs_json_len: usize,
    outputs_json_ptr: *const u8,
    outputs_json_len: usize,
    fee: u64,
    reference_block_ptr: *const u8,
    tree_root_ptr: *const u8,
    tree_depth: u8,
) -> ShekylSignResult {
    if spend_secret_ptr.is_null()
        || tx_prefix_hash_ptr.is_null()
        || inputs_json_ptr.is_null()
        || outputs_json_ptr.is_null()
        || reference_block_ptr.is_null()
        || tree_root_ptr.is_null()
    {
        return ShekylSignResult::err(-1, "null pointer argument".into());
    }

    let spend_secret: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(spend_secret_ptr, buf.as_mut_ptr(), 32);
        buf
    });
    let tx_prefix_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tx_prefix_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let reference_block: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(reference_block_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let Some(inputs_json) = (unsafe { slice_from_ptr(inputs_json_ptr, inputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid inputs_json pointer".into());
    };
    let Some(outputs_json) = (unsafe { slice_from_ptr(outputs_json_ptr, outputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid outputs_json pointer".into());
    };

    let collapsed_inputs: Vec<FcmpSignInput> = match serde_json::from_slice(inputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("inputs JSON parse error: {e}")),
    };
    let outputs: Vec<shekyl_tx_builder::OutputInfo> = match serde_json::from_slice(outputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("outputs JSON parse error: {e}")),
    };

    use shekyl_crypto_pq::derivation::derive_output_secrets;
    use zeroize::Zeroize;

    let Some(mut b_scalar) = curve25519_scalar_from_bytes(&spend_secret) else {
        return ShekylSignResult::err(-5, "invalid spend secret key".into());
    };

    let mut spend_inputs: Vec<shekyl_tx_builder::SpendInput> =
        Vec::with_capacity(collapsed_inputs.len());
    for inp in &collapsed_inputs {
        if inp.combined_ss.len() != 64 {
            drop(spend_inputs);
            return ShekylSignResult::err(
                -5,
                format!(
                    "combined_ss must be 64 bytes, got {}",
                    inp.combined_ss.len()
                ),
            );
        }
        let mut ss = [0u8; 64];
        ss.copy_from_slice(&inp.combined_ss);
        let secrets = derive_output_secrets(&ss, inp.output_index);
        ss.zeroize();

        let Some(ho_scalar) = curve25519_scalar_from_bytes(&secrets.ho) else {
            drop(spend_inputs);
            return ShekylSignResult::err(-5, "invalid ho scalar".into());
        };
        let x = ho_scalar + b_scalar;
        let mut x_bytes = x.to_bytes();

        spend_inputs.push(shekyl_tx_builder::SpendInput {
            output_key: inp.output_key,
            commitment: inp.commitment,
            amount: inp.amount,
            spend_key_x: x_bytes,
            spend_key_y: secrets.y,
            commitment_mask: inp.commitment_mask,
            h_pqc: inp.hp_of_O,
            combined_ss: inp.combined_ss.clone(),
            output_index: inp.output_index,
            leaf_chunk: inp.leaf_chunk.clone(),
            c1_layers: inp.c1_layers.clone(),
            c2_layers: inp.c2_layers.clone(),
        });

        x_bytes.zeroize();
    }

    // C++ wallet passes LMDB depth; convert to upstream layers (depth + 1).
    let layers = tree_depth.saturating_add(1);
    let tree = shekyl_tx_builder::TreeContext {
        reference_block,
        tree_root,
        tree_depth: layers,
    };

    let result = match shekyl_tx_builder::sign_transaction(
        tx_prefix_hash,
        &spend_inputs,
        &outputs,
        fee,
        &tree,
    ) {
        Ok(proofs) => match serde_json::to_vec(&proofs) {
            Ok(json) => ShekylSignResult::ok(json),
            Err(e) => ShekylSignResult::err(-3, format!("result serialization error: {e}")),
        },
        Err(e) => {
            let code = tx_builder_error_code(&e);
            ShekylSignResult::err(code, e.to_string())
        }
    };

    drop(spend_inputs);
    b_scalar.zeroize();
    result
}

fn curve25519_scalar_from_bytes(bytes: &[u8; 32]) -> Option<curve25519_dalek::Scalar> {
    Option::from(curve25519_dalek::Scalar::from_canonical_bytes(*bytes))
}

// ─── Output Construction / Scanning / PQC Signing ────────────────────────────

/// Build the 256-byte witness header from a typed struct.
///
/// # Safety
/// - `input` must point to a valid `ProveInputFields`.
/// - `out_buf` must point to at least 256 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_build_witness_header(
    input: *const ProveInputFields,
    out_buf: *mut u8,
) -> bool {
    if input.is_null() || out_buf.is_null() {
        return false;
    }
    let inp = &*input;
    let buf = std::slice::from_raw_parts_mut(out_buf, SHEKYL_PROVE_WITNESS_HEADER_BYTES);
    buf[0..32].copy_from_slice(&inp.output_key);
    buf[32..64].copy_from_slice(&inp.key_image_gen);
    buf[64..96].copy_from_slice(&inp.commitment);
    buf[96..128].copy_from_slice(&inp.h_pqc);
    buf[128..160].copy_from_slice(&inp.spend_key_x);
    buf[160..192].copy_from_slice(&inp.spend_key_y);
    buf[192..224].copy_from_slice(&inp.commitment_mask);
    buf[224..256].copy_from_slice(&inp.pseudo_out_blind);
    true
}

/// Construct a two-component output via the unified HKDF path.
///
/// # Safety
/// - `tx_key_secret_ptr` must point to 32 bytes (sender's tx secret key).
/// - `x25519_pk` must point to 32 bytes.
/// - `ml_kem_ek` must point to `ml_kem_ek_len` bytes (expected: 1184).
/// - `spend_key` must point to 32 bytes (compressed Edwards point B).
/// - The returned `ShekylOutputData` owns its buffer fields; free them
///   with `shekyl_buffer_free` when done.
#[no_mangle]
pub unsafe extern "C" fn shekyl_construct_output(
    tx_key_secret_ptr: *const u8,
    x25519_pk: *const u8,
    ml_kem_ek: *const u8,
    ml_kem_ek_len: usize,
    spend_key: *const u8,
    amount: u64,
    output_index: u64,
) -> ShekylOutputData {
    let fail = ShekylOutputData {
        output_key: [0; 32],
        commitment: [0; 32],
        enc_amount: [0; 8],
        amount_tag: 0,
        view_tag_x25519: 0,
        kem_ciphertext_x25519: [0; 32],
        kem_ciphertext_ml_kem: ShekylBuffer::null(),
        pqc_public_key: ShekylBuffer::null(),
        h_pqc: [0; 32],
        y: [0; 32],
        z: [0; 32],
        k_amount: [0; 32],
        success: false,
    };

    let Some(tx_key) = arr32_from_ptr(tx_key_secret_ptr) else {
        return fail;
    };
    let Some(x_pk) = arr32_from_ptr(x25519_pk) else {
        return fail;
    };
    let Some(sk) = arr32_from_ptr(spend_key) else {
        return fail;
    };
    let Some(ek) = (unsafe { slice_from_ptr(ml_kem_ek, ml_kem_ek_len) }) else {
        return fail;
    };

    use shekyl_crypto_pq::output::construct_output;
    match construct_output(&tx_key, &x_pk, ek, &sk, amount, output_index) {
        Ok(out) => ShekylOutputData {
            output_key: out.output_key,
            commitment: out.commitment,
            enc_amount: out.enc_amount,
            amount_tag: out.amount_tag,
            view_tag_x25519: out.view_tag_x25519,
            kem_ciphertext_x25519: out.kem_ciphertext_x25519,
            kem_ciphertext_ml_kem: ShekylBuffer::from_vec(out.kem_ciphertext_ml_kem.clone()),
            pqc_public_key: ShekylBuffer::from_vec(out.pqc_public_key.clone()),
            h_pqc: out.h_pqc,
            y: out.y,
            z: out.z,
            k_amount: out.k_amount,
            success: true,
            // out drops here — ZeroizeOnDrop wipes y, z, k_amount
        },
        Err(_) => fail,
    }
}

/// Free a ShekylOutputData's heap-allocated buffer fields.
///
/// # Safety
/// Only call once per ShekylOutputData returned from `shekyl_construct_output`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_output_data_free(data: *mut ShekylOutputData) {
    if data.is_null() {
        return;
    }
    let d = &mut *data;
    // Wipe secret fields
    use zeroize::Zeroize;
    d.y.zeroize();
    d.z.zeroize();
    d.k_amount.zeroize();
    if !d.kem_ciphertext_ml_kem.ptr.is_null() {
        shekyl_buffer_free(d.kem_ciphertext_ml_kem.ptr, d.kem_ciphertext_ml_kem.len);
        d.kem_ciphertext_ml_kem = ShekylBuffer::null();
    }
    if !d.pqc_public_key.ptr.is_null() {
        shekyl_buffer_free(d.pqc_public_key.ptr, d.pqc_public_key.len);
        d.pqc_public_key = ShekylBuffer::null();
    }
}

/// Scan an output: KEM decap + HKDF derivation + verification.
///
/// # Safety
/// - Pointer parameters must be valid and sized as documented.
/// - `y_out`, `z_out`, `k_amount_out` must each point to 32 writable bytes
///   (caller-owned secret buffers; caller is responsible for wiping).
#[no_mangle]
pub unsafe extern "C" fn shekyl_scan_output(
    x25519_sk: *const u8,
    ml_kem_dk: *const u8,
    ml_kem_dk_len: usize,
    kem_ct_x25519: *const u8,
    kem_ct_ml_kem: *const u8,
    kem_ct_ml_kem_len: usize,
    output_key: *const u8,
    commitment: *const u8,
    enc_amount: *const u8,
    amount_tag_on_chain: u8,
    view_tag_on_chain: u8,
    spend_key: *const u8,
    output_index: u64,
    y_out: *mut u8,
    z_out: *mut u8,
    k_amount_out: *mut u8,
    amount_out: *mut u64,
    pqc_pk_out: *mut ShekylBuffer,
    pqc_sk_out: *mut ShekylBuffer,
    h_pqc_out: *mut [u8; 32],
) -> bool {
    let Some(x_sk) = arr32_from_ptr(x25519_sk) else {
        return false;
    };
    let Some(dk) = (unsafe { slice_from_ptr(ml_kem_dk, ml_kem_dk_len) }) else {
        return false;
    };
    let Some(ct_x) = arr32_from_ptr(kem_ct_x25519) else {
        return false;
    };
    let Some(ct_ml) = (unsafe { slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) }) else {
        return false;
    };
    let Some(o) = arr32_from_ptr(output_key) else {
        return false;
    };
    let Some(c) = arr32_from_ptr(commitment) else {
        return false;
    };
    let ea = match unsafe { slice_from_ptr(enc_amount, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let Some(sk) = arr32_from_ptr(spend_key) else {
        return false;
    };

    if y_out.is_null()
        || z_out.is_null()
        || k_amount_out.is_null()
        || amount_out.is_null()
        || pqc_pk_out.is_null()
        || pqc_sk_out.is_null()
        || h_pqc_out.is_null()
    {
        return false;
    }

    use shekyl_crypto_pq::output::scan_output;
    match scan_output(
        &x_sk,
        dk,
        &ct_x,
        ct_ml,
        &o,
        &c,
        &ea,
        amount_tag_on_chain,
        view_tag_on_chain,
        &sk,
        output_index,
    ) {
        Ok(scanned) => {
            std::ptr::copy_nonoverlapping(scanned.y.as_ptr(), y_out, 32);
            std::ptr::copy_nonoverlapping(scanned.z.as_ptr(), z_out, 32);
            std::ptr::copy_nonoverlapping(scanned.k_amount.as_ptr(), k_amount_out, 32);
            *amount_out = scanned.amount;
            *pqc_pk_out = ShekylBuffer::from_vec(scanned.pqc_public_key.clone());
            *pqc_sk_out = ShekylBuffer::from_vec(scanned.pqc_secret_key.clone());
            *h_pqc_out = scanned.h_pqc;
            // scanned drops here — ZeroizeOnDrop wipes y, z, k_amount, pqc_secret_key
            true
        }
        Err(_) => false,
    }
}

/// Scan an output recovering the spend key B' = O - ho*G - y*T.
///
/// Unlike `shekyl_scan_output`, this function does NOT take a `spend_key`
/// parameter. Instead, it returns the recovered spend key so the caller
/// can look it up in a subaddress table.
///
/// # Safety
/// - Same pointer requirements as `shekyl_scan_output`.
/// - `recovered_spend_key_out`, `ho_out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_scan_output_recover(
    x25519_sk: *const u8,
    ml_kem_dk: *const u8,
    ml_kem_dk_len: usize,
    kem_ct_x25519: *const u8,
    kem_ct_ml_kem: *const u8,
    kem_ct_ml_kem_len: usize,
    output_key: *const u8,
    commitment: *const u8,
    enc_amount: *const u8,
    amount_tag_on_chain: u8,
    view_tag_on_chain: u8,
    output_index: u64,
    ho_out: *mut u8,
    y_out: *mut u8,
    z_out: *mut u8,
    k_amount_out: *mut u8,
    amount_out: *mut u64,
    recovered_spend_key_out: *mut u8,
    pqc_pk_out: *mut ShekylBuffer,
    pqc_sk_out: *mut ShekylBuffer,
    h_pqc_out: *mut [u8; 32],
) -> bool {
    let Some(x_sk) = arr32_from_ptr(x25519_sk) else {
        return false;
    };
    let Some(dk) = (unsafe { slice_from_ptr(ml_kem_dk, ml_kem_dk_len) }) else {
        return false;
    };
    let Some(ct_x) = arr32_from_ptr(kem_ct_x25519) else {
        return false;
    };
    let Some(ct_ml) = (unsafe { slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) }) else {
        return false;
    };
    let Some(o) = arr32_from_ptr(output_key) else {
        return false;
    };
    let Some(c) = arr32_from_ptr(commitment) else {
        return false;
    };
    let ea = match unsafe { slice_from_ptr(enc_amount, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };

    if ho_out.is_null()
        || y_out.is_null()
        || z_out.is_null()
        || k_amount_out.is_null()
        || amount_out.is_null()
        || recovered_spend_key_out.is_null()
        || pqc_pk_out.is_null()
        || pqc_sk_out.is_null()
        || h_pqc_out.is_null()
    {
        return false;
    }

    use shekyl_crypto_pq::output::scan_output_recover;
    match scan_output_recover(
        &x_sk,
        dk,
        &ct_x,
        ct_ml,
        &o,
        &c,
        &ea,
        amount_tag_on_chain,
        view_tag_on_chain,
        output_index,
    ) {
        Ok(recovered) => {
            std::ptr::copy_nonoverlapping(recovered.ho.as_ptr(), ho_out, 32);
            std::ptr::copy_nonoverlapping(recovered.y.as_ptr(), y_out, 32);
            std::ptr::copy_nonoverlapping(recovered.z.as_ptr(), z_out, 32);
            std::ptr::copy_nonoverlapping(recovered.k_amount.as_ptr(), k_amount_out, 32);
            *amount_out = recovered.amount;
            std::ptr::copy_nonoverlapping(
                recovered.recovered_spend_key.as_ptr(),
                recovered_spend_key_out,
                32,
            );
            *pqc_pk_out = ShekylBuffer::from_vec(recovered.pqc_public_key.clone());
            *pqc_sk_out = ShekylBuffer::from_vec(recovered.pqc_secret_key.clone());
            *h_pqc_out = recovered.h_pqc;
            true
        }
        Err(_) => false,
    }
}

/// Sign a message using the HKDF-derived hybrid PQC keypair for an output.
/// ML-DSA secret key never crosses this boundary — it lives and dies in Rust.
///
/// # Safety
/// - `combined_ss` must point to 64 bytes.
/// - `message` must point to `message_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_sign_pqc_auth(
    combined_ss: *const u8,
    output_index: u64,
    message: *const u8,
    message_len: usize,
) -> ShekylPqcAuthResult {
    let fail = ShekylPqcAuthResult {
        hybrid_public_key: ShekylBuffer::null(),
        signature: ShekylBuffer::null(),
        success: false,
    };

    let ss = match unsafe { slice_from_ptr(combined_ss, 64) } {
        Some(v) => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(v);
            arr
        }
        None => return fail,
    };
    let Some(msg) = (unsafe { slice_from_ptr(message, message_len) }) else {
        return fail;
    };

    use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
    match sign_pqc_auth_for_output(&ss, output_index, msg) {
        Ok(auth) => ShekylPqcAuthResult {
            hybrid_public_key: ShekylBuffer::from_vec(auth.hybrid_public_key),
            signature: ShekylBuffer::from_vec(auth.signature),
            success: true,
        },
        Err(_) => fail,
    }
}

/// Free a ShekylPqcAuthResult's heap-allocated fields.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pqc_auth_result_free(result: *mut ShekylPqcAuthResult) {
    if result.is_null() {
        return;
    }
    let r = &mut *result;
    if !r.hybrid_public_key.ptr.is_null() {
        shekyl_buffer_free(r.hybrid_public_key.ptr, r.hybrid_public_key.len);
        r.hybrid_public_key = ShekylBuffer::null();
    }
    if !r.signature.ptr.is_null() {
        shekyl_buffer_free(r.signature.ptr, r.signature.len);
        r.signature = ShekylBuffer::null();
    }
}

// ─── PR-wallet Phase 1b: Merged scan, key image, proofs, cache crypto ────────

/// Merged scan + key image computation.
///
/// Scans an output (KEM decap, HKDF derivation, amount decryption) and computes
/// the key image in a single call. All secret outputs are written directly into
/// caller-provided destination addresses (transfer_details fields). No
/// intermediate scratch buffers are created on the C++ stack.
///
/// # Safety
/// - All pointer parameters must be valid for reads/writes of their documented sizes.
/// - `ho_out`, `y_out`, `z_out`, `k_amount_out`: 32 writable bytes each.
/// - `key_image_out`: 32 writable bytes.
/// - `recovered_spend_key_out`: 32 writable bytes.
/// - `combined_ss_out`: 64 writable bytes if `persist_combined_ss` is true, or nullptr.
/// - `spend_secret_key`: 32 bytes (wallet master spend key `b`).
/// - `hp_of_O`: 32 bytes (hash_to_ec of the output key, precomputed by C++).
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn shekyl_scan_and_recover(
    x25519_sk: *const u8,
    ml_kem_dk: *const u8,
    ml_kem_dk_len: usize,
    kem_ct_x25519: *const u8,
    kem_ct_ml_kem: *const u8,
    kem_ct_ml_kem_len: usize,
    output_key: *const u8,
    commitment: *const u8,
    enc_amount: *const u8,
    amount_tag_on_chain: u8,
    view_tag_on_chain: u8,
    output_index: u64,
    spend_secret_key: *const u8,
    hp_of_O: *const u8,
    persist_combined_ss: bool,
    ho_out: *mut u8,
    y_out: *mut u8,
    z_out: *mut u8,
    k_amount_out: *mut u8,
    amount_out: *mut u64,
    recovered_spend_key_out: *mut u8,
    key_image_out: *mut u8,
    combined_ss_out: *mut u8,
    pqc_pk_out: *mut ShekylBuffer,
    pqc_sk_out: *mut ShekylBuffer,
    h_pqc_out: *mut [u8; 32],
) -> bool {
    let Some(x_sk) = arr32_from_ptr(x25519_sk) else {
        return false;
    };
    let Some(dk) = (unsafe { slice_from_ptr(ml_kem_dk, ml_kem_dk_len) }) else {
        return false;
    };
    let Some(ct_x) = arr32_from_ptr(kem_ct_x25519) else {
        return false;
    };
    let Some(ct_ml) = (unsafe { slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) }) else {
        return false;
    };
    let Some(o) = arr32_from_ptr(output_key) else {
        return false;
    };
    let Some(c) = arr32_from_ptr(commitment) else {
        return false;
    };
    let ea = match unsafe { slice_from_ptr(enc_amount, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let have_spend_key = !spend_secret_key.is_null() && !hp_of_O.is_null();

    if ho_out.is_null()
        || y_out.is_null()
        || z_out.is_null()
        || k_amount_out.is_null()
        || amount_out.is_null()
        || recovered_spend_key_out.is_null()
        || key_image_out.is_null()
        || pqc_pk_out.is_null()
        || pqc_sk_out.is_null()
        || h_pqc_out.is_null()
    {
        return false;
    }
    if persist_combined_ss && combined_ss_out.is_null() {
        return false;
    }

    use shekyl_crypto_pq::output::{compute_output_key_image_from_ho, scan_output_recover};

    let Ok(recovered) = scan_output_recover(
        &x_sk,
        dk,
        &ct_x,
        ct_ml,
        &o,
        &c,
        &ea,
        amount_tag_on_chain,
        view_tag_on_chain,
        output_index,
    ) else {
        return false;
    };

    std::ptr::copy_nonoverlapping(recovered.ho.as_ptr(), ho_out, 32);
    std::ptr::copy_nonoverlapping(recovered.y.as_ptr(), y_out, 32);
    std::ptr::copy_nonoverlapping(recovered.z.as_ptr(), z_out, 32);
    std::ptr::copy_nonoverlapping(recovered.k_amount.as_ptr(), k_amount_out, 32);
    *amount_out = recovered.amount;
    std::ptr::copy_nonoverlapping(
        recovered.recovered_spend_key.as_ptr(),
        recovered_spend_key_out,
        32,
    );
    *pqc_pk_out = ShekylBuffer::from_vec(recovered.pqc_public_key.clone());
    *pqc_sk_out = ShekylBuffer::from_vec(recovered.pqc_secret_key.clone());
    *h_pqc_out = recovered.h_pqc;

    if have_spend_key {
        let b_key = &*(spend_secret_key as *const [u8; 32]);
        let hp = &*(hp_of_O as *const [u8; 32]);
        let Ok(ki_result) = compute_output_key_image_from_ho(&recovered.ho, b_key, hp) else {
            return false;
        };
        std::ptr::copy_nonoverlapping(ki_result.key_image.as_ptr(), key_image_out, 32);
    } else {
        std::ptr::write_bytes(key_image_out, 0, 32);
    }

    if persist_combined_ss {
        std::ptr::copy_nonoverlapping(recovered.combined_ss.as_ptr(), combined_ss_out, 64);
    }

    true
}

/// Compute key image from persisted `combined_ss` + `output_index`.
///
/// Derives `ho` from HKDF, computes `KI = (ho + b) * Hp(O)`.
/// Used at stake claim (1 site).
///
/// # Safety
/// - `combined_ss`: 64 bytes. `spend_secret_key`, `hp_of_O`, `out_ki`: 32 bytes each.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn shekyl_compute_output_key_image(
    combined_ss: *const u8,
    output_index: u64,
    spend_secret_key: *const u8,
    hp_of_O: *const u8,
    out_ki: *mut u8,
) -> bool {
    let ss = match unsafe { slice_from_ptr(combined_ss, 64) } {
        Some(v) => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let Some(b) = arr32_from_ptr(spend_secret_key) else {
        return false;
    };
    let Some(hp) = arr32_from_ptr(hp_of_O) else {
        return false;
    };
    if out_ki.is_null() {
        return false;
    }

    match shekyl_crypto_pq::output::compute_output_key_image(&ss, output_index, &b, &hp) {
        Ok(result) => {
            std::ptr::copy_nonoverlapping(result.key_image.as_ptr(), out_ki, 32);
            true
        }
        Err(_) => false,
    }
}

/// Compute key image from pre-derived `ho` scalar.
///
/// Computes `KI = (ho + b) * Hp(O)`.
/// Used at `tx_source_entry` boundary (1 site).
///
/// # Safety
/// - `ho`, `spend_secret_key`, `hp_of_O`, `out_ki`: 32 bytes each.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn shekyl_compute_output_key_image_from_ho(
    ho: *const u8,
    spend_secret_key: *const u8,
    hp_of_O: *const u8,
    out_ki: *mut u8,
) -> bool {
    let Some(ho_arr) = arr32_from_ptr(ho) else {
        return false;
    };
    let Some(b) = arr32_from_ptr(spend_secret_key) else {
        return false;
    };
    let Some(hp) = arr32_from_ptr(hp_of_O) else {
        return false;
    };
    if out_ki.is_null() {
        return false;
    }

    match shekyl_crypto_pq::output::compute_output_key_image_from_ho(&ho_arr, &b, &hp) {
        Ok(result) => {
            std::ptr::copy_nonoverlapping(result.key_image.as_ptr(), out_ki, 32);
            true
        }
        Err(_) => false,
    }
}

/// Derive the ProofSecrets projection from `combined_ss`.
///
/// Writes `ho`, `y`, `z`, `k_amount` directly to caller-provided destination
/// addresses (no scratch buffers).
///
/// # Safety
/// - `combined_ss`: 64 bytes.
/// - `out_ho`, `out_y`, `out_z`, `out_k_amount`: 32 writable bytes each.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_proof_secrets(
    combined_ss: *const u8,
    output_index: u64,
    out_ho: *mut u8,
    out_y: *mut u8,
    out_z: *mut u8,
    out_k_amount: *mut u8,
) -> bool {
    let ss = match unsafe { slice_from_ptr(combined_ss, 64) } {
        Some(v) => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    if out_ho.is_null() || out_y.is_null() || out_z.is_null() || out_k_amount.is_null() {
        return false;
    }

    let secrets = shekyl_crypto_pq::output::derive_proof_secrets(&ss, output_index);
    std::ptr::copy_nonoverlapping(secrets.ho.as_ptr(), out_ho, 32);
    std::ptr::copy_nonoverlapping(secrets.y.as_ptr(), out_y, 32);
    std::ptr::copy_nonoverlapping(secrets.z.as_ptr(), out_z, 32);
    std::ptr::copy_nonoverlapping(secrets.k_amount.as_ptr(), out_k_amount, 32);
    true
}

// ─── Engine cache AEAD encryption ────────────────────────────────────────────

/// Encrypt wallet cache plaintext with XChaCha20-Poly1305 AEAD.
///
/// `cache_format_version` is bound into the Poly1305 AAD. Version changes
/// invalidate existing ciphertext. The output format is:
/// `[version_byte][nonce(24)][ciphertext][tag(16)]`.
///
/// # Safety
/// - `plaintext`: `plaintext_len` readable bytes.
/// - `password_derived_key`: 32 bytes.
/// - `out_buf`: pointer to writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_encrypt_wallet_cache(
    plaintext: *const u8,
    plaintext_len: usize,
    cache_format_version: u8,
    password_derived_key: *const u8,
    out_buf: *mut ShekylBuffer,
) -> bool {
    let Some(pt) = (unsafe { slice_from_ptr(plaintext, plaintext_len) }) else {
        return false;
    };
    let Some(key) = arr32_from_ptr(password_derived_key) else {
        return false;
    };
    if out_buf.is_null() {
        return false;
    }

    let aad = [cache_format_version];
    let encrypted = shekyl_chacha::encrypt_with_aad(&key, &aad, pt);

    let mut output = Vec::with_capacity(1 + encrypted.len());
    output.push(cache_format_version);
    output.extend_from_slice(&encrypted);

    *out_buf = ShekylBuffer::from_vec(output);
    true
}

/// Decrypt wallet cache ciphertext with XChaCha20-Poly1305 AEAD.
///
/// Returns 0 on success, negative on error:
///   -1: version mismatch (first byte != expected_version)
///   -2: authentication failure (AAD/tag mismatch)
///   -3: invalid format (too short)
///   -4: null pointer argument
///
/// # Safety
/// - `ciphertext`: `ciphertext_len` readable bytes.
/// - `password_derived_key`: 32 bytes.
/// - `out_buf`: pointer to writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_decrypt_wallet_cache(
    ciphertext: *const u8,
    ciphertext_len: usize,
    expected_version: u8,
    password_derived_key: *const u8,
    out_buf: *mut ShekylBuffer,
) -> i32 {
    if ciphertext.is_null() || password_derived_key.is_null() || out_buf.is_null() {
        return -4;
    }
    let Some(ct) = (unsafe { slice_from_ptr(ciphertext, ciphertext_len) }) else {
        return -4;
    };
    let Some(key) = arr32_from_ptr(password_derived_key) else {
        return -4;
    };

    if ct.is_empty() {
        return -3;
    }

    let on_disk_version = ct[0];
    if on_disk_version != expected_version {
        return -1;
    }

    let aead_data = &ct[1..];
    let aad = [on_disk_version];

    match shekyl_chacha::decrypt_with_aad(&key, &aad, aead_data) {
        Ok(plaintext) => {
            *out_buf = ShekylBuffer::from_vec(plaintext);
            0
        }
        Err(_) => -2,
    }
}

// ─── Engine proof FFI exports ────────────────────────────────────────────────
//
// These FFI wrappers delegate to shekyl_proofs::{tx_proof, reserve_proof}.
// The C++ caller gathers wallet/blockchain data into flat byte arrays; Rust
// handles all cryptographic proof generation and verification.

/// Generate outbound transaction proof (sender proves payment).
///
/// Rust re-derives `combined_ss` from `tx_key_secret` + recipient KEM keys,
/// projects to `ProofSecrets`, and builds the Schnorr proof.
///
/// # Safety
/// - `tx_key_secret`, `txid`: 32 bytes each.
/// - `address`: `address_len` bytes.
/// - `message`: `message_len` bytes (may be 0).
/// - `recipient_x25519_pk`: 32 bytes.
/// - `recipient_ml_kem_ek`: `ml_kem_ek_len` bytes.
/// - `output_indices`: `output_count` u64 values.
/// - `proof_out`: writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generate_tx_proof_outbound(
    tx_key_secret: *const u8,
    txid: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    recipient_x25519_pk: *const u8,
    recipient_ml_kem_ek: *const u8,
    ml_kem_ek_len: usize,
    output_indices: *const u64,
    output_count: u32,
    proof_out: *mut ShekylBuffer,
) -> bool {
    let Some(tx_key) = arr32_from_ptr(tx_key_secret) else {
        return false;
    };
    let Some(tx_id) = arr32_from_ptr(txid) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let Some(x25519_pk) = arr32_from_ptr(recipient_x25519_pk) else {
        return false;
    };
    let Some(ml_kem_ek) = (unsafe { slice_from_ptr(recipient_ml_kem_ek, ml_kem_ek_len) }) else {
        return false;
    };
    if proof_out.is_null() || output_count == 0 || output_indices.is_null() {
        return false;
    }

    let indices = std::slice::from_raw_parts(output_indices, output_count as usize);

    match shekyl_proofs::tx_proof::generate_outbound_proof(
        &tx_key, &tx_id, addr, msg, &x25519_pk, ml_kem_ek, indices,
    ) {
        Ok(proof_bytes) => {
            *proof_out = ShekylBuffer::from_vec(proof_bytes);
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Verify outbound transaction proof.
///
/// On success, writes verified per-output amounts to `amounts_out`.
///
/// # Safety
/// - `proof_bytes`: `proof_len` bytes.
/// - `txid`, `recipient_spend_pubkey`, `recipient_x25519_pk`: 32 bytes each.
/// - `address`: `address_len` bytes.
/// - `recipient_ml_kem_ek`: `ml_kem_ek_len` bytes.
/// - `output_keys`, `commitments`, `x25519_eph_pks`: `output_count * 32` each.
/// - `enc_amounts`: `output_count * 8` bytes.
/// - `ml_kem_cts`: `ml_kem_cts_len` bytes total (contiguous, evenly divisible).
/// - `amounts_out`: `output_count` u64 values.
#[no_mangle]
pub unsafe extern "C" fn shekyl_verify_tx_proof_outbound(
    proof_bytes: *const u8,
    proof_len: usize,
    txid: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    recipient_spend_pubkey: *const u8,
    recipient_x25519_pk: *const u8,
    recipient_ml_kem_ek: *const u8,
    ml_kem_ek_len: usize,
    output_keys: *const u8,
    commitments: *const u8,
    enc_amounts: *const u8,
    x25519_eph_pks: *const u8,
    ml_kem_cts: *const u8,
    ml_kem_cts_len: usize,
    output_count: u32,
    amounts_out: *mut u64,
) -> bool {
    let Some(proof) = (unsafe { slice_from_ptr(proof_bytes, proof_len) }) else {
        return false;
    };
    let Some(tx_id) = arr32_from_ptr(txid) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let Some(spend_pk) = arr32_from_ptr(recipient_spend_pubkey) else {
        return false;
    };
    let Some(x25519_pk) = arr32_from_ptr(recipient_x25519_pk) else {
        return false;
    };
    let Some(ml_ek) = (unsafe { slice_from_ptr(recipient_ml_kem_ek, ml_kem_ek_len) }) else {
        return false;
    };
    let n = output_count as usize;
    if amounts_out.is_null() || n == 0 {
        return false;
    }

    let Some(okeys) = (unsafe { slice_from_ptr(output_keys, n * 32) }) else {
        return false;
    };
    let Some(comms) = (unsafe { slice_from_ptr(commitments, n * 32) }) else {
        return false;
    };
    let Some(eamts) = (unsafe { slice_from_ptr(enc_amounts, n * 8) }) else {
        return false;
    };
    let Some(eph_pks) = (unsafe { slice_from_ptr(x25519_eph_pks, n * 32) }) else {
        return false;
    };
    let Some(ml_cts) = (unsafe { slice_from_ptr(ml_kem_cts, ml_kem_cts_len) }) else {
        return false;
    };

    if !ml_kem_cts_len.is_multiple_of(n) {
        return false;
    }
    let ct_size = ml_kem_cts_len / n;

    let on_chain: Vec<shekyl_proofs::tx_proof::OnChainOutput> = (0..n)
        .map(|i| {
            let mut ok = [0u8; 32];
            let mut cm = [0u8; 32];
            let mut ea = [0u8; 8];
            let mut ep = [0u8; 32];
            ok.copy_from_slice(&okeys[i * 32..(i + 1) * 32]);
            cm.copy_from_slice(&comms[i * 32..(i + 1) * 32]);
            ea.copy_from_slice(&eamts[i * 8..(i + 1) * 8]);
            ep.copy_from_slice(&eph_pks[i * 32..(i + 1) * 32]);
            shekyl_proofs::tx_proof::OnChainOutput {
                output_key: ok,
                commitment: cm,
                enc_amount: ea,
                x25519_eph_pk: ep,
                ml_kem_ct: ml_cts[i * ct_size..(i + 1) * ct_size].to_vec(),
            }
        })
        .collect();

    match shekyl_proofs::tx_proof::verify_outbound_proof(
        proof, &tx_id, addr, msg, &spend_pk, &x25519_pk, ml_ek, &on_chain,
    ) {
        Ok(verified) => {
            let out_slice = std::slice::from_raw_parts_mut(amounts_out, n);
            for v in &verified {
                if v.output_index < n {
                    out_slice[v.output_index] = v.amount;
                }
            }
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Generate inbound transaction proof (recipient proves receipt).
///
/// # Safety
/// - `view_secret_key`, `txid`: 32 bytes each.
/// - `address`: `address_len` bytes.
/// - `proof_secrets`: `output_count * 128` bytes (ho[32]+y[32]+z[32]+k_amount[32]).
/// - `proof_out`: writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generate_tx_proof_inbound(
    view_secret_key: *const u8,
    txid: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    proof_secrets_ptr: *const u8,
    output_count: u32,
    proof_out: *mut ShekylBuffer,
) -> bool {
    let Some(vsk) = arr32_from_ptr(view_secret_key) else {
        return false;
    };
    let Some(tx_id) = arr32_from_ptr(txid) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let n = output_count as usize;
    if proof_out.is_null() || n == 0 {
        return false;
    }

    let Some(ps_bytes) = (unsafe { slice_from_ptr(proof_secrets_ptr, n * 128) }) else {
        return false;
    };
    let secrets: Vec<shekyl_crypto_pq::output::ProofSecrets> = (0..n)
        .map(|i| {
            let base = i * 128;
            let mut ho = [0u8; 32];
            let mut y = [0u8; 32];
            let mut z = [0u8; 32];
            let mut k_amount = [0u8; 32];
            ho.copy_from_slice(&ps_bytes[base..base + 32]);
            y.copy_from_slice(&ps_bytes[base + 32..base + 64]);
            z.copy_from_slice(&ps_bytes[base + 64..base + 96]);
            k_amount.copy_from_slice(&ps_bytes[base + 96..base + 128]);
            shekyl_crypto_pq::output::ProofSecrets { ho, y, z, k_amount }
        })
        .collect();

    match shekyl_proofs::tx_proof::generate_inbound_proof(&vsk, &tx_id, addr, msg, &secrets) {
        Ok(proof_bytes) => {
            *proof_out = ShekylBuffer::from_vec(proof_bytes);
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Verify inbound transaction proof.
///
/// # Safety
/// - `proof_bytes`: `proof_len` bytes.
/// - `txid`, `view_public_key`, `recipient_spend_pubkey`: 32 bytes each.
/// - `output_keys`, `commitments`, `x25519_eph_pks`: `output_count * 32` each.
/// - `enc_amounts`: `output_count * 8` bytes.
/// - `ml_kem_cts`: `ml_kem_cts_len` bytes total.
/// - `amounts_out`: `output_count` u64 values.
#[no_mangle]
pub unsafe extern "C" fn shekyl_verify_tx_proof_inbound(
    proof_bytes: *const u8,
    proof_len: usize,
    txid: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    view_public_key: *const u8,
    recipient_spend_pubkey: *const u8,
    output_keys: *const u8,
    commitments: *const u8,
    enc_amounts: *const u8,
    x25519_eph_pks: *const u8,
    ml_kem_cts: *const u8,
    ml_kem_cts_len: usize,
    output_count: u32,
    amounts_out: *mut u64,
) -> bool {
    let Some(proof) = (unsafe { slice_from_ptr(proof_bytes, proof_len) }) else {
        return false;
    };
    let Some(tx_id) = arr32_from_ptr(txid) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let Some(vpk) = arr32_from_ptr(view_public_key) else {
        return false;
    };
    let Some(spend_pk) = arr32_from_ptr(recipient_spend_pubkey) else {
        return false;
    };
    let n = output_count as usize;
    if amounts_out.is_null() || n == 0 {
        return false;
    }

    let Some(okeys) = (unsafe { slice_from_ptr(output_keys, n * 32) }) else {
        return false;
    };
    let Some(comms) = (unsafe { slice_from_ptr(commitments, n * 32) }) else {
        return false;
    };
    let Some(eamts) = (unsafe { slice_from_ptr(enc_amounts, n * 8) }) else {
        return false;
    };
    let Some(eph_pks) = (unsafe { slice_from_ptr(x25519_eph_pks, n * 32) }) else {
        return false;
    };
    let Some(ml_cts) = (unsafe { slice_from_ptr(ml_kem_cts, ml_kem_cts_len) }) else {
        return false;
    };

    if !ml_kem_cts_len.is_multiple_of(n) {
        return false;
    }
    let ct_size = ml_kem_cts_len / n;

    let on_chain: Vec<shekyl_proofs::tx_proof::OnChainOutput> = (0..n)
        .map(|i| {
            let mut ok = [0u8; 32];
            let mut cm = [0u8; 32];
            let mut ea = [0u8; 8];
            let mut ep = [0u8; 32];
            ok.copy_from_slice(&okeys[i * 32..(i + 1) * 32]);
            cm.copy_from_slice(&comms[i * 32..(i + 1) * 32]);
            ea.copy_from_slice(&eamts[i * 8..(i + 1) * 8]);
            ep.copy_from_slice(&eph_pks[i * 32..(i + 1) * 32]);
            shekyl_proofs::tx_proof::OnChainOutput {
                output_key: ok,
                commitment: cm,
                enc_amount: ea,
                x25519_eph_pk: ep,
                ml_kem_ct: ml_cts[i * ct_size..(i + 1) * ct_size].to_vec(),
            }
        })
        .collect();

    match shekyl_proofs::tx_proof::verify_inbound_proof(
        proof, &tx_id, addr, msg, &vpk, &spend_pk, &on_chain,
    ) {
        Ok(verified) => {
            let out_slice = std::slice::from_raw_parts_mut(amounts_out, n);
            for v in &verified {
                if v.output_index < n {
                    out_slice[v.output_index] = v.amount;
                }
            }
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Generate reserve proof (prove ownership of unspent outputs).
///
/// # Safety
/// - `spend_secret_key`: 32 bytes.
/// - `address`: `address_len` bytes.
/// - `proof_secrets`: `output_count * 128` bytes.
/// - `key_images`, `spend_secrets`, `output_keys`: `output_count * 32` each.
/// - `proof_out`: writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generate_reserve_proof(
    spend_secret_key: *const u8,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    proof_secrets_ptr: *const u8,
    key_images: *const u8,
    spend_secrets: *const u8,
    output_keys: *const u8,
    output_count: u32,
    proof_out: *mut ShekylBuffer,
) -> bool {
    let Some(bsk) = arr32_from_ptr(spend_secret_key) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let n = output_count as usize;
    if proof_out.is_null() || n == 0 {
        return false;
    }

    let Some(ps_bytes) = (unsafe { slice_from_ptr(proof_secrets_ptr, n * 128) }) else {
        return false;
    };
    let Some(ki_bytes) = (unsafe { slice_from_ptr(key_images, n * 32) }) else {
        return false;
    };
    let Some(ss_bytes) = (unsafe { slice_from_ptr(spend_secrets, n * 32) }) else {
        return false;
    };
    let Some(ok_bytes) = (unsafe { slice_from_ptr(output_keys, n * 32) }) else {
        return false;
    };

    let entries: Vec<shekyl_proofs::reserve_proof::ReserveOutputEntry> = (0..n)
        .map(|i| {
            let base = i * 128;
            let mut ho = [0u8; 32];
            let mut y = [0u8; 32];
            let mut z = [0u8; 32];
            let mut k_amount = [0u8; 32];
            ho.copy_from_slice(&ps_bytes[base..base + 32]);
            y.copy_from_slice(&ps_bytes[base + 32..base + 64]);
            z.copy_from_slice(&ps_bytes[base + 64..base + 96]);
            k_amount.copy_from_slice(&ps_bytes[base + 96..base + 128]);

            let mut ki = [0u8; 32];
            let mut ss = [0u8; 32];
            let mut ok = [0u8; 32];
            ki.copy_from_slice(&ki_bytes[i * 32..(i + 1) * 32]);
            ss.copy_from_slice(&ss_bytes[i * 32..(i + 1) * 32]);
            ok.copy_from_slice(&ok_bytes[i * 32..(i + 1) * 32]);

            shekyl_proofs::reserve_proof::ReserveOutputEntry {
                proof_secrets: shekyl_crypto_pq::output::ProofSecrets { ho, y, z, k_amount },
                key_image: ki,
                spend_secret: ss,
                output_key: ok,
            }
        })
        .collect();

    match shekyl_proofs::reserve_proof::generate_reserve_proof(&bsk, addr, msg, &entries) {
        Ok(proof_bytes) => {
            *proof_out = ShekylBuffer::from_vec(proof_bytes);
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

/// Verify reserve proof.
///
/// `enc_amounts` MUST be fetched from the blockchain, NOT from the proof.
/// On success, writes total verified amount to `total_amount_out`.
///
/// # Safety
/// - `proof_bytes`: `proof_len` bytes.
/// - `address`: `address_len` bytes.
/// - `spend_pubkey`: 32 bytes.
/// - `output_keys`, `commitments`: `output_count * 32` each.
/// - `enc_amounts`: `output_count * 8` bytes.
/// - `total_amount_out`: writable u64.
#[no_mangle]
pub unsafe extern "C" fn shekyl_verify_reserve_proof(
    proof_bytes: *const u8,
    proof_len: usize,
    address: *const u8,
    address_len: usize,
    message: *const u8,
    message_len: usize,
    spend_pubkey: *const u8,
    output_keys: *const u8,
    commitments: *const u8,
    enc_amounts: *const u8,
    output_count: u32,
    total_amount_out: *mut u64,
) -> bool {
    let Some(proof) = (unsafe { slice_from_ptr(proof_bytes, proof_len) }) else {
        return false;
    };
    let Some(addr) = (unsafe { slice_from_ptr(address, address_len) }) else {
        return false;
    };
    let msg = if message_len == 0 {
        &[] as &[u8]
    } else {
        match unsafe { slice_from_ptr(message, message_len) } {
            Some(v) => v,
            None => return false,
        }
    };
    let Some(spk) = arr32_from_ptr(spend_pubkey) else {
        return false;
    };
    let n = output_count as usize;
    if total_amount_out.is_null() || n == 0 {
        return false;
    }

    let Some(ok_bytes) = (unsafe { slice_from_ptr(output_keys, n * 32) }) else {
        return false;
    };
    let Some(cm_bytes) = (unsafe { slice_from_ptr(commitments, n * 32) }) else {
        return false;
    };
    let Some(ea_bytes) = (unsafe { slice_from_ptr(enc_amounts, n * 8) }) else {
        return false;
    };

    let on_chain: Vec<shekyl_proofs::reserve_proof::ReserveOnChainOutput> = (0..n)
        .map(|i| {
            let mut ok = [0u8; 32];
            let mut cm = [0u8; 32];
            let mut ea = [0u8; 8];
            ok.copy_from_slice(&ok_bytes[i * 32..(i + 1) * 32]);
            cm.copy_from_slice(&cm_bytes[i * 32..(i + 1) * 32]);
            ea.copy_from_slice(&ea_bytes[i * 8..(i + 1) * 8]);
            shekyl_proofs::reserve_proof::ReserveOnChainOutput {
                output_key: ok,
                commitment: cm,
                enc_amount: ea,
            }
        })
        .collect();

    match shekyl_proofs::reserve_proof::verify_reserve_proof(proof, addr, msg, &spk, &on_chain) {
        Ok(verified) => {
            let total: u64 = verified.iter().map(|v| v.amount).sum();
            *total_amount_out = total;
            true
        }
        Err(e) => {
            let _ = e;
            false
        }
    }
}

fn arr32_from_ptr(ptr: *const u8) -> Option<[u8; 32]> {
    if ptr.is_null() {
        return None;
    }
    let mut arr = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(ptr, arr.as_mut_ptr(), 32) };
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let ptr = shekyl_rust_version();
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(s.to_str().unwrap(), "2.0.0");
    }

    #[test]
    fn test_release_multiplier_ffi() {
        let m = shekyl_calc_release_multiplier(100, 100, 800_000, 1_300_000);
        assert_eq!(m, 1_000_000);
    }

    #[test]
    fn test_burn_split_ffi() {
        let split = shekyl_compute_burn_split(1_000_000_000, 400_000, 200_000);
        assert_eq!(split.miner_fee_income, 600_000_000);
        assert_eq!(split.staker_pool_amount, 80_000_000);
        assert_eq!(split.actually_destroyed, 320_000_000);
    }

    #[test]
    fn test_stake_weight_ffi() {
        assert_eq!(shekyl_stake_weight(1_000_000_000, 0), 1_000_000_000); // 1.0x
        assert_eq!(shekyl_stake_weight(1_000_000_000, 2), 2_000_000_000); // 2.0x
        assert_eq!(shekyl_stake_weight(1_000_000_000, 99), 0); // invalid tier
    }

    #[test]
    fn test_per_block_staker_reward_ffi() {
        unsafe {
            let mut overflow = 0u8;
            let q = shekyl_calc_per_block_staker_reward(
                1_000_000,
                500_000,
                2_000_000,
                0,
                &raw mut overflow,
            );
            assert_eq!(overflow, 0);
            assert_eq!(q, 250_000);
            assert_eq!(
                shekyl_calc_per_block_staker_reward(100, 0, 50, 0, std::ptr::null_mut()),
                0
            );
            let q2 = shekyl_calc_per_block_staker_reward(10, 10, 1, 0, std::ptr::null_mut());
            assert_eq!(q2, 100);
        }
    }

    #[test]
    fn test_per_block_staker_reward_overflow_flag() {
        unsafe {
            let mut overflow = 0u8;
            let q =
                shekyl_calc_per_block_staker_reward(u64::MAX, u64::MAX, 1, 0, &raw mut overflow);
            assert_eq!(q, 0);
            assert_eq!(overflow, 1);
        }
    }

    #[test]
    fn test_per_block_staker_reward_u128_denominator() {
        unsafe {
            let mut overflow = 0u8;
            let q =
                shekyl_calc_per_block_staker_reward(1_000_000, 1_000_000, 0, 1, &raw mut overflow);
            assert_eq!(overflow, 0);
            assert_eq!(q, 0);

            let q2 = shekyl_calc_per_block_staker_reward(u64::MAX, 2, 100, 1, &raw mut overflow);
            assert_eq!(overflow, 0);
            assert_eq!(q2, 1);
        }
    }

    #[test]
    fn test_stake_tier_enum_ffi() {
        assert_eq!(shekyl_stake_tier_count(), 3);
        assert!(shekyl_stake_max_claim_range() > 0);
        use std::ffi::CStr;
        unsafe {
            assert_eq!(
                CStr::from_ptr(shekyl_stake_tier_name(0)).to_str().unwrap(),
                shekyl_staking::tiers::TIERS[0].name
            );
            assert!(shekyl_stake_tier_name(99).is_null());
        }
    }

    #[test]
    fn test_stake_ratio_ffi() {
        let ratio = shekyl_calc_stake_ratio(500_000_000, 1_000_000_000);
        assert_eq!(ratio, 500_000); // 0.5
    }

    #[test]
    fn test_emission_share_genesis() {
        let share = shekyl_calc_emission_share(0, 0, 150_000, 900_000, 262_800);
        assert_eq!(share, 150_000);
    }

    #[test]
    fn test_emission_share_year_1() {
        let share = shekyl_calc_emission_share(262_800, 0, 150_000, 900_000, 262_800);
        assert_eq!(share, 135_000);
    }

    #[test]
    fn test_emission_split_ffi() {
        let split = shekyl_split_block_emission(1_000_000_000, 150_000);
        assert_eq!(split.staker_emission, 150_000_000);
        assert_eq!(split.miner_emission, 850_000_000);
    }

    #[test]
    fn test_burn_pct_ffi_matches_rust_impl() {
        let cases = [
            (
                50u64,
                50u64,
                1_000_000u64,
                4_294_967_296_000_000_000u64,
                100_000u64,
                500_000u64,
                900_000u64,
            ),
            (
                200,
                50,
                2_000_000_000_000_000_000,
                4_294_967_296_000_000_000,
                250_000,
                500_000,
                900_000,
            ),
            (
                500,
                50,
                3_000_000_000_000_000_000,
                4_294_967_296_000_000_000,
                400_000,
                500_000,
                900_000,
            ),
        ];
        for (txv, base, circ, total, stake, rate, cap) in cases {
            let ffi = shekyl_calc_burn_pct(txv, base, circ, total, stake, rate, cap);
            let direct =
                shekyl_economics::burn::calc_burn_pct(txv, base, circ, total, stake, rate, cap);
            assert_eq!(ffi, direct);
        }
    }

    #[test]
    fn test_emission_share_ffi_matches_rust_impl() {
        let cases = [
            (0u64, 0u64, 150_000u64, 900_000u64, 262_800u64),
            (262_800, 0, 150_000, 900_000, 262_800),
            (2 * 262_800, 0, 150_000, 900_000, 262_800),
            (10 * 262_800, 0, 150_000, 900_000, 262_800),
        ];
        for (height, genesis, initial, decay, bpy) in cases {
            let ffi = shekyl_calc_emission_share(height, genesis, initial, decay, bpy);
            let direct = shekyl_economics::emission_share::calc_effective_emission_share(
                height, genesis, initial, decay, bpy,
            );
            assert_eq!(ffi, direct);
        }
    }

    #[test]
    fn test_pqc_keygen_sign_verify_ffi() {
        unsafe {
            let kp = shekyl_pqc_keypair_generate();
            assert!(kp.success);
            assert!(!kp.public_key.ptr.is_null());
            assert!(!kp.secret_key.ptr.is_null());

            let msg = b"ffi hybrid pq signature";
            let sig = shekyl_pqc_sign(
                kp.secret_key.ptr,
                kp.secret_key.len,
                msg.as_ptr(),
                msg.len(),
            );
            assert!(sig.success);
            assert!(!sig.signature.ptr.is_null());

            let result = shekyl_pqc_verify(
                1,
                kp.public_key.ptr,
                kp.public_key.len,
                sig.signature.ptr,
                sig.signature.len,
                msg.as_ptr(),
                msg.len(),
            );
            assert_eq!(result, 0, "expected success (0), got error code {result}");

            shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
            shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
            shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
        }
    }

    #[test]
    fn test_ssl_cert_generation_ecdsa() {
        unsafe {
            let mut key_pem = ShekylBuffer::null();
            let mut cert_pem = ShekylBuffer::null();
            let ok = shekyl_generate_ssl_certificate(&raw mut key_pem, &raw mut cert_pem);
            assert!(ok);
            assert!(!key_pem.ptr.is_null());
            assert!(!cert_pem.ptr.is_null());
            let key_str =
                std::str::from_utf8(std::slice::from_raw_parts(key_pem.ptr, key_pem.len)).unwrap();
            let cert_str =
                std::str::from_utf8(std::slice::from_raw_parts(cert_pem.ptr, cert_pem.len))
                    .unwrap();
            assert!(key_str.contains("BEGIN PRIVATE KEY"));
            assert!(cert_str.contains("BEGIN CERTIFICATE"));
            shekyl_buffer_free(key_pem.ptr, key_pem.len);
            shekyl_buffer_free(cert_pem.ptr, cert_pem.len);
        }
    }

    #[test]
    fn test_memwipe_zeroes_buffer() {
        let mut buf = vec![0xABu8; 64];
        unsafe { shekyl_memwipe(buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_page_size_nonzero() {
        let ps = unsafe { shekyl_page_size() };
        assert!(ps > 0, "page size should be > 0, got {ps}");
        assert!(ps.is_power_of_two(), "page size should be power of 2");
    }

    #[test]
    fn test_pqc_verify_rejects_modified_signature() {
        unsafe {
            let kp = shekyl_pqc_keypair_generate();
            let msg = b"ffi hybrid pq signature";
            let sig = shekyl_pqc_sign(
                kp.secret_key.ptr,
                kp.secret_key.len,
                msg.as_ptr(),
                msg.len(),
            );
            assert!(sig.success);

            let mut sig_bytes =
                std::slice::from_raw_parts(sig.signature.ptr, sig.signature.len).to_vec();
            let last = sig_bytes.len() - 1;
            sig_bytes[last] ^= 0x01;

            let result = shekyl_pqc_verify(
                1,
                kp.public_key.ptr,
                kp.public_key.len,
                sig_bytes.as_ptr(),
                sig_bytes.len(),
                msg.as_ptr(),
                msg.len(),
            );
            assert_ne!(result, 0, "corrupted signature should not verify");

            shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
            shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
            shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
        }
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_import_null_returns_null() {
        let handle = unsafe { shekyl_frost_keys_import(std::ptr::null(), 0) };
        assert!(handle.is_null());
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_import_invalid_data_returns_null() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF];
        let handle = unsafe { shekyl_frost_keys_import(garbage.as_ptr(), garbage.len()) };
        assert!(handle.is_null());
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_validate_null_returns_false() {
        let valid = unsafe { shekyl_frost_keys_validate(std::ptr::null(), 2, 3) };
        assert!(!valid);
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_group_key_null_returns_false() {
        let mut out = [0u8; 32];
        let ok = unsafe { shekyl_frost_keys_group_key(std::ptr::null(), out.as_mut_ptr()) };
        assert!(!ok);
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_free_null_is_safe() {
        unsafe { shekyl_frost_keys_free(std::ptr::null_mut()) };
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_sal_session_new_null_returns_null() {
        let session = unsafe {
            shekyl_frost_sal_session_new(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        assert!(session.is_null());
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_sal_session_free_null_is_safe() {
        unsafe { shekyl_frost_sal_session_free(std::ptr::null_mut()) };
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_sal_get_rerand_null_returns_empty() {
        let buf = unsafe { shekyl_frost_sal_get_rerand(std::ptr::null()) };
        assert!(buf.ptr.is_null());
        assert_eq!(buf.len, 0);
    }

    // ── Witness header round-trip tests ──────────────────────────────────
    //
    // Verifies that shekyl_fcmp_build_witness_header (writer) and
    // parse_prove_witness (reader) agree byte-for-byte on all 8 header
    // fields, using locked vectors from docs/test_vectors/WITNESS_HEADER.json.

    #[derive(serde::Deserialize)]
    struct WitnessHeaderVector {
        output_key: String,
        key_image_gen: String,
        commitment: String,
        h_pqc: String,
        spend_key_x: String,
        spend_key_y: String,
        commitment_mask: String,
        pseudo_out_blind: String,
    }

    #[derive(serde::Deserialize)]
    struct WitnessHeaderFile {
        vectors: Vec<WitnessHeaderVector>,
    }

    fn decode_32(hex_str: &str, label: &str, vec_idx: usize) -> [u8; 32] {
        let bytes = hex::decode(hex_str)
            .unwrap_or_else(|_| panic!("vector {vec_idx}: invalid hex for {label}"));
        bytes
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("vector {vec_idx}: {label} not 32 bytes"))
    }

    #[test]
    fn witness_header_build_then_parse_roundtrip() {
        let json = include_str!("../../../docs/test_vectors/WITNESS_HEADER.json");
        let file: WitnessHeaderFile =
            serde_json::from_str(json).expect("failed to parse WITNESS_HEADER.json");
        assert!(
            !file.vectors.is_empty(),
            "no vectors in WITNESS_HEADER.json"
        );

        for (i, v) in file.vectors.iter().enumerate() {
            let fields = ProveInputFields {
                output_key: decode_32(&v.output_key, "output_key", i),
                key_image_gen: decode_32(&v.key_image_gen, "key_image_gen", i),
                commitment: decode_32(&v.commitment, "commitment", i),
                h_pqc: decode_32(&v.h_pqc, "h_pqc", i),
                spend_key_x: decode_32(&v.spend_key_x, "spend_key_x", i),
                spend_key_y: decode_32(&v.spend_key_y, "spend_key_y", i),
                commitment_mask: decode_32(&v.commitment_mask, "commitment_mask", i),
                pseudo_out_blind: decode_32(&v.pseudo_out_blind, "pseudo_out_blind", i),
            };

            // Build: typed struct → 256-byte blob (same path as C++ FFI)
            let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
            let ok =
                unsafe { shekyl_fcmp_build_witness_header(&raw const fields, blob.as_mut_ptr()) };
            assert!(
                ok,
                "vector {i}: shekyl_fcmp_build_witness_header returned false"
            );
            assert_eq!(blob.len(), 256, "vector {i}: blob not 256 bytes");

            // Verify raw byte layout matches the field offsets
            assert_eq!(
                &blob[0..32],
                fields.output_key.as_slice(),
                "vector {i}: O mismatch in blob"
            );
            assert_eq!(
                &blob[32..64],
                fields.key_image_gen.as_slice(),
                "vector {i}: I mismatch in blob"
            );
            assert_eq!(
                &blob[64..96],
                fields.commitment.as_slice(),
                "vector {i}: C mismatch in blob"
            );
            assert_eq!(
                &blob[96..128],
                fields.h_pqc.as_slice(),
                "vector {i}: h_pqc mismatch in blob"
            );
            assert_eq!(
                &blob[128..160],
                fields.spend_key_x.as_slice(),
                "vector {i}: x mismatch in blob"
            );
            assert_eq!(
                &blob[160..192],
                fields.spend_key_y.as_slice(),
                "vector {i}: y mismatch in blob"
            );
            assert_eq!(
                &blob[192..224],
                fields.commitment_mask.as_slice(),
                "vector {i}: z mismatch in blob"
            );
            assert_eq!(
                &blob[224..256],
                fields.pseudo_out_blind.as_slice(),
                "vector {i}: a mismatch in blob"
            );

            // Parse: 256-byte blob → ProveInput (same path as Rust FFI verifier).
            // parse_prove_witness expects a full witness (header + leaf + branch data).
            // We append a minimal valid trailer: 1 leaf entry + 0 branch layers.
            let mut witness = blob.clone();
            // leaf chunk_count = 1 (must have at least 1 to parse)
            witness.extend_from_slice(&1u32.to_le_bytes());
            // one leaf entry: 4 x 32 bytes (O, I, C, h_pqc)
            witness.extend_from_slice(&fields.output_key);
            witness.extend_from_slice(&fields.key_image_gen);
            witness.extend_from_slice(&fields.commitment);
            witness.extend_from_slice(&fields.h_pqc);
            // c1_layer_count = 0
            witness.extend_from_slice(&0u32.to_le_bytes());
            // c2_layer_count = 0
            witness.extend_from_slice(&0u32.to_le_bytes());

            let parsed = parse_prove_witness(&witness, 1);
            assert!(
                parsed.is_some(),
                "vector {i}: parse_prove_witness returned None"
            );
            let inputs = parsed.unwrap();
            assert_eq!(inputs.len(), 1, "vector {i}: expected 1 input");
            let pi = &inputs[0];

            assert_eq!(
                pi.output_key, fields.output_key,
                "vector {i}: parsed O mismatch"
            );
            assert_eq!(
                pi.key_image_gen, fields.key_image_gen,
                "vector {i}: parsed I mismatch"
            );
            assert_eq!(
                pi.commitment, fields.commitment,
                "vector {i}: parsed C mismatch"
            );
            assert_eq!(
                pi.h_pqc.0, fields.h_pqc,
                "vector {i}: parsed h_pqc mismatch"
            );
            assert_eq!(
                pi.spend_key_x, fields.spend_key_x,
                "vector {i}: parsed x mismatch"
            );
            assert_eq!(
                pi.spend_key_y, fields.spend_key_y,
                "vector {i}: parsed y mismatch"
            );
            assert_eq!(
                pi.commitment_mask, fields.commitment_mask,
                "vector {i}: parsed z mismatch"
            );
            assert_eq!(
                pi.pseudo_out_blind, fields.pseudo_out_blind,
                "vector {i}: parsed a mismatch"
            );
        }
    }
}
