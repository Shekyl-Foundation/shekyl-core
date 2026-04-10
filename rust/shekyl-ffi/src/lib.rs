//! FFI bridge between the C++ core and Rust modules.
//!
//! Exposes Rust functionality to C++ through a C-compatible ABI.
//! All public functions use `extern "C"` with `#[no_mangle]`.

use std::os::raw::c_char;
use std::sync::Mutex;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme,
};

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
pub extern "C" fn shekyl_buffer_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            use zeroize::Zeroize;
            std::slice::from_raw_parts_mut(ptr, len).zeroize();
            drop(Vec::from_raw_parts(ptr, len, len));
        }
    }
}

fn slice_from_ptr<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
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
    let Some(secret_key_bytes) = slice_from_ptr(secret_key_ptr, secret_key_len) else {
        return ShekylPqcSignatureResult {
            signature: ShekylBuffer::null(),
            success: false,
        };
    };
    let Some(message) = slice_from_ptr(message_ptr, message_len) else {
        return ShekylPqcSignatureResult {
            signature: ShekylBuffer::null(),
            success: false,
        };
    };

    let scheme = HybridEd25519MlDsa;
    let secret_key = match HybridSecretKey::from_canonical_bytes(secret_key_bytes) {
        Ok(sk) => sk,
        Err(_) => {
            return ShekylPqcSignatureResult {
                signature: ShekylBuffer::null(),
                success: false,
            }
        }
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
) -> bool {
    let Some(pk_bytes) = slice_from_ptr(pubkey_blob, pubkey_len) else {
        return false;
    };
    let Some(msg) = slice_from_ptr(message, message_len) else {
        return false;
    };
    let Some(sig_bytes) = slice_from_ptr(sig_blob, sig_len) else {
        return false;
    };

    match scheme_id {
        1 => {
            let scheme = HybridEd25519MlDsa;
            let pk = match HybridPublicKey::from_canonical_bytes(pk_bytes) {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sig = match HybridSignature::from_canonical_bytes(sig_bytes) {
                Ok(s) => s,
                Err(_) => return false,
            };
            scheme.verify(&pk, msg, &sig).unwrap_or(false)
        }
        2 => {
            use shekyl_crypto_pq::multisig::verify_multisig;
            verify_multisig(scheme_id, pk_bytes, sig_bytes, msg, None).unwrap_or(false)
        }
        _ => false,
    }
}

/// Debug variant of verify: returns `PqcVerifyError` discriminant (1-11) on failure, 0 on success.
/// Only compiled in debug/test builds to prevent use as a signature oracle.
#[cfg(any(debug_assertions, test, feature = "debug-verify"))]
#[no_mangle]
pub extern "C" fn shekyl_pqc_verify_debug(
    scheme_id: u8,
    pubkey_blob: *const u8,
    pubkey_len: usize,
    sig_blob: *const u8,
    sig_len: usize,
    message: *const u8,
    message_len: usize,
) -> u8 {
    let Some(pk_bytes) = slice_from_ptr(pubkey_blob, pubkey_len) else {
        return 11; // DeserializationFailed
    };
    let Some(msg) = slice_from_ptr(message, message_len) else {
        return 11;
    };
    let Some(sig_bytes) = slice_from_ptr(sig_blob, sig_len) else {
        return 11;
    };

    match scheme_id {
        1 => {
            let scheme = HybridEd25519MlDsa;
            let pk = match HybridPublicKey::from_canonical_bytes(pk_bytes) {
                Ok(pk) => pk,
                Err(_) => return 11,
            };
            let sig = match HybridSignature::from_canonical_bytes(sig_bytes) {
                Ok(s) => s,
                Err(_) => return 11,
            };
            match scheme.verify(&pk, msg, &sig) {
                Ok(true) => 0,
                Ok(false) => 10, // CryptoVerifyFailed
                Err(_) => 10,
            }
        }
        2 => {
            use shekyl_crypto_pq::multisig::verify_multisig;
            match verify_multisig(scheme_id, pk_bytes, sig_bytes, msg, None) {
                Ok(true) => 0,
                Ok(false) => 10,
                Err(e) => e as u8,
            }
        }
        _ => 1, // SchemeMismatch
    }
}

/// Compute the deterministic group_id for a MultisigKeyContainer blob.
///
/// Writes 32 bytes to `out_ptr`. Returns true on success.
#[no_mangle]
pub extern "C" fn shekyl_pqc_multisig_group_id(
    keys_ptr: *const u8,
    keys_len: usize,
    out_ptr: *mut u8,
) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let Some(keys_bytes) = slice_from_ptr(keys_ptr, keys_len) else {
        return false;
    };

    use shekyl_crypto_pq::multisig::{MultisigKeyContainer, multisig_group_id};

    let container = match MultisigKeyContainer::from_canonical_bytes(keys_bytes) {
        Ok(c) => c,
        Err(_) => return false,
    };

    match multisig_group_id(&container) {
        Ok(id) => {
            unsafe {
                std::ptr::copy_nonoverlapping(id.as_ptr(), out_ptr, 32);
            }
            true
        }
        Err(_) => false,
    }
}

// ─── Crypto: Hash Functions ──────────────────────────────────────────────────

/// Compute Keccak-256 (cn_fast_hash) of `data_len` bytes at `data_ptr`.
/// Result is written to `out_ptr` which must point to 32 writable bytes.
/// Returns true on success, false if pointers are null.
#[no_mangle]
pub extern "C" fn shekyl_cn_fast_hash(
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let data = match slice_from_ptr(data_ptr, data_len) {
        Some(s) => s,
        None => return false,
    };
    let hash = shekyl_crypto_hash::cn_fast_hash(data);
    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, 32);
    }
    true
}

/// Compute Merkle tree root hash from an array of 32-byte hashes.
/// `hashes_ptr` points to `count * 32` contiguous bytes.
/// Result is written to `out_ptr` (32 bytes).
#[no_mangle]
pub extern "C" fn shekyl_tree_hash(
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
        let byte_len = match count.checked_mul(32) {
            Some(n) => n,
            None => return false,
        };
        let raw = unsafe { std::slice::from_raw_parts(hashes_ptr, byte_len) };
        raw.chunks_exact(32)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect()
    };
    let root = shekyl_crypto_hash::tree_hash(&hashes);
    unsafe {
        std::ptr::copy_nonoverlapping(root.as_ptr(), out_ptr, 32);
    }
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
    let split =
        shekyl_economics::burn::compute_burn_split(total_fees, burn_pct, staker_pool_share);
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
    let tier = match tier_by_id(tier_id) {
        Some(t) => t,
        None => return 0,
    };
    ((amount as u128 * tier.yield_multiplier as u128)
        / shekyl_economics::params::SCALE as u128) as u64
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
#[no_mangle]
pub extern "C" fn shekyl_calc_per_block_staker_reward(
    total_reward_at_height: u64,
    stake_weight: u64,
    total_weighted_stake_lo: u64,
    total_weighted_stake_hi: u64,
    overflow_out: *mut u8,
) -> u64 {
    unsafe {
        if !overflow_out.is_null() {
            *overflow_out = 0;
        }
    }
    let total_weighted_stake = (total_weighted_stake_hi as u128) << 64 | (total_weighted_stake_lo as u128);
    if total_weighted_stake == 0 {
        return 0;
    }
    let num = (total_reward_at_height as u128) * (stake_weight as u128);
    let q = num / total_weighted_stake;
    if q > u64::MAX as u128 {
        unsafe {
            if !overflow_out.is_null() {
                *overflow_out = 1;
            }
        }
        return 0;
    }
    q as u64
}

/// Number of staking lock tiers (length of `TIERS`).
#[no_mangle]
pub extern "C" fn shekyl_stake_tier_count() -> u32 {
    shekyl_staking::tiers::TIERS.len() as u32
}

/// UTF-8 tier display name, null-terminated. Returns null for invalid `tier_id`.
#[no_mangle]
pub extern "C" fn shekyl_stake_tier_name(tier_id: u8) -> *const c_char {
    match tier_id {
        0 => b"Short\0".as_ptr() as *const c_char,
        1 => b"Medium\0".as_ptr() as *const c_char,
        2 => b"Long\0".as_ptr() as *const c_char,
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
    (total_staked as u128 * shekyl_economics::params::SCALE as u128
        / circulating_supply as u128) as u64
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
#[no_mangle]
pub extern "C" fn shekyl_generate_ssl_certificate(
    key_pem_out: *mut ShekylBuffer,
    cert_pem_out: *mut ShekylBuffer,
) -> bool {
    if key_pem_out.is_null() || cert_pem_out.is_null() {
        return false;
    }

    let key_pair = match rcgen::KeyPair::generate() {
        Ok(kp) => kp,
        Err(_) => return false,
    };

    let cert = match rcgen::CertificateParams::default().self_signed(&key_pair) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let key_pem_str = key_pair.serialize_pem();
    let cert_pem_str = cert.pem();

    unsafe {
        *key_pem_out = ShekylBuffer::from_vec(key_pem_str.into_bytes());
        *cert_pem_out = ShekylBuffer::from_vec(cert_pem_str.into_bytes());
    }
    true
}

// ─── Secure Memory ──────────────────────────────────────────────────────────

/// Securely wipe memory at `ptr` for `len` bytes.
///
/// Uses `zeroize` to guarantee the write is not optimized away.
/// C signature: `void shekyl_memwipe(void *ptr, size_t len)`
#[no_mangle]
pub extern "C" fn shekyl_memwipe(ptr: *mut libc::c_void, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        use zeroize::Zeroize;
        std::slice::from_raw_parts_mut(ptr as *mut u8, len).zeroize();
    }
}

/// Lock memory pages containing `[ptr, ptr+len)` into RAM.
///
/// Returns 0 on success, -1 on failure (mirrors POSIX mlock).
/// C signature: `int shekyl_mlock(const void *ptr, size_t len)`
#[no_mangle]
pub extern "C" fn shekyl_mlock(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(unix)]
    {
        unsafe { libc::mlock(ptr, len) }
    }
    #[cfg(windows)]
    {
        extern "system" {
            fn VirtualLock(lpAddress: *const libc::c_void, dwSize: usize) -> i32;
        }
        let ret = unsafe { VirtualLock(ptr, len) };
        if ret != 0 { 0 } else { -1 }
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
#[no_mangle]
pub extern "C" fn shekyl_munlock(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(unix)]
    {
        unsafe { libc::munlock(ptr, len) }
    }
    #[cfg(windows)]
    {
        extern "system" {
            fn VirtualUnlock(lpAddress: *const libc::c_void, dwSize: usize) -> i32;
        }
        let ret = unsafe { VirtualUnlock(ptr, len) };
        if ret != 0 { 0 } else { -1 }
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
#[no_mangle]
pub extern "C" fn shekyl_madvise_dontdump(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP) }
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
#[no_mangle]
pub extern "C" fn shekyl_page_size() -> usize {
    #[cfg(unix)]
    {
        let ret = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ret <= 0 { 0 } else { ret as usize }
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct SystemInfo { _pad: [u8; 4], page_size: u32, _rest: [u8; 52] }
        extern "system" {
            fn GetSystemInfo(info: *mut SystemInfo);
        }
        let mut info = SystemInfo { _pad: [0; 4], page_size: 0, _rest: [0; 52] };
        unsafe { GetSystemInfo(&mut info); }
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
#[no_mangle]
pub extern "C" fn shekyl_generator_T(out_ptr: *mut u8) {
    use ciphersuite::group::GroupEncoding;
    if out_ptr.is_null() { return; }
    let t_bytes: [u8; 32] = shekyl_generators::T.to_bytes().into();
    unsafe { std::ptr::copy_nonoverlapping(t_bytes.as_ptr(), out_ptr, 32) };
}

// ─── FCMP++: Proof and Tree Operations ──────────────────────────────────────

/// Compute H(pqc_pk) leaf scalar for a PQC public key.
///
/// Writes 32 bytes to `out_ptr`. Returns true on success.
#[no_mangle]
pub extern "C" fn shekyl_fcmp_pqc_leaf_hash(
    pqc_pk_ptr: *const u8,
    pqc_pk_len: usize,
    out_ptr: *mut u8,
) -> bool {
    let Some(pk_bytes) = slice_from_ptr(pqc_pk_ptr, pqc_pk_len) else {
        return false;
    };
    if out_ptr.is_null() {
        return false;
    }
    let hash = shekyl_crypto_pq::derivation::hash_pqc_public_key(pk_bytes);
    unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, 32) };
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
#[no_mangle]
pub extern "C" fn shekyl_derive_output_secrets(
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

    let ss = unsafe {
        std::slice::from_raw_parts(combined_ss_ptr, combined_ss_len as usize)
    };

    let secrets = shekyl_crypto_pq::derivation::derive_output_secrets(ss, output_index);

    unsafe {
        std::ptr::copy_nonoverlapping(secrets.ho.as_ptr(), out_ho, 32);
        std::ptr::copy_nonoverlapping(secrets.y.as_ptr(), out_y, 32);
        std::ptr::copy_nonoverlapping(secrets.z.as_ptr(), out_z, 32);
        std::ptr::copy_nonoverlapping(secrets.k_amount.as_ptr(), out_k_amount, 32);
        *out_view_tag_combined = secrets.view_tag_combined;
        *out_amount_tag = secrets.amount_tag;
        std::ptr::copy_nonoverlapping(secrets.ml_dsa_seed.as_ptr(), out_ml_dsa_seed, 32);
    }

    true
}

/// Derive the X25519-only view tag for scanner pre-filtering.
///
/// `x25519_ss_ptr` must point to exactly 32 bytes. Returns the 1-byte tag.
/// Returns 0 if the pointer is null (callers should check for null separately).
#[no_mangle]
pub extern "C" fn shekyl_derive_view_tag_x25519(
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
#[no_mangle]
pub extern "C" fn shekyl_fcmp_prove(
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

    let Some(witness) = slice_from_ptr(witness_ptr, witness_len) else {
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

fn parse_prove_witness(data: &[u8], num_inputs: usize) -> Option<Vec<shekyl_fcmp::proof::ProveInput>> {
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
        pseudo_out_blind.copy_from_slice(&data[offset + 224..offset + SHEKYL_PROVE_WITNESS_HEADER_BYTES]);
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
/// `signable_tx_hash_ptr`: 32-byte hash that binds the proof to the transaction.
/// Returns true if the proof is valid.
#[no_mangle]
pub extern "C" fn shekyl_fcmp_verify(
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
) -> bool {
    let Some(proof_bytes) = slice_from_ptr(proof_ptr, proof_len) else {
        return false;
    };
    let Some(ki_bytes) = slice_from_ptr(key_images_ptr, ki_count * 32) else {
        return false;
    };
    let Some(po_bytes) = slice_from_ptr(pseudo_outs_ptr, po_count * 32) else {
        return false;
    };
    let Some(ph_bytes) = slice_from_ptr(pqc_pk_hashes_ptr, pqc_hash_count * 32) else {
        return false;
    };
    if tree_root_ptr.is_null() || signable_tx_hash_ptr.is_null()
        || ki_count != po_count || ki_count != pqc_hash_count
    {
        return false;
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

    let proof = shekyl_fcmp::proof::ShekylFcmpProof {
        data: proof_bytes.to_vec(),
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
        &proof, &key_images, &pseudo_outs, &pqc_hashes,
        &tree_root, tree_depth, signable_tx_hash,
    ) {
        Ok(ok) => ok,
        Err(_) => false,
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
    let Some(bytes) = slice_from_ptr(outputs_ptr, total) else {
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
#[no_mangle]
pub extern "C" fn shekyl_frost_sal_session_new(
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
        unsafe { std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 32) };
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
            unsafe {
                std::ptr::copy_nonoverlapping(
                    session.pseudo_out().as_ptr(),
                    pseudo_out_ptr,
                    32,
                );
            }
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
#[no_mangle]
pub extern "C" fn shekyl_frost_sal_get_rerand(
    session: *const ShekylFrostSalSession,
) -> ShekylBuffer {
    if session.is_null() {
        return ShekylBuffer::null();
    }
    let session = unsafe { &*session };
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
pub extern "C" fn shekyl_frost_coordinator_new(
    num_inputs: u32,
    included_ptr: *const u16,
    num_included: u32,
) -> *mut ShekylFrostCoordinator {
    if included_ptr.is_null() || num_included == 0 || num_inputs == 0 {
        return std::ptr::null_mut();
    }

    let included: Vec<modular_frost::Participant> = (0..num_included as usize)
        .filter_map(|i| {
            let idx = unsafe { *included_ptr.add(i) };
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
pub extern "C" fn shekyl_frost_coordinator_add_preprocesses(
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
    let coord = unsafe { &mut *coord };
    let n = num_inputs as usize;

    let mut preprocesses = Vec::with_capacity(n);
    for i in 0..n {
        let offset = i * 32;
        let slice = unsafe { std::slice::from_raw_parts(data_ptr.add(offset), 32) };
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
pub extern "C" fn shekyl_frost_coordinator_nonce_sums(
    coord: *mut ShekylFrostCoordinator,
) -> ShekylBuffer {
    if coord.is_null() {
        return ShekylBuffer::null();
    }
    let coord = unsafe { &mut *coord };
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
pub extern "C" fn shekyl_frost_coordinator_add_shares(
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
    let coord = unsafe { &mut *coord };
    let n = num_inputs as usize;

    let mut shares = Vec::with_capacity(n);
    for i in 0..n {
        let mut buf = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(data_ptr.add(i * 32), buf.as_mut_ptr(), 32);
        }
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
pub extern "C" fn shekyl_frost_coordinator_aggregate_and_prove(
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

    if coord.is_null() || session_ptrs.is_null() || group_key_ptr.is_null()
        || witness_ptr.is_null() || tree_root_ptr.is_null()
    {
        return fail;
    }

    let n = num_inputs as usize;
    if n == 0 || n > shekyl_fcmp::MAX_INPUTS {
        return fail;
    }

    let read32 = |ptr: *const u8| -> [u8; 32] {
        let mut buf = [0u8; 32];
        unsafe { std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), 32) };
        buf
    };

    let group_key_bytes = read32(group_key_ptr);
    let Some(witness) = slice_from_ptr(witness_ptr, witness_len) else {
        return fail;
    };

    use ciphersuite::group::GroupEncoding;
    let gk_ct = <dalek_ff_group::EdwardsPoint as GroupEncoding>::from_bytes(&group_key_bytes.into());
    if bool::from(gk_ct.is_none()) {
        return fail;
    }
    let group_key: dalek_ff_group::EdwardsPoint = gk_ct.unwrap();

    let Some(prove_inputs) = parse_prove_witness(witness, n) else {
        return fail;
    };

    let mut coord_box = unsafe { Box::from_raw(coord) };

    let mut sessions: Vec<shekyl_fcmp::frost_sal::FrostSalSession> = Vec::with_capacity(n);
    for i in 0..n {
        let ptr = unsafe { *session_ptrs.add(i) };
        if ptr.is_null() {
            return fail;
        }
        sessions.push(unsafe { Box::from_raw(ptr) }.0);
    }

    let original_outputs: Vec<_> = sessions.iter().map(|s| *s.original_output()).collect();
    let rerands: Vec<_> = sessions.iter().map(|s| s.rerandomized_output().clone()).collect();
    let pseudo_outs_flat: Vec<u8> = sessions.iter().flat_map(|s| s.pseudo_out().iter().copied()).collect();

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

    let sal_pairs = match coord_box.0.aggregate_all(sessions, group_key) {
        Ok(pairs) => pairs,
        Err(_) => return fail,
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
pub extern "C" fn shekyl_frost_coordinator_free(coord: *mut ShekylFrostCoordinator) {
    if !coord.is_null() {
        unsafe { drop(Box::from_raw(coord)); }
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
pub extern "C" fn shekyl_frost_signer_preprocess(
    session: *mut ShekylFrostSalSession,
    keys_handle: *const ShekylFrostThresholdKeys,
) -> ShekylBuffer {
    if session.is_null() || keys_handle.is_null() {
        return ShekylBuffer::null();
    }
    let session = unsafe { &mut *session };
    let keys_handle = unsafe { &*keys_handle };

    let keys = match keys_handle.0.deserialize() {
        Ok(k) => k,
        Err(_) => return ShekylBuffer::null(),
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
pub extern "C" fn shekyl_frost_signer_sign(
    session: *mut ShekylFrostSalSession,
    keys_handle: *const ShekylFrostThresholdKeys,
    included_ptr: *const u16,
    num_included: u32,
    nonce_sums_ptr: *const u8,
) -> ShekylBuffer {
    if session.is_null() || keys_handle.is_null() || included_ptr.is_null() || nonce_sums_ptr.is_null() {
        return ShekylBuffer::null();
    }

    let session = unsafe { &mut *session };
    let keys_handle = unsafe { &*keys_handle };

    let keys = match keys_handle.0.deserialize() {
        Ok(k) => k,
        Err(_) => return ShekylBuffer::null(),
    };

    let included: Vec<modular_frost::Participant> = (0..num_included as usize)
        .filter_map(|i| {
            let idx = unsafe { *included_ptr.add(i) };
            modular_frost::Participant::new(idx)
        })
        .collect();

    let view = keys.view(included).unwrap();

    let mut nonce_sum_bytes = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(nonce_sums_ptr, nonce_sum_bytes.as_mut_ptr(), 32) };

    use ciphersuite::group::GroupEncoding;
    let nonce_sum_ct = <dalek_ff_group::EdwardsPoint as GroupEncoding>::from_bytes(&nonce_sum_bytes.into());
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
#[no_mangle]
pub extern "C" fn shekyl_frost_sal_session_free(session: *mut ShekylFrostSalSession) {
    if !session.is_null() {
        unsafe {
            drop(Box::from_raw(session));
        }
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
#[no_mangle]
pub extern "C" fn shekyl_frost_keys_import(
    data_ptr: *const u8,
    data_len: usize,
) -> *mut ShekylFrostThresholdKeys {
    if data_ptr.is_null() || data_len == 0 {
        return std::ptr::null_mut();
    }
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    let serialized = shekyl_fcmp::frost_dkg::SerializedThresholdKeys::from_bytes(data);
    if serialized.deserialize().is_err() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(ShekylFrostThresholdKeys(serialized)))
}

#[cfg(feature = "multisig")]
/// Export FROST threshold keys as a serialized blob.
/// Returns a ShekylBuffer with the serialized data, or empty on failure.
#[no_mangle]
pub extern "C" fn shekyl_frost_keys_export(
    handle: *const ShekylFrostThresholdKeys,
) -> ShekylBuffer {
    let fail = ShekylBuffer { ptr: std::ptr::null_mut(), len: 0 };
    if handle.is_null() {
        return fail;
    }
    let keys = unsafe { &*handle };
    let bytes = keys.0.as_bytes().to_vec();
    let len = bytes.len();
    let ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8;
    ShekylBuffer { ptr, len }
}

#[cfg(feature = "multisig")]
/// Get the 32-byte group public key from threshold keys.
/// Writes 32 bytes to `out_ptr`. Returns true on success.
#[no_mangle]
pub extern "C" fn shekyl_frost_keys_group_key(
    handle: *const ShekylFrostThresholdKeys,
    out_ptr: *mut u8,
) -> bool {
    if handle.is_null() || out_ptr.is_null() {
        return false;
    }
    let keys_handle = unsafe { &*handle };
    match keys_handle.0.deserialize() {
        Ok(keys) => {
            let gk = shekyl_fcmp::frost_dkg::group_key_bytes(&keys);
            unsafe { std::ptr::copy_nonoverlapping(gk.as_ptr(), out_ptr, 32) };
            true
        }
        Err(_) => false,
    }
}

#[cfg(feature = "multisig")]
/// Validate that threshold keys match expected M-of-N parameters.
/// Returns true if valid.
#[no_mangle]
pub extern "C" fn shekyl_frost_keys_validate(
    handle: *const ShekylFrostThresholdKeys,
    expected_m: u16,
    expected_n: u16,
) -> bool {
    if handle.is_null() {
        return false;
    }
    let keys_handle = unsafe { &*handle };
    match keys_handle.0.deserialize() {
        Ok(keys) => shekyl_fcmp::frost_dkg::validate_keys(&keys, expected_m, expected_n).is_ok(),
        Err(_) => false,
    }
}

#[cfg(feature = "multisig")]
/// Free a FROST threshold keys handle.
#[no_mangle]
pub extern "C" fn shekyl_frost_keys_free(handle: *mut ShekylFrostThresholdKeys) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle));
        }
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

/// Encapsulate to a hybrid public key. Returns ciphertext in the buffer.
/// Combined shared secret is written to `ss_out_ptr` (64 bytes).
#[no_mangle]
pub extern "C" fn shekyl_kem_encapsulate(
    pk_x25519_ptr: *const u8,
    pk_ml_kem_ptr: *const u8,
    pk_ml_kem_len: usize,
    ct_out: *mut ShekylBuffer,
    ss_out_ptr: *mut u8,
) -> bool {
    use shekyl_crypto_pq::kem::{HybridKemPublicKey, HybridX25519MlKem, KeyEncapsulation};

    if pk_x25519_ptr.is_null() || pk_ml_kem_ptr.is_null() || ct_out.is_null() || ss_out_ptr.is_null() {
        return false;
    }

    let x25519: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(pk_x25519_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let Some(ml_kem) = slice_from_ptr(pk_ml_kem_ptr, pk_ml_kem_len) else {
        return false;
    };

    let pk = HybridKemPublicKey { x25519, ml_kem: ml_kem.to_vec() };
    let kem = HybridX25519MlKem;

    match kem.encapsulate(&pk) {
        Ok((ss, ct)) => {
            let mut ct_bytes = Vec::new();
            ct_bytes.extend_from_slice(&ct.x25519);
            ct_bytes.extend_from_slice(&ct.ml_kem);

            unsafe {
                *ct_out = ShekylBuffer::from_vec(ct_bytes);
                std::ptr::copy_nonoverlapping(ss.0.as_ptr(), ss_out_ptr, 64);
            }
            true
        }
        Err(_) => false,
    }
}

/// Decapsulate a hybrid ciphertext. Writes combined shared secret to `ss_out_ptr` (64 bytes).
#[no_mangle]
pub extern "C" fn shekyl_kem_decapsulate(
    sk_x25519_ptr: *const u8,
    sk_ml_kem_ptr: *const u8,
    sk_ml_kem_len: usize,
    ct_x25519_ptr: *const u8,
    ct_ml_kem_ptr: *const u8,
    ct_ml_kem_len: usize,
    ss_out_ptr: *mut u8,
) -> bool {
    use shekyl_crypto_pq::kem::{HybridCiphertext, HybridKemSecretKey, HybridX25519MlKem, KeyEncapsulation};

    if sk_x25519_ptr.is_null() || sk_ml_kem_ptr.is_null() || ct_x25519_ptr.is_null()
        || ct_ml_kem_ptr.is_null() || ss_out_ptr.is_null()
    {
        return false;
    }

    let sk_x25519: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(sk_x25519_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let Some(sk_ml_kem) = slice_from_ptr(sk_ml_kem_ptr, sk_ml_kem_len) else {
        return false;
    };
    let ct_x25519: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(ct_x25519_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let Some(ct_ml_kem) = slice_from_ptr(ct_ml_kem_ptr, ct_ml_kem_len) else {
        return false;
    };

    let sk = HybridKemSecretKey { x25519: sk_x25519, ml_kem: sk_ml_kem.to_vec() };
    let ct = HybridCiphertext { x25519: ct_x25519, ml_kem: ct_ml_kem.to_vec() };
    let kem = HybridX25519MlKem;

    match kem.decapsulate(&sk, &ct) {
        Ok(ss) => {
            unsafe { std::ptr::copy_nonoverlapping(ss.0.as_ptr(), ss_out_ptr, 64) };
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
#[no_mangle]
pub extern "C" fn shekyl_address_encode(
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
        let Some(slice) = slice_from_ptr(ml_kem_ek_ptr, ml_kem_ek_len) else {
            return ShekylBuffer::null();
        };
        slice.to_vec()
    };

    let addr = shekyl_address::ShekylAddress::new(
        net,
        spend_key,
        view_key,
        ml_kem_ek,
    );

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
#[no_mangle]
pub extern "C" fn shekyl_address_decode(
    encoded_ptr: *const c_char,
    network_out: *mut u8,
    spend_key_out: *mut u8,
    view_key_out: *mut u8,
) -> ShekylBuffer {
    if encoded_ptr.is_null() || network_out.is_null()
        || spend_key_out.is_null() || view_key_out.is_null()
    {
        return ShekylBuffer::null();
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(encoded_ptr) };
    let encoded = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ShekylBuffer::null(),
    };

    match shekyl_address::ShekylAddress::decode(encoded) {
        Ok(addr) => {
            unsafe {
                *network_out = addr.network.as_u8();
                std::ptr::copy_nonoverlapping(addr.spend_key.as_ptr(), spend_key_out, 32);
                std::ptr::copy_nonoverlapping(addr.view_key.as_ptr(), view_key_out, 32);
            }
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
    let Some(hrp_bytes) = slice_from_ptr(hrp_ptr, hrp_len) else {
        return ShekylBuffer::null();
    };
    let hrp = match std::str::from_utf8(hrp_bytes) {
        Ok(s) => s,
        Err(_) => return ShekylBuffer::null(),
    };
    let Some(data) = slice_from_ptr(data_ptr, data_len) else {
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
#[no_mangle]
pub extern "C" fn shekyl_decode_blob(
    encoded_ptr: *const c_char,
    hrp_out: *mut u8,
    hrp_out_cap: usize,
    hrp_len_out: *mut usize,
    data_out: *mut u8,
    data_out_cap: usize,
    data_len_out: *mut usize,
) -> bool {
    if encoded_ptr.is_null() || hrp_out.is_null() || hrp_len_out.is_null()
        || data_out.is_null() || data_len_out.is_null()
    {
        return false;
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(encoded_ptr) };
    let encoded = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let (hrp, data) = match shekyl_encoding::decode_blob(encoded) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let hrp_bytes = hrp.as_bytes();
    if hrp_bytes.len() > hrp_out_cap || data.len() > data_out_cap {
        return false;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(hrp_bytes.as_ptr(), hrp_out, hrp_bytes.len());
        *hrp_len_out = hrp_bytes.len();
        std::ptr::copy_nonoverlapping(data.as_ptr(), data_out, data.len());
        *data_len_out = data.len();
    }
    true
}

// ─── FCMP++: Seed Derivation ────────────────────────────────────────────────

/// Derive Ed25519 spend secret key from master seed.
/// `seed_ptr`: 32 bytes. Writes 32 bytes to `out_ptr`.
#[no_mangle]
pub extern "C" fn shekyl_seed_derive_spend(seed_ptr: *const u8, out_ptr: *mut u8) -> bool {
    if seed_ptr.is_null() || out_ptr.is_null() {
        return false;
    }
    let seed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(seed_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let key = shekyl_crypto_pq::kem::SeedDerivation::derive_ed25519_spend(&seed);
    unsafe { std::ptr::copy_nonoverlapping(key.as_ptr(), out_ptr, 32) };
    true
}

/// Derive Ed25519 view secret key from master seed.
#[no_mangle]
pub extern "C" fn shekyl_seed_derive_view(seed_ptr: *const u8, out_ptr: *mut u8) -> bool {
    if seed_ptr.is_null() || out_ptr.is_null() {
        return false;
    }
    let seed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(seed_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let key = shekyl_crypto_pq::kem::SeedDerivation::derive_ed25519_view(&seed);
    unsafe { std::ptr::copy_nonoverlapping(key.as_ptr(), out_ptr, 32) };
    true
}

/// Derive ML-KEM-768 seed material from master seed.
/// Writes 64 bytes to `out_ptr`.
#[no_mangle]
pub extern "C" fn shekyl_seed_derive_ml_kem(seed_ptr: *const u8, out_ptr: *mut u8) -> bool {
    if seed_ptr.is_null() || out_ptr.is_null() {
        return false;
    }
    let seed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(seed_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let material = shekyl_crypto_pq::kem::SeedDerivation::derive_ml_kem_seed(&seed);
    unsafe { std::ptr::copy_nonoverlapping(material.as_ptr(), out_ptr, 64) };
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
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_hash_grow_selene(
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

    let n = num_children as usize;
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(new_children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_grow_selene(&existing_hash, offset as usize, &existing_child, &children)
    {
        Some(result) => {
            unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32) };
            true
        }
        None => false,
    }
}

/// Incrementally grow a Helios-layer chunk hash with new children.
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_hash_grow_helios(
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

    let n = num_children as usize;
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(new_children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_grow_helios(&existing_hash, offset as usize, &existing_child, &children)
    {
        Some(result) => {
            unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32) };
            true
        }
        None => false,
    }
}

/// Trim children from a Selene-layer chunk hash.
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_hash_trim_selene(
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

    let n = num_children as usize;
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_trim_selene(&existing_hash, offset as usize, &children, &grow_back)
    {
        Some(result) => {
            unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32) };
            true
        }
        None => false,
    }
}

/// Trim children from a Helios-layer chunk hash.
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_hash_trim_helios(
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

    let n = num_children as usize;
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_trim_helios(&existing_hash, offset as usize, &children, &grow_back)
    {
        Some(result) => {
            unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32) };
            true
        }
        None => false,
    }
}

/// Convert a Selene point to a Helios scalar (x-coordinate extraction).
///
/// Used when propagating Selene layer hashes up to the next Helios layer.
/// Writes 32 bytes to `out_scalar_ptr`.
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_selene_to_helios_scalar(
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
            unsafe { std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32) };
            true
        }
        None => false,
    }
}

/// Convert a Helios point to a Selene scalar (x-coordinate extraction).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_helios_to_selene_scalar(
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
            unsafe { std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32) };
            true
        }
        None => false,
    }
}

/// Get the Selene hash initialization point (32 bytes).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_selene_hash_init(out_ptr: *mut u8) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let init = shekyl_fcmp::tree::selene_hash_init();
    unsafe { std::ptr::copy_nonoverlapping(init.as_ptr(), out_ptr, 32) };
    true
}

/// Get the Helios hash initialization point (32 bytes).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_helios_hash_init(out_ptr: *mut u8) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let init = shekyl_fcmp::tree::helios_hash_init();
    unsafe { std::ptr::copy_nonoverlapping(init.as_ptr(), out_ptr, 32) };
    true
}

/// Return the number of scalars per leaf (4 for Shekyl: O.x, I.x, C.x, H(pqc_pk)).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_scalars_per_leaf() -> u32 {
    shekyl_fcmp::SCALARS_PER_LEAF as u32
}

/// Return the Selene-layer chunk width (branching factor = LAYER_ONE_LEN = 38).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_selene_chunk_width() -> u32 {
    shekyl_fcmp::SELENE_CHUNK_WIDTH as u32
}

/// Return the Helios-layer chunk width (branching factor = LAYER_TWO_LEN = 18).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_helios_chunk_width() -> u32 {
    shekyl_fcmp::HELIOS_CHUNK_WIDTH as u32
}

// ─── FCMP++: Ed25519 → Selene scalar conversion ────────────────────────────

/// Convert a compressed Ed25519 point (32 bytes) to a Selene scalar
/// (Wei25519 x-coordinate, 32 bytes).
///
/// Returns true on success (writes 32 bytes to `out_scalar_ptr`).
/// Returns false if the point cannot be decompressed or is the identity.
#[no_mangle]
pub extern "C" fn shekyl_ed25519_to_selene_scalar(
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
            unsafe { std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32) };
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
#[no_mangle]
pub extern "C" fn shekyl_construct_curve_tree_leaf(
    output_key_ptr: *const u8,
    commitment_ptr: *const u8,
    h_pqc_ptr: *const u8,
    leaf_out_ptr: *mut u8,
) -> bool {
    if output_key_ptr.is_null() || commitment_ptr.is_null()
        || h_pqc_ptr.is_null() || leaf_out_ptr.is_null()
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
            unsafe { std::ptr::copy_nonoverlapping(leaf.as_ptr(), leaf_out_ptr, 128) };
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
#[no_mangle]
pub extern "C" fn shekyl_sign_transaction(
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

    let Some(inputs_json) = slice_from_ptr(inputs_json_ptr, inputs_json_len) else {
        return ShekylSignResult::err(-1, "invalid inputs_json pointer".into());
    };
    let Some(outputs_json) = slice_from_ptr(outputs_json_ptr, outputs_json_len) else {
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
        Ok(proofs) => {
            match serde_json::to_vec(&proofs) {
                Ok(json) => ShekylSignResult::ok(json),
                Err(e) => ShekylSignResult::err(-3, format!("result serialization error: {e}")),
            }
        }
        Err(e) => {
            let code = tx_builder_error_code(&e);
            ShekylSignResult::err(code, e.to_string())
        }
    }
}

fn tx_builder_error_code(e: &shekyl_tx_builder::TxBuilderError) -> i32 {
    use shekyl_tx_builder::TxBuilderError::*;
    match e {
        NoInputs => -10,
        TooManyInputs(_) => -11,
        NoOutputs => -12,
        TooManyOutputs(_) => -13,
        ZeroInputAmount { .. } => -14,
        ZeroOutputAmount { .. } => -15,
        InputAmountOverflow => -16,
        OutputAmountOverflow => -17,
        InsufficientFunds { .. } => -18,
        EmptyLeafChunk { .. } => -19,
        LeafChunkTooLarge { .. } => -20,
        ZeroTreeDepth => -21,
        BranchLayerMismatch { .. } => -22,
        InvalidCombinedSsLength { .. } => -23,
        BulletproofError(_) => -24,
        FcmpProveError(_) => -25,
        PqcSignError { .. } => -26,
    }
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

    let tx_key = match arr32_from_ptr(tx_key_secret_ptr) {
        Some(v) => v,
        None => return fail,
    };
    let x_pk = match arr32_from_ptr(x25519_pk) {
        Some(v) => v,
        None => return fail,
    };
    let sk = match arr32_from_ptr(spend_key) {
        Some(v) => v,
        None => return fail,
    };
    let ek = match slice_from_ptr(ml_kem_ek, ml_kem_ek_len) {
        Some(v) => v,
        None => return fail,
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
    let x_sk = match arr32_from_ptr(x25519_sk) {
        Some(v) => v,
        None => return false,
    };
    let dk = match slice_from_ptr(ml_kem_dk, ml_kem_dk_len) {
        Some(v) => v,
        None => return false,
    };
    let ct_x = match arr32_from_ptr(kem_ct_x25519) {
        Some(v) => v,
        None => return false,
    };
    let ct_ml = match slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) {
        Some(v) => v,
        None => return false,
    };
    let o = match arr32_from_ptr(output_key) {
        Some(v) => v,
        None => return false,
    };
    let c = match arr32_from_ptr(commitment) {
        Some(v) => v,
        None => return false,
    };
    let ea = match slice_from_ptr(enc_amount, 8) {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        },
        None => return false,
    };
    let sk = match arr32_from_ptr(spend_key) {
        Some(v) => v,
        None => return false,
    };

    if y_out.is_null() || z_out.is_null() || k_amount_out.is_null()
        || amount_out.is_null() || pqc_pk_out.is_null() || pqc_sk_out.is_null()
        || h_pqc_out.is_null()
    {
        return false;
    }

    use shekyl_crypto_pq::output::scan_output;
    match scan_output(
        &x_sk, dk, &ct_x, ct_ml, &o, &c, &ea,
        amount_tag_on_chain, view_tag_on_chain, &sk, output_index,
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
        },
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
    let x_sk = match arr32_from_ptr(x25519_sk) {
        Some(v) => v,
        None => return false,
    };
    let dk = match slice_from_ptr(ml_kem_dk, ml_kem_dk_len) {
        Some(v) => v,
        None => return false,
    };
    let ct_x = match arr32_from_ptr(kem_ct_x25519) {
        Some(v) => v,
        None => return false,
    };
    let ct_ml = match slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) {
        Some(v) => v,
        None => return false,
    };
    let o = match arr32_from_ptr(output_key) {
        Some(v) => v,
        None => return false,
    };
    let c = match arr32_from_ptr(commitment) {
        Some(v) => v,
        None => return false,
    };
    let ea = match slice_from_ptr(enc_amount, 8) {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        },
        None => return false,
    };

    if ho_out.is_null() || y_out.is_null() || z_out.is_null() || k_amount_out.is_null()
        || amount_out.is_null() || recovered_spend_key_out.is_null()
        || pqc_pk_out.is_null() || pqc_sk_out.is_null() || h_pqc_out.is_null()
    {
        return false;
    }

    use shekyl_crypto_pq::output::scan_output_recover;
    match scan_output_recover(
        &x_sk, dk, &ct_x, ct_ml, &o, &c, &ea,
        amount_tag_on_chain, view_tag_on_chain, output_index,
    ) {
        Ok(recovered) => {
            std::ptr::copy_nonoverlapping(recovered.ho.as_ptr(), ho_out, 32);
            std::ptr::copy_nonoverlapping(recovered.y.as_ptr(), y_out, 32);
            std::ptr::copy_nonoverlapping(recovered.z.as_ptr(), z_out, 32);
            std::ptr::copy_nonoverlapping(recovered.k_amount.as_ptr(), k_amount_out, 32);
            *amount_out = recovered.amount;
            std::ptr::copy_nonoverlapping(recovered.recovered_spend_key.as_ptr(), recovered_spend_key_out, 32);
            *pqc_pk_out = ShekylBuffer::from_vec(recovered.pqc_public_key.clone());
            *pqc_sk_out = ShekylBuffer::from_vec(recovered.pqc_secret_key.clone());
            *h_pqc_out = recovered.h_pqc;
            true
        },
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

    let ss = match slice_from_ptr(combined_ss, 64) {
        Some(v) => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(v);
            arr
        },
        None => return fail,
    };
    let msg = match slice_from_ptr(message, message_len) {
        Some(v) => v,
        None => return fail,
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
        let mut overflow = 0u8;
        let q = shekyl_calc_per_block_staker_reward(1_000_000, 500_000, 2_000_000, 0, &mut overflow);
        assert_eq!(overflow, 0);
        assert_eq!(q, 250_000);
        assert_eq!(shekyl_calc_per_block_staker_reward(100, 0, 50, 0, std::ptr::null_mut()), 0);
        let q2 = shekyl_calc_per_block_staker_reward(10, 10, 1, 0, std::ptr::null_mut());
        assert_eq!(q2, 100);
    }

    #[test]
    fn test_per_block_staker_reward_overflow_flag() {
        let mut overflow = 0u8;
        let q = shekyl_calc_per_block_staker_reward(u64::MAX, u64::MAX, 1, 0, &mut overflow);
        assert_eq!(q, 0);
        assert_eq!(overflow, 1);
    }

    #[test]
    fn test_per_block_staker_reward_u128_denominator() {
        let mut overflow = 0u8;
        // Denominator = 1 << 64 = u64::MAX + 1 (hi=1, lo=0)
        let q = shekyl_calc_per_block_staker_reward(1_000_000, 1_000_000, 0, 1, &mut overflow);
        assert_eq!(overflow, 0);
        // numerator = 10^12, denominator = 2^64 ≈ 1.844 * 10^19
        // result = 10^12 / 1.844*10^19 ≈ 0 (floor)
        assert_eq!(q, 0);

        // Smaller hi value: denominator = (1 << 64) + 100
        let q2 = shekyl_calc_per_block_staker_reward(u64::MAX, 2, 100, 1, &mut overflow);
        assert_eq!(overflow, 0);
        // numerator = 2 * u64::MAX ≈ 3.69 * 10^19, denom ≈ 1.844 * 10^19 + 100
        // result ≈ 1 (floor division)
        assert_eq!(q2, 1);
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
            (50u64, 50u64, 1_000_000u64, 4_294_967_296_000_000_000u64, 100_000u64, 500_000u64, 900_000u64),
            (200, 50, 2_000_000_000_000_000_000, 4_294_967_296_000_000_000, 250_000, 500_000, 900_000),
            (500, 50, 3_000_000_000_000_000_000, 4_294_967_296_000_000_000, 400_000, 500_000, 900_000),
        ];
        for (txv, base, circ, total, stake, rate, cap) in cases {
            let ffi = shekyl_calc_burn_pct(txv, base, circ, total, stake, rate, cap);
            let direct = shekyl_economics::burn::calc_burn_pct(txv, base, circ, total, stake, rate, cap);
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

        let verified = shekyl_pqc_verify(
            1, // scheme_id for single-signer
            kp.public_key.ptr,
            kp.public_key.len,
            sig.signature.ptr,
            sig.signature.len,
            msg.as_ptr(),
            msg.len(),
        );
        assert!(verified);

        shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
        shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
        shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
    }

    #[test]
    fn test_ssl_cert_generation_ecdsa() {
        let mut key_pem = ShekylBuffer::null();
        let mut cert_pem = ShekylBuffer::null();
        let ok = shekyl_generate_ssl_certificate(
            &mut key_pem,
            &mut cert_pem,
        );
        assert!(ok);
        assert!(!key_pem.ptr.is_null());
        assert!(!cert_pem.ptr.is_null());
        let key_str = unsafe { std::str::from_utf8(std::slice::from_raw_parts(key_pem.ptr, key_pem.len)).unwrap() };
        let cert_str = unsafe { std::str::from_utf8(std::slice::from_raw_parts(cert_pem.ptr, cert_pem.len)).unwrap() };
        assert!(key_str.contains("BEGIN PRIVATE KEY"));
        assert!(cert_str.contains("BEGIN CERTIFICATE"));
        shekyl_buffer_free(key_pem.ptr, key_pem.len);
        shekyl_buffer_free(cert_pem.ptr, cert_pem.len);
    }

    #[test]
    fn test_memwipe_zeroes_buffer() {
        let mut buf = vec![0xABu8; 64];
        shekyl_memwipe(buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_page_size_nonzero() {
        let ps = shekyl_page_size();
        assert!(ps > 0, "page size should be > 0, got {}", ps);
        assert!(ps.is_power_of_two(), "page size should be power of 2");
    }

    #[test]
    fn test_pqc_verify_rejects_modified_signature() {
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
            unsafe { std::slice::from_raw_parts(sig.signature.ptr, sig.signature.len) }.to_vec();
        let last = sig_bytes.len() - 1;
        sig_bytes[last] ^= 0x01;

        let verified = shekyl_pqc_verify(
            1, // scheme_id for single-signer
            kp.public_key.ptr,
            kp.public_key.len,
            sig_bytes.as_ptr(),
            sig_bytes.len(),
            msg.as_ptr(),
            msg.len(),
        );
        assert!(!verified);

        shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
        shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
        shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_import_null_returns_null() {
        let handle = shekyl_frost_keys_import(std::ptr::null(), 0);
        assert!(handle.is_null());
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_import_invalid_data_returns_null() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF];
        let handle = shekyl_frost_keys_import(garbage.as_ptr(), garbage.len());
        assert!(handle.is_null());
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_validate_null_returns_false() {
        let valid = shekyl_frost_keys_validate(std::ptr::null(), 2, 3);
        assert!(!valid);
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_group_key_null_returns_false() {
        let mut out = [0u8; 32];
        let ok = shekyl_frost_keys_group_key(std::ptr::null(), out.as_mut_ptr());
        assert!(!ok);
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_keys_free_null_is_safe() {
        shekyl_frost_keys_free(std::ptr::null_mut());
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_sal_session_new_null_returns_null() {
        let session = shekyl_frost_sal_session_new(
            std::ptr::null(), std::ptr::null(), std::ptr::null(),
            std::ptr::null(), std::ptr::null(), std::ptr::null_mut(),
        );
        assert!(session.is_null());
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_sal_session_free_null_is_safe() {
        shekyl_frost_sal_session_free(std::ptr::null_mut());
    }

    #[cfg(feature = "multisig")]
    #[test]
    fn test_frost_sal_get_rerand_null_returns_empty() {
        let buf = shekyl_frost_sal_get_rerand(std::ptr::null());
        assert!(buf.ptr.is_null());
        assert_eq!(buf.len, 0);
    }
}
