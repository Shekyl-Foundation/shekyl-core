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

#[no_mangle]
pub extern "C" fn shekyl_buffer_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
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

/// Verify a message using canonical-encoded hybrid public key and signature.
///
/// Returns false on malformed input or failed verification.
#[no_mangle]
pub extern "C" fn shekyl_pqc_verify(
    public_key_ptr: *const u8,
    public_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    signature_ptr: *const u8,
    signature_len: usize,
) -> bool {
    let Some(public_key_bytes) = slice_from_ptr(public_key_ptr, public_key_len) else {
        return false;
    };
    let Some(message) = slice_from_ptr(message_ptr, message_len) else {
        return false;
    };
    let Some(signature_bytes) = slice_from_ptr(signature_ptr, signature_len) else {
        return false;
    };

    let scheme = HybridEd25519MlDsa;
    let public_key = match HybridPublicKey::from_canonical_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let signature = match HybridSignature::from_canonical_bytes(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    scheme.verify(&public_key, message, &signature).unwrap_or(false)
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
        let raw = unsafe { std::slice::from_raw_parts(hashes_ptr, count * 32) };
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
            kp.public_key.ptr,
            kp.public_key.len,
            msg.as_ptr(),
            msg.len(),
            sig.signature.ptr,
            sig.signature.len,
        );
        assert!(verified);

        shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
        shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
        shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
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
            kp.public_key.ptr,
            kp.public_key.len,
            msg.as_ptr(),
            msg.len(),
            sig_bytes.as_ptr(),
            sig_bytes.len(),
        );
        assert!(!verified);

        shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
        shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
        shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
    }
}
