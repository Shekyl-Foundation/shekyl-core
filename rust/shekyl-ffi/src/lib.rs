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

/// Verify a PQC-authenticated message.
///
/// `scheme_id = 1`: single-signer hybrid Ed25519 + ML-DSA-65.
/// `scheme_id = 2`: M-of-N multisig over hybrid keys.
///
/// For scheme_id 1, `pubkey_blob` and `sig_blob` are single canonical encodings.
/// For scheme_id 2, `pubkey_blob` is a MultisigKeyContainer and `sig_blob` is a
/// MultisigSigContainer in canonical encoding. Group ID check is skipped (pass
/// `shekyl_pqc_verify_multisig_with_group_id` for consensus verification).
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
        struct SystemInfo { _pad: [u8; 4], dw_page_size: u32, _rest: [u8; 52] }
        extern "system" {
            fn GetSystemInfo(info: *mut SystemInfo);
        }
        let mut info = SystemInfo { _pad: [0; 4], dw_page_size: 0, _rest: [0; 52] };
        unsafe { GetSystemInfo(&mut info); }
        info.dw_page_size as usize
    }
    #[cfg(not(any(unix, windows)))]
    {
        0
    }
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

/// Derive a per-output PQC keypair from combined KEM shared secret + output index.
///
/// Returns a ShekylPqcKeypair with the ML-DSA-65 public and secret keys.
#[no_mangle]
pub extern "C" fn shekyl_fcmp_derive_pqc_keypair(
    combined_ss_ptr: *const u8,
    output_index: u64,
) -> ShekylPqcKeypair {
    let fail = ShekylPqcKeypair {
        public_key: ShekylBuffer::null(),
        secret_key: ShekylBuffer::null(),
        success: false,
    };

    if combined_ss_ptr.is_null() {
        return fail;
    }
    let ss: [u8; 64] = unsafe {
        let mut buf = [0u8; 64];
        std::ptr::copy_nonoverlapping(combined_ss_ptr, buf.as_mut_ptr(), 64);
        buf
    };

    match shekyl_crypto_pq::derivation::derive_pqc_keypair(&ss, output_index) {
        Ok(mut kp) => {
            let pk = std::mem::take(&mut kp.public_key);
            let sk = std::mem::take(&mut kp.secret_key);
            ShekylPqcKeypair {
                public_key: ShekylBuffer::from_vec(pk),
                secret_key: ShekylBuffer::from_vec(sk),
                success: true,
            }
        }
        Err(_) => fail,
    }
}

/// Compute the expected FCMP++ proof size given input count and tree depth.
#[no_mangle]
pub extern "C" fn shekyl_fcmp_proof_len(num_inputs: u32, tree_depth: u8) -> usize {
    shekyl_fcmp::tree::proof_size(num_inputs as usize, tree_depth as usize)
}

/// Construct an FCMP++ proof (scaffold -- upstream integration pending).
///
/// `leaves_ptr`: packed 128-byte ShekylLeaf structs, `num_inputs` count.
/// `tree_paths_ptr`: concatenated per-input tree paths, each `tree_path_len` bytes.
/// `key_images_ptr`: packed 32-byte key images, `num_inputs` count.
/// `pseudo_outs_ptr`: packed 32-byte pseudo-outs, `num_inputs` count.
/// `pqc_hashes_ptr`: packed 32-byte H(pqc_pk) values, `num_inputs` count.
/// `tree_root_ptr`: 32-byte tree root.
///
/// Returns a ShekylBuffer containing the serialized proof, or null on error.
#[no_mangle]
pub extern "C" fn shekyl_fcmp_prove(
    leaves_ptr: *const u8,
    num_inputs: u32,
    tree_paths_ptr: *const u8,
    tree_path_len: u32,
    key_images_ptr: *const u8,
    pseudo_outs_ptr: *const u8,
    pqc_hashes_ptr: *const u8,
    tree_root_ptr: *const u8,
    tree_depth: u8,
) -> ShekylBuffer {
    let n = num_inputs as usize;
    let leaf_total = n * 128;
    let ki_total = n * 32;
    let po_total = n * 32;
    let ph_total = n * 32;
    let tp_total = n * tree_path_len as usize;

    let Some(leaf_bytes) = slice_from_ptr(leaves_ptr, leaf_total) else {
        return ShekylBuffer::null();
    };
    let Some(tp_bytes) = slice_from_ptr(tree_paths_ptr, tp_total) else {
        return ShekylBuffer::null();
    };
    let Some(ki_bytes) = slice_from_ptr(key_images_ptr, ki_total) else {
        return ShekylBuffer::null();
    };
    let Some(po_bytes) = slice_from_ptr(pseudo_outs_ptr, po_total) else {
        return ShekylBuffer::null();
    };
    let Some(ph_bytes) = slice_from_ptr(pqc_hashes_ptr, ph_total) else {
        return ShekylBuffer::null();
    };
    if tree_root_ptr.is_null() {
        return ShekylBuffer::null();
    }
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let mut inputs = Vec::with_capacity(n);
    for i in 0..n {
        let leaf_slice: &[u8; 128] = leaf_bytes[i * 128..(i + 1) * 128]
            .try_into()
            .unwrap();
        let leaf = shekyl_fcmp::leaf::ShekylLeaf::from_bytes(leaf_slice);

        let tp_start = i * tree_path_len as usize;
        let tp_end = tp_start + tree_path_len as usize;
        let tree_path = tp_bytes[tp_start..tp_end].to_vec();

        let mut ki = [0u8; 32];
        ki.copy_from_slice(&ki_bytes[i * 32..(i + 1) * 32]);

        let mut po = [0u8; 32];
        po.copy_from_slice(&po_bytes[i * 32..(i + 1) * 32]);

        let mut ph = [0u8; 32];
        ph.copy_from_slice(&ph_bytes[i * 32..(i + 1) * 32]);

        inputs.push(shekyl_fcmp::proof::ProveInput {
            leaf,
            tree_path,
            key_image: ki,
            pseudo_out: po,
            pqc_hash: shekyl_fcmp::leaf::PqcLeafScalar(ph),
        });
    }

    match shekyl_fcmp::proof::prove(&inputs, &tree_root, tree_depth) {
        Ok(proof) => ShekylBuffer::from_vec(proof.data),
        Err(_) => ShekylBuffer::null(),
    }
}

/// Verify an FCMP++ proof.
///
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
    if tree_root_ptr.is_null() || ki_count != po_count || ki_count != pqc_hash_count {
        return false;
    }
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
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

    shekyl_fcmp::proof::verify(&proof, &key_images, &pseudo_outs, &pqc_hashes, &tree_root, tree_depth)
        .unwrap_or(false)
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

// ─── FCMP++: Bech32m Address Encoding ───────────────────────────────────────

/// Encode a Shekyl Bech32m address from raw key material.
///
/// `spend_key_ptr`: 32 bytes. `view_key_ptr`: 32 bytes.
/// `ml_kem_ek_ptr`: 1184 bytes (ML-KEM-768 encapsulation key).
///
/// Returns a ShekylBuffer containing the UTF-8 encoded address string.
#[no_mangle]
pub extern "C" fn shekyl_address_encode(
    spend_key_ptr: *const u8,
    view_key_ptr: *const u8,
    ml_kem_ek_ptr: *const u8,
    ml_kem_ek_len: usize,
) -> ShekylBuffer {
    if spend_key_ptr.is_null() || view_key_ptr.is_null() || ml_kem_ek_ptr.is_null() {
        return ShekylBuffer::null();
    }

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
    let Some(ml_kem_ek) = slice_from_ptr(ml_kem_ek_ptr, ml_kem_ek_len) else {
        return ShekylBuffer::null();
    };

    let addr = shekyl_crypto_pq::address::ShekylAddress {
        version: shekyl_crypto_pq::address::ADDRESS_VERSION_V1,
        spend_key,
        view_key,
        ml_kem_encap_key: ml_kem_ek.to_vec(),
    };

    match addr.encode() {
        Ok(s) => ShekylBuffer::from_vec(s.into_bytes()),
        Err(_) => ShekylBuffer::null(),
    }
}

/// Decode a Bech32m-encoded Shekyl address.
///
/// `encoded_ptr`: null-terminated UTF-8 string.
/// Writes: 32 bytes to `spend_key_out`, 32 bytes to `view_key_out`.
/// Returns ML-KEM encapsulation key in a ShekylBuffer (1184 bytes).
#[no_mangle]
pub extern "C" fn shekyl_address_decode(
    encoded_ptr: *const c_char,
    spend_key_out: *mut u8,
    view_key_out: *mut u8,
) -> ShekylBuffer {
    if encoded_ptr.is_null() || spend_key_out.is_null() || view_key_out.is_null() {
        return ShekylBuffer::null();
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(encoded_ptr) };
    let encoded = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ShekylBuffer::null(),
    };

    match shekyl_crypto_pq::address::ShekylAddress::decode(encoded) {
        Ok(addr) => {
            unsafe {
                std::ptr::copy_nonoverlapping(addr.spend_key.as_ptr(), spend_key_out, 32);
                std::ptr::copy_nonoverlapping(addr.view_key.as_ptr(), view_key_out, 32);
            }
            ShekylBuffer::from_vec(addr.ml_kem_encap_key)
        }
        Err(_) => ShekylBuffer::null(),
    }
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
}
