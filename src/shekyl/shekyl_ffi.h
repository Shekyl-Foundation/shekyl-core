// C++ declarations for functions exported by the Rust shekyl-ffi crate.
// Link against libshekyl_ffi.a to resolve these symbols.

#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

// Version / init
const char* shekyl_rust_version();
bool shekyl_rust_init();
const char* shekyl_active_consensus_module();

// Generic Rust-owned buffer
struct ShekylBuffer {
    uint8_t* ptr;
    size_t len;
};

void shekyl_buffer_free(uint8_t* ptr, size_t len);

// PQC: Hybrid signatures
struct ShekylPqcKeypair {
    ShekylBuffer public_key;
    ShekylBuffer secret_key;
    bool success;
};

struct ShekylPqcSignatureResult {
    ShekylBuffer signature;
    bool success;
};

ShekylPqcKeypair shekyl_pqc_keypair_generate();
ShekylPqcSignatureResult shekyl_pqc_sign(
    const uint8_t* secret_key_ptr,
    size_t secret_key_len,
    const uint8_t* message_ptr,
    size_t message_len);
bool shekyl_pqc_verify(
    uint8_t scheme_id,
    const uint8_t* pubkey_blob,
    size_t pubkey_len,
    const uint8_t* sig_blob,
    size_t sig_len,
    const uint8_t* message,
    size_t message_len);

uint8_t shekyl_pqc_verify_debug(
    uint8_t scheme_id,
    const uint8_t* pubkey_blob,
    size_t pubkey_len,
    const uint8_t* sig_blob,
    size_t sig_len,
    const uint8_t* message,
    size_t message_len);

bool shekyl_pqc_multisig_group_id(
    const uint8_t* keys_ptr,
    size_t keys_len,
    uint8_t* out_ptr);

// Crypto: Hash functions
bool shekyl_cn_fast_hash(
    const uint8_t* data_ptr,
    size_t data_len,
    uint8_t* out_ptr);

bool shekyl_tree_hash(
    const uint8_t* hashes_ptr,
    size_t count,
    uint8_t* out_ptr);

// Release rate
uint64_t shekyl_calc_release_multiplier(
    uint64_t tx_volume_avg,
    uint64_t tx_volume_baseline,
    uint64_t release_min,
    uint64_t release_max);

uint64_t shekyl_apply_release_multiplier(
    uint64_t base_reward,
    uint64_t multiplier);

// Fee burn
uint64_t shekyl_calc_burn_pct(
    uint64_t tx_volume,
    uint64_t tx_baseline,
    uint64_t circulating_supply,
    uint64_t total_supply,
    uint64_t stake_ratio,
    uint64_t burn_base_rate,
    uint64_t burn_cap);

struct ShekylBurnSplit {
    uint64_t miner_fee_income;
    uint64_t staker_pool_amount;
    uint64_t actually_destroyed;
};

ShekylBurnSplit shekyl_compute_burn_split(
    uint64_t total_fees,
    uint64_t burn_pct,
    uint64_t staker_pool_share);

// Staking
uint64_t shekyl_stake_weight(uint64_t amount, uint8_t tier_id);
uint64_t shekyl_stake_lock_blocks(uint8_t tier_id);
uint64_t shekyl_stake_yield_multiplier(uint8_t tier_id);
uint64_t shekyl_calc_stake_ratio(uint64_t total_staked, uint64_t circulating_supply);

// Emission share (Component 4)
uint64_t shekyl_calc_emission_share(
    uint64_t current_height,
    uint64_t genesis_height,
    uint64_t initial_share,
    uint64_t annual_decay,
    uint64_t blocks_per_year);

struct ShekylEmissionSplit {
    uint64_t miner_emission;
    uint64_t staker_emission;
};

ShekylEmissionSplit shekyl_split_block_emission(
    uint64_t block_emission,
    uint64_t effective_share);

// SSL certificate generation (replaces deprecated OpenSSL RSA/EC_KEY APIs)
bool shekyl_generate_ssl_certificate(
    ShekylBuffer* key_pem_out,
    ShekylBuffer* cert_pem_out);

// ─── FCMP++: Proof and tree operations ──────────────────────────────────────

// Compute H(pqc_pk) leaf scalar. Writes 32 bytes to out_ptr.
bool shekyl_fcmp_pqc_leaf_hash(
    const uint8_t* pqc_pk_ptr,
    size_t pqc_pk_len,
    uint8_t* out_ptr);

// Derive per-output ML-DSA-65 keypair from combined KEM shared secret.
// combined_ss_ptr: 64 bytes.
ShekylPqcKeypair shekyl_fcmp_derive_pqc_keypair(
    const uint8_t* combined_ss_ptr,
    uint64_t output_index);

// Expected proof size for given inputs and tree depth.
size_t shekyl_fcmp_proof_len(uint32_t num_inputs, uint8_t tree_depth);

// Construct FCMP++ proof.
ShekylBuffer shekyl_fcmp_prove(
    const uint8_t* leaves_ptr,
    uint32_t num_inputs,
    const uint8_t* tree_paths_ptr,
    uint32_t tree_path_len,
    const uint8_t* key_images_ptr,
    const uint8_t* pseudo_outs_ptr,
    const uint8_t* pqc_hashes_ptr,
    const uint8_t* tree_root_ptr,
    uint8_t tree_depth);

// Verify FCMP++ proof. pqc_hash_count must equal ki_count.
bool shekyl_fcmp_verify(
    const uint8_t* proof_ptr,
    size_t proof_len,
    const uint8_t* key_images_ptr,
    size_t ki_count,
    const uint8_t* pseudo_outs_ptr,
    size_t po_count,
    const uint8_t* pqc_pk_hashes_ptr,
    size_t pqc_hash_count,
    const uint8_t* tree_root_ptr,
    uint8_t tree_depth);

// Convert raw output tuples into serialized 4-scalar leaves.
ShekylBuffer shekyl_fcmp_outputs_to_leaves(
    const uint8_t* outputs_ptr,
    size_t count);

// ─── FCMP++: KEM operations ─────────────────────────────────────────────────

// Generate hybrid X25519 + ML-KEM-768 keypair.
ShekylPqcKeypair shekyl_kem_keypair_generate();

// Encapsulate to hybrid public key.
// pk_ml_kem_ptr: 1184 bytes (ML-KEM-768 encap key).
// ct_out: receives ciphertext buffer (32 + 1088 bytes).
// ss_out_ptr: receives 64-byte combined shared secret.
bool shekyl_kem_encapsulate(
    const uint8_t* pk_x25519_ptr,
    const uint8_t* pk_ml_kem_ptr,
    size_t pk_ml_kem_len,
    ShekylBuffer* ct_out,
    uint8_t* ss_out_ptr);

// Decapsulate hybrid ciphertext.
// ct_ml_kem_ptr: 1088 bytes (ML-KEM-768 ciphertext).
// ss_out_ptr: receives 64-byte combined shared secret.
bool shekyl_kem_decapsulate(
    const uint8_t* sk_x25519_ptr,
    const uint8_t* sk_ml_kem_ptr,
    size_t sk_ml_kem_len,
    const uint8_t* ct_x25519_ptr,
    const uint8_t* ct_ml_kem_ptr,
    size_t ct_ml_kem_len,
    uint8_t* ss_out_ptr);

// ─── FCMP++: Bech32m address encoding ───────────────────────────────────────

// Encode Shekyl Bech32m address. Returns UTF-8 string in ShekylBuffer.
ShekylBuffer shekyl_address_encode(
    const uint8_t* spend_key_ptr,
    const uint8_t* view_key_ptr,
    const uint8_t* ml_kem_ek_ptr,
    size_t ml_kem_ek_len);

// Decode Shekyl Bech32m address.
// Writes 32 bytes each to spend_key_out and view_key_out.
// Returns ML-KEM encap key (1184 bytes) in ShekylBuffer.
ShekylBuffer shekyl_address_decode(
    const char* encoded_ptr,
    uint8_t* spend_key_out,
    uint8_t* view_key_out);

// ─── FCMP++: Seed derivation ────────────────────────────────────────────────

// Derive Ed25519 spend key from 32-byte master seed. Writes 32 bytes.
bool shekyl_seed_derive_spend(const uint8_t* seed_ptr, uint8_t* out_ptr);

// Derive Ed25519 view key from 32-byte master seed. Writes 32 bytes.
bool shekyl_seed_derive_view(const uint8_t* seed_ptr, uint8_t* out_ptr);

// Derive ML-KEM-768 seed material from 32-byte master seed. Writes 64 bytes.
bool shekyl_seed_derive_ml_kem(const uint8_t* seed_ptr, uint8_t* out_ptr);

// Daemon RPC (Axum)
typedef struct ShekylDaemonRpcHandle ShekylDaemonRpcHandle;

// Start the Axum daemon RPC server on a dedicated Tokio runtime.
// rpc_server_ptr: pointer to an initialized core_rpc_server.
// bind_addr: "ip:port" C string.
// restricted: true to block admin-only endpoints.
// Returns an opaque handle, or NULL on failure.
ShekylDaemonRpcHandle* shekyl_daemon_rpc_start(
    void* rpc_server_ptr,
    const char* bind_addr,
    bool restricted);

// Gracefully stop the Axum daemon RPC server and free the handle.
void shekyl_daemon_rpc_stop(ShekylDaemonRpcHandle* handle);

} // extern "C"

// Secure memory primitives are declared in shekyl/shekyl_secure_mem.h
// (C-compatible header used by both memwipe.c and mlocker.cpp)
