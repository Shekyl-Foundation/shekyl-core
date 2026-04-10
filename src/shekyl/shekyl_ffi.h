// C++ declarations for functions exported by the Rust shekyl-ffi crate.
// Link against libshekyl_ffi.a to resolve these symbols.

#pragma once

#include <cstddef>
#include <cstdint>

// Fixed-size witness header per input in the FCMP++ prove/verify FFI.
// Layout: [O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]
//   x, y = SAL spend secrets (O = xG + yT)
//   z    = Pedersen commitment mask (C = zG + amount*H)
//   a    = pseudo-out blinding factor (r_c = a - z)
#define SHEKYL_PROVE_WITNESS_HEADER_BYTES 256

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

// Free a buffer allocated by a Rust FFI export. `len` MUST equal the original
// ShekylBuffer::len returned by the paired Rust call. Mismatched lengths cause UB.
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

#ifndef NDEBUG
uint8_t shekyl_pqc_verify_debug(
    uint8_t scheme_id,
    const uint8_t* pubkey_blob,
    size_t pubkey_len,
    const uint8_t* sig_blob,
    size_t sig_len,
    const uint8_t* message,
    size_t message_len);
#endif

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
/// Per-block staker reward share: (total_reward_at_height * stake_weight) / total_weighted_stake.
/// total_weighted_stake is passed as a 128-bit value split into lo/hi u64 halves.
/// If overflow_out is non-null, *overflow_out is set to 1 when the quotient does not fit in u64.
uint64_t shekyl_calc_per_block_staker_reward(
    uint64_t total_reward_at_height,
    uint64_t stake_weight,
    uint64_t total_weighted_stake_lo,
    uint64_t total_weighted_stake_hi,
    uint8_t *overflow_out);
uint32_t shekyl_stake_tier_count(void);
/// Null-terminated UTF-8 tier name, or null if tier_id is invalid.
const char *shekyl_stake_tier_name(uint8_t tier_id);
uint64_t shekyl_stake_max_claim_range(void);
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

// ─── FCMP++: Generators ─────────────────────────────────────────────────────

// Write the compressed Ed25519 bytes of generator T (32 bytes) to out_ptr.
// T = hash_to_point(keccak256("Monero Generator T")) — used in two-component
// output keys: O = xG + yT.
void shekyl_generator_T(uint8_t* out_ptr);

// ─── FCMP++: Proof and tree operations ──────────────────────────────────────

// Compute H(pqc_pk) leaf scalar. Writes 32 bytes to out_ptr.
bool shekyl_fcmp_pqc_leaf_hash(
    const uint8_t* pqc_pk_ptr,
    size_t pqc_pk_len,
    uint8_t* out_ptr);

// Derive h_pqc = H(hybrid_public_key) from combined KEM shared secret and
// output index. Secret key derived internally and zeroized; never returned.
// combined_ss_ptr: 64 bytes. h_pqc_out: 32-byte caller-provided buffer.
bool shekyl_derive_pqc_leaf_hash(
    const uint8_t* combined_ss_ptr,
    uint64_t output_index,
    uint8_t* h_pqc_out);

// Derive canonical hybrid public key bytes from combined KEM shared secret
// and output index. Secret key derived internally and zeroized; never returned.
// combined_ss_ptr: 64 bytes. Returns heap-allocated buffer; free with
// shekyl_buffer_free.
ShekylBuffer shekyl_derive_pqc_public_key(
    const uint8_t* combined_ss_ptr,
    uint64_t output_index);

// Derive all per-output secrets from the combined KEM shared secret.
// Writes: ho(32), y(32), z(32), k_amount(32), view_tag_combined(1),
// amount_tag(1), ml_dsa_seed(32). Returns true on success.
bool shekyl_derive_output_secrets(
    const uint8_t* combined_ss_ptr,
    uint32_t combined_ss_len,
    uint64_t output_index,
    uint8_t* out_ho,
    uint8_t* out_y,
    uint8_t* out_z,
    uint8_t* out_k_amount,
    uint8_t* out_view_tag_combined,
    uint8_t* out_amount_tag,
    uint8_t* out_ml_dsa_seed);

// Derive X25519-only view tag for scanner pre-filtering.
// x25519_ss_ptr: exactly 32 bytes. Returns 1-byte tag.
uint8_t shekyl_derive_view_tag_x25519(
    const uint8_t* x25519_ss_ptr,
    uint64_t output_index);

// Expected proof size for given inputs and tree depth.
size_t shekyl_fcmp_proof_len(uint32_t num_inputs, uint8_t tree_depth);

// FCMP++ prove result (proof blob + pseudo-outs).
struct ShekylFcmpProveResult {
    ShekylBuffer proof;
    ShekylBuffer pseudo_outs;    // num_inputs * 32 bytes (C_tilde compressed)
    bool success;
};

// Construct FCMP++ proof from variable-length witness blob.
// witness_ptr / witness_len: serialized witness for all inputs.
// Per input: fixed header (256 bytes) + leaf chunk + C1/C2 branch layers.
// Header: [O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]
//   y = SAL output-key secret (0 for legacy one-time addresses)
//   z = Pedersen commitment mask
//   a = desired pseudo-out blinding factor
// See shekyl-ffi crate docs for the full wire format specification.
ShekylFcmpProveResult shekyl_fcmp_prove(
    const uint8_t* witness_ptr,
    size_t witness_len,
    uint32_t num_inputs,
    const uint8_t* tree_root_ptr,
    uint8_t tree_depth,
    const uint8_t* signable_tx_hash_ptr);

// Verify FCMP++ proof with batch verification.
// signable_tx_hash_ptr: 32-byte transaction binding hash.
// pqc_hash_count must equal ki_count.
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
    uint8_t tree_depth,
    const uint8_t* signable_tx_hash_ptr);

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

// ─── Bech32m address encoding ────────────────────────────────────────────────

// Encode Shekyl Bech32m address. Returns UTF-8 string in ShekylBuffer.
// network: 0=mainnet, 1=testnet, 2=stagenet.
ShekylBuffer shekyl_address_encode(
    uint8_t network,
    const uint8_t* spend_key_ptr,
    const uint8_t* view_key_ptr,
    const uint8_t* ml_kem_ek_ptr,
    size_t ml_kem_ek_len);

// Decode Shekyl Bech32m address.
// network_out: receives network discriminant (0=mainnet, 1=testnet, 2=stagenet).
// Writes 32 bytes each to spend_key_out and view_key_out.
// Returns ML-KEM encap key in ShekylBuffer (1184 bytes, or 0 if classical-only).
ShekylBuffer shekyl_address_decode(
    const char* encoded_ptr,
    uint8_t* network_out,
    uint8_t* spend_key_out,
    uint8_t* view_key_out);

// ─── Bech32m blob encoding ──────────────────────────────────────────────────

// Encode arbitrary binary data as Bech32m with the given HRP.
// Returns UTF-8 encoded Bech32m string in ShekylBuffer, or null on failure.
ShekylBuffer shekyl_encode_blob(
    const uint8_t* hrp_ptr,
    size_t hrp_len,
    const uint8_t* data_ptr,
    size_t data_len);

// Decode a Bech32m string into HRP + payload.
// hrp_out/hrp_out_cap: buffer for decoded HRP (UTF-8, not null-terminated).
// hrp_len_out: receives actual HRP byte length.
// data_out/data_out_cap: buffer for decoded payload.
// data_len_out: receives actual payload byte length.
// Returns true on success, false if decoding fails or buffers are too small.
bool shekyl_decode_blob(
    const char* encoded_ptr,
    uint8_t* hrp_out,
    size_t hrp_out_cap,
    size_t* hrp_len_out,
    uint8_t* data_out,
    size_t data_out_cap,
    size_t* data_len_out);

// ─── Output Construction / Scanning / PQC Signing ────────────────────────────

// Typed struct for FCMP++ prover inputs (replaces hand-counted memcpy offsets).
struct ProveInputFields {
    uint8_t output_key[32];
    uint8_t key_image_gen[32];
    uint8_t commitment[32];
    uint8_t h_pqc[32];
    uint8_t spend_key_x[32];
    uint8_t spend_key_y[32];
    uint8_t commitment_mask[32];
    uint8_t pseudo_out_blind[32];
};

// Build the 256-byte witness header from a typed ProveInputFields.
// out_buf must point to at least 256 writable bytes.
bool shekyl_fcmp_build_witness_header(
    const ProveInputFields* input,
    uint8_t* out_buf);

// Result of construct_output.
struct ShekylOutputData {
    uint8_t output_key[32];
    uint8_t commitment[32];
    uint8_t enc_amount[8];
    uint8_t amount_tag;
    uint8_t view_tag_x25519;
    uint8_t kem_ciphertext_x25519[32];
    ShekylBuffer kem_ciphertext_ml_kem;
    ShekylBuffer pqc_public_key;
    uint8_t h_pqc[32];
    uint8_t y[32];
    uint8_t z[32];
    uint8_t k_amount[32];
    bool success;
};

// Construct a two-component output via unified HKDF path.
// tx_key_secret: 32-byte ephemeral transaction secret key (drives KEM encapsulation).
ShekylOutputData shekyl_construct_output(
    const uint8_t* tx_key_secret,
    const uint8_t* x25519_pk,
    const uint8_t* ml_kem_ek,
    size_t ml_kem_ek_len,
    const uint8_t* spend_key,
    uint64_t amount,
    uint64_t output_index);

// Free heap-allocated fields in ShekylOutputData.
void shekyl_output_data_free(ShekylOutputData* data);

// Scan an output: KEM decap + HKDF + verification.
// y_out, z_out, k_amount_out: caller-owned 32-byte buffers for secrets.
// Caller is responsible for wiping these after use.
bool shekyl_scan_output(
    const uint8_t* x25519_sk,
    const uint8_t* ml_kem_dk,
    size_t ml_kem_dk_len,
    const uint8_t* kem_ct_x25519,
    const uint8_t* kem_ct_ml_kem,
    size_t kem_ct_ml_kem_len,
    const uint8_t* output_key,
    const uint8_t* commitment,
    const uint8_t* enc_amount,
    uint8_t amount_tag_on_chain,
    uint8_t view_tag_on_chain,
    const uint8_t* spend_key,
    uint64_t output_index,
    uint8_t* y_out,
    uint8_t* z_out,
    uint8_t* k_amount_out,
    uint64_t* amount_out,
    ShekylBuffer* pqc_pk_out,
    ShekylBuffer* pqc_sk_out,
    uint8_t* h_pqc_out);

// Scan an output recovering the spend key B' = O - ho*G - y*T.
// Caller looks up B' in subaddress table to determine ownership.
bool shekyl_scan_output_recover(
    const uint8_t* x25519_sk,
    const uint8_t* ml_kem_dk,
    size_t ml_kem_dk_len,
    const uint8_t* kem_ct_x25519,
    const uint8_t* kem_ct_ml_kem,
    size_t kem_ct_ml_kem_len,
    const uint8_t* output_key,
    const uint8_t* commitment,
    const uint8_t* enc_amount,
    uint8_t amount_tag_on_chain,
    uint8_t view_tag_on_chain,
    uint64_t output_index,
    uint8_t* ho_out,
    uint8_t* y_out,
    uint8_t* z_out,
    uint8_t* k_amount_out,
    uint64_t* amount_out,
    uint8_t* recovered_spend_key_out,
    ShekylBuffer* pqc_pk_out,
    ShekylBuffer* pqc_sk_out,
    uint8_t* h_pqc_out);

// ─── Merged scan + key image (PR-wallet Phase 1b) ────────────────────────────

// Scan an output, recover all secrets, and compute the key image — all in one
// call.  All secret output pointers write directly into transfer_details fields
// (direct-write-to-destination pattern: no intermediate scratch buffers).
//
// persist_combined_ss: if false, Rust wipes combined_ss internally and
//   combined_ss_out is ignored (pass nullptr). If true, Rust writes directly
//   to combined_ss_out (64 bytes).
//
// Returns true on success (output belongs to this wallet).
bool shekyl_scan_and_recover(
    const uint8_t* x25519_sk,
    const uint8_t* ml_kem_dk,
    size_t ml_kem_dk_len,
    const uint8_t* kem_ct_x25519,
    const uint8_t* kem_ct_ml_kem,
    size_t kem_ct_ml_kem_len,
    const uint8_t* output_key,
    const uint8_t* commitment,
    const uint8_t* enc_amount,
    uint8_t amount_tag_on_chain,
    uint8_t view_tag_on_chain,
    uint64_t output_index,
    const uint8_t* spend_secret_key,
    const uint8_t* hp_of_O,
    bool persist_combined_ss,
    uint8_t* ho_out,
    uint8_t* y_out,
    uint8_t* z_out,
    uint8_t* k_amount_out,
    uint64_t* amount_out,
    uint8_t* recovered_spend_key_out,
    uint8_t* key_image_out,
    uint8_t* combined_ss_out,
    ShekylBuffer* pqc_pk_out,
    ShekylBuffer* pqc_sk_out,
    uint8_t* h_pqc_out);

// ─── Key image computation (2 remaining sites) ──────────────────────────────

// Compute key image from persisted combined_ss + output_index.
// Used at stake claim (1 site). Derives ho from HKDF, computes KI = (ho+b)*Hp(O).
// out_ki: 32 writable bytes for the key image.
bool shekyl_compute_output_key_image(
    const uint8_t* combined_ss,
    uint64_t output_index,
    const uint8_t* spend_secret_key,
    const uint8_t* hp_of_O,
    uint8_t* out_ki);

// Compute key image from pre-derived ho scalar.
// Used at tx_source_entry boundary (1 site). Computes KI = (ho+b)*Hp(O).
// ho: 32-byte HKDF-derived secret scalar.
// out_ki: 32 writable bytes for the key image.
bool shekyl_compute_output_key_image_from_ho(
    const uint8_t* ho,
    const uint8_t* spend_secret_key,
    const uint8_t* hp_of_O,
    uint8_t* out_ki);

// ─── Proof secrets helper ────────────────────────────────────────────────────

// Derive the ProofSecrets projection from combined_ss.
// out_ho, out_y, out_z, out_k_amount: each 32 writable bytes.
// Callers pass destination addresses directly (no scratch buffers).
bool shekyl_derive_proof_secrets(
    const uint8_t* combined_ss,
    uint64_t output_index,
    uint8_t* out_ho,
    uint8_t* out_y,
    uint8_t* out_z,
    uint8_t* out_k_amount);

// ─── Wallet proofs (6 exports) ───────────────────────────────────────────────

// Generate outbound transaction proof.
// tx_key_secret: 32-byte ephemeral tx secret key.
// Returns proof bytes via ShekylBuffer (caller frees with shekyl_buffer_free).
bool shekyl_generate_tx_proof_outbound(
    const uint8_t* tx_key_secret,
    const uint8_t* txid,
    const uint8_t* recipient_address,
    size_t recipient_address_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* kem_cts_x25519,
    const uint8_t* kem_cts_ml_kem,
    size_t kem_cts_ml_kem_len,
    const uint8_t* output_keys,
    const uint8_t* commitments,
    const uint8_t* enc_amounts,
    const uint8_t* amount_tags,
    uint32_t output_count,
    ShekylBuffer* proof_out);

// Verify outbound transaction proof.
bool shekyl_verify_tx_proof_outbound(
    const uint8_t* proof_bytes,
    size_t proof_len,
    const uint8_t* txid,
    const uint8_t* recipient_address,
    size_t recipient_address_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* kem_cts_x25519,
    const uint8_t* kem_cts_ml_kem,
    size_t kem_cts_ml_kem_len,
    const uint8_t* output_keys,
    const uint8_t* commitments,
    const uint8_t* enc_amounts,
    const uint8_t* amount_tags,
    uint32_t output_count,
    uint64_t* amounts_out);

// Generate inbound transaction proof.
bool shekyl_generate_tx_proof_inbound(
    const uint8_t* view_secret_key,
    const uint8_t* ml_kem_dk,
    size_t ml_kem_dk_len,
    const uint8_t* txid,
    const uint8_t* sender_address,
    size_t sender_address_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* kem_cts_x25519,
    const uint8_t* kem_cts_ml_kem,
    size_t kem_cts_ml_kem_len,
    const uint8_t* output_keys,
    const uint8_t* commitments,
    const uint8_t* enc_amounts,
    const uint8_t* amount_tags,
    uint32_t output_count,
    ShekylBuffer* proof_out);

// Verify inbound transaction proof.
bool shekyl_verify_tx_proof_inbound(
    const uint8_t* proof_bytes,
    size_t proof_len,
    const uint8_t* view_public_key,
    const uint8_t* txid,
    const uint8_t* sender_address,
    size_t sender_address_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* kem_cts_x25519,
    const uint8_t* kem_cts_ml_kem,
    size_t kem_cts_ml_kem_len,
    const uint8_t* output_keys,
    const uint8_t* commitments,
    const uint8_t* enc_amounts,
    const uint8_t* amount_tags,
    uint32_t output_count,
    uint64_t* amounts_out);

// Generate reserve proof.
bool shekyl_generate_reserve_proof(
    const uint8_t* spend_secret_key,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* combined_ss_array,
    const uint64_t* output_indices,
    const uint8_t* output_keys,
    const uint8_t* hp_of_O_array,
    uint32_t output_count,
    ShekylBuffer* proof_out);

// Verify reserve proof.
// enc_amounts: 8 * output_count bytes — fetched from the blockchain, NOT from the proof.
bool shekyl_verify_reserve_proof(
    const uint8_t* proof_bytes,
    size_t proof_len,
    const uint8_t* spend_public_key,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* output_keys,
    const uint8_t* commitments,
    const uint8_t* enc_amounts,
    const uint8_t* hp_of_O_array,
    uint32_t output_count,
    uint64_t* total_amount_out);

// ─── Wallet cache encryption (AEAD with AAD binding) ─────────────────────────

// Encrypt wallet cache plaintext with XChaCha20-Poly1305 AEAD.
// cache_format_version is bound into the Poly1305 AAD — version changes
// invalidate existing ciphertext.
// password_derived_key: 32 bytes.
// Returns encrypted blob via out_buf. Caller frees with shekyl_buffer_free.
bool shekyl_encrypt_wallet_cache(
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t cache_format_version,
    const uint8_t* password_derived_key,
    ShekylBuffer* out_buf);

// Decrypt wallet cache ciphertext.
// expected_version: asserted before decryption — returns distinct error for
//   version mismatch vs auth failure vs corruption.
// Returns 0 on success, negative on error:
//   -1: version mismatch
//   -2: authentication failure (AAD/tag mismatch)
//   -3: invalid format / too short
//   -4: null pointer argument
int32_t shekyl_decrypt_wallet_cache(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t expected_version,
    const uint8_t* password_derived_key,
    ShekylBuffer* out_buf);

// PQC auth result (hybrid pk + signature).
struct ShekylPqcAuthResult {
    ShekylBuffer hybrid_public_key;
    ShekylBuffer signature;
    bool success;
};

// Sign using HKDF-derived hybrid PQC keypair. ML-DSA secret key never
// crosses this boundary — derived, used, and wiped entirely in Rust.
ShekylPqcAuthResult shekyl_sign_pqc_auth(
    const uint8_t* combined_ss,
    uint64_t output_index,
    const uint8_t* message,
    size_t message_len);

void shekyl_pqc_auth_result_free(ShekylPqcAuthResult* result);

// ─── FCMP++: Seed derivation ────────────────────────────────────────────────

// Derive Ed25519 spend key from 32-byte master seed. Writes 32 bytes.
bool shekyl_seed_derive_spend(const uint8_t* seed_ptr, uint8_t* out_ptr);

// Derive Ed25519 view key from 32-byte master seed. Writes 32 bytes.
bool shekyl_seed_derive_view(const uint8_t* seed_ptr, uint8_t* out_ptr);

// Derive ML-KEM-768 seed material from 32-byte master seed. Writes 64 bytes.
bool shekyl_seed_derive_ml_kem(const uint8_t* seed_ptr, uint8_t* out_ptr);

// ─── FCMP++: Curve tree hash operations ─────────────────────────────────────

// Incrementally grow a Selene-layer chunk hash (leaf layer + even internal layers).
// existing_hash_ptr: 32 bytes (Selene point, use hash_init for new chunk).
// existing_child_at_offset_ptr: 32 bytes (old Selene scalar at offset, zero for fresh).
// new_children_ptr: num_children * 32 bytes (Selene scalars).
// out_hash_ptr: 32 bytes output (new Selene point).
bool shekyl_curve_tree_hash_grow_selene(
    const uint8_t* existing_hash_ptr,
    uint64_t offset,
    const uint8_t* existing_child_at_offset_ptr,
    const uint8_t* new_children_ptr,
    uint64_t num_children,
    uint8_t* out_hash_ptr);

// Incrementally grow a Helios-layer chunk hash (odd internal layers).
bool shekyl_curve_tree_hash_grow_helios(
    const uint8_t* existing_hash_ptr,
    uint64_t offset,
    const uint8_t* existing_child_at_offset_ptr,
    const uint8_t* new_children_ptr,
    uint64_t num_children,
    uint8_t* out_hash_ptr);

// Trim children from a Selene-layer chunk hash.
bool shekyl_curve_tree_hash_trim_selene(
    const uint8_t* existing_hash_ptr,
    uint64_t offset,
    const uint8_t* children_ptr,
    uint64_t num_children,
    const uint8_t* child_to_grow_back_ptr,
    uint8_t* out_hash_ptr);

// Trim children from a Helios-layer chunk hash.
bool shekyl_curve_tree_hash_trim_helios(
    const uint8_t* existing_hash_ptr,
    uint64_t offset,
    const uint8_t* children_ptr,
    uint64_t num_children,
    const uint8_t* child_to_grow_back_ptr,
    uint8_t* out_hash_ptr);

// Convert Selene point to Helios scalar (x-coordinate extraction).
bool shekyl_curve_tree_selene_to_helios_scalar(
    const uint8_t* selene_point_ptr,
    uint8_t* out_scalar_ptr);

// Convert Helios point to Selene scalar (x-coordinate extraction).
bool shekyl_curve_tree_helios_to_selene_scalar(
    const uint8_t* helios_point_ptr,
    uint8_t* out_scalar_ptr);

// Get the Selene hash initialization point (32 bytes).
bool shekyl_curve_tree_selene_hash_init(uint8_t* out_ptr);

// Get the Helios hash initialization point (32 bytes).
bool shekyl_curve_tree_helios_hash_init(uint8_t* out_ptr);

// Tree structure constants.
uint32_t shekyl_curve_tree_scalars_per_leaf();    // 4
uint32_t shekyl_curve_tree_selene_chunk_width();  // 38 (LAYER_ONE_LEN)
uint32_t shekyl_curve_tree_helios_chunk_width();  // 18 (LAYER_TWO_LEN)

// Ed25519 → Selene scalar conversion (Wei25519 x-coordinate).
// compressed_ptr: 32 bytes compressed Ed25519 point.
// out_scalar_ptr: 32 bytes output Selene scalar.
// Returns true on success.
bool shekyl_ed25519_to_selene_scalar(
    const uint8_t* compressed_ptr,
    uint8_t* out_scalar_ptr);

// Construct a 128-byte curve tree leaf from output pubkey, commitment, and PQC hash.
// output_key_ptr: 32 bytes compressed Ed25519 output public key (O).
// commitment_ptr: 32 bytes compressed Ed25519 amount commitment (C).
// h_pqc_ptr: 32 bytes H(pqc_pk) scalar (or 32 zero bytes if unavailable).
// leaf_out_ptr: 128 bytes output for {O.x, I.x, C.x, H(pqc_pk)}.
// Returns true on success.
bool shekyl_construct_curve_tree_leaf(
    const uint8_t* output_key_ptr,
    const uint8_t* commitment_ptr,
    const uint8_t* h_pqc_ptr,
    uint8_t* leaf_out_ptr);

// ─── Transaction Builder ─────────────────────────────────────────────────────
// Single-call FCMP++ proof generation: BP+, membership proof, ECDH, pseudo-outs.
// Replaces the old genRctFcmpPlusPlus + shekyl_fcmp_prove + shekyl_pqc_sign
// multi-FFI round-trip.

/// Result of shekyl_sign_transaction.
/// On success: proofs_json contains JSON-encoded SignedProofs; error_code == 0.
/// On failure: proofs_json is null; error_code < 0; error_message describes the failure.
/// The caller must free proofs_json and error_message via shekyl_buffer_free.
struct ShekylSignResult {
    ShekylBuffer proofs_json;
    bool success;
    int32_t error_code;
    ShekylBuffer error_message;
};

/// Collapsed FCMP++ signing: Rust owns all witness assembly.
///
/// C++ passes the wallet master spend key `b` (one value, not per-input) plus
/// per-input data that includes combined_ss + output_index. Rust derives
/// x = ho + b and y internally. C++ never touches x.
///
/// Input JSON format (FcmpSignInput):
///   {ki, combined_ss (hex, 128 chars), output_index, hp_of_O, amount,
///    commitment_mask, commitment, output_key, h_pqc,
///    leaf_chunk, c1_layers, c2_layers}
///
/// @param spend_secret_ptr     32-byte wallet master private spend key (b).
/// @param tx_prefix_hash_ptr   32-byte Keccak-256 hash of serialized tx prefix.
/// @param inputs_json_ptr      JSON array of FcmpSignInput objects.
/// @param outputs_json_ptr     JSON array of OutputInfo objects.
/// @param fee                  Transaction fee in atomic units.
/// @param reference_block_ptr  32-byte reference block hash.
/// @param tree_root_ptr        32-byte Selene curve tree root.
/// @param tree_depth           Number of curve tree layers (>= 1).
///
/// Error codes: -1 null pointer, -2 JSON parse, -5 key derivation error,
///              -10..-29 TxBuilderError variants.
ShekylSignResult shekyl_sign_fcmp_transaction(
    const uint8_t* spend_secret_ptr,
    const uint8_t* tx_prefix_hash_ptr,
    const uint8_t* inputs_json_ptr, size_t inputs_json_len,
    const uint8_t* outputs_json_ptr, size_t outputs_json_len,
    uint64_t fee,
    const uint8_t* reference_block_ptr,
    const uint8_t* tree_root_ptr,
    uint8_t tree_depth);

/// Generate FCMP++ transaction proofs (BP+, membership proof, ECDH, pseudo-outs).
///
/// @param tx_prefix_hash_ptr  32-byte Keccak-256 hash of the serialized tx prefix.
/// @param inputs_json_ptr     JSON array of SpendInput objects (see shekyl-tx-builder docs).
/// @param inputs_json_len     Length of inputs JSON.
/// @param outputs_json_ptr    JSON array of OutputInfo objects.
/// @param outputs_json_len    Length of outputs JSON.
/// @param fee                 Transaction fee in atomic units.
/// @param reference_block_ptr 32-byte block hash of the reference block.
/// @param tree_root_ptr       32-byte Selene curve tree root from the block header.
///                            This is NOT the block hash — passing the wrong value
///                            produces an invalid proof.
/// @param tree_depth          Number of curve tree layers (>= 1).
///
/// Error codes: -1 null pointer, -2 JSON parse, -10..-29 TxBuilderError variants.
ShekylSignResult shekyl_sign_transaction(
    const uint8_t* tx_prefix_hash_ptr,
    const uint8_t* inputs_json_ptr, size_t inputs_json_len,
    const uint8_t* outputs_json_ptr, size_t outputs_json_len,
    uint64_t fee,
    const uint8_t* reference_block_ptr,
    const uint8_t* tree_root_ptr,
    uint8_t tree_depth);

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
