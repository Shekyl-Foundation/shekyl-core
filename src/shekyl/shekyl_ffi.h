// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

/// @file shekyl_ffi.h
/// @brief C declarations for the Rust shekyl-ffi crate (libshekyl_ffi.a).
///
/// This header is the sole FFI boundary between C++ and Rust in the Shekyl
/// codebase. Every function here has a corresponding `#[no_mangle] pub extern "C"`
/// in `rust/shekyl-ffi/src/lib.rs`.
///
/// ## Linking
///
/// Link against `libshekyl_ffi.a` (static archive produced by `cargo build`).
/// The CMake integration is in `cmake/BuildRust.cmake`.
///
/// ## Memory model
///
/// All `ShekylBuffer` values returned by Rust are allocated on the Rust heap.
/// The caller MUST free them with `shekyl_buffer_free(buf.ptr, buf.len)`.
/// `shekyl_buffer_free` wipes the buffer contents before deallocation (defense
/// against secrets leaking through freed memory).
///
/// ## Secret handling
///
/// Functions that accept secret material (keys, shared secrets, seeds) copy the
/// input into `Zeroizing` containers on the Rust side. The C++ caller is
/// responsible for wiping its copy after the call returns. See
/// `docs/POST_QUANTUM_CRYPTOGRAPHY.md` for the full secret lifecycle.
///
/// ## Error reporting
///
/// Functions that can fail return either `bool` (success/failure) or `int32_t`
/// (0 = success, negative = error code). Error codes are documented per function.
/// Functions NEVER embed secret material in error messages or logs.

#pragma once

#include <cstddef>
#include <cstdint>

/// Witness header size for the legacy FCMP++ prove path (shekyl_fcmp_prove).
/// Used only by genRctFcmpPlusPlus in core_tests/chaingen.cpp.
/// Production signing uses shekyl_sign_fcmp_transaction (collapsed path).
#define SHEKYL_PROVE_WITNESS_HEADER_BYTES 256

/// m_pqc_public_key canonical layout: X25519_pub[32] || ML-KEM-768_ek[1184].
#define SHEKYL_PQC_PUBLIC_KEY_BYTES 1216
#define SHEKYL_X25519_PK_BYTES 32
#define SHEKYL_ML_KEM_768_EK_BYTES 1184
#define SHEKYL_ML_KEM_768_DK_BYTES 2400

/// Uniform master seed produced by `shekyl_seed_normalize`.
#define SHEKYL_MASTER_SEED_BYTES 64
/// Raw 32-byte seed accepted by testnet/fakechain generate flows.
#define SHEKYL_RAW_SEED_BYTES 32
/// Canonical 64-byte classical address body used by wallet-file AAD and
/// by `shekyl_account_public_address_build` / `_check`.
#define SHEKYL_CLASSICAL_ADDRESS_BYTES 64

/// BIP-39 inputs: 32-byte entropy, 24 words, 64-byte PBKDF2-HMAC-SHA512 output,
/// max mnemonic string length (24 × longest English word "mountain"=8 + 23
/// spaces + trailing NUL slack, rounded up to 256 to simplify stack buffers).
#define SHEKYL_BIP39_ENTROPY_BYTES 32
#define SHEKYL_BIP39_WORD_COUNT 24
#define SHEKYL_BIP39_PBKDF2_OUTPUT_BYTES 64
#define SHEKYL_BIP39_MNEMONIC_MAX_BYTES 256

/// Bind symbolic `DerivationNetwork` values to their u8 wire representation
/// used by every account-derivation FFI. Matches Rust `account::DerivationNetwork`.
#define SHEKYL_DERIVATION_NETWORK_MAINNET   0
#define SHEKYL_DERIVATION_NETWORK_TESTNET   1
#define SHEKYL_DERIVATION_NETWORK_STAGENET  2
#define SHEKYL_DERIVATION_NETWORK_FAKECHAIN 3

/// Bind symbolic `SeedFormat` values to their u8 wire representation. Matches
/// Rust `account::SeedFormat`.
#define SHEKYL_SEED_FORMAT_BIP39 0
#define SHEKYL_SEED_FORMAT_RAW32 1

// Pin the address invariant shared with Rust `account::PQC_PUBLIC_KEY_BYTES`.
// If these constants ever drift, the freeze is broken and the assembler in
// get_account_address_from_str must be audited before touching anything else.
// This is a compile-time tripwire; there is no runtime fallback path.
static_assert(
    SHEKYL_PQC_PUBLIC_KEY_BYTES == SHEKYL_X25519_PK_BYTES + SHEKYL_ML_KEM_768_EK_BYTES,
    "SHEKYL_PQC_PUBLIC_KEY_BYTES must equal X25519_pub || ML-KEM-768_ek (32 + 1184)");

extern "C" {

/// Return the Rust crate version string (null-terminated, static lifetime).
const char* shekyl_rust_version();

/// Initialize the Rust runtime (logging, panic hooks). Call once at startup.
/// Returns false if initialization fails.
bool shekyl_rust_init();

/// Return the active consensus module name (e.g. "fcmp++", static lifetime).
const char* shekyl_active_consensus_module();

/// Generic Rust-owned buffer.
struct ShekylBuffer {
    uint8_t* ptr;
    size_t len;
};

/// Free a buffer allocated by a Rust FFI export. `len` MUST equal the original
/// ShekylBuffer::len returned by the paired Rust call. Mismatched lengths cause UB.
void shekyl_buffer_free(uint8_t* ptr, size_t len);

/// PQC: Hybrid signatures.
struct ShekylPqcKeypair {
    ShekylBuffer public_key;
    ShekylBuffer secret_key;
    bool success;
};

struct ShekylPqcSignatureResult {
    ShekylBuffer signature;
    bool success;
};

/// Generate a hybrid ML-DSA + Ed25519 keypair.
/// Free both buffers with shekyl_buffer_free. Wipe secret_key after use.
ShekylPqcKeypair shekyl_pqc_keypair_generate();

/// Sign a message with a hybrid ML-DSA secret key.
/// secret_key_ptr/len: secret key bytes from shekyl_pqc_keypair_generate.
/// Returns signature blob. Caller frees with shekyl_buffer_free.
ShekylPqcSignatureResult shekyl_pqc_sign(
    const uint8_t* secret_key_ptr,
    size_t secret_key_len,
    const uint8_t* message_ptr,
    size_t message_len);

/// Verify a hybrid PQC signature.
///
/// Returns 0 on success, or a nonzero PqcVerifyError discriminant on failure:
///   1  = SchemeMismatch         5  = ThresholdMismatch     9  = GroupIdMismatch
///   2  = ParameterBounds        6  = IndexOutOfRange       10 = CryptoVerifyFailed
///   3  = KeyBlobLength          7  = IndicesNotAscending   11 = DeserializationFailed
///   4  = SigBlobLength          8  = DuplicateKeys
/// For scheme_id 1 (single-signer), only codes 10 and 11 apply.
/// See rust/shekyl-crypto-pq/src/error.rs PqcVerifyError for canonical definitions.
uint8_t shekyl_pqc_verify(
    uint8_t scheme_id,
    const uint8_t* pubkey_blob,
    size_t pubkey_len,
    const uint8_t* sig_blob,
    size_t sig_len,
    const uint8_t* message,
    size_t message_len);

/// Verify a hybrid PQC signature with optional group ID binding.
/// Same error codes as shekyl_pqc_verify (0=success, 1-11=PqcVerifyError).
/// For scheme_id=2, passes expected_group_id to verify_multisig for
/// defense-in-depth group binding (PQC_MULTISIG.md SS16.3).
/// expected_group_id: 32 bytes, or NULL to skip group ID check.
uint8_t shekyl_pqc_verify_with_group_id(
    uint8_t scheme_id,
    const uint8_t* pubkey_blob,
    size_t pubkey_len,
    const uint8_t* sig_blob,
    size_t sig_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* expected_group_id);

/// Compute a deterministic group ID from a sorted set of participant keys.
/// keys_ptr: concatenated public key blobs, keys_len total bytes.
/// out_ptr: 32 writable bytes for the group ID hash.
bool shekyl_pqc_multisig_group_id(
    const uint8_t* keys_ptr,
    size_t keys_len,
    uint8_t* out_ptr);

/// Compute Keccak-256 hash of data_ptr[0..data_len].
/// out_ptr: 32 writable bytes for the hash output.
bool shekyl_cn_fast_hash(
    const uint8_t* data_ptr,
    size_t data_len,
    uint8_t* out_ptr);

/// Compute Merkle tree hash over `count` 32-byte hashes.
/// hashes_ptr: count * 32 bytes (contiguous). out_ptr: 32 writable bytes.
bool shekyl_tree_hash(
    const uint8_t* hashes_ptr,
    size_t count,
    uint8_t* out_ptr);

/// Calculate the adaptive release multiplier based on transaction volume.
/// Returns multiplier in fixed-point (1e18 = 1.0).
uint64_t shekyl_calc_release_multiplier(
    uint64_t tx_volume_avg,
    uint64_t tx_volume_baseline,
    uint64_t release_min,
    uint64_t release_max);

uint64_t shekyl_apply_release_multiplier(
    uint64_t base_reward,
    uint64_t multiplier);

/// Calculate fee burn percentage based on network metrics.
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

/// Compute stake weight for a given amount and tier.
uint64_t shekyl_stake_weight(uint64_t amount, uint8_t tier_id);
/// Minimum lock duration in blocks for a stake tier.
uint64_t shekyl_stake_lock_blocks(uint8_t tier_id);
/// Yield multiplier (fixed-point) for a stake tier.
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

/// Calculate emission share (Component 4) based on chain age and decay curve.
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

/// Generate self-signed SSL certificate (Ed25519 key + X.509 via rcgen).
bool shekyl_generate_ssl_certificate(
    ShekylBuffer* key_pem_out,
    ShekylBuffer* cert_pem_out);

// ─── FCMP++: Generators ─────────────────────────────────────────────────────

/// Write the compressed Ed25519 bytes of generator T (32 bytes) to out_ptr.
/// T = hash_to_point(keccak256("Monero Generator T")) — used in two-component
/// output keys: O = xG + yT.
void shekyl_generator_T(uint8_t* out_ptr);

// ─── FCMP++: Proof and tree operations ──────────────────────────────────────

/// Compute H(pqc_pk) leaf scalar. Writes 32 bytes to out_ptr.
bool shekyl_fcmp_pqc_leaf_hash(
    const uint8_t* pqc_pk_ptr,
    size_t pqc_pk_len,
    uint8_t* out_ptr);

/// Derive h_pqc = H(hybrid_public_key) from combined KEM shared secret and
/// output index. Secret key derived internally and zeroized; never returned.
/// combined_ss_ptr: 64 bytes. h_pqc_out: 32-byte caller-provided buffer.
bool shekyl_derive_pqc_leaf_hash(
    const uint8_t* combined_ss_ptr,
    uint64_t output_index,
    uint8_t* h_pqc_out);

/// Derive canonical hybrid public key bytes from combined KEM shared secret
/// and output index. Secret key derived internally and zeroized; never returned.
/// combined_ss_ptr: 64 bytes. Returns heap-allocated buffer; free with
/// shekyl_buffer_free.
ShekylBuffer shekyl_derive_pqc_public_key(
    const uint8_t* combined_ss_ptr,
    uint64_t output_index);

/// Derive all per-output secrets from the combined KEM shared secret.
/// Writes: ho(32), y(32), z(32), k_amount(32), view_tag_combined(1),
/// amount_tag(1), ml_dsa_seed(32). Returns true on success.
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

/// Derive X25519-only view tag for scanner pre-filtering.
/// x25519_ss_ptr: exactly 32 bytes. Returns 1-byte tag.
uint8_t shekyl_derive_view_tag_x25519(
    const uint8_t* x25519_ss_ptr,
    uint64_t output_index);

/// Expected proof size for given inputs and tree depth.
size_t shekyl_fcmp_proof_len(uint32_t num_inputs, uint8_t tree_depth);

/// FCMP++ prove result (proof blob + pseudo-outs).
struct ShekylFcmpProveResult {
    ShekylBuffer proof;
    ShekylBuffer pseudo_outs;    // num_inputs * 32 bytes (C_tilde compressed)
    bool success;
};

/// Construct FCMP++ proof from variable-length witness blob.
/// witness_ptr / witness_len: serialized witness for all inputs.
/// Per input: fixed header (256 bytes) + leaf chunk + C1/C2 branch layers.
/// Header: [O:32][I:32][C:32][h_pqc:32][x:32][y:32][z:32][a:32]
///   y = SAL output-key secret (0 for legacy one-time addresses)
///   z = Pedersen commitment mask
///   a = desired pseudo-out blinding factor
/// See shekyl-ffi crate docs for the full wire format specification.
///
/// tree_depth: upstream library `layers` count (= LMDB depth + 1).
/// C++ callers must convert: layers = lmdb_depth + 1.
ShekylFcmpProveResult shekyl_fcmp_prove(
    const uint8_t* witness_ptr,
    size_t witness_len,
    uint32_t num_inputs,
    const uint8_t* tree_root_ptr,
    uint8_t tree_depth,
    const uint8_t* signable_tx_hash_ptr);

/// Verify FCMP++ proof with batch verification.
///
/// Returns 0 on success, or a nonzero VerifyError discriminant (1-7) on failure:
///   1 = DeserializationFailed   4 = KeyImageCountMismatch  7 = TreeDepthTooLarge
///   2 = InvalidTreeRoot         5 = UpstreamError
///   3 = PqcCommitmentMismatch   6 = BatchVerificationFailed
/// See rust/shekyl-fcmp/src/proof.rs VerifyError for canonical definitions.
///
/// tree_depth: upstream library `layers` count (= LMDB depth + 1).
/// C++ callers must convert: layers = lmdb_depth + 1.
/// signable_tx_hash_ptr: 32-byte transaction binding hash.
/// pqc_hash_count must equal ki_count.
uint8_t shekyl_fcmp_verify(
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

/// Convert raw output tuples into serialized 4-scalar leaves.
ShekylBuffer shekyl_fcmp_outputs_to_leaves(
    const uint8_t* outputs_ptr,
    size_t count);

// ─── FCMP++: KEM operations ─────────────────────────────────────────────────

/// Generate hybrid X25519 + ML-KEM-768 keypair.
ShekylPqcKeypair shekyl_kem_keypair_generate();

/// Convert an Ed25519 view public key to its X25519 (Montgomery u-coordinate)
/// equivalent via the birational map u = (1+y)/(1-y).
/// ed_pub_ptr: 32-byte Ed25519 public key.
/// x25519_out_ptr: receives 32-byte X25519 public key.
/// Returns false on rejection (identity, non-canonical).
bool shekyl_view_pub_to_x25519_pub(
    const uint8_t* ed_pub_ptr,
    uint8_t* x25519_out_ptr);

/// Encapsulate to hybrid public key.
/// pk_ml_kem_ptr: 1184 bytes (ML-KEM-768 encap key).
/// ct_out: receives ciphertext buffer (32 + 1088 bytes).
/// ss_out_ptr: receives 64-byte combined shared secret.
bool shekyl_kem_encapsulate(
    const uint8_t* pk_x25519_ptr,
    const uint8_t* pk_ml_kem_ptr,
    size_t pk_ml_kem_len,
    ShekylBuffer* ct_out,
    uint8_t* ss_out_ptr);

/// Decapsulate hybrid ciphertext.
/// ct_ml_kem_ptr: 1088 bytes (ML-KEM-768 ciphertext).
/// ss_out_ptr: receives 64-byte combined shared secret.
bool shekyl_kem_decapsulate(
    const uint8_t* sk_x25519_ptr,
    const uint8_t* sk_ml_kem_ptr,
    size_t sk_ml_kem_len,
    const uint8_t* ct_x25519_ptr,
    const uint8_t* ct_ml_kem_ptr,
    size_t ct_ml_kem_len,
    uint8_t* ss_out_ptr);

// ─── Bech32m address encoding ────────────────────────────────────────────────

/// Encode Shekyl Bech32m address. Returns UTF-8 string in ShekylBuffer.
/// network: 0=mainnet, 1=testnet, 2=stagenet.
ShekylBuffer shekyl_address_encode(
    uint8_t network,
    const uint8_t* spend_key_ptr,
    const uint8_t* view_key_ptr,
    const uint8_t* ml_kem_ek_ptr,
    size_t ml_kem_ek_len);

/// Decode Shekyl Bech32m address.
/// network_out: receives network discriminant (0=mainnet, 1=testnet, 2=stagenet).
/// Writes 32 bytes each to spend_key_out and view_key_out.
/// Returns ML-KEM encap key in ShekylBuffer (1184 bytes, or 0 if classical-only).
ShekylBuffer shekyl_address_decode(
    const char* encoded_ptr,
    uint8_t* network_out,
    uint8_t* spend_key_out,
    uint8_t* view_key_out);

// ─── Bech32m blob encoding ──────────────────────────────────────────────────

/// Encode arbitrary binary data as Bech32m with the given HRP.
/// Returns UTF-8 encoded Bech32m string in ShekylBuffer, or null on failure.
ShekylBuffer shekyl_encode_blob(
    const uint8_t* hrp_ptr,
    size_t hrp_len,
    const uint8_t* data_ptr,
    size_t data_len);

/// Decode a Bech32m string into HRP + payload.
/// hrp_out/hrp_out_cap: buffer for decoded HRP (UTF-8, not null-terminated).
/// hrp_len_out: receives actual HRP byte length.
/// data_out/data_out_cap: buffer for decoded payload.
/// data_len_out: receives actual payload byte length.
/// Returns true on success, false if decoding fails or buffers are too small.
bool shekyl_decode_blob(
    const char* encoded_ptr,
    uint8_t* hrp_out,
    size_t hrp_out_cap,
    size_t* hrp_len_out,
    uint8_t* data_out,
    size_t data_out_cap,
    size_t* data_len_out);

// ─── Output Construction / Scanning / PQC Signing ────────────────────────────

/// Typed struct for FCMP++ prover inputs (replaces hand-counted memcpy offsets).
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

/// Build the 256-byte witness header from a typed ProveInputFields.
/// out_buf must point to at least 256 writable bytes.
bool shekyl_fcmp_build_witness_header(
    const ProveInputFields* input,
    uint8_t* out_buf);

/// Result of construct_output.
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

/// Construct a two-component output via unified HKDF path.
/// tx_key_secret: 32-byte ephemeral transaction secret key (drives KEM encapsulation).
ShekylOutputData shekyl_construct_output(
    const uint8_t* tx_key_secret,
    const uint8_t* x25519_pk,
    const uint8_t* ml_kem_ek,
    size_t ml_kem_ek_len,
    const uint8_t* spend_key,
    uint64_t amount,
    uint64_t output_index);

/// Free heap-allocated fields in ShekylOutputData.
void shekyl_output_data_free(ShekylOutputData* data);

/// Scan an output: KEM decap + HKDF + verification.
/// y_out, z_out, k_amount_out: caller-owned 32-byte buffers for secrets.
/// Caller is responsible for wiping these after use.
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

/// Scan an output recovering the spend key B' = O - ho*G - y*T.
/// Caller looks up B' in subaddress table to determine ownership.
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

/// Scan an output, recover all secrets, and compute the key image — all in one
/// call.  All secret output pointers write directly into transfer_details fields
/// (direct-write-to-destination pattern: no intermediate scratch buffers).
///
/// persist_combined_ss: if false, Rust wipes combined_ss internally and
///   combined_ss_out is ignored (pass nullptr). If true, Rust writes directly
///   to combined_ss_out (64 bytes).
///
/// Returns true on success (output belongs to this wallet).
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

/// Compute key image from persisted combined_ss + output_index.
/// Used at stake claim (1 site). Derives ho from HKDF, computes KI = (ho+b)*Hp(O).
/// out_ki: 32 writable bytes for the key image.
bool shekyl_compute_output_key_image(
    const uint8_t* combined_ss,
    uint64_t output_index,
    const uint8_t* spend_secret_key,
    const uint8_t* hp_of_O,
    uint8_t* out_ki);

/// Compute key image from pre-derived ho scalar.
/// Used at tx_source_entry boundary (1 site). Computes KI = (ho+b)*Hp(O).
/// ho: 32-byte HKDF-derived secret scalar.
/// out_ki: 32 writable bytes for the key image.
bool shekyl_compute_output_key_image_from_ho(
    const uint8_t* ho,
    const uint8_t* spend_secret_key,
    const uint8_t* hp_of_O,
    uint8_t* out_ki);

// ─── Proof secrets helper ────────────────────────────────────────────────────

/// Derive the ProofSecrets projection from combined_ss.
/// out_ho, out_y, out_z, out_k_amount: each 32 writable bytes.
/// Callers pass destination addresses directly (no scratch buffers).
bool shekyl_derive_proof_secrets(
    const uint8_t* combined_ss,
    uint64_t output_index,
    uint8_t* out_ho,
    uint8_t* out_y,
    uint8_t* out_z,
    uint8_t* out_k_amount);

// ─── Wallet proofs (6 exports) ───────────────────────────────────────────────
///
/// All proof functions delegate to the shekyl-proofs Rust crate via the FFI
/// bridge. The C++ caller gathers wallet/blockchain data and passes flat
/// byte arrays; Rust handles all cryptographic proof generation/verification.

/// Generate outbound transaction proof (sender proves payment).
/// Rust re-derives combined_ss from tx_key_secret + recipient KEM keys,
/// then projects to ProofSecrets and builds the Schnorr proof.
/// output_indices: which tx output indices belong to this recipient.
bool shekyl_generate_tx_proof_outbound(
    const uint8_t* tx_key_secret,          // 32 bytes
    const uint8_t* txid,                   // 32 bytes
    const uint8_t* address,                // address_len bytes (serialized)
    size_t address_len,
    const uint8_t* message,                // message_len bytes
    size_t message_len,
    const uint8_t* recipient_x25519_pk,    // 32 bytes
    const uint8_t* recipient_ml_kem_ek,    // ml_kem_ek_len bytes
    size_t ml_kem_ek_len,
    const uint64_t* output_indices,        // output_count values
    uint32_t output_count,
    ShekylBuffer* proof_out);

/// Verify outbound transaction proof.
/// On success, writes verified per-output amounts to amounts_out.
/// ml_kem_cts: contiguous per-output ML-KEM ciphertexts, each
///   ml_kem_cts_len/output_count bytes.
bool shekyl_verify_tx_proof_outbound(
    const uint8_t* proof_bytes,
    size_t proof_len,
    const uint8_t* txid,                   // 32 bytes
    const uint8_t* address,                // address_len bytes
    size_t address_len,
    const uint8_t* message,                // message_len bytes
    size_t message_len,
    const uint8_t* recipient_spend_pubkey, // 32 bytes
    const uint8_t* recipient_x25519_pk,    // 32 bytes
    const uint8_t* recipient_ml_kem_ek,    // ml_kem_ek_len bytes
    size_t ml_kem_ek_len,
    const uint8_t* output_keys,            // output_count * 32 bytes
    const uint8_t* commitments,            // output_count * 32 bytes
    const uint8_t* enc_amounts,            // output_count * 8 bytes
    const uint8_t* x25519_eph_pks,         // output_count * 32 bytes
    const uint8_t* ml_kem_cts,             // ml_kem_cts_len total bytes
    size_t ml_kem_cts_len,
    uint32_t output_count,
    uint64_t* amounts_out);                // output_count u64 values

/// Generate inbound transaction proof (recipient proves receipt).
/// proof_secrets: output_count * 128 bytes — packed (ho[32]+y[32]+z[32]+k_amount[32])
///   per output, derived via shekyl_derive_proof_secrets.
bool shekyl_generate_tx_proof_inbound(
    const uint8_t* view_secret_key,        // 32 bytes
    const uint8_t* txid,                   // 32 bytes
    const uint8_t* address,                // address_len bytes
    size_t address_len,
    const uint8_t* message,                // message_len bytes
    size_t message_len,
    const uint8_t* proof_secrets,          // output_count * 128 bytes
    uint32_t output_count,
    ShekylBuffer* proof_out);

/// Verify inbound transaction proof.
/// On success, writes verified per-output amounts to amounts_out.
bool shekyl_verify_tx_proof_inbound(
    const uint8_t* proof_bytes,
    size_t proof_len,
    const uint8_t* txid,                   // 32 bytes
    const uint8_t* address,                // address_len bytes
    size_t address_len,
    const uint8_t* message,                // message_len bytes
    size_t message_len,
    const uint8_t* view_public_key,        // 32 bytes
    const uint8_t* recipient_spend_pubkey, // 32 bytes
    const uint8_t* output_keys,            // output_count * 32 bytes
    const uint8_t* commitments,            // output_count * 32 bytes
    const uint8_t* enc_amounts,            // output_count * 8 bytes
    const uint8_t* x25519_eph_pks,         // output_count * 32 bytes
    const uint8_t* ml_kem_cts,             // ml_kem_cts_len total bytes
    size_t ml_kem_cts_len,
    uint32_t output_count,
    uint64_t* amounts_out);                // output_count u64 values

/// Generate reserve proof (prove ownership of unspent outputs).
/// proof_secrets: output_count * 128 bytes — packed per output.
/// spend_secrets: output_count * 32 bytes — per-output subaddress spend secret.
bool shekyl_generate_reserve_proof(
    const uint8_t* spend_secret_key,       // 32 bytes (master)
    const uint8_t* address,                // address_len bytes
    size_t address_len,
    const uint8_t* message,                // message_len bytes
    size_t message_len,
    const uint8_t* proof_secrets,          // output_count * 128 bytes
    const uint8_t* key_images,             // output_count * 32 bytes
    const uint8_t* spend_secrets,          // output_count * 32 bytes
    const uint8_t* output_keys,            // output_count * 32 bytes
    uint32_t output_count,
    ShekylBuffer* proof_out);

/// Verify reserve proof.
/// enc_amounts MUST be fetched from the blockchain, NOT from the proof.
/// On success, writes total verified amount to total_amount_out.
bool shekyl_verify_reserve_proof(
    const uint8_t* proof_bytes,
    size_t proof_len,
    const uint8_t* address,                // address_len bytes
    size_t address_len,
    const uint8_t* message,                // message_len bytes
    size_t message_len,
    const uint8_t* spend_pubkey,           // 32 bytes
    const uint8_t* output_keys,            // output_count * 32 bytes
    const uint8_t* commitments,            // output_count * 32 bytes
    const uint8_t* enc_amounts,            // output_count * 8 bytes
    uint32_t output_count,
    uint64_t* total_amount_out);

// ─── Wallet cache encryption (AEAD with AAD binding) ─────────────────────────

/// Encrypt wallet cache plaintext with XChaCha20-Poly1305 AEAD.
/// cache_format_version is bound into the Poly1305 AAD — version changes
/// invalidate existing ciphertext.
/// password_derived_key: 32 bytes.
/// Returns encrypted blob via out_buf. Caller frees with shekyl_buffer_free.
bool shekyl_encrypt_wallet_cache(
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t cache_format_version,
    const uint8_t* password_derived_key,
    ShekylBuffer* out_buf);

/// Decrypt wallet cache ciphertext.
/// expected_version: asserted before decryption — returns distinct error for
///   version mismatch vs auth failure vs corruption.
/// Returns 0 on success, negative on error:
///   -1: version mismatch
///   -2: authentication failure (AAD/tag mismatch)
///   -3: invalid format / too short
///   -4: null pointer argument
int32_t shekyl_decrypt_wallet_cache(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t expected_version,
    const uint8_t* password_derived_key,
    ShekylBuffer* out_buf);

/// PQC auth result (hybrid pk + signature).
struct ShekylPqcAuthResult {
    ShekylBuffer hybrid_public_key;
    ShekylBuffer signature;
    bool success;
};

/// Sign using HKDF-derived hybrid PQC keypair. ML-DSA secret key never
/// crosses this boundary — derived, used, and wiped entirely in Rust.
ShekylPqcAuthResult shekyl_sign_pqc_auth(
    const uint8_t* combined_ss,
    uint64_t output_index,
    const uint8_t* message,
    size_t message_len);

/// Free a ShekylPqcAuthResult. Wipes signature and key material before deallocation.
void shekyl_pqc_auth_result_free(ShekylPqcAuthResult* result);

// ─── FCMP++: Seed derivation (legacy, pending wallet-account-rewire) ───────
//
// These three primitives are the pre-stabilization derivation path kept alive
// only so the in-tree account.cpp can continue to build while the C++ side is
// migrated to the v1 `shekyl_account_*` flows below. All three will be removed
// once the wallet-account-rewire slice lands. Do not introduce new callers.

/// Derive Ed25519 spend key from 32-byte master seed. Writes 32 bytes.
bool shekyl_seed_derive_spend(const uint8_t* seed_ptr, uint8_t* out_ptr);

/// Derive Ed25519 view key from 32-byte master seed. Writes 32 bytes.
bool shekyl_seed_derive_view(const uint8_t* seed_ptr, uint8_t* out_ptr);

/// Derive ML-KEM-768 seed material from 32-byte master seed. Writes 64 bytes.
bool shekyl_seed_derive_ml_kem(const uint8_t* seed_ptr, uint8_t* out_ptr);

// ─── Account derivation (v1, stabilized) ───────────────────────────────────
//
// All functions in this section follow the FFI-discipline pattern:
//   * Out-pointer, caller-allocated buffers (the C++ wallet owns the
//     `mlock`'d region; Rust never keeps a heap copy of secret material).
//   * Fail-closed: every out-pointer buffer is explicitly zeroed before the
//     function returns `false`. Read patterns are therefore identical whether
//     the call succeeded or not — constant-time at the ABI boundary.
//   * Pinned sizes: every variable-length concept has a `#define` above that
//     can be consumed by `static_assert` on the C++ side.
// See rust/shekyl-ffi/src/account_ffi.rs for the authoritative contract.

/// Validate a candidate 24-word English BIP-39 mnemonic. The input is *not*
/// copied; after this call returns, the caller's buffer can be wiped.
bool shekyl_bip39_validate(const uint8_t* words_ptr, size_t words_len);

/// Build the English 24-word BIP-39 mnemonic for 32 bytes of entropy.
/// `out_words_ptr` is an externally-allocated buffer of capacity
/// `out_words_cap` (at least `SHEKYL_BIP39_MNEMONIC_MAX_BYTES` is sufficient);
/// `*out_words_len` receives the number of bytes written on success.
/// The entropy is copied into a `Zeroizing` container on the Rust side and
/// wiped before return.
bool shekyl_bip39_mnemonic_from_entropy(
    const uint8_t* entropy32_ptr,
    uint8_t* out_words_ptr,
    size_t out_words_cap,
    size_t* out_words_len);

/// Run BIP-39 PBKDF2-HMAC-SHA512 (2048 iterations) over the NFKD form of the
/// mnemonic + "mnemonic"||passphrase salt. Writes 64 bytes to `out64_ptr`.
/// The passphrase is optional; pass `pass_ptr=nullptr, pass_len=0` for none.
bool shekyl_bip39_mnemonic_to_pbkdf2_seed(
    const uint8_t* words_ptr,
    size_t words_len,
    const uint8_t* pass_ptr,
    size_t pass_len,
    uint8_t* out64_ptr);

/// Generate 32 bytes of fresh entropy via OS CSPRNG. Used for
/// testnet/fakechain raw-seed generation only; mainnet/stagenet flows go
/// through BIP-39.
bool shekyl_raw_seed_generate(uint8_t* out32_ptr);

/// HKDF-SHA-512 extract+expand a variable-length input into a uniform
/// 64-byte `master_seed` under the label `"shekyl-seed-normalize-v1"`.
/// Caller-allocated `out64_ptr` receives the result.
bool shekyl_seed_normalize(
    const uint8_t* ikm_ptr,
    size_t ikm_len,
    uint8_t* out64_ptr);

/// Network-bound 64-byte HKDF-Expand for the Ed25519 spend branch. Output is
/// secret and must be fed to `shekyl_ed25519_scalar_wide_reduce`.
bool shekyl_seed_derive_spend_wide(
    const uint8_t* master_seed64_ptr,
    uint8_t network,
    uint8_t seed_format,
    uint8_t* out64_ptr);

/// Network-bound 64-byte HKDF-Expand for the Ed25519 view branch. Output is
/// secret and must be fed to `shekyl_ed25519_scalar_wide_reduce`.
bool shekyl_seed_derive_view_wide(
    const uint8_t* master_seed64_ptr,
    uint8_t network,
    uint8_t seed_format,
    uint8_t* out64_ptr);

/// Wide-reduce a 64-byte secret into a canonical Ed25519 scalar (mod ℓ).
/// This is the single collapse point for all 64-byte HKDF sub-derivations.
bool shekyl_ed25519_scalar_wide_reduce(
    const uint8_t* in64_ptr,
    uint8_t* out32_ptr);

/// Deterministically derive an ML-KEM-768 keypair from the master seed.
/// `ek_out_ptr` receives SHEKYL_ML_KEM_768_EK_BYTES; `dk_out_ptr` receives
/// SHEKYL_ML_KEM_768_DK_BYTES. The decapsulation key is highly sensitive and
/// must be mlock'd by the caller *before* the call.
bool shekyl_kem_keypair_from_master_seed(
    const uint8_t* master_seed64_ptr,
    uint8_t network,
    uint8_t seed_format,
    uint8_t* ek_out_ptr,
    uint8_t* dk_out_ptr);

/// `#[repr(C)]` bundle of every byte in an account. Public-side fields are
/// mirrored verbatim into `account_public_address` and into the bech32m
/// assembler; secret-side fields are copied into `account_keys` and wiped.
/// The caller owns the allocation; Rust zeroizes the whole struct on failure.
struct ShekylAllKeysBlob {
    // public ------------------------------------------------------------------
    uint8_t spend_pk[32];
    uint8_t view_pk[32];
    uint8_t ml_kem_ek[SHEKYL_ML_KEM_768_EK_BYTES];
    uint8_t x25519_pk[32];
    uint8_t pqc_public_key[SHEKYL_PQC_PUBLIC_KEY_BYTES];
    uint8_t classical_address_bytes[SHEKYL_CLASSICAL_ADDRESS_BYTES];
    // secret ------------------------------------------------------------------
    uint8_t spend_sk[32];
    uint8_t view_sk[32];
    uint8_t ml_kem_dk[SHEKYL_ML_KEM_768_DK_BYTES];
};

static_assert(sizeof(ShekylAllKeysBlob) ==
    32 + 32 + SHEKYL_ML_KEM_768_EK_BYTES + 32 + SHEKYL_PQC_PUBLIC_KEY_BYTES
        + SHEKYL_CLASSICAL_ADDRESS_BYTES + 32 + 32 + SHEKYL_ML_KEM_768_DK_BYTES,
    "ShekylAllKeysBlob layout must exactly match Rust account::AllKeysBlob");

/// End-to-end mainnet/stagenet account generation from a BIP-39 mnemonic.
/// Outputs the 64-byte master seed (so the caller can persist it) and a fully
/// populated ShekylAllKeysBlob. `pass_ptr=nullptr, pass_len=0` for no
/// passphrase.
bool shekyl_account_generate_from_bip39(
    const uint8_t* words_ptr,
    size_t words_len,
    const uint8_t* pass_ptr,
    size_t pass_len,
    uint8_t network,
    uint8_t* master_seed_out64,
    ShekylAllKeysBlob* blob_out);

/// End-to-end testnet/fakechain account generation from a 32-byte raw seed.
bool shekyl_account_generate_from_raw_seed(
    const uint8_t* raw_seed32_ptr,
    uint8_t network,
    uint8_t* master_seed_out64,
    ShekylAllKeysBlob* blob_out);

/// Rederive every byte of an account from a persisted `master_seed_64` plus
/// the recorded `seed_format`. Returns `false` without writing if the
/// network/format pair is not permitted. This is the wallet-open hot path.
bool shekyl_account_rederive(
    const uint8_t* master_seed64_ptr,
    uint8_t network,
    uint8_t seed_format,
    ShekylAllKeysBlob* blob_out);

/// Assemble the canonical m_pqc_public_key = X25519_pub || ML-KEM_ek given
/// its two components. Writes SHEKYL_PQC_PUBLIC_KEY_BYTES. Does not touch
/// secret material.
bool shekyl_account_public_address_build(
    const uint8_t* x25519_pk_ptr,
    const uint8_t* ml_kem_ek_ptr,
    uint8_t* pqc_public_key_out);

/// Verify that a `pqc_public_key` is internally consistent: its X25519 prefix
/// is the Edwards→Montgomery image of the accompanying Ed25519 view public
/// key, and the ML-KEM encapsulation key is a well-formed fixed-length
/// suffix. Returns true iff the triple (view_pub, pqc_public_key) is a legal
/// canonical address. Used by every decoder as a post-assembly tripwire.
bool shekyl_account_public_address_check(
    const uint8_t* view_pub_ptr,
    const uint8_t* pqc_public_key_ptr);

// ─── FCMP++: Curve tree hash operations ─────────────────────────────────────

/// Incrementally grow a Selene-layer chunk hash (leaf layer + even internal layers).
/// existing_hash_ptr: 32 bytes (Selene point, use hash_init for new chunk).
/// existing_child_at_offset_ptr: 32 bytes (old Selene scalar at offset, zero for fresh).
/// new_children_ptr: num_children * 32 bytes (Selene scalars).
/// out_hash_ptr: 32 bytes output (new Selene point).
bool shekyl_curve_tree_hash_grow_selene(
    const uint8_t* existing_hash_ptr,
    uint64_t offset,
    const uint8_t* existing_child_at_offset_ptr,
    const uint8_t* new_children_ptr,
    uint64_t num_children,
    uint8_t* out_hash_ptr);

/// Incrementally grow a Helios-layer chunk hash (odd internal layers).
bool shekyl_curve_tree_hash_grow_helios(
    const uint8_t* existing_hash_ptr,
    uint64_t offset,
    const uint8_t* existing_child_at_offset_ptr,
    const uint8_t* new_children_ptr,
    uint64_t num_children,
    uint8_t* out_hash_ptr);

/// Trim children from a Selene-layer chunk hash.
bool shekyl_curve_tree_hash_trim_selene(
    const uint8_t* existing_hash_ptr,
    uint64_t offset,
    const uint8_t* children_ptr,
    uint64_t num_children,
    const uint8_t* child_to_grow_back_ptr,
    uint8_t* out_hash_ptr);

/// Trim children from a Helios-layer chunk hash.
bool shekyl_curve_tree_hash_trim_helios(
    const uint8_t* existing_hash_ptr,
    uint64_t offset,
    const uint8_t* children_ptr,
    uint64_t num_children,
    const uint8_t* child_to_grow_back_ptr,
    uint8_t* out_hash_ptr);

/// Convert Selene point to Helios scalar (x-coordinate extraction).
bool shekyl_curve_tree_selene_to_helios_scalar(
    const uint8_t* selene_point_ptr,
    uint8_t* out_scalar_ptr);

/// Convert Helios point to Selene scalar (x-coordinate extraction).
bool shekyl_curve_tree_helios_to_selene_scalar(
    const uint8_t* helios_point_ptr,
    uint8_t* out_scalar_ptr);

/// Get the Selene hash initialization point (32 bytes).
bool shekyl_curve_tree_selene_hash_init(uint8_t* out_ptr);

/// Get the Helios hash initialization point (32 bytes).
bool shekyl_curve_tree_helios_hash_init(uint8_t* out_ptr);

/// Tree structure constants.
uint32_t shekyl_curve_tree_scalars_per_leaf();    // 4
uint32_t shekyl_curve_tree_selene_chunk_width();  // 38 (LAYER_ONE_LEN)
uint32_t shekyl_curve_tree_helios_chunk_width();  // 18 (LAYER_TWO_LEN)

/// Ed25519 → Selene scalar conversion (Wei25519 x-coordinate).
/// compressed_ptr: 32 bytes compressed Ed25519 point.
/// out_scalar_ptr: 32 bytes output Selene scalar.
/// Returns true on success.
bool shekyl_ed25519_to_selene_scalar(
    const uint8_t* compressed_ptr,
    uint8_t* out_scalar_ptr);

/// Construct a 128-byte curve tree leaf from output pubkey, commitment, and PQC hash.
/// output_key_ptr: 32 bytes compressed Ed25519 output public key (O).
/// commitment_ptr: 32 bytes compressed Ed25519 amount commitment (C).
/// h_pqc_ptr: 32 bytes H(pqc_pk) scalar (or 32 zero bytes if unavailable).
/// leaf_out_ptr: 128 bytes output for {O.x, I.x, C.x, H(pqc_pk)}.
/// Returns true on success.
bool shekyl_construct_curve_tree_leaf(
    const uint8_t* output_key_ptr,
    const uint8_t* commitment_ptr,
    const uint8_t* h_pqc_ptr,
    uint8_t* leaf_out_ptr);

// ─── Transaction Builder ─────────────────────────────────────────────────────
/// Single-call FCMP++ proof generation: BP+, membership proof, pseudo-outs.
/// Rust owns all witness assembly. C++ never touches ephemeral spend secrets.

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

/// Opaque handle to the Axum-based daemon RPC server.
typedef struct ShekylDaemonRpcHandle ShekylDaemonRpcHandle;

/// Start the Axum daemon RPC server on a dedicated Tokio runtime.
/// rpc_server_ptr: pointer to an initialized core_rpc_server.
/// bind_addr: "ip:port" C string.
/// restricted: true to block admin-only endpoints.
/// Returns an opaque handle, or NULL on failure.
ShekylDaemonRpcHandle* shekyl_daemon_rpc_start(
    void* rpc_server_ptr,
    const char* bind_addr,
    bool restricted);

/// Gracefully stop the Axum daemon RPC server and free the handle.
void shekyl_daemon_rpc_stop(ShekylDaemonRpcHandle* handle);

// ─── Wallet file format v1 (WALLET_FILE_FORMAT_V1) ──────────────────────────
//
// Two-file envelope: `.wallet.keys` (seed block, write-once) + `.wallet`
// (state block, frequently rewritten). Password-stretched via Argon2id;
// content encrypted under XChaCha20-Poly1305 with a minimum-leak AAD model
// (see docs/WALLET_FILE_FORMAT_V1.md for the byte-level spec). Every
// variable-length output uses the probe-and-retry pattern:
//   1. call with out_buf = nullptr, out_cap = 0 → out_len_required is set
//      and the function returns false with out_error =
//      SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL;
//   2. allocate a buffer of at least out_len_required bytes; call again.
// On real errors (wrong password, tampered file, unsupported mode) the
// function returns false and out_error is set to a specific code;
// out_buf is zeroed (to the extent it was touched) so observers see the
// same write pattern on every failure path.

#define SHEKYL_WALLET_FILE_FORMAT_VERSION 0x01
#define SHEKYL_WALLET_STATE_FILE_FORMAT_VERSION 0x01

#define SHEKYL_WALLET_KDF_ALGO_ARGON2ID 0x01
#define SHEKYL_WALLET_KDF_DEFAULT_M_LOG2 0x10 /* 64 MiB */
#define SHEKYL_WALLET_KDF_DEFAULT_T 0x03
#define SHEKYL_WALLET_KDF_DEFAULT_P 0x01

#define SHEKYL_WALLET_CAPABILITY_FULL             0x01
#define SHEKYL_WALLET_CAPABILITY_VIEW_ONLY        0x02
#define SHEKYL_WALLET_CAPABILITY_HARDWARE_OFFLOAD 0x03
#define SHEKYL_WALLET_CAPABILITY_RESERVED_MULTISIG 0x04

#define SHEKYL_WALLET_KEYS_WRAP_SALT_BYTES 16
#define SHEKYL_WALLET_SEED_BLOCK_TAG_BYTES 16
/// Canonical classical-address layout used by the wallet envelope.
/// version(1) || spend_pk(32) || view_pk(32).
#define SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES 65

#define SHEKYL_WALLET_ERR_OK 0
#define SHEKYL_WALLET_ERR_TOO_SHORT 1
#define SHEKYL_WALLET_ERR_BAD_MAGIC 2
#define SHEKYL_WALLET_ERR_VERSION_TOO_NEW 3
#define SHEKYL_WALLET_ERR_UNSUPPORTED_KDF_ALGO 4
#define SHEKYL_WALLET_ERR_KDF_PARAMS_OUT_OF_RANGE 5
#define SHEKYL_WALLET_ERR_UNSUPPORTED_WRAP_COUNT 6
#define SHEKYL_WALLET_ERR_CAP_CONTENT_LEN_MISMATCH 7
#define SHEKYL_WALLET_ERR_UNKNOWN_CAPABILITY_MODE 8
#define SHEKYL_WALLET_ERR_REQUIRES_MULTISIG 9
#define SHEKYL_WALLET_ERR_INVALID_PASSWORD_OR_CORRUPT 10
#define SHEKYL_WALLET_ERR_STATE_SEED_BLOCK_MISMATCH 11
#define SHEKYL_WALLET_ERR_INTERNAL 12
#define SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL 13
#define SHEKYL_WALLET_ERR_NULL_POINTER 14

/* Error codes emitted by the high-level orchestrator FFI
 * (shekyl_wallet_create / shekyl_wallet_open / shekyl_wallet_save_state /
 * shekyl_wallet_rotate_password). The envelope-only codes above are
 * reused where the underlying failure is an envelope failure, so
 * wallet2.cpp only needs one taxonomy. */
#define SHEKYL_WALLET_ERR_IO                              15
#define SHEKYL_WALLET_ERR_PAYLOAD                         16
#define SHEKYL_WALLET_ERR_LEDGER                          17
#define SHEKYL_WALLET_ERR_KEYS_FILE_ALREADY_EXISTS        18
#define SHEKYL_WALLET_ERR_ALREADY_LOCKED                  19
#define SHEKYL_WALLET_ERR_ATOMIC_WRITE_RENAME             20
#define SHEKYL_WALLET_ERR_UNKNOWN_NETWORK                 21
#define SHEKYL_WALLET_ERR_NETWORK_MISMATCH                22
#define SHEKYL_WALLET_ERR_KEYS_FILE_WRITE_ONCE_VIOLATION  23
#define SHEKYL_WALLET_ERR_PREFS                           24

/* Transitional (2k.a -> 2m-keys) capability-refusal codes emitted by
 * shekyl_wallet_extract_rederivation_inputs. Distinct codes per
 * capability so the C++ wallet2 shim can translate each to its own
 * capability-mode branch rather than collapsing them into a generic
 * "not FULL" failure. Both codes are slated for deletion alongside
 * the extract FFI in 2m-keys. Rule 40 (zero-on-failure) still applies:
 * the 64-byte master-seed out-buffer is zero-filled on either refusal.
 *
 * Naming-stability note: the symbol suffix reads `_NO_SPEND` even
 * though the FFI now returns the 64-byte master seed rather than a
 * 32-byte spend scalar. The suffix refers to the capability-mode
 * refusal category ("this wallet has no spend capability"), not to
 * any specific byte count. Renaming would churn every C++ call site
 * for a cosmetic gain; the constants retire in 2m-keys regardless. */
#define SHEKYL_WALLET_ERR_CAPABILITY_VIEW_ONLY_NO_SPEND         25
#define SHEKYL_WALLET_ERR_CAPABILITY_HARDWARE_OFFLOAD_NO_SPEND  26

/* 2l.a — save_as + typed-ledger FFI surface (design pin #10 / Q2.A,
 * design pin #2 / Q1.alpha-Shape-2). Save_as is atomic only within a
 * single filesystem; cross-filesystem rename is refused outright so
 * the caller (typically the GUI) can fall back to a non-atomic
 * export flow that the user explicitly confirms. The ledger setters
 * may also refuse with BLOCK_NOT_HYDRATED if the C++ side calls a
 * setter for a block whose getter has not been invoked since open;
 * 2l.a leaves that branch unwired (the codepoint is reserved for
 * 2l.b/c when the hydrate-then-emit dance starts running). */
#define SHEKYL_WALLET_ERR_SAVE_AS_CROSS_FILESYSTEM        27
#define SHEKYL_WALLET_ERR_SAVE_AS_TARGET_EXISTS           28
#define SHEKYL_WALLET_ERR_BLOCK_NOT_HYDRATED              29

/// AAD-readable header view of a `.wallet.keys` file. Layout pinned by
/// `static_assert` below; any change in Rust flow-checks against the
/// `#[repr(C)]` struct in `rust/shekyl-ffi/src/wallet_envelope_ffi.rs`.
struct ShekylKeysFileHeaderView {
    uint8_t format_version;
    uint8_t kdf_algo;
    uint8_t kdf_m_log2;
    uint8_t kdf_t;
    uint8_t kdf_p;
    uint8_t wrap_count;
    uint8_t _reserved[2];
    uint8_t wrap_salt[SHEKYL_WALLET_KEYS_WRAP_SALT_BYTES];
};
static_assert(sizeof(ShekylKeysFileHeaderView) == 8 + SHEKYL_WALLET_KEYS_WRAP_SALT_BYTES,
    "ShekylKeysFileHeaderView layout must match Rust #[repr(C)] (padding pinned by _reserved[2])");

/// Full post-decryption view of a `.wallet.keys` file (fixed-size metadata).
/// The variable-length `cap_content` bytes are written into a caller-
/// provided buffer by `shekyl_wallet_keys_open`.
///
/// Padding is spelled out explicitly so the layout does not depend on the
/// compiler's implicit alignment rules for `uint64_t`. `_reserved_align[7]`
/// is the pad between `expected_classical_address` (odd 65-byte length)
/// and `creation_timestamp` (8-byte aligned). The Rust `#[repr(C)]`
/// counterpart in `rust/shekyl-ffi/src/wallet_envelope_ffi.rs` carries the
/// same explicit field so both sides agree at sizeof = 112 bytes.
struct ShekylOpenedKeysInfo {
    uint8_t format_version;
    uint8_t capability_mode;
    uint8_t network;
    uint8_t seed_format;
    uint8_t _reserved[4];
    uint8_t expected_classical_address[SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES];
    uint8_t _reserved_align[7];
    uint64_t creation_timestamp;
    uint32_t restore_height_hint;
    uint32_t cap_content_len;
    uint8_t seed_block_tag[SHEKYL_WALLET_SEED_BLOCK_TAG_BYTES];
};
static_assert(sizeof(ShekylOpenedKeysInfo) ==
    8 + SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES + 7 + 8 + 4 + 4
        + SHEKYL_WALLET_SEED_BLOCK_TAG_BYTES,
    "ShekylOpenedKeysInfo layout must match Rust #[repr(C)]");

/// Parse only the AAD-readable header of a `.wallet.keys` file. Cheap;
/// does not touch the password. Returns false with BAD_MAGIC for pre-v1
/// files so wallet2.cpp can surface the dedicated "restore from seed"
/// upgrade message.
bool shekyl_wallet_keys_inspect(
    const uint8_t* bytes_ptr, size_t bytes_len,
    ShekylKeysFileHeaderView* out_view,
    uint32_t* out_error);

/// Seal a fresh `.wallet.keys` file. See header comment for the two-call
/// sizing pattern. `cap_content_ptr/len` carries the capability-mode bytes
/// with the layout documented in docs/WALLET_FILE_FORMAT_V1.md.
bool shekyl_wallet_keys_seal(
    const uint8_t* password_ptr, size_t password_len,
    uint8_t network,
    uint8_t seed_format,
    uint8_t capability_mode,
    const uint8_t* cap_content_ptr, size_t cap_content_len,
    uint64_t creation_timestamp,
    uint32_t restore_height_hint,
    const uint8_t* expected_classical_address_ptr,
    uint8_t kdf_m_log2, uint8_t kdf_t, uint8_t kdf_p,
    uint8_t* out_buf, size_t out_cap, size_t* out_len_required,
    uint32_t* out_error);

/// Decrypt a `.wallet.keys` file and populate `out_info` plus the
/// `cap_content_buf`. Two-call sizing: call once with
/// `cap_content_buf = nullptr, cap_content_cap = 0` to discover
/// `out_info->cap_content_len`, then retry with a sufficient buffer.
bool shekyl_wallet_keys_open(
    const uint8_t* password_ptr, size_t password_len,
    const uint8_t* bytes_ptr, size_t bytes_len,
    ShekylOpenedKeysInfo* out_info,
    uint8_t* cap_content_buf, size_t cap_content_cap,
    uint32_t* out_error);

/// Rotate the wrapping password on a `.wallet.keys` file. The output has
/// the same byte length as the input; region 1 bytes are byte-identical
/// across the rotation (enforced by debug_assert on the Rust side).
/// Pass `new_kdf_present = 0` to preserve the existing KDF parameters.
bool shekyl_wallet_keys_rewrap_password(
    const uint8_t* old_password_ptr, size_t old_password_len,
    const uint8_t* new_password_ptr, size_t new_password_len,
    const uint8_t* bytes_ptr, size_t bytes_len,
    uint8_t new_kdf_present,
    uint8_t new_kdf_m_log2, uint8_t new_kdf_t, uint8_t new_kdf_p,
    uint8_t* out_buf, size_t out_cap, size_t* out_len_required,
    uint32_t* out_error);

/// Seal a `.wallet` state file. Each call re-runs the Argon2id wrap to
/// recover `file_kek` (no file_kek is cached across FFI calls).
bool shekyl_wallet_state_seal(
    const uint8_t* password_ptr, size_t password_len,
    const uint8_t* keys_file_ptr, size_t keys_file_len,
    const uint8_t* state_plain_ptr, size_t state_plain_len,
    uint8_t* out_buf, size_t out_cap, size_t* out_len_required,
    uint32_t* out_error);

/// Open a `.wallet` state file. Cross-checks the seed_block_tag with the
/// companion `.wallet.keys`; returns
/// SHEKYL_WALLET_ERR_STATE_SEED_BLOCK_MISMATCH if the two do not belong
/// together (swap-detection).
bool shekyl_wallet_state_open(
    const uint8_t* password_ptr, size_t password_len,
    const uint8_t* keys_file_ptr, size_t keys_file_len,
    const uint8_t* state_file_ptr, size_t state_file_len,
    uint8_t* out_buf, size_t out_cap, size_t* out_len_required,
    uint32_t* out_error);

/* ----------------------------------------------------------------------
 * High-level wallet-file orchestrator (opaque handle)
 * ----------------------------------------------------------------------
 *
 * `ShekylWallet` is an opaque handle produced by `shekyl_wallet_create`
 * and `shekyl_wallet_open`, consumed by every other function in this
 * block, and destroyed exclusively by `shekyl_wallet_free`. Internally
 * it owns the Rust `WalletFileHandle` (which holds the advisory file
 * lock, cached keys-file bytes, and decoded non-secret metadata) plus
 * the loaded `WalletLedger`.
 *
 * Before this surface, wallet2.cpp re-implemented companion-path
 * derivation, atomic writes, advisory locking, and write-once
 * enforcement in C++. This surface moves all of that into Rust; C++
 * only calls the lifecycle operations and reads non-secret metadata.
 *
 * Thread-safety: C++ must not call two mutating operations on the same
 * handle concurrently. Read-only getters may overlap with each other
 * but not with writers. The handle itself is `!Send` on the Rust side.
 */

/* Opaque forward declaration; the layout of `ShekylWallet` is private
 * to Rust. C++ consumers hold `ShekylWallet*` and pass it unchanged. */
struct ShekylWallet;

/* Non-secret wallet metadata view. Populated by
 * `shekyl_wallet_get_metadata`; fields mirror the Rust `#[repr(C)]`
 * struct in `rust/shekyl-ffi/src/wallet_file_ffi.rs`. Layout pinned by
 * the `static_assert` below. */
struct ShekylWalletMetadata {
    uint8_t network;          /* 0 = Mainnet, 1 = Testnet, 2 = Stagenet */
    uint8_t capability_mode;  /* SHEKYL_WALLET_CAPABILITY_* */
    uint8_t seed_format;      /* 0x00 = BIP-39, 0x01 = raw hex */
    uint8_t _reserved[5];     /* aligns the u64 below */
    uint64_t creation_timestamp;
    uint32_t restore_height_hint;
    uint8_t _reserved_align[4];
    uint8_t expected_classical_address[SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES];
    uint8_t _tail_pad[7];     /* pads the struct to its 8-byte-aligned size */
};
static_assert(sizeof(ShekylWalletMetadata) ==
    8 + 8 + 4 + 4 + SHEKYL_WALLET_EXPECTED_CLASSICAL_ADDRESS_BYTES + 7,
    "ShekylWalletMetadata layout must match Rust #[repr(C)] in wallet_file_ffi.rs");

/* Create a fresh wallet pair (`.wallet.keys` + `.wallet`) at
 * `base_path_ptr/len` (UTF-8) and return an owning handle via
 * `*out_handle`. On failure, `*out_handle` is left NULL.
 *
 * `initial_ledger_postcard_*` may be `(NULL, 0)`; an empty
 * `WalletLedger` is synthesized. Non-empty bytes must decode as a
 * valid ledger, otherwise this function returns
 * SHEKYL_WALLET_ERR_LEDGER without touching disk. */
bool shekyl_wallet_create(
    const char* base_path_ptr, size_t base_path_len,
    const uint8_t* password_ptr, size_t password_len,
    uint8_t network,
    uint8_t seed_format,
    uint8_t capability_mode,
    const uint8_t* cap_content_ptr, size_t cap_content_len,
    uint64_t creation_timestamp,
    uint32_t restore_height_hint,
    const uint8_t* expected_classical_address_ptr,
    uint8_t kdf_m_log2, uint8_t kdf_t, uint8_t kdf_p,
    const uint8_t* initial_ledger_postcard_ptr, size_t initial_ledger_postcard_len,
    ShekylWallet** out_handle,
    uint32_t* out_error);

/* CLI-ephemeral safety overrides for the current wallet session. Mirrors
 * the Rust `#[repr(C)]` `ShekylSafetyOverrides` and the in-tree
 * `shekyl_wallet_file::SafetyOverrides`. Implements the
 * "CLI-ephemeral overrides" layer of the three-layer preference model
 * pinned in docs/WALLET_PREFS.md §2.3 and §3.3.
 *
 * Each field is a `(has_<name>, <name>)` pair:
 *   * `has_<name> == 0` → honor the network default
 *     (`NetworkSafetyConstants::for_network(network).<default>`).
 *   * `has_<name> != 0` → use `<name>` for this session only. The
 *     value is NOT persisted; the orchestrator emits a `tracing::warn!`
 *     line at open time naming the field, the value, and the default.
 *
 * The `_pad*` fields are explicit 7-byte pads so the `uint64_t` members
 * start on their natural 8-byte alignment regardless of compiler rules.
 * They MUST be zero; the Rust side does not currently check this, but
 * future versions may, so do not smuggle side-channel data through them.
 *
 * Pass a NULL `ShekylSafetyOverrides*` to `shekyl_wallet_open` to mean
 * "no overrides" (equivalent to a zeroed struct). The GUI path always
 * passes NULL; only the shekyl-cli --advanced flags produce a non-NULL
 * pointer. */
struct ShekylSafetyOverrides {
    uint8_t has_max_reorg_depth;
    uint8_t _pad0[7];
    uint64_t max_reorg_depth;
    uint8_t has_skip_to_height;
    uint8_t _pad1[7];
    uint64_t skip_to_height;
    uint8_t has_refresh_from_block_height;
    uint8_t _pad2[7];
    uint64_t refresh_from_block_height;
};
static_assert(sizeof(ShekylSafetyOverrides) == 48,
    "ShekylSafetyOverrides layout must match Rust #[repr(C)] in wallet_file_ffi.rs");

/* Open an existing wallet pair. On success populates `*out_handle`,
 * `*out_state_lost`, and `*out_restore_from_height`.
 *
 * `overrides` may be NULL, meaning "no CLI overrides active" (the GUI
 * path). A non-NULL pointer supplies the CLI-ephemeral layer; see
 * `ShekylSafetyOverrides` above.
 *
 * When `*out_state_lost` is true, `.wallet` was absent on disk and the
 * orchestrator synthesized a fresh ledger seeded with the keys-file's
 * `restore_height_hint`. The caller MUST drive a rescan starting at
 * `*out_restore_from_height` and then call `shekyl_wallet_save_state`
 * with the rebuilt ledger before closing. */
bool shekyl_wallet_open(
    const char* base_path_ptr, size_t base_path_len,
    const uint8_t* password_ptr, size_t password_len,
    uint8_t expected_network,
    const struct ShekylSafetyOverrides* overrides,
    ShekylWallet** out_handle,
    bool* out_state_lost,
    uint64_t* out_restore_from_height,
    uint32_t* out_error);

/* Destroy a handle returned by `shekyl_wallet_create` or
 * `shekyl_wallet_open`. Calling with NULL is a no-op so C++ RAII
 * wrappers can be branchless. Passing the same non-null pointer twice
 * is undefined behavior. */
void shekyl_wallet_free(ShekylWallet* h);

/* Populate `*out` with the non-secret wallet metadata. Returns false
 * only on null-pointer arguments; the metadata itself cannot fail to
 * read because it was fully decoded at create/open time. */
bool shekyl_wallet_get_metadata(
    ShekylWallet* h,
    ShekylWalletMetadata* out,
    uint32_t* out_error);

/* Serialize the handle's in-memory `WalletLedger` to postcard bytes
 * using the standard two-call sizing convention. The emitted bytes
 * contain secrets (TxSecretKey fields); callers must zeroize before
 * free and never log. */
bool shekyl_wallet_export_ledger_postcard(
    ShekylWallet* h,
    uint8_t* out_buf, size_t out_cap, size_t* out_len_required,
    uint32_t* out_error);

/* Seal a new `.wallet` from the given ledger postcard bytes. The bytes
 * are re-parsed before Argon2id runs so malformed input is rejected
 * cheaply. On success the handle's in-memory ledger is replaced so
 * subsequent `shekyl_wallet_export_ledger_postcard` calls reflect the
 * save. */
bool shekyl_wallet_save_state(
    ShekylWallet* h,
    const uint8_t* password_ptr, size_t password_len,
    const uint8_t* ledger_postcard_ptr, size_t ledger_postcard_len,
    uint32_t* out_error);

/* Rotate the wallet password. `use_new_kdf = 0` preserves the existing
 * KDF parameters; non-zero picks up `new_kdf_{m_log2,t,p}`. Region 1 of
 * `.wallet.keys` and every byte of `.wallet` are byte-identical after
 * the rotation — only the wrap layer changes. */
bool shekyl_wallet_rotate_password(
    ShekylWallet* h,
    const uint8_t* old_password_ptr, size_t old_password_len,
    const uint8_t* new_password_ptr, size_t new_password_len,
    uint8_t use_new_kdf,
    uint8_t new_kdf_m_log2, uint8_t new_kdf_t, uint8_t new_kdf_p,
    uint32_t* out_error);

/* ---------------------------------------------------------------------------
 * Transitional: 64-byte master-seed extraction (2k.a -> 2m-keys).
 *
 * Extracts the 64-byte master seed from a FULL-mode wallet handle so
 * the C++ `wallet2::load_keys` shim can drive the existing
 * (non-transitional) shekyl_account_rederive FFI, which rebuilds
 * `m_spend_secret_key`, `m_view_secret_key`, and `m_ml_kem_decap_key`
 * locally in C++. No HKDF runs inside this function: the seed is
 * already in `cap_content` under the FULL layout, authenticated at
 * open time by the envelope AAD, and this call just copies the bytes
 * out under the capability gate.
 *
 * Design rationale (Option A'):
 *   The classical spend/view scalars and m_ml_kem_decap_key are
 *   OUTPUTS of shekyl_account_rederive, not independent secrets. The
 *   2k.a design pins this FFI to the master seed alone so (1)
 *   derivation lives in one place on the Rust side, (2) there is no
 *   intermediate state in which C++ holds classical scalars without
 *   the seed (or vice versa), and (3) the deletion surface in
 *   2m-keys is one pointer argument and one error-code group.
 *
 * Capability-mode policy:
 *   FULL             -> writes all 64 bytes, returns true, OK.
 *   VIEW_ONLY        -> writes zeros, returns false,
 *                       SHEKYL_WALLET_ERR_CAPABILITY_VIEW_ONLY_NO_SPEND.
 *   HARDWARE_OFFLOAD -> writes zeros, returns false,
 *                       SHEKYL_WALLET_ERR_CAPABILITY_HARDWARE_OFFLOAD_NO_SPEND.
 *
 * Rule 40 (zero-on-failure): `out_master_seed_64` is unconditionally
 * zero-filled on function entry; only on success does it hold the
 * 64 seed bytes.
 *
 * Leak-on-success defense (caller contract): the C++ call site MUST
 * receive these bytes into auto-wiping storage -- the canonical
 * pattern is an `epee::mlocked<tools::scrubbed_arr<uint8_t, 64>>`
 * member inside the `wallet2::TransitionalSecretKeys` RAII struct,
 * never a raw `uint8_t[64]` stack local. After the C++ side has
 * driven shekyl_account_rederive and rebuilt m_ml_kem_decap_key,
 * it MUST also scrub `m_account.m_keys.m_master_seed_64` via
 * `cryptonote::account_base::forget_master_seed()` so the
 * ShekylWallet handle remains the single in-memory source of truth
 * for the master seed (Option β, 2k.a design pin 12). */
bool shekyl_wallet_extract_rederivation_inputs(
    ShekylWallet* h,
    uint8_t* out_master_seed_64,
    uint32_t* out_error);

/* ---------------------------------------------------------------------------
 * Wallet preferences (Layer 2 of the three-layer config model).
 *
 * On-disk these live in a co-located `<P>.prefs.toml` plus
 * `<P>.prefs.toml.hmac` pair, where `<P>` is the state file path with
 * any trailing `.wallet` suffix stripped. The HMAC key is derived
 * inside Rust from the handle's `file_kek` + `expected_classical_address`,
 * so C++ never sees key material.
 *
 * The FFI surface uses JSON as the wire format even though the on-disk
 * form is TOML — rapidjson is already linked from wallet2.cpp and the
 * JSON↔TOML conversion happens behind the handle. The JSON schema is
 * the serde serialization of `shekyl_wallet_prefs::WalletPrefs`:
 * nested objects named `cosmetic`, `operational`, `device`, `rpc`, and
 * the top-level `subaddress_lookahead`. All nested structs carry
 * `#[serde(deny_unknown_fields)]`, so callers MUST NOT attempt to
 * smuggle Bucket-3 fields (`max_reorg_depth`, `skip_to_height`,
 * `refresh_from_block_height`) through this surface — those are
 * CLI-ephemeral overrides passed to `shekyl_wallet_open` via
 * `ShekylSafetyOverrides`.
 *
 * The get path is advisory: a missing file or tampered HMAC pair is
 * not an error. Defaults are returned, the tamper event is surfaced
 * via `out_was_tampered`, and the corrupt files (if any) are moved
 * aside by the Rust layer. This matches the refuse-to-load policy for
 * the keys/state files (which DO refuse) but acknowledges that losing
 * user preferences is a UX regression rather than a security event.
 * See `docs/WALLET_PREFS.md §5`.
 * ---------------------------------------------------------------------------
 */

/* Read the wallet's preferences, serialized as UTF-8 JSON, into
 * `out_buf`. Uses the standard two-call sizing discipline:
 *
 *     size_t n = 0; uint32_t e = 0;
 *     shekyl_wallet_prefs_get_json(h, NULL, 0, &n, &tampered, &e);
 *     // e == SHEKYL_WALLET_ERR_BUFFER_TOO_SMALL, n now holds length
 *     std::vector<uint8_t> buf(n);
 *     shekyl_wallet_prefs_get_json(h, buf.data(), n, &n, &tampered, &e);
 *
 * The JSON is NOT NUL-terminated. `out_was_tampered` receives true iff
 * the on-disk pair was corrupt and has been quarantined; defaults are
 * still returned. wallet2.cpp should surface a UI banner on tamper
 * but MUST NOT refuse to open the wallet. */
bool shekyl_wallet_prefs_get_json(
    ShekylWallet* h,
    uint8_t* out_buf, size_t out_cap, size_t* out_len_required,
    bool* out_was_tampered,
    uint32_t* out_error);

/* Persist caller-supplied preferences JSON. The JSON must round-trip
 * through `shekyl_wallet_prefs::WalletPrefs`'s strict schema; unknown
 * fields or Bucket-3 field names land as `SHEKYL_WALLET_ERR_PREFS`.
 * On success both `<base>.prefs.toml` and `<base>.prefs.toml.hmac`
 * have been atomically rewritten. */
bool shekyl_wallet_prefs_set_json(
    ShekylWallet* h,
    const uint8_t* json_ptr, size_t json_len,
    uint32_t* out_error);

/* ===========================================================================
 * 2l.a -- save_as + typed per-block ledger FFI surface
 * ---------------------------------------------------------------------------
 * Design pin #2 (Option alpha-Shape-2): per-element repr(C) structs whose
 * layout is bit-for-bit pinned by the static_asserts below. Hot scalars and
 * fixed-size byte arrays (txid, key_image, output_public_key, ...) are
 * direct fields; variable-length parts and Phase-6-sensitive secrets
 * (combined_shared_secret, FCMP precomputed path, tx secret-key scalars)
 * live inside an `opaque_blob` that Rust serializes via postcard. C++
 * MUST NOT inspect the opaque blob -- it carries it back unchanged on
 * save. This keeps the wire format under Rust's exclusive ownership and
 * eliminates the need for a hand-rolled C++ postcard reader.
 *
 * Memory ownership:
 *   * `shekyl_wallet_get_*` returns Rust-allocated buffers. Caller
 *     releases each with the paired `shekyl_wallet_free_*`.
 *   * `shekyl_wallet_set_*` takes borrowed pointers; Rust copies every
 *     scalar / array / heap byte before returning. Callers may free
 *     their input buffers immediately after the setter returns.
 *
 * The C++ wallet2 hydrate / emit helpers wrap each block in an RAII
 * view class (added in 2l.b under src/wallet/wallet2_handle_views.h);
 * raw pointer access from wallet2.cpp is forbidden by code review.
 * ===========================================================================
 */

/* --- LedgerBlock leaves ------------------------------------------------- */

typedef struct ShekylTransferDetailsC {
    uint8_t  tx_hash[32];
    uint64_t internal_output_index;
    uint64_t global_output_index;
    uint64_t block_height;
    /* Compressed Edwards encoding of the output public key. */
    uint8_t  key_compressed[32];
    /* Canonical 32-byte scalar encoding of the per-output key offset. */
    uint8_t  key_offset[32];
    /* Pedersen commitment mask (32-byte scalar) and amount split for
     * efficient hot-path read; the full Commitment is reconstructed in
     * Rust on set. */
    uint8_t  commitment_mask[32];
    uint64_t commitment_amount;
    uint8_t  spent;          /* 0 / 1 */
    uint8_t  has_key_image;  /* 0 / 1 -- gate for `key_image` validity */
    uint8_t  _pad0[6];
    uint8_t  key_image[32];
    uint8_t  staked;         /* 0 / 1 */
    uint8_t  stake_tier;
    uint8_t  _pad1[6];
    uint64_t stake_lock_until;
    uint64_t last_claimed_height;
    uint64_t eligible_height;
    uint8_t  frozen;         /* 0 / 1 */
    uint8_t  _pad2[7];
    uint8_t* opaque_blob;
    size_t   opaque_blob_len;
} ShekylTransferDetailsC;
static_assert(sizeof(ShekylTransferDetailsC) == 256,
    "ShekylTransferDetailsC layout must match the Rust const-assert in "
    "rust/shekyl-ffi/src/wallet_ledger_ffi.rs");

typedef struct ShekylBlockchainTipC {
    uint64_t synced_height;
    uint8_t  has_hash;       /* 0 == None, 1 == Some(tip_hash) */
    uint8_t  _pad0[7];
    uint8_t  tip_hash[32];
} ShekylBlockchainTipC;
static_assert(sizeof(ShekylBlockchainTipC) == 48,
    "ShekylBlockchainTipC layout must match the Rust const-assert");

typedef struct ShekylReorgBlockEntryC {
    uint64_t height;
    uint8_t  hash[32];
} ShekylReorgBlockEntryC;
static_assert(sizeof(ShekylReorgBlockEntryC) == 40,
    "ShekylReorgBlockEntryC layout must match the Rust const-assert");

/* --- BookkeepingBlock leaves ------------------------------------------- */

typedef struct ShekylSubaddressRegistryEntryC {
    uint8_t  spend_pk_bytes[32];
    uint32_t major;
    uint32_t minor;
} ShekylSubaddressRegistryEntryC;
static_assert(sizeof(ShekylSubaddressRegistryEntryC) == 40,
    "ShekylSubaddressRegistryEntryC layout must match the Rust const-assert");

typedef struct ShekylSubaddressLabelEntryC {
    uint32_t major;
    uint32_t minor;
    uint8_t* label_ptr;
    size_t   label_len;
} ShekylSubaddressLabelEntryC;
static_assert(sizeof(ShekylSubaddressLabelEntryC) == 24,
    "ShekylSubaddressLabelEntryC layout must match the Rust const-assert");

typedef struct ShekylAddressBookEntryC {
    uint8_t* address_ptr;
    size_t   address_len;
    uint8_t* description_ptr;
    size_t   description_len;
    uint8_t  has_payment_id; /* 0 == None */
    uint8_t  is_subaddress;  /* 0 / 1 */
    uint8_t  _pad0[6];
    uint8_t  payment_id_bytes[8];
} ShekylAddressBookEntryC;
static_assert(sizeof(ShekylAddressBookEntryC) == 48,
    "ShekylAddressBookEntryC layout must match the Rust const-assert");

typedef struct ShekylTagDescriptionEntryC {
    uint8_t* tag_ptr;
    size_t   tag_len;
    uint8_t* description_ptr;
    size_t   description_len;
} ShekylTagDescriptionEntryC;
static_assert(sizeof(ShekylTagDescriptionEntryC) == 32,
    "ShekylTagDescriptionEntryC layout must match the Rust const-assert");

typedef struct ShekylAccountTagAssignmentEntryC {
    uint32_t account;
    uint8_t  _pad0[4];
    uint8_t* tag_ptr;
    size_t   tag_len;
} ShekylAccountTagAssignmentEntryC;
static_assert(sizeof(ShekylAccountTagAssignmentEntryC) == 24,
    "ShekylAccountTagAssignmentEntryC layout must match the Rust const-assert");

/* --- TxMetaBlock leaves ------------------------------------------------ */

typedef struct ShekylTxKeyEntryC {
    uint8_t  txid[32];
    uint32_t additional_count; /* diagnostic; must equal blob's vec len */
    uint8_t  _pad0[4];
    /* Postcard-encoded TxSecretKeys (primary + Vec<additional>). Secret
     * scalar bytes never cross the FFI as plaintext arrays. */
    uint8_t* opaque_blob;
    size_t   opaque_blob_len;
} ShekylTxKeyEntryC;
static_assert(sizeof(ShekylTxKeyEntryC) == 56,
    "ShekylTxKeyEntryC layout must match the Rust const-assert");

typedef struct ShekylTxNoteEntryC {
    uint8_t  txid[32];
    uint8_t* note_ptr;
    size_t   note_len;
} ShekylTxNoteEntryC;
static_assert(sizeof(ShekylTxNoteEntryC) == 48,
    "ShekylTxNoteEntryC layout must match the Rust const-assert");

typedef struct ShekylTxAttributeEntryC {
    uint8_t* key_ptr;
    size_t   key_len;
    uint8_t* value_ptr;
    size_t   value_len;
} ShekylTxAttributeEntryC;
static_assert(sizeof(ShekylTxAttributeEntryC) == 32,
    "ShekylTxAttributeEntryC layout must match the Rust const-assert");

typedef struct ShekylScannedPoolTxEntryC {
    uint8_t  txid[32];
    uint64_t first_seen_unix_secs;
    uint8_t  double_spend_seen;
    uint8_t  _pad0[7];
} ShekylScannedPoolTxEntryC;
static_assert(sizeof(ShekylScannedPoolTxEntryC) == 48,
    "ShekylScannedPoolTxEntryC layout must match the Rust const-assert");

/* --- SyncStateBlock scalars (variable-length pending_tx_hashes is a
 *     separate array trio below) ----------------------------------------- */

typedef struct ShekylSyncStateScalarsC {
    uint32_t block_version;
    uint32_t confirmations_required;
    uint64_t restore_from_height;
    uint8_t  has_creation_anchor;
    uint8_t  scan_completed;
    uint8_t  trusted_daemon;
    uint8_t  _pad0[5];
    uint8_t  creation_anchor_hash[32];
} ShekylSyncStateScalarsC;
static_assert(sizeof(ShekylSyncStateScalarsC) == 56,
    "ShekylSyncStateScalarsC layout must match the Rust const-assert");

/* --- save_as ----------------------------------------------------------- */

/* Atomic-within-a-filesystem relocate of the wallet pair to a new
 * base path. Cross-filesystem rename is refused with
 * SHEKYL_WALLET_ERR_SAVE_AS_CROSS_FILESYSTEM; pre-existing target
 * files refuse with SHEKYL_WALLET_ERR_SAVE_AS_TARGET_EXISTS. The
 * companion `<base>.address.txt` and `<base>.prefs.toml` are NOT
 * relocated -- the address file is a UX cosmetic, the prefs file
 * is the caller's responsibility. */
bool shekyl_wallet_save_as(
    ShekylWallet* h,
    const char* new_base_path_ptr, size_t new_base_path_len,
    const uint8_t* password_ptr, size_t password_len,
    uint32_t* out_error);

/* --- LedgerBlock get / set / free trios -------------------------------- */

bool shekyl_wallet_get_transfers(
    ShekylWallet* h,
    ShekylTransferDetailsC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_transfers(
    ShekylWallet* h,
    const ShekylTransferDetailsC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_transfers(
    ShekylTransferDetailsC* ptr, size_t count);

bool shekyl_wallet_get_blockchain_tip(
    ShekylWallet* h, ShekylBlockchainTipC* out, uint32_t* out_error);
bool shekyl_wallet_set_blockchain_tip(
    ShekylWallet* h, const ShekylBlockchainTipC* in_ptr, uint32_t* out_error);

bool shekyl_wallet_get_reorg_blocks(
    ShekylWallet* h,
    ShekylReorgBlockEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_reorg_blocks(
    ShekylWallet* h,
    const ShekylReorgBlockEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_reorg_blocks(
    ShekylReorgBlockEntryC* ptr, size_t count);

bool shekyl_wallet_get_ledger_block_version(
    ShekylWallet* h, uint32_t* out, uint32_t* out_error);
bool shekyl_wallet_set_ledger_block_version(
    ShekylWallet* h, uint32_t version, uint32_t* out_error);

/* --- BookkeepingBlock get / set / free trios --------------------------- */

bool shekyl_wallet_get_subaddress_registry(
    ShekylWallet* h,
    ShekylSubaddressRegistryEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_subaddress_registry(
    ShekylWallet* h,
    const ShekylSubaddressRegistryEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_subaddress_registry(
    ShekylSubaddressRegistryEntryC* ptr, size_t count);

/* The primary subaddress label is round-tripped as a single string
 * since SubaddressLabels models it separately from per_index. */
bool shekyl_wallet_get_primary_label(
    ShekylWallet* h,
    uint8_t** out_ptr, size_t* out_len,
    uint32_t* out_error);
bool shekyl_wallet_set_primary_label(
    ShekylWallet* h,
    const uint8_t* in_ptr, size_t in_len,
    uint32_t* out_error);
void shekyl_wallet_free_primary_label(uint8_t* ptr, size_t len);

bool shekyl_wallet_get_subaddress_labels(
    ShekylWallet* h,
    ShekylSubaddressLabelEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_subaddress_labels(
    ShekylWallet* h,
    const ShekylSubaddressLabelEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_subaddress_labels(
    ShekylSubaddressLabelEntryC* ptr, size_t count);

bool shekyl_wallet_get_address_book(
    ShekylWallet* h,
    ShekylAddressBookEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_address_book(
    ShekylWallet* h,
    const ShekylAddressBookEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_address_book(
    ShekylAddressBookEntryC* ptr, size_t count);

bool shekyl_wallet_get_tag_descriptions(
    ShekylWallet* h,
    ShekylTagDescriptionEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_tag_descriptions(
    ShekylWallet* h,
    const ShekylTagDescriptionEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_tag_descriptions(
    ShekylTagDescriptionEntryC* ptr, size_t count);

bool shekyl_wallet_get_account_tags(
    ShekylWallet* h,
    ShekylAccountTagAssignmentEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_account_tags(
    ShekylWallet* h,
    const ShekylAccountTagAssignmentEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_account_tags(
    ShekylAccountTagAssignmentEntryC* ptr, size_t count);

bool shekyl_wallet_get_bookkeeping_block_version(
    ShekylWallet* h, uint32_t* out, uint32_t* out_error);
bool shekyl_wallet_set_bookkeeping_block_version(
    ShekylWallet* h, uint32_t version, uint32_t* out_error);

/* --- TxMetaBlock get / set / free trios -------------------------------- */

bool shekyl_wallet_get_tx_keys(
    ShekylWallet* h,
    ShekylTxKeyEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_tx_keys(
    ShekylWallet* h,
    const ShekylTxKeyEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_tx_keys(
    ShekylTxKeyEntryC* ptr, size_t count);

bool shekyl_wallet_get_tx_notes(
    ShekylWallet* h,
    ShekylTxNoteEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_tx_notes(
    ShekylWallet* h,
    const ShekylTxNoteEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_tx_notes(
    ShekylTxNoteEntryC* ptr, size_t count);

bool shekyl_wallet_get_tx_attributes(
    ShekylWallet* h,
    ShekylTxAttributeEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_tx_attributes(
    ShekylWallet* h,
    const ShekylTxAttributeEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_tx_attributes(
    ShekylTxAttributeEntryC* ptr, size_t count);

bool shekyl_wallet_get_scanned_pool_txs(
    ShekylWallet* h,
    ShekylScannedPoolTxEntryC** out_ptr, size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_scanned_pool_txs(
    ShekylWallet* h,
    const ShekylScannedPoolTxEntryC* in_ptr, size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_scanned_pool_txs(
    ShekylScannedPoolTxEntryC* ptr, size_t count);

bool shekyl_wallet_get_tx_meta_block_version(
    ShekylWallet* h, uint32_t* out, uint32_t* out_error);
bool shekyl_wallet_set_tx_meta_block_version(
    ShekylWallet* h, uint32_t version, uint32_t* out_error);

/* --- SyncStateBlock scalar struct + pending_tx_hashes trio ------------- */

bool shekyl_wallet_get_sync_state_scalars(
    ShekylWallet* h,
    ShekylSyncStateScalarsC* out,
    uint32_t* out_error);
bool shekyl_wallet_set_sync_state_scalars(
    ShekylWallet* h,
    const ShekylSyncStateScalarsC* in_ptr,
    uint32_t* out_error);

/* `out_ptr` points to an array of 32-byte tx hashes. Use the
 * standard Rust-allocated lifetime: free with
 * shekyl_wallet_free_pending_tx_hashes after reading. */
bool shekyl_wallet_get_pending_tx_hashes(
    ShekylWallet* h,
    uint8_t (**out_ptr)[32], size_t* out_count,
    uint32_t* out_error);
bool shekyl_wallet_set_pending_tx_hashes(
    ShekylWallet* h,
    const uint8_t (*in_ptr)[32], size_t in_count,
    uint32_t* out_error);
void shekyl_wallet_free_pending_tx_hashes(
    uint8_t (*ptr)[32], size_t count);

/* --- Cross-block preflight -------------------------------------------- */

/* Run WalletLedger::preflight_save() against the in-memory ledger.
 * Used by the C++ save path (2l.c) before invoking save_state so a
 * schema-invariant violation surfaces before the AEAD seal runs. */
bool shekyl_wallet_ledger_preflight(
    ShekylWallet* h, uint32_t* out_error);

} // extern "C"

/// Secure memory primitives are declared in shekyl/shekyl_secure_mem.h
/// (C-compatible header used by both memwipe.c and mlocker.cpp).
