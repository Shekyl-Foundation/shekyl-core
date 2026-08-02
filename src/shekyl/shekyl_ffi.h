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
/// Canonical 65-byte classical address body (`version || spend_pk || view_pk`)
/// used by wallet-file AAD and by `shekyl_account_public_address_build` /
/// `_check`. Must match Rust `account::CLASSICAL_ADDRESS_BYTES` exactly; a
/// drift here corrupts every later field of `ShekylAllKeysBlob` because the
/// FFI is declared `#[repr(C)]` with byte-aligned `[u8; N]` arrays.
#define SHEKYL_CLASSICAL_ADDRESS_BYTES 65

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
/// authoritative Rust `account::SEED_FORMAT_*` constants in
/// `shekyl-crypto-pq` (re-exported as `SHEKYL_SEED_FORMAT_*` from
/// `shekyl-ffi`). The header values are 1-based, not 0-based, because Rust
/// reserves 0 for "unset"; a 0 received over the FFI is rejected.
#define SHEKYL_SEED_FORMAT_BIP39 1
#define SHEKYL_SEED_FORMAT_RAW32 2

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

/// MSW-1 cross-language consistency: the canonical PQC multisig wire lengths,
/// owned by shekyl-crypto-pq. The `cryptonote_config.h` twins are pinned equal
/// to these by a unit test — the only check that catches C++ and Rust drifting
/// from each other (F-1: each side internally consistent, disagreeing across
/// the FFI). All fields are byte counts.
struct ShekylPqcCanonicalLens {
    size_t single_key_len;
    size_t single_sig_len;
    size_t spend_auth_pubkey_len;
    size_t max_multisig_participants;
    size_t max_public_key_blob;
    size_t max_signature_blob;
};

/// Return the canonical PQC multisig wire lengths (see ShekylPqcCanonicalLens).
ShekylPqcCanonicalLens shekyl_pqc_canonical_lens();

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
///   1  = SchemeMismatch         5  = ThresholdMismatch     (9 retired — see below)
///   2  = ParameterBounds        6  = IndexOutOfRange       10 = CryptoVerifyFailed
///   3  = KeyBlobLength          7  = IndicesNotAscending   11 = DeserializationFailed
///   4  = SigBlobLength          8  = DuplicateKeys
/// Discriminant 9 (formerly GroupIdMismatch, "check 9") is retired: Option E′
/// deleted group_id, so verify is a 9-check pipeline. 9 is left as a gap; 10/11
/// keep their values (not renumbered).
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

// D2 escalation (ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md §6.1). The staker
// share is no longer a constant: it is a pure map of the burden operand
// n = frozen_segment_count. Rust derives it from the shipped EconomicParams, so
// the escalation numerics never cross this boundary and C++ cannot be handed a
// parameterization that differs from the one consensus pays on.
//
// frozen_segment_count MUST be read at PARENT-BLOCK state -- the same
// read-point discipline as the archival admission gate (M3-1 cached-counter
// drift class). Reading tip would let the block under validation move its own
// split.
//
// The share cannot reach miner_fee_income: compute_burn_split applies it to
// burned_amount, while miner_fee_income = total_fees - burned_amount depends
// only on total_fees and burn_pct. Escalating moves value from
// actually_destroyed to staker_pool_amount and nowhere else, so the
// security-budget channel is structurally unreachable (§12.11.1 Leg 1).
//
// At the genesis-neutral parameterization (asymptote == staker_pool_share) this
// is BIT-IDENTICAL to shekyl_compute_burn_split with the flat constant, at
// every n. Shipping the frozen shape does not ship an unpinned number; the
// asymptote is ceremony-gated (§11.4).
ShekylBurnSplit shekyl_compute_burn_split_escalated(
    uint64_t total_fees,
    uint64_t burn_pct,
    uint64_t frozen_segment_count);

/// The D2-escalated staker share at frozen_segment_count, fixed-point SCALE.
/// Observability / callers needing the share without a split. Same parent-state
/// read-point obligation as shekyl_compute_burn_split_escalated.
uint64_t shekyl_staker_pool_share_at(uint64_t frozen_segment_count);

/// Base block subsidy before weight penalty and release multiplier (0h KAT export).
uint64_t shekyl_base_block_reward(uint64_t already_generated_coins);

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

/// Derive ML-KEM-keyed view-tag pre-filter byte (FA-6).
/// ml_kem_ss_ptr: exactly 32 bytes. Returns 1-byte wire tag.
uint8_t shekyl_derive_view_tag_prefilter(
    const uint8_t* ml_kem_ss_ptr,
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

/// Verify a membership-only FCMP++ proof (reward-emission backing; NO key image).
/// Mirror of shekyl_fcmp_verify without the key-image array. Anti-replay for this
/// path is the emission per-epoch dedup, not a key image; the ML-DSA leaf gate is
/// shekyl_emission_hybrid_auth_verify. po_count must equal pqc_hash_count.
/// po_count must be in 1..=MAX_INPUTS (= 8); 0 or larger is rejected up front.
/// Returns 0 on success, else the VerifyError discriminant:
///   1 = Deserialization (also: null ptr; po_count == 0 or > MAX_INPUTS; po_count*32 usize overflow)
///   2 = InvalidTreeRoot   3 = PqcCommitmentMismatch
///   5 = UpstreamError     6 = BatchVerificationFailed   7 = TreeDepthTooLarge
///   8 = InputCountMismatch (po_count != pqc_hash_count)
/// Code 4 (KeyImageCountMismatch) is unreachable here — this path has no key images.
uint8_t shekyl_fcmp_membership_only_verify(
    const uint8_t* proof_ptr,
    size_t proof_len,
    const uint8_t* pseudo_outs_ptr,
    size_t po_count,
    const uint8_t* pqc_pk_hashes_ptr,
    size_t pqc_hash_count,
    const uint8_t* tree_root_ptr,
    uint8_t tree_depth,
    const uint8_t* signable_tx_hash_ptr);

/// Reward-emission hybrid vin-auth verify (PR-E1; the C-1 hard-gate core). C-1 calls
/// this once per auth (Auth-B backing, Auth-P pseudonym).
///   (1) recompute hash_pqc_public_key(pubkey) and require equality with the in-circuit
///       committed leaf_hash (binds the auth to the proven leaf, gate-6 §9.6);
///   (2) verify the HYBRID (Ed25519 + ML-DSA-65) signature over msg.
/// The auth is hybrid, matching every other signature in the system — NOT ML-DSA-only.
/// Ratified for defense-in-depth against a classical break of ML-DSA-65 (Auth-P has no
/// membership-proof classical fallback). See REWARD_EMISSION_VIN_PLAN.md R1.A(2) retraction.
/// pubkey_ptr: canonical hybrid public key bytes. sig_ptr: canonical hybrid
/// signature bytes. leaf_hash_ptr: 32-byte in-circuit committed leaf hash.
/// pubkey_len / sig_len MUST equal the canonical hybrid pubkey / signature lengths — a
/// non-canonical length is rejected UP FRONT (before any pointer is read) as PubkeyDeser (2) /
/// SigDeser (3), NOT NullPtr. Pass the exact canonical byte counts, not a buffer capacity.
/// LEAF-HASH INPUT — do not get this wrong: despite the pqc_pk naming, the leaf hash is
/// hash_pqc_public_key over the FULL canonical hybrid pubkey bytes (Ed25519 || ML-DSA-65),
/// exactly what curve-tree leaves commit (derivation.rs::derive_pqc_leaf_hash). Hashing only
/// the ML-DSA component yields a different leaf_hash and systematic LeafHashMismatch (code 4).
/// Returns 0 on success, else:
///   1 = NullPtr   2 = PubkeyDeser   3 = SigDeser
///   4 = LeafHashMismatch   5 = Verify (signature did not verify).
uint8_t shekyl_emission_hybrid_auth_verify(
    const uint8_t* pubkey_ptr,
    size_t pubkey_len,
    const uint8_t* msg_ptr,
    size_t msg_len,
    const uint8_t* sig_ptr,
    size_t sig_len,
    const uint8_t* leaf_hash_ptr);

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
    uint8_t enc_label[8];
    uint8_t label_tag;
    uint8_t view_tag_prefilter;
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

/// Construct output with explicit 8-byte label plaintext (FA-8 cooperative send).
ShekylOutputData shekyl_construct_output_labeled(
    const uint8_t* tx_key_secret,
    const uint8_t* x25519_pk,
    const uint8_t* ml_kem_ek,
    size_t ml_kem_ek_len,
    const uint8_t* spend_key,
    uint64_t amount,
    uint64_t output_index,
    const uint8_t* label_plaintext);

/// Label plaintext for a payment URI (ungated; see SUBADDRESS_UNDER_PQC.md
/// §5.7.10). Parses `shekyl:…?rid=…` and returns 0 on success (REQUEST
/// plaintext if a valid u48-encodable `rid` is present, else sentinel — a
/// missing or out-of-range `rid` also yields the sentinel with rc 0). On -3
/// (parse/UTF-8 failure) the output is still the sentinel plaintext. -4 is
/// returned on null pointer without writing `out_plaintext`.
int32_t shekyl_label_plaintext_for_payment_uri(
    const char* uri,
    uint8_t* out_plaintext);

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
    const uint8_t* enc_label,
    uint8_t label_tag_on_chain,
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
    const uint8_t* enc_label,
    uint8_t label_tag_on_chain,
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
    const uint8_t* enc_label,
    uint8_t label_tag_on_chain,
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
/// output_indices: output_count u32 vout indices, strictly increasing, entry i
///   pairing with proof-secrets entry i (carried in the proof wire format).
bool shekyl_generate_tx_proof_inbound(
    const uint8_t* view_secret_key,        // 32 bytes
    const uint8_t* txid,                   // 32 bytes
    const uint8_t* address,                // address_len bytes
    size_t address_len,
    const uint8_t* message,                // message_len bytes
    size_t message_len,
    const uint8_t* proof_secrets,          // output_count * 128 bytes
    const uint32_t* output_indices,        // output_count u32 values
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
/// Spend authority is the single master spend_secret_key; there is no
/// per-output spend secret (the prover derives x = ho + b from the master).
bool shekyl_generate_reserve_proof(
    const uint8_t* spend_secret_key,       // 32 bytes (master)
    const uint8_t* address,                // address_len bytes
    size_t address_len,
    const uint8_t* message,                // message_len bytes
    size_t message_len,
    const uint8_t* proof_secrets,          // output_count * 128 bytes
    const uint8_t* key_images,             // output_count * 32 bytes
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

/// Recover the 32-byte BIP-39 entropy from a validated 24-word English
/// mnemonic phrase. Writes 32 bytes to `out32_ptr` on success; zero-fills
/// `out32_ptr` and returns `false` on validation failure or null
/// `out32_ptr`. The inverse of `shekyl_bip39_mnemonic_from_entropy` above;
/// used by the wallet keyfile JSON-restore path to extract the entropy
/// bytes for `store_keys`-encrypted persistence in `m_bip39_entropy`. See
/// `docs/completed/ELECTRUM_WORDS_REMOVAL.md` §4.10 for the keyfile schema
/// rationale.
bool shekyl_bip39_mnemonic_to_entropy(
    const uint8_t* words_ptr,
    size_t words_len,
    uint8_t* out32_ptr);

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
///
/// Parameter order matches the Rust definition in
/// `rust/shekyl-ffi/src/account_ffi.rs::shekyl_account_public_address_check`:
/// the 1216-byte `pqc_public_key` comes first, the 32-byte `view_pub` second.
/// Swapping the order silently passes garbage through the FIPS-203
/// well-formedness check; that mistake produced the 14 `uri.*` regressions
/// in commit 0092a8da1 (surfaced at merge 30db140fe).
bool shekyl_account_public_address_check(
    const uint8_t* pqc_public_key_ptr,
    const uint8_t* view_pub_ptr);

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

/// Compose every curve-tree layer ABOVE the leaf layer, narrow from the leaf-chunk
/// layer — the correct producer-side grow that telescopes to the reference root
/// (fixes the depth-3 layer-2 incremental-deepening divergence: an in-place deepen
/// dropped the pre-existing sibling). The daemon keeps maintaining the leaf layer
/// with shekyl_curve_tree_hash_grow_selene (which telescopes), then calls this to
/// recompose every upper layer and obtain the consensus root.
///
/// Output sizes are deterministic from num_leaf_chunks via the SELENE/HELIOS
/// chunk-width ladder, so the caller pre-allocates:
///   leaf_chunks_ptr:      num_leaf_chunks * 32 bytes (leaf-layer chunk hashes).
///   out_chunks_ptr:       the upper chunks, layer 1 first then layer 2, …, 32B each.
///   out_chunks_capacity:  a COUNT of 32-byte chunks (NOT bytes); must be
///                         >= the sum of the upper-layer chunk counts.
///   out_layer_sizes_ptr:  one chunk-count per upper layer.
///   out_layer_sizes_capacity: a COUNT of uint64_t entries (NOT bytes); must be
///                         >= the number of upper layers.
///   out_num_upper_layers: number of upper layers written.
///   out_root_ptr:         32 bytes — the consensus curve-tree root.
/// Returns true on success; false on a null pointer, insufficient capacity, or a
/// malformed leaf node.
bool shekyl_curve_tree_grow_upper_layers(
    const uint8_t* leaf_chunks_ptr,
    uint64_t num_leaf_chunks,
    uint8_t* out_chunks_ptr,
    uint64_t out_chunks_capacity,
    uint64_t* out_layer_sizes_ptr,
    uint64_t out_layer_sizes_capacity,
    uint64_t* out_num_upper_layers,
    uint8_t* out_root_ptr);

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
/// cors_origins: optional comma-separated allow-list from
///   --rpc-access-control-origins; NULL or empty = CORS default-deny.
/// max_connections / max_connections_per_public_ip /
///   max_connections_per_private_ip: concurrent-connection caps enforced by the
///   Rust listener (0 = unlimited), already cross-validated by
///   core_rpc_server::init.
/// Returns an opaque handle, or NULL on failure.
ShekylDaemonRpcHandle* shekyl_daemon_rpc_start(
    void* rpc_server_ptr,
    const char* bind_addr,
    bool restricted,
    const char* cors_origins,
    uint64_t max_connections,
    uint64_t max_connections_per_public_ip,
    uint64_t max_connections_per_private_ip);

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

/* save_as refusal codes. save_as is atomic only within a single
 * filesystem (design pin #10 / Q2.A); cross-filesystem rename is
 * refused outright so the caller (typically the GUI) can fall back
 * to a non-atomic export flow that the user explicitly confirms.
 * Pre-existing target files refuse so the orchestrator never
 * silently overwrites a wallet pair. The companion typed-ledger
 * FFI surface and its BLOCK_NOT_HYDRATED codepoint were deleted as
 * a Phase 5 pre-emption; see docs/V3_WALLET_DECISION_LOG.md. */
#define SHEKYL_WALLET_ERR_SAVE_AS_CROSS_FILESYSTEM        27
#define SHEKYL_WALLET_ERR_SAVE_AS_TARGET_EXISTS           28

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
 * it owns the Rust `WalletFile` (which holds the advisory file
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
 * are re-parsed before AEAD sealing so malformed input is rejected cheaply.
 * Steady-state saves use the session-cached `wrap_key_region_2` (no Argon2).
 * On success the handle's in-memory ledger is replaced so subsequent
 * `shekyl_wallet_export_ledger_postcard` calls reflect the save. */
bool shekyl_wallet_save_state(
    ShekylWallet* h,
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

/* ===========================================================================
 * save_as -- atomic-within-a-filesystem wallet relocate
 * ---------------------------------------------------------------------------
 * The companion typed per-block ledger FFI surface (the per-element
 * repr(C) structs and `shekyl_wallet_{get,set,free}_*` trios that
 * shipped under the 2l.a sub-commit) was deleted as a Phase 5
 * pre-emption: zero `.cpp` callers ever materialized, and waiting
 * for Phase 5's mass deletion would have left an unused FFI surface
 * sitting on the maintenance budget. See
 * `docs/V3_WALLET_DECISION_LOG.md` -- "Phase 5 pre-emption rule" --
 * for the precedent that gates further individual pre-emptions.
 * ===========================================================================
 */

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

// ---------------------------------------------------------------------------
// Archival serve-credit verification (ARCHIVAL_RETENTION_GATE2.md §5.3)
// ---------------------------------------------------------------------------

struct shekyl_archival_verify_ctx {
    uint64_t current_height;
    uint64_t settlement_epoch;
    uint8_t block_hash_at_seal[32];
    uint8_t registry_segment_subroot_rk[32];
    uint64_t segment_leaf_count;
    const uint8_t* pqc_pubkey_ptr;
    size_t pqc_pubkey_len;
    /// Flattened Selene leaf-layer scalars (`N × 32` bytes); not a scalar count.
    const uint8_t* leaf_layer_scalars_ptr;
    size_t leaf_layer_scalars_len;
};

#define SHEKYL_ARCHIVAL_VERIFY_OK                    0
#define SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR        1
#define SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE              2
#define SHEKYL_ARCHIVAL_VERIFY_ERR_PATH_TOO_SHALLOW 3
#define SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_NOT_IN_OPENING 4
#define SHEKYL_ARCHIVAL_VERIFY_ERR_SUBROOT_MISMATCH  5
#define SHEKYL_ARCHIVAL_VERIFY_ERR_LEAF_INDEX        6
#define SHEKYL_ARCHIVAL_VERIFY_ERR_REGISTRY_RK       7
#define SHEKYL_ARCHIVAL_VERIFY_ERR_FIRE_NOT_REACHED  8
#define SHEKYL_ARCHIVAL_VERIFY_ERR_CREDIT_DEADLINE   9
#define SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_VERIFY       10
#define SHEKYL_ARCHIVAL_VERIFY_ERR_PQC_DESER        11
#define SHEKYL_ARCHIVAL_VERIFY_ERR_ZERO_GEOMETRY      12
#define SHEKYL_ARCHIVAL_VERIFY_ERR_EPOCH_MISMATCH    13
#define SHEKYL_ARCHIVAL_VERIFY_ERR_SCALAR_SHAPE      14

/// Returns 1 on success; writes 32-byte `P_canonical_id` to `out_p_id`.
uint8_t shekyl_archival_p_canonical_id_from_pubkey(
    const uint8_t* hybrid_pubkey_ptr,
    size_t hybrid_pubkey_len,
    uint8_t* out_p_id);

uint64_t shekyl_archival_epoch_open_height(uint64_t settlement_epoch);
uint64_t shekyl_archival_epoch_close_height(uint64_t settlement_epoch);
/// The close-processing boundary (E+1)·SEB — the height the close runs at
/// and the shard-age operand it received; 0 for the overflowing epoch.
uint64_t shekyl_archival_epoch_close_processing_height(uint64_t settlement_epoch);
uint64_t shekyl_archival_challenge_resolution_blocks(void);
uint64_t shekyl_archival_epoch_slash_deadline_height(uint64_t settlement_epoch);
uint64_t shekyl_archival_challenge_seal_height(uint64_t h_open);
/// 1 iff the epoch's challenge seal block is committed at chain_height (block
/// count, m_db->height()) — i.e. H_seal = challenge_seal_height(h_open) <
/// chain_height. The serve-credit gate calls this before reading
/// block_hash(H_seal), so a future-epoch response is rejected by predicate
/// rather than by catching a BLOCK_DNE throw.
uint8_t shekyl_archival_challenge_seal_on_chain(uint64_t h_open, uint64_t chain_height);
uint64_t shekyl_archival_challenge_fire_height(
    uint64_t h_open,
    uint64_t h_close,
    const uint8_t* block_hash_at_seal,
    const uint8_t* p_id,
    uint64_t shard_id,
    uint64_t settlement_epoch);

/// `vin_payload` is the vin body after the `0x04` type tag.
uint8_t shekyl_archival_verify_serve_credit_vin(
    const uint8_t* vin_payload_ptr,
    size_t vin_payload_len,
    const struct shekyl_archival_verify_ctx* ctx_ptr);

// Bond-post CT balance (ARCHIVAL_BOND_GATE4.md §3.2)
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK                    0
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR        1
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS      2
/// Invalid point, non-32-byte-aligned flat buffer, or count*32 overflow.
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT   3
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_SUM_MISMATCH    4
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NO_BOND_TERM    5

/// Flattened `num_pseudo_outs` / `num_out_masks` arrays of 32-byte curve points.
uint8_t shekyl_archival_verify_bond_post_ct_balance(
    const uint8_t* pseudo_outs_ptr,
    size_t num_pseudo_outs,
    const uint8_t* out_masks_ptr,
    size_t num_out_masks,
    uint64_t txn_fee,
    uint64_t bond_credit,
    uint64_t bond_debit);

// General CT cleartext balance (GENESIS_TX_WIRE_FORMAT.md §2.3): the no-bond-term
// shape for verRctSemanticsSimple / verRctSemanticsFeeOnly. Canonical prime-order
// points only; INVALID_POINT is checked before the sum, so a torsion-laden input
// returns INVALID_POINT (never SUM_MISMATCH).
#define SHEKYL_CT_BALANCE_OK                  0
#define SHEKYL_CT_BALANCE_ERR_NULL_PTR        1
#define SHEKYL_CT_BALANCE_ERR_INVALID_POINT   2
#define SHEKYL_CT_BALANCE_ERR_SUM_MISMATCH    3

/// Verify `sum(pseudoOuts) = sum(out_masks) + fee*H` over flattened `N x 32`
/// curve points (the fee contributes its commitment `fee*H`, not a bare scalar).
/// Either pointer may be null when its count is zero (fee-only shape).
uint8_t shekyl_verify_ct_balance(
    const uint8_t* pseudo_outs_ptr,
    size_t num_pseudo_outs,
    const uint8_t* out_masks_ptr,
    size_t num_out_masks,
    uint64_t txn_fee);

// Output-point validity (GENESIS_TX_WIRE_FORMAT.md §2.3, output-point rule):
// admission gates for output public keys and outPk commitment masks. Every
// point must be a canonical, prime-order (torsion-free) encoding — the same
// strictness the FCMP++ leaf builder applies, so nothing admitted here is
// silently skipped from the curve tree. Replaces crypto::check_key and the
// native check_commitment_mask_valid fingerprint block on the admission path.
#define SHEKYL_OUTPUT_POINTS_OK                0
#define SHEKYL_OUTPUT_POINTS_ERR_NULL_PTR      1
/// Output key non-canonical / torsioned / identity, or count*32 overflow.
#define SHEKYL_OUTPUT_POINTS_ERR_INVALID_KEY   2
/// Mask non-canonical / torsioned, or count*32 overflow.
#define SHEKYL_OUTPUT_POINTS_ERR_INVALID_MASK  3
/// Mask in a trivial amount-leaking form: identity, G, or coinbase
/// zeroCommit(amount).
#define SHEKYL_OUTPUT_POINTS_ERR_TRIVIAL_MASK  4

/// Flattened `num_keys x 32` output public keys; `keys_ptr` may be null when
/// `num_keys` is zero.
uint8_t shekyl_check_output_keys(
    const uint8_t* keys_ptr,
    size_t num_keys);

/// Flattened `num_masks x 32` outPk masks. For a coinbase tx pass the
/// cleartext vout amounts (mask i is checked against zeroCommit(amounts[i])
/// for i < num_coinbase_amounts); for non-coinbase pass (NULL, 0). Either
/// pointer may be null when its count is zero.
uint8_t shekyl_check_commitment_masks(
    const uint8_t* masks_ptr,
    size_t num_masks,
    const uint64_t* coinbase_amounts_ptr,
    size_t num_coinbase_amounts);

// JoinMarket bond-post semantic verify (gate-4 §3.5; hybrid pubkey + P_id hint stay C++).
// Codes 1 (NULL_PTR), 19 (LEN_OVERFLOW), and 23 (BOND_SPEND_PK_COUPLING) are shared
// vin-marshaling guards from the common vin marshaler, so BOTH bond-post entry points
// can return them: JoinMarket returns 0-10, 19, or 23; Unbond additionally returns
// 11-18 and 20-22.
#define SHEKYL_ARCHIVAL_BOND_POST_OK                           0
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_NULL_PTR                 1
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND                2
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_SHARD_SET_EMPTY           3
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_COMPLETE_TREE_WITH_SHARDS 4
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_DEBIT_NONZERO        5
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_BOTH_TERMS                6
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_ZERO                7
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_FLOOR_MISMATCH            8
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_EXISTS             9
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_KIND            10

/// `record_exists` is 1 when LMDB already stores a bond record for this P_id.
/// `bond_spend_pk_*` is the vin's GF-1 debit authorizer (§9.11); the shared vin
/// marshaler enforces the JoinMarket coupling — exact canonical single-key
/// length iff JoinMarket, empty otherwise — returning
/// SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING (code 23, shared by
/// both entry points like LEN_OVERFLOW) instead of building a vin the Rust
/// wire codec would refuse to serialize.
uint8_t shekyl_archival_verify_join_market_bond_post(
    uint8_t post_kind,
    uint8_t holdings_kind,
    const uint64_t* shard_ids_ptr,
    size_t shard_ids_len,
    const uint8_t* bond_spend_pk_ptr,
    size_t bond_spend_pk_len,
    uint64_t bonded_total_atomic,
    uint64_t bond_credit,
    uint64_t bond_debit,
    uint8_t record_exists);

// D3/R3 admission viability gate (ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md
// §12.9). Its own error space — a separate consensus predicate called
// alongside the vin verify, not part of it. The numeric codes below are
// single-sourced from shekyl-archival-retention::admission::codes; the reason
// STRINGS come from admission::admission_code_cstr -- the one table -- surfaced
// here as shekyl_archival_admission_err_string. `codes` carries no strings, and
// the FFI holds no second table of its own.
#define SHEKYL_ARCHIVAL_ADMISSION_OK                            0
#define SHEKYL_ARCHIVAL_ADMISSION_ERR_NULL_PTR                  1
#define SHEKYL_ARCHIVAL_ADMISSION_ERR_HOLDINGS_KIND             2
#define SHEKYL_ARCHIVAL_ADMISSION_ERR_GATHER_MISMATCH           3
#define SHEKYL_ARCHIVAL_ADMISSION_ERR_BELOW_FLOOR               4
// Gather columns ragged among THEMSELVES -- distinct from _GATHER_MISMATCH,
// which compares the gather to the vin. Two different caller bugs, so two
// codes: sharing one would force a reason string too vague to help either.
#define SHEKYL_ARCHIVAL_ADMISSION_ERR_GATHER_COLUMNS            5

/// Settlement epoch whose archival_r_market rows are readable as of the parent
/// block. C++ uses this as the LMDB key; do not re-derive E-1 in the daemon.
uint64_t shekyl_archival_last_settled_epoch_as_of_parent(uint64_t parent_height);

/// NUL-terminated static reason for an admission code (do not free). Distinguishes
/// marshal failures from the below-floor verdict.
const char* shekyl_archival_admission_err_string(uint8_t code);

/// Refuse a bond whose holdings credit no work: admission runs the SAME chain
/// that pays (shard_work_micro -> work_milli_from_micro).
///
/// r_market_* / freeze_height_* / has_segment_* are ALL parallel to the vin's
/// shard list; key r_market with
/// shekyl_archival_last_settled_epoch_as_of_parent(parent_height). A missing
/// r_market row marshals as 0 (Rust scores r_market+1). parent_height MUST be
/// chain_height - 1. CompleteTree: vin_shard_count = 0 and NULL arrays.
///
/// has_segment_* MUST be the real presence bit -- the RETURN VALUE of
/// archival_shard_freeze_height, not inferred from the height. A shard with no
/// frozen segment scores age_milli = 0, matching the reward path's
/// shard_contribution_micro; and freeze_height 0 is a legitimate genesis-band
/// value, so presence cannot be recovered from the height. Passing true with a
/// defaulted 0 height scores the MAXIMUM age where the reward path scores zero.
uint8_t shekyl_archival_check_bond_admission(
    uint8_t holdings_kind,
    size_t vin_shard_count,
    const uint64_t* r_market_ptr,
    size_t r_market_len,
    const uint64_t* freeze_height_ptr,
    size_t freeze_height_len,
    const uint8_t* has_segment_ptr,
    size_t has_segment_len,
    uint64_t parent_height);

// Unbond bond-post semantic verify (gate-4 §3.5 debit path; PHASE_2B_FSM_RETOOL.md
// P2B-8). Extends the shared SHEKYL_ARCHIVAL_BOND_POST_* error space above: 11-18,
// 20, 21, and 22 are Unbond-semantic; 19 (LEN_OVERFLOW) and 23
// (BOND_SPEND_PK_COUPLING) are shared vin-marshaling guards returned by both
// entry points (see the JoinMarket block above).
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_UNBOND    11
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_RECORD_MISSING          12
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_NOTHING_TO_UNBOND       13
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_CREDIT           14
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_FLOOR_MISMATCH   15
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_NOT_FULL_UNBOND         16
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_DEBIT_NOT_FULL          17
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_COOLDOWN_NOT_ELAPSED    18
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_LEN_OVERFLOW            19
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_UNBOND_HOLDINGS_NOT_EMPTY 20
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_INTERVAL_LOG_FULL       21
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_SLASH_SETTLEMENT_PENDING 22
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_BOND_SPEND_PK_COUPLING  23

// HoldingsUpdate bond-post semantics (gate-4 §4.4; PHASE_2B_FSM_RETOOL.md P2B-7,
// grace-tail DROP). Extends the shared SHEKYL_ARCHIVAL_BOND_POST_* space: 24-30
// are the ADD (credit) arm, 31-35 the DROP (grace-tail debit) arm; the shared
// vin-marshaling guards (19 LEN_OVERFLOW, 23 BOND_SPEND_PK_COUPLING) and the
// HOLDINGS_KIND guard (10) apply to both entry points as above.
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_HOLDINGS_UPDATE 24
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ON_COMPLETE_TREE     25
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_POST_NOT_COMPACT     26
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_TERMS            27
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_GOOD_STANDING    28
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_ADD       29
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_ADD_FLOOR_MISMATCH   30
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_TERMS           31
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_NOT_SINGLE_DROP      32
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_LAST_SHARD      33
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_FLOOR_MISMATCH  34
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_DROP_WITHIN_HORIZON  35
// The record is not Bonded (zero collateral / no held shards) — P2B-7 Pin 1:
// HoldingsUpdate is Bonded→Bonded; an Exited or slash-emptied record re-enters
// via JoinMarket/Rebond, never a voluntary adjustment. Shared by both HU arms.
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_RECORD_NOT_BONDED    36

// Rebond bond-post semantics (gate-4 §3.4; P2B-9 reinstatement pins). Extends
// the shared SHEKYL_ARCHIVAL_BOND_POST_* space: 37-44 are Rebond-semantic; the
// shared marshaling guards (10 HOLDINGS_KIND, 19 LEN_OVERFLOW, 23
// BOND_SPEND_PK_COUPLING) and the reused RECORD_MISSING (12) /
// SHARD_SET_EMPTY (2) apply as above.
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_POST_KIND_NOT_REBOND    37
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_ON_COMPLETE_TREE 38
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_POST_NOT_COMPACT 39
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_NOT_SLASHED      40
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_MULTIPLE_OPEN    41
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_LOG_HEADROOM     42
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_TERMS            43
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_NOT_SUPERSET     44
// RETIRED — never returned. Code 45 was the Rebond verify-level oversize belt,
// removed with the Rust ShardSet newtype (an oversize post is now
// unrepresentable in the vin's holdings). The symbol stays DEFINED and reserved
// (rather than renumbering 46/47/48) so the Rust<->C++ code contract is explicit
// and a stray/legacy 45 maps to a meaningful message, not "unknown".
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_POST_OVERSIZE_RETIRED 45
// Record bonded_total != bond_floor(record holdings) — floor-drifted record,
// rejected at verify so the tx never rides to the connect fold's FATAL belt.
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_REBOND_RECORD_FLOOR     46
// Shared vin marshal (every bond-post verify entry): the vin's holdings shard
// count exceeds the wire codec bound (MAX_HOLDINGS_SHARDS) — the FFI marshal
// routes through ShardSet::new, a second decoder for the same wire object.
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_COUNT_EXCEEDED 47
// Shared vin marshal: the vin's holdings carry a duplicate shard id (rejected
// at the same ShardSet::new boundary as the count cap — "a set on the wire").
#define SHEKYL_ARCHIVAL_BOND_POST_ERR_HOLDINGS_DUPLICATE_SHARD 48

/// Unbond bond-post verify. `record_exists`/`record_bonded_total`/
/// `record_bad_interval_count` come from the LMDB bond record;
/// `per_shard_last_served_ptr` is the array of the served shards' last-served
/// settlement epochs (never-served shards omitted; for a CompleteTree record,
/// the all-shards P-prefix scan), folded Rust-side to the whole-record
/// release-cooldown anchor. `last_settled_slash_epoch` is the slash scheduler's
/// monotone watermark (archival_last_slash_epoch; u64 max = no epoch settled
/// yet, the scheduler's own storage sentinel) — the release verifies only once
/// every epoch through the anchor is slash-settled, closing the one-block
/// connect-ordering race (add_transaction runs before
/// process_archival_slash_at_height in add_block). `current_settlement_epoch`
/// is the epoch the Unbond lands in. A record whose interval log is at the
/// codec cap rejects (INTERVAL_LOG_FULL): the connect's clean interval-close
/// could not append, and a verified-but-unconnectable tx would be a
/// deterministic halt.
uint8_t shekyl_archival_verify_unbond_bond_post(
    uint8_t post_kind,
    uint8_t holdings_kind,
    const uint64_t* shard_ids_ptr,
    size_t shard_ids_len,
    const uint8_t* bond_spend_pk_ptr,
    size_t bond_spend_pk_len,
    uint64_t bonded_total_atomic,
    uint64_t bond_credit,
    uint64_t bond_debit,
    uint8_t record_exists,
    uint64_t record_bonded_total,
    size_t record_bad_interval_count,
    const uint64_t* per_shard_last_served_ptr,
    size_t per_shard_last_served_len,
    uint64_t last_settled_slash_epoch,
    uint64_t current_settlement_epoch);

// Unbond block-connect fold + pop twin (gate-4 §4.3 "On confirm" / §5;
// PHASE_2B_FSM_RETOOL.md P2B-8 implementation locus). The C++ connect arm owns
// the LMDB write txn and writes EXACTLY what the out-params dictate; no
// consensus arithmetic caller-side. Non-OK codes are connect-time invariant
// breaches / pop-time journal desyncs — the caller maps them to a FATAL abort
// (the emission-connect posture), never a soft skip.
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_OK                          0
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_NULL_PTR                1
// Code 2 (LEN_OVERFLOW) is retired: the connect fold takes the record's held
// shard COUNT, not a pointer/length pair, so no slice marshal exists to guard.
// The value stays reserved so the family's codes never renumber.
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_HOLDINGS_KIND           3
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_DEBIT_ZERO              4
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_DEBIT_NOT_RECORD_TOTAL  5
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_FLOOR_INVARIANT  6
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_TOTAL_BONDED_UNDERFLOW  7
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_INTERVAL_LOG_FULL       8
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_RECORD_NOT_EXITED       9
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_MISSING_CLEAN_CLOSE    10
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_PRE_IMAGE_EMPTY        11
#define SHEKYL_ARCHIVAL_UNBOND_APPLY_ERR_TOTAL_BONDED_OVERFLOW  12

/// Unbond connect fold: record inputs are the record's CURRENT state (before
/// the release); the outs are the full post-connect write set — record becomes
/// post_bonded_total/post_holdings_kind with post_held_shard_count (always 0)
/// shard ids, the clean interval-close [start, end) is APPENDED to the record's
/// interval log (zero-length — good_through-inert, records the exit epoch), and
/// the global counter becomes new_total_bonded. Journal the record's full
/// pre-image BEFORE applying (emission WS-2 §6.3 shape); the refund needs no
/// write here — bond_debit is the CT-balance source term on the wire. The
/// record's holdings arrive as (kind, held shard count) — the fold's floor
/// invariant never reads shard-id values, so no shard-id array crosses the FFI
/// (the shekyl_archival_unbond_pop shape).
uint8_t shekyl_archival_unbond_connect(
    uint64_t record_bonded_total,
    uint8_t record_holdings_kind,
    uint64_t record_held_shard_count,
    size_t record_bad_interval_count,
    uint64_t vin_bond_debit,
    uint64_t total_bonded_atomic,
    uint64_t unbond_settlement_epoch,
    uint64_t* post_bonded_total_out,
    uint8_t* post_holdings_kind_out,
    uint64_t* post_held_shard_count_out,
    uint64_t* interval_close_start_out,
    uint64_t* interval_close_end_out,
    uint64_t* new_total_bonded_out);

/// Block-level intra-block cross-tx bond-post uniqueness verdict — at most ONE
/// bond-post vin per P_canonical_id per block (gate-4 §3.5; the
/// shekyl_emission_block_claims_unique sibling, keyed on P alone). Per-tx
/// verify runs against pre-block DB state, so every same-P same-block pair
/// (JoinMarket+JoinMarket double-credit, Unbond+Unbond double-debit, mixed
/// kinds) passes it independently; this pass — run once per block over every
/// bond-post vin's P_canonical_id, before connect — is the layer that REJECTS
/// the block. The §4.5 conservation audit is NOT a backstop (a double-credit
/// doubles both sides consistently). ids_ptr = flattened num_ids × 32-byte
/// P_canonical_ids in block order. Returns 1 when all distinct; 0 on any
/// duplicate or a null pointer with num_ids > 0 (fail closed).
uint8_t shekyl_archival_bond_post_block_unique(
    const uint8_t* ids_ptr,
    size_t num_ids);

/// Unbond pop twin: validates the tip record is the connect's product (Exited
/// state + trailing clean interval-close for unbond_settlement_epoch), then
/// re-credits total_bonded_atomic with the journaled pre-image balance. The
/// record fields themselves are restored caller-side as a byte-copy of the
/// pre-image journal row. `has_trailing_interval` is 0 when the record's
/// interval log is empty (the trailing start/end operands are then ignored).
uint8_t shekyl_archival_unbond_pop(
    uint64_t current_record_bonded_total,
    uint64_t current_record_held_shard_count,
    uint8_t has_trailing_interval,
    uint64_t trailing_interval_start,
    uint64_t trailing_interval_end,
    uint64_t unbond_settlement_epoch,
    uint64_t journal_pre_bonded_total,
    uint64_t total_bonded_atomic,
    uint64_t* new_total_bonded_out);

// HoldingsUpdate verify + connect/pop (gate-4 §4.4). Semantic verify returns the
// shared SHEKYL_ARCHIVAL_BOND_POST_* space (OK=0, 24-35 HU-semantic, plus the
// shared marshaling guards); the connect/pop folds return the HU_APPLY family
// below. As with Unbond, a non-OK apply code is a connect-time invariant breach /
// pop-time journal desync — the caller maps it to a FATAL abort, never a soft
// skip.
#define SHEKYL_ARCHIVAL_HU_APPLY_OK                        0
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_NULL_PTR              1
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_LEN_OVERFLOW          2
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_ADD        3
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_DROP       4
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_DROP_LAST_SHARD       5
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_RECORD_FLOOR_INVARIANT 6
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_COUNTER_RANGE         7
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_NOT_SINGLE_DELTA      8
// Connect-fold belt of the verify-side Bonded gate (an Exited record cannot
// be resurrected through a voluntary adjustment).
#define SHEKYL_ARCHIVAL_HU_APPLY_ERR_RECORD_NOT_BONDED     9

/// HoldingsUpdate-ADD verify (gate-4 §4.4 credit path). `shard_ids_*` is the
/// vin's POST holdings; `record_shard_ids_*` the record's CURRENT holdings (for
/// the single-shard diff); `record_bad_intervals_ptr` is the flattened
/// (start, end) interval pairs feeding good-standing, where
/// `record_bad_intervals_len` counts **pairs** and the buffer therefore holds
/// `2 * record_bad_intervals_len` u64s. A HoldingsUpdate vin never carries
/// bond_spend_pk (credit path) — pass null/0.
uint8_t shekyl_archival_verify_holdings_update_add(
    uint8_t post_kind,
    uint8_t holdings_kind,
    const uint64_t* shard_ids_ptr,
    size_t shard_ids_len,
    const uint8_t* bond_spend_pk_ptr,
    size_t bond_spend_pk_len,
    uint64_t bonded_total_atomic,
    uint64_t bond_credit,
    uint64_t bond_debit,
    uint8_t record_exists,
    uint64_t record_bonded_total,
    uint8_t record_holdings_kind,
    const uint64_t* record_shard_ids_ptr,
    size_t record_shard_ids_len,
    uint64_t record_join_settlement_epoch,
    const uint64_t* record_bad_intervals_ptr,
    size_t record_bad_intervals_len,
    uint64_t current_settlement_epoch);

/// HoldingsUpdate-DROP verify (gate-4 §4.4 grace-tail debit path). C++ finds the
/// dropped shard by set-difference (record CURRENT \ vin POST) and reads its
/// per-shard facts: `dropped_shard_add_epoch` (the shard's stored v6 add-epoch)
/// and `dropped_shard_freeze_height` (the shard SEGMENT's freeze height — 0 when
/// the segment has no freeze row yet, the fail-closed oldest sentinel); the Rust
/// verify derives age-at-add from the pair by evaluating the freeze against
/// `H_close(add_epoch)` (`ShardAgeAtAdd::from_add`), then the retention horizon.
/// `dropped_shard_last_served` (u64 max = never served) is the release-cooldown
/// anchor; `last_settled_slash_epoch` is the slash scheduler's monotone
/// watermark (u64 max = no epoch settled yet). The Rust verify recomputes the
/// diff and cross-checks `dropped_shard_id`.
uint8_t shekyl_archival_verify_holdings_update_drop(
    uint8_t post_kind,
    uint8_t holdings_kind,
    const uint64_t* shard_ids_ptr,
    size_t shard_ids_len,
    const uint8_t* bond_spend_pk_ptr,
    size_t bond_spend_pk_len,
    uint64_t bonded_total_atomic,
    uint64_t bond_credit,
    uint64_t bond_debit,
    uint8_t record_exists,
    uint64_t record_bonded_total,
    uint8_t record_holdings_kind,
    const uint64_t* record_shard_ids_ptr,
    size_t record_shard_ids_len,
    uint64_t dropped_shard_id,
    uint64_t dropped_shard_add_epoch,
    uint64_t dropped_shard_freeze_height,
    uint64_t dropped_shard_last_served,
    uint64_t last_settled_slash_epoch,
    uint64_t current_settlement_epoch);

/// HoldingsUpdate-ADD connect fold (gate-4 §4.4). The C++ arm journals the record
/// pre-image, sets held_shard_ids = post + appends `add_settlement_epoch_out` as
/// the added shard's coupled add-epoch, and writes the counters from
/// new_bonded_total_out / new_total_bonded_out. `total_bonded_atomic` is the LIVE
/// global counter (thread it per post — never a hoisted block-start read).
uint8_t shekyl_archival_holdings_update_add_connect(
    uint64_t record_bonded_total,
    const uint64_t* record_shard_ids_ptr,
    size_t record_shard_ids_len,
    const uint64_t* post_shard_ids_ptr,
    size_t post_shard_ids_len,
    uint64_t total_bonded_atomic,
    uint64_t add_settlement_epoch,
    uint64_t* added_shard_id_out,
    uint64_t* add_settlement_epoch_out,
    uint64_t* new_bonded_total_out,
    uint64_t* new_total_bonded_out);

/// HoldingsUpdate-DROP connect fold (gate-4 §4.4 grace-tail). The C++ arm journals
/// the pre-image, sets held_shard_ids = post (dropping the coupled add-epoch of
/// `dropped_shard_id_out`), and writes the counters. `refund_out` (== FLOOR) is
/// the bond_debit CT-balance source term — no ledger write here. `total_bonded_atomic`
/// is the LIVE global counter (thread it per post).
uint8_t shekyl_archival_holdings_update_drop_connect(
    uint64_t record_bonded_total,
    const uint64_t* record_shard_ids_ptr,
    size_t record_shard_ids_len,
    const uint64_t* post_shard_ids_ptr,
    size_t post_shard_ids_len,
    uint64_t total_bonded_atomic,
    uint64_t* dropped_shard_id_out,
    uint64_t* new_bonded_total_out,
    uint64_t* new_total_bonded_out,
    uint64_t* refund_out);

/// HoldingsUpdate pop twin (add + drop; gate-4 §5). The record fields are restored
/// caller-side as a byte-copy of the pre-image journal row; this reverts the global
/// total_bonded_atomic by the connect's ±FLOOR delta, guarding that the tip
/// record's bonded_total and the journaled pre-image differ by exactly one FLOOR.
uint8_t shekyl_archival_holdings_update_pop(
    uint64_t current_record_bonded_total,
    uint64_t journal_pre_bonded_total,
    uint64_t total_bonded_atomic,
    uint64_t* new_total_bonded_out);

// Rebond verify + connect/pop (gate-4 §3.4; P2B-9 reinstatement). Semantic
// verify returns the shared SHEKYL_ARCHIVAL_BOND_POST_* space (OK=0, 37-44
// Rebond-semantic, plus the shared guards); the connect/pop folds return the
// REBOND_APPLY family below. As with Unbond/HoldingsUpdate, a non-OK apply code
// is a connect-time invariant breach / pop-time journal desync — the caller
// maps it to a FATAL abort, never a soft skip.
#define SHEKYL_ARCHIVAL_REBOND_APPLY_OK                          0
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NULL_PTR                1
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_LEN_OVERFLOW            2
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NOT_SUPERSET            3
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_EMPTY_POST              4
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_RECORD_FLOOR_INVARIANT  5
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NO_OPEN_INTERVAL        6
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_MULTIPLE_OPEN_INTERVALS 7
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_INTERVAL_ORDERING       8
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_COUNTER_RANGE           9
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_NOT_REBOND_DELTA       10
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_ADDED_BUFFER_TOO_SMALL 11
#define SHEKYL_ARCHIVAL_REBOND_APPLY_ERR_POST_OVERSIZE          12

/// Rebond verify (gate-4 §3.4; P2B-9). `shard_ids_*` is the vin's POST holdings
/// (the superset re-spec); `record_shard_ids_*` the record's CURRENT holdings;
/// `record_bad_intervals_ptr` the flattened (start, end_exclusive) interval
/// pairs, where `record_bad_intervals_len` counts PAIRS (buffer holds 2*len
/// u64s) — carries the open-interval precondition and the Pin-6 headroom bound.
/// A Rebond vin never carries bond_spend_pk (credit path; the record keeps its
/// join-time key) — pass null/0. No epoch operand: the precondition is interval-
/// shaped, not epoch-shaped (an open interval covers every later epoch).
uint8_t shekyl_archival_verify_rebond_bond_post(
    uint8_t post_kind,
    uint8_t holdings_kind,
    const uint64_t* shard_ids_ptr,
    size_t shard_ids_len,
    const uint8_t* bond_spend_pk_ptr,
    size_t bond_spend_pk_len,
    uint64_t bonded_total_atomic,
    uint64_t bond_credit,
    uint64_t bond_debit,
    uint8_t record_exists,
    uint64_t record_bonded_total,
    uint8_t record_holdings_kind,
    const uint64_t* record_shard_ids_ptr,
    size_t record_shard_ids_len,
    const uint64_t* record_bad_intervals_ptr,
    size_t record_bad_intervals_len);

/// Rebond connect fold (gate-4 §3.4; P2B-9). The C++ arm journals the record
/// pre-image (including the closed interval's index + start), sets
/// held_shard_ids = post and rebuilds the coupled add-epochs (carried shards
/// keep theirs; every id in added_shard_ids_out takes add_settlement_epoch_out
/// = E_rebond — Pin 7), closes the open interval IN PLACE
/// (bad_intervals[closed_interval_index_out].end_exclusive =
/// interval_end_exclusive_out == E_rebond + 1 — Pin 3), and writes the counters.
/// `total_bonded_atomic` is the LIVE global counter (thread per post).
/// `added_shard_ids_cap` must be >= the post length (added ⊆ post).
uint8_t shekyl_archival_rebond_connect(
    uint64_t record_bonded_total,
    const uint64_t* record_shard_ids_ptr,
    size_t record_shard_ids_len,
    const uint64_t* record_bad_intervals_ptr,
    size_t record_bad_intervals_len,
    const uint64_t* post_shard_ids_ptr,
    size_t post_shard_ids_len,
    uint64_t total_bonded_atomic,
    uint64_t rebond_settlement_epoch,
    uint64_t* added_shard_ids_out,
    size_t added_shard_ids_cap,
    size_t* added_shard_ids_len_out,
    uint64_t* add_settlement_epoch_out,
    uint64_t* closed_interval_index_out,
    uint64_t* interval_end_exclusive_out,
    uint64_t* new_bonded_total_out,
    uint64_t* new_total_bonded_out);

/// Rebond pop twin (gate-4 §5): the record fields are restored caller-side as a
/// byte-copy of the pre-image journal row (including re-opening the closed
/// interval to end_exclusive = MAX); this reverts the global total_bonded_atomic
/// by the connect's |added|·FLOOR credit — zero delta included (the common
/// standing-only reinstatement moved no collateral).
uint8_t shekyl_archival_rebond_pop(
    uint64_t current_record_bonded_total,
    uint64_t journal_pre_bonded_total,
    uint64_t total_bonded_atomic,
    uint64_t* new_total_bonded_out);

/// Returns 1 when settlement_epoch >= join_settlement_epoch + 1 (E_first lower bound).
uint8_t shekyl_archival_serve_credit_epoch_ok(
    uint64_t settlement_epoch,
    uint64_t join_settlement_epoch);

// ---------------------------------------------------------------------------
// Segment-freeze pipeline (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §5.1). The
// first-crossing boundary division lives ONLY here; both daemon hooks
// (add_block freeze processor, pop_block revert) call the entry point and
// C++ never divides by SHEKYL_ARCHIVAL_SEGMENT_LEAF_COUNT inline
// (division-one-site tripwire, pipeline doc §8).

/// Frozen-segment count at a curve-tree leaf count:
/// floor(leaf_count / SEGMENT_LEAF_COUNT).
uint64_t shekyl_archival_frozen_segment_count(uint64_t leaf_count);

/// Leaf-layer chunk backing challenged index `leaf_index_in_segment` of
/// frozen shard `shard_id`, as a global position range over the daemon's
/// curve-tree leaf table (pipeline doc §6.2). Returns 1 and writes the
/// bounds; 0 (no write) on out-of-segment index, overflow, or null out
/// pointer — verifier-input rejection, not abort.
uint8_t shekyl_archival_challenge_leaf_chunk_bounds(
    uint64_t shard_id,
    uint64_t leaf_index_in_segment,
    uint64_t* out_first_leaf_position,
    uint64_t* out_leaf_count);

// ---------------------------------------------------------------------------
// Archival epoch-close consensus computation (ARCHIVAL_CONSENSUS_STATE.md §3.3,
// §3.5). The daemon gathers raw LMDB rows and delegates the entire consensus
// computation — membership, R_market counting, age weighting, scarcity, curve,
// Σwork — to Rust in one coarse call (40-ffi-discipline.mdc). C++ performs no
// consensus arithmetic.

// Same-epoch slash-coalescing decision (P2B-9 Pin 5). The decision AND the
// interval shape live Rust-side; the C++ slash writer appends exactly what
// the call returns, deciding nothing.
#define SHEKYL_ARCHIVAL_SLASH_INTERVAL_COALESCE    0
#define SHEKYL_ARCHIVAL_SLASH_INTERVAL_APPEND      1
#define SHEKYL_ARCHIVAL_SLASH_INTERVAL_ERR_MARSHAL 2

/// Returns SHEKYL_ARCHIVAL_SLASH_INTERVAL_APPEND and writes the open interval
/// [settlement_epoch, u64 MAX) when the record carries no open bad interval;
/// SHEKYL_ARCHIVAL_SLASH_INTERVAL_COALESCE (no write) when one exists (the
/// same-epoch sibling slash appends nothing — at most one open interval ever).
/// SHEKYL_ARCHIVAL_SLASH_INTERVAL_ERR_MARSHAL is a marshal fault the slash
/// writer maps to a FATAL abort, never a skip. `bad_intervals_ptr` is
/// `2 × bad_intervals_len` u64s — the shekyl_archival_good_through layout.
uint8_t shekyl_archival_slash_open_interval_to_append(
    const uint64_t* bad_intervals_ptr,
    size_t bad_intervals_len,
    uint64_t settlement_epoch,
    uint64_t* interval_start_out,
    uint64_t* interval_end_out);

// Sliding-window m-of-n failure confirmation
// (docs/completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md §1). A single missed
// baseline is NOT a slashable failure: the slash fires only when m misses fall
// within the last n baseline OBSERVATIONS for a (P_id, shard). The gather (LMDB
// reads) is C++; the decision, the parameters, and the window contract are Rust.
#define SHEKYL_ARCHIVAL_FAILURE_WINDOW_ABSORB      0
#define SHEKYL_ARCHIVAL_FAILURE_WINDOW_SLASH       1
#define SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL 2

/// Window parameters from the one authority (config/consensus_constants.json →
/// shekyl-archival-retention). Read here rather than from a generated header
/// constant so there is no cross-language drift pair: m/n exist in exactly one
/// place, and C++ holds no second copy to keep aligned. (A Round-2 re-pin still
/// touches two sites by design — the JSON value plus the Round-1 sentinel
/// const-assert in failure_window.rs; see that module.) `serve_budget_out` is
/// `n - m`: once the gather has
/// seen more than that many PASSED observations, m is unreachable and the
/// look-back can stop reading LMDB (the arithmetic is Rust-side by design).
/// Returns SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL on a null out-pointer.
uint8_t shekyl_archival_failure_window_params(
    uint32_t* m_out,
    uint32_t* n_out,
    uint32_t* serve_budget_out);

/// Is this observation sequence a slashable failure? Two parallel arrays of
/// `observations_len` entries, MOST RECENT FIRST: `observation_epochs_ptr` is
/// strictly descending settlement epochs (head = the decision epoch);
/// `observation_served_ptr` is 0 iff that epoch's serve_credit_bit is unset (the
/// miss the window counts), nonzero for a pass.
///
/// Only epochs at which a challenge was actually POSED belong in the arrays —
/// bonded-but-untested epochs are not observations and must not appear. The
/// caller stops gathering at the boundary of the pair's current continuous
/// challengeable run (before E_join + 1, before the shard's E_add + 1, or at a
/// closed bad interval — a reinstated record starts the window clean), so a
/// shorter-than-n window is normal and is evaluated as-is.
///
/// Returns SHEKYL_ARCHIVAL_FAILURE_WINDOW_SLASH / _ABSORB, or _ERR_MARSHAL for a
/// malformed window (null pointer, an empty window with observations_len == 0,
/// longer than n, non-descending epochs, passed head) — which the slash scan
/// maps to a FATAL abort, never a skip in either direction: a slash decided over
/// a malformed window is a consensus divergence.
uint8_t shekyl_archival_failure_window_slashable(
    const uint64_t* observation_epochs_ptr,
    const uint8_t* observation_served_ptr,
    size_t observations_len);

/// `good_through(P, E)` from bond fields (§3.4 interval semantics).
/// `bad_intervals_ptr` is `2 × bad_intervals_len` u64s — flattened
/// `(start_epoch, end_exclusive)` pairs. Returns 0 (fail-closed) on malformed input.
uint8_t shekyl_archival_good_through(
    uint64_t join_settlement_epoch,
    uint64_t settlement_epoch,
    const uint64_t* bad_intervals_ptr,
    size_t bad_intervals_len);

/// Settlement epoch containing `block_height` (bond-connect join epoch).
uint64_t shekyl_archival_settlement_epoch_at_height(uint64_t block_height);

/// The effective settlement-epoch length in blocks (genesis-pinned 10 000,
/// or the clamped SHEKYL_SETTLEMENT_EPOCH_BLOCKS override — the
/// fakechain-only regtest lever). Single source for consumers needing the
/// length itself; the schedule functions here consume it internally.
uint64_t shekyl_archival_settlement_epoch_blocks(void);

/// True iff a SHEKYL_SETTLEMENT_EPOCH_BLOCKS override is active (effective
/// schedule differs from the genesis default — which requires this process
/// to have armed via shekyl_archival_settlement_epoch_arm_regtest). Drives
/// the daemon's loud fakechain warning.
bool shekyl_archival_settlement_epoch_overridden(void);

/// True iff SHEKYL_SETTLEMENT_EPOCH_BLOCKS is present in the environment at
/// all (no validation, no schedule latch). Drives Blockchain::init's
/// fail-closed public-network refusal: the schedule is consensus, and on a
/// non-FAKECHAIN net the lever's presence is the operator error to refuse
/// on, before any question of the value's validity.
bool shekyl_archival_settlement_epoch_override_present(void);

/// Arm the SHEKYL_SETTLEMENT_EPOCH_BLOCKS override (FAKECHAIN startup path
/// only), latching the validated override (or the genesis pin when unset).
/// An unarmed process ignores the lever entirely.
///
/// Returns one of SHEKYL_ARCHIVAL_SEB_ARM_* below, because the two refusals
/// need different remedies.
uint8_t shekyl_archival_settlement_epoch_arm_regtest(void);

/// Armed (or the variable is unset and the genesis pin latched).
#define SHEKYL_ARCHIVAL_SEB_ARM_OK                   0
/// The value is not an integer in the accepted range — an operator input
/// error: fix the value or unset the variable.
#define SHEKYL_ARCHIVAL_SEB_ARM_ERR_INVALID          1
/// The schedule already latched before the call — an initialization-order
/// defect in the daemon, NOT a bad value.
#define SHEKYL_ARCHIVAL_SEB_ARM_ERR_TOO_LATE         2

/// Returns 1 and writes the settlement epoch whose close is processed at
/// `block_height`; 0 (no write) at height 0 or non-boundary heights.
uint8_t shekyl_archival_epoch_close_due(
    uint64_t block_height,
    uint64_t* out_settlement_epoch);

/// Returns 1 and writes the prune horizon (`tip_epoch - MAX_CLAIM_AGE_W`) when
/// the chain is older than the claim window at `block_height`; 0 otherwise.
uint8_t shekyl_archival_prune_below_epoch(
    uint64_t block_height,
    uint64_t* out_prune_below_epoch);

/// The oldest still-claimable settlement epoch for `current_settled_epoch` —
/// a thin delegate to the Rust `claim_window_floor`, the single source of the
/// claim-window boundary. The emission claim-source RPC handler derives its
/// window low end through this (never an inline `settled - W` copy), per
/// `EMISSION_CLAIM_BUILDER.md` §2 step 1.
uint64_t shekyl_archival_claim_window_floor(uint64_t current_settled_epoch);

/* `epoch` inserted into the claimed set (stale entries pruned in place). */
#define SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED        0
/* `epoch` already claimed — hard error on the connect path (WS-2 §6.2). */
#define SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ALREADY_CLAIMED 1
/* `epoch >= current_settled_epoch`: not yet settled. */
#define SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_NOT_SETTLED 2
/* `epoch` below the claim window (`MAX_CLAIM_AGE_W`). */
#define SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_EXPIRED     3
/* Null pointer, capacity overflow, or non-strictly-increasing set. */
#define SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID     4

/// Record `epoch` as claimed in the caller-owned claimed-epoch buffer — the
/// single writer for `ArchivalBondValue::claimed_settlement_epochs` (WS-2
/// §6.2; the emission connect path is the only caller). Window maintenance
/// (prune below `current_settled_epoch − W`) happens on insert, so on
/// `INSERTED` the buffer contents *and* `*set_len` change in place; on any
/// other return both are untouched. `set_ptr` must address `set_cap`
/// writable `uint64_t`s with `*set_len <= set_cap <= 32` (the
/// `kMaxClaimedEpochs` cap).
uint8_t shekyl_archival_claimed_epochs_check_and_set(
    uint64_t* set_ptr,
    size_t* set_len,
    size_t set_cap,
    uint64_t epoch,
    uint64_t current_settled_epoch);

#define SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK                0
#define SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR      1
#define SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_LEN_OVERFLOW  2
#define SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE   3

/// One gathered bond. Layout must match `ShekylArchivalEpochCloseBond` in
/// `rust/shekyl-ffi/src/archival_ffi.rs`.
///
/// Carries no holdings descriptor (WS-1): the held-and-served set is sourced
/// solely from the serve-credit ledger rows the gather passes as credit
/// pairs, so tip holdings never cross into the work channel.
struct shekyl_archival_epoch_close_bond
{
  uint64_t join_settlement_epoch;
  /// Flattened (start_epoch, end_exclusive) pairs; `2 * bad_intervals_len` u64s.
  const uint64_t* bad_intervals_ptr;
  /// Pair count (not u64 count).
  size_t bad_intervals_len;
  uint8_t is_foundation_complete_tree;
};

/// One gathered shard-registry row. Layout must match
/// `ShekylArchivalEpochCloseShard` in `rust/shekyl-ffi/src/archival_ffi.rs`.
struct shekyl_archival_epoch_close_shard
{
  uint64_t shard_id;
  uint64_t freeze_height;
  /// 0 when no frozen segment row exists (shard age is then zero).
  uint8_t has_segment;
};

/// One serve-credit row as indices into the bond/shard gather arrays.
/// Layout must match `ShekylArchivalCreditPair` in `rust/shekyl-ffi/src/archival_ffi.rs`.
struct shekyl_archival_credit_pair
{
  size_t bond_idx;
  size_t shard_idx;
};

/// Full epoch-close computation. Writes `R_market` per input shard to
/// `out_r_market_ptr` (`shards_len` u64s) and `Σwork(E)` milli to
/// `out_sigma_work_milli_ptr`. Outputs are zeroed before computation; a
/// non-zero return never leaves stale values. Credit pairs must be distinct
/// (the serve-credit ledger key `(P, shard, E)` guarantees this at gather).
///
uint8_t shekyl_archival_epoch_close_compute(
    uint64_t settlement_epoch,
    uint64_t close_block_height,
    const struct shekyl_archival_epoch_close_bond* bonds_ptr,
    size_t bonds_len,
    const struct shekyl_archival_epoch_close_shard* shards_ptr,
    size_t shards_len,
    const struct shekyl_archival_credit_pair* credit_pairs_ptr,
    size_t credit_pairs_len,
    uint64_t* out_r_market_ptr,
    uint64_t* out_sigma_work_milli_ptr);

/// The M-2/Q7 as-of-E consensus snapshot for one claimed settlement epoch
/// (REWARD_EMISSION_E3_GATING_ROUND.md §3 item 2; REWARD_EMISSION_VIN_PLAN.md
/// §8.0.2(B)). Layout must match `ShekylArchivalEmissionEpochSnapshot` in
/// `rust/shekyl-ffi/src/archival_ffi.rs`.
///
/// Marshaled by value from the frozen E-close materialization: the
/// serve-credit rows for E (the WS-1 §5 held source), the credited bonds'
/// standing fields, shard freeze heights, and the **persisted** Σwork(E) —
/// never the live bond holdings descriptor. Every row is immutable for a
/// claimable E, so a re-gather at any height in the claim window reproduces
/// the close's gather exactly
/// (`BlockchainLMDB::gather_archival_emission_epoch_snapshot` performs it).
///
/// `sigma_work_milli` must be the persisted close output, not a recompute —
/// the close's outcome reaches verify only through the stored denominator.
struct shekyl_archival_emission_epoch_snapshot
{
  uint64_t settlement_epoch;
  /// The close-processing height (E+1)·SEB the gather froze at (shard-age
  /// operand; must equal the height the close ran at). NOT H_close(E) =
  /// shekyl_archival_epoch_close_height(E) = the epoch's last block =
  /// (E+1)·SEB − 1, one block lower.
  uint64_t close_block_height;
  /// Persisted finalized Σwork(E) milli — the stored denominator.
  uint64_t sigma_work_milli;
  /// Persisted frozen budget(E) atomic — the gate-1 numerator operand, stored
  /// at close beside Σwork(E) (the archival_budget close row,
  /// ARCHIVAL_BUDGET_SCHEDULE.md §5). Always the stored value, never a
  /// recompute: the accrual accumulator is live state; only the close row is
  /// frozen.
  uint64_t budget_atomic;
  const struct shekyl_archival_epoch_close_bond* bonds_ptr;
  size_t bonds_len;
  const struct shekyl_archival_epoch_close_shard* shards_ptr;
  size_t shards_len;
  const struct shekyl_archival_credit_pair* credit_pairs_ptr;
  size_t credit_pairs_len;
  /// Claimant P's index into `bonds`, or SIZE_MAX when P has no serve-credit
  /// row in E (its work is then zero by construction).
  size_t claimant_bond_idx;
};

/// Claimant work over the as-of-E snapshot: writes P's `work_P(E)` milli to
/// `out_work_milli` and its membership-gated credited term to
/// `out_credited_work_milli` — the emission verify numerator
/// (REWARD_EMISSION_VIN_PLAN.md §8.0.2 step 4). D3/R2: credited work is linear
/// in work (no plateau); non-members credit zero.
///
/// Sources via the same single sourcing function whose output built the
/// persisted Σwork(E) denominator at close, over the same frozen gather, so
/// the credited output is P's exact per-P term of that denominator by
/// construction (WS-1 §5.5). Note this is the numerator only: it does NOT
/// consult `snapshot->sigma_work_milli` — an empty epoch persists
/// Σwork(E) == 0 while this may still return a positive credited term, so the
/// consumer MUST divide through the persisted denominator (reward is 0 when
/// Σwork(E) == 0). Both outputs are
/// zero when P has no credit row in E or is not a market member at E. Errors
/// reuse the SHEKYL_ARCHIVAL_EPOCH_CLOSE_* codes; outputs are zeroed on entry.
uint8_t shekyl_archival_emission_epoch_work(
    const struct shekyl_archival_emission_epoch_snapshot* snapshot,
    uint64_t* out_work_milli,
    uint64_t* out_credited_work_milli);

/* ---------------------------------------------------------------------------
 * C-1 emission-vin verify FFI (REWARD_EMISSION_E3_GATING_ROUND.md §9.5 items
 * 3–5; REWARD_EMISSION_VIN_PLAN.md §7.1). Two entries: a pre-parse extractor
 * for operand gathering, and the coarse verify call running the full §7.1
 * body (claims 1–5, membership-only backing 6, hybrid auth gate 8) in one
 * FFI crossing. Step 7 (FCMP balance over fee txin_to_keys) stays with the
 * existing C++ tx layer.
 * ------------------------------------------------------------------------ */

/* Verdict: the emission vin verified end-to-end. */
#define SHEKYL_EMISSION_VIN_OK                        0
/* Required pointer was null (or an output buffer too small). */
#define SHEKYL_EMISSION_VIN_ERR_NULL_PTR              1
/* Canonical bytes failed the wire parse or structural re-validate. */
#define SHEKYL_EMISSION_VIN_ERR_WIRE                  2
/* Caller marshaling inconsistent (snapshot misalignment, malformed gather,
 * claimant index out of range) — a daemon bug surfaced loudly, never a
 * claimant-attributable rejection. */
#define SHEKYL_EMISSION_VIN_ERR_MARSHAL               3
/* Step 1: claimed epoch not finalized at the carrying height. */
#define SHEKYL_EMISSION_VIN_ERR_EPOCH_NOT_FINALIZED   4
/* Step 1: claimed epoch below the claim window (MAX_CLAIM_AGE_W). */
#define SHEKYL_EMISSION_VIN_ERR_EPOCH_EXPIRED         5
/* Step 2: no bond record for the claimant. */
#define SHEKYL_EMISSION_VIN_ERR_BOND_MISSING          6
/* Step 2: vin holdings descriptor does not match the bond record. */
#define SHEKYL_EMISSION_VIN_ERR_HOLDINGS_MISMATCH     7
/* Step 2: claimed epoch precedes the join epoch's claimable range. */
#define SHEKYL_EMISSION_VIN_ERR_EPOCH_BEFORE_JOIN     8
/* Step 3 (WS-2 read-only layer): epoch already in the claimed set. */
#define SHEKYL_EMISSION_VIN_ERR_ALREADY_CLAIMED       9
/* Step 4: work claim contradicts the frozen as-of-E recompute. */
#define SHEKYL_EMISSION_VIN_ERR_WORK_MISMATCH         10
/* Step 5 (R1.B zero-tolerance): reward differs from the recompute. */
#define SHEKYL_EMISSION_VIN_ERR_REWARD_MISMATCH       11
/* Step 5 (loud inflation check): Σ rewards != reward vout sum. */
#define SHEKYL_EMISSION_VIN_ERR_VOUT_SUM_MISMATCH     12
/* Step 6: backing pubkey does not hash to the committed leaf. */
#define SHEKYL_EMISSION_VIN_ERR_BACKING_LEAF          13
/* Step 6: membership-only proof rejected. */
#define SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED      14
/* Step 8: auth pubkey/signature failed hybrid deserialization. */
#define SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED        15
/* Step 8: hybrid auth signature rejected over its Q1 binding message. */
#define SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED         16

/* Upper bound on settlement_epochs per emission vin — mirrors the Rust wire
 * pin MAX_SETTLEMENT_EPOCHS_PER_EMISSION (emission_wire.rs; the parse rejects
 * longer sets), sizing the extract/verify epoch output buffers. */
#define SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS         15

/// Pre-parse extractor for dispatch operand gathering: parses the opaque
/// txin_archival_reward_emission canonical bytes (tag included) and writes
/// the claimant's P_canonical_id (32 bytes, recomputed from P_pubkey per
/// emission §6.1 — the bond-record key) and the claimed settlement_epochs
/// (one as-of-E snapshot gather per entry). Extraction implies nothing about
/// validity beyond the wire parse; shekyl_emission_vin_verify re-parses the
/// same bytes. `out_epochs_ptr` must address `epochs_cap` writable uint64_t
/// with `epochs_cap >= 15` (MAX_SETTLEMENT_EPOCHS_PER_EMISSION; the parse
/// rejects longer sets). Returns SHEKYL_EMISSION_VIN_OK or an error above.
uint8_t shekyl_archival_emission_vin_extract(
    const uint8_t* vin_ptr,
    size_t vin_len,
    uint8_t* out_p_canonical_id,
    uint64_t* out_epochs_ptr,
    size_t epochs_cap,
    size_t* out_epochs_len);

/// Overflow-checked sum of plaintext output amounts (rule 20: amount
/// arithmetic on untrusted tx data lives behind the FFI). Writes the sum to
/// *out_sum; returns 0 on success, 1 on u64 overflow or invalid args (the
/// caller MUST reject the tx on any non-zero return). `amounts_ptr` may be
/// null iff `len == 0`.
uint8_t shekyl_checked_sum_amounts(
    const uint64_t* amounts_ptr,
    size_t len,
    uint64_t* out_sum);

/// Block-level intra-block cross-tx (P, E) uniqueness verdict (E3 gating
/// round §6.2 layer 2; decision-placement pin §9.5 item 6 — C++ marshals the
/// block's claim pairs, Rust decides). `pairs_ptr` is a flattened array of
/// `num_pairs` 40-byte entries: p_canonical_id[32] || epoch[8] (LE; any
/// consistent injective encoding preserves the verdict), one entry per
/// (P, E_i) of every emission vin in the block, in block order. Returns 1
/// when every pair is distinct, 0 on any duplicate or on a null pointer
/// with num_pairs > 0 (fail closed).
uint8_t shekyl_emission_block_claims_unique(
    const uint8_t* pairs_ptr,
    size_t num_pairs);

/// The full §7.1 emission verify body in one coarse crossing. Operands:
/// - vin bytes: the opaque blob, tag included (C++ never parses inside it).
/// - Bond record: the claimant's PRE-BLOCK ArchivalBondValue fields keyed by
///   the extract call's P_canonical_id; `bond_present == 0` marshals "no
///   record" (reject; remaining bond arguments are then ignored).
/// - snapshots: one frozen as-of-E snapshot per claimed epoch in claim
///   order (gather_archival_emission_epoch_snapshot), each carrying the
///   persisted Σwork(E) and budget(E) close rows.
/// - tree_root (32 bytes) / tree_depth: the reference block's curve-tree
///   root context; signable_tx_hash (32 bytes): the emission tx's signable
///   hash.
/// - reward_commits: the ordered reward vout commit set as flattened
///   72-byte entries (commitment[32] ‖ amount_plain LE u64[8] ‖
///   one_time_key[32]) — the R1.A destination binding; reward_commits_len
///   is the ENTRY count.
/// - vout_reward_sum: Σ reward vout amount_plain (step 5's loud compare).
///
/// On SHEKYL_EMISSION_VIN_OK, `*out_total_reward` is the verified Σ reward
/// (the connect arm's mint amount) and `out_epochs_ptr[0..*out_epochs_len]`
/// the epochs to commit via shekyl_archival_claimed_epochs_check_and_set, in
/// wire order (`epochs_cap >= 15` suffices). Outputs are zeroed on entry; a
/// non-zero return never leaves stale values.
uint8_t shekyl_emission_vin_verify(
    const uint8_t* vin_ptr,
    size_t vin_len,
    uint64_t current_block_height,
    uint64_t vout_reward_sum,
    uint8_t bond_present,
    uint64_t bond_join_settlement_epoch,
    uint8_t bond_holdings_kind,
    const uint64_t* bond_shard_ids_ptr,
    size_t bond_shard_ids_len,
    const uint64_t* claimed_epochs_ptr,
    size_t claimed_epochs_len,
    const struct shekyl_archival_emission_epoch_snapshot* snapshots_ptr,
    size_t snapshots_len,
    const uint8_t* tree_root,
    uint8_t tree_depth,
    const uint8_t* signable_tx_hash,
    const uint8_t* reward_commits_ptr,
    size_t reward_commits_len,
    uint64_t* out_total_reward,
    uint64_t* out_epochs_ptr,
    size_t epochs_cap,
    size_t* out_epochs_len);

// ---------------------------------------------------------------------------
// LWMA-1 difficulty-adjustment FFI surface
//
// Single function: `shekyl_difficulty_lwma1_next`. Wraps the
// `shekyl-difficulty` crate's `lwma1_next` per `docs/completed/DAA_LWMA1.md`
// §5.3 and §6.1. The C-ABI difficulty type is `struct shekyl_u128`
// (two u64 halves, little-endian) per Round 5's ABI disposition --
// Rust `u128`'s C ABI was target-dependent until rustc 1.77 and the
// decomposition eliminates the exposure on every supported target.
//
// `struct shekyl_u128` is declared inside this `extern "C"` block (C++
// permits `struct` definitions inside `extern "C"`; the linkage
// specification applies to function and variable declarations only).
// Macros are emitted at file scope below the block so they remain
// preprocessor-visible without being inside the linkage block.
// ---------------------------------------------------------------------------

/// Difficulty target at the C-ABI boundary.
///
/// Decomposes a 128-bit value into two `uint64_t` halves with
/// universally stable C ABI. Little-endian: `lo` carries bits 0..64,
/// `hi` carries bits 64..128. Callers with a native `uint128_t`-typed
/// buffer MUST explicitly construct `shekyl_u128` instances at the
/// call site (e.g. `{ .lo = (uint64_t)v, .hi = (uint64_t)(v >> 64) }`)
/// and decompose returned values symmetrically; reinterpret-casting
/// `uint128_t` to `shekyl_u128` relies on target-defined struct-layout
/// ABI that Round 5 of `DAA_LWMA1.md` §6.1 explicitly rejects.
struct shekyl_u128 {
    uint64_t lo;   /* little-endian lower 64 bits */
    uint64_t hi;   /* little-endian upper 64 bits */
};

/// Compute the next LWMA-1 difficulty target.
///
/// `timestamps` and `cum_difficulties` are parallel arrays of length
/// `count`, ordered oldest-first. Both must equal `SHEKYL_DAA_WINDOW_N + 1`
/// when `chain_height >= SHEKYL_DAA_WINDOW_N`; both must equal zero
/// when `chain_height < SHEKYL_DAA_WINDOW_N` (the genesis short-circuit
/// returns `SHEKYL_DAA_GENESIS_DIFFICULTY` without inspecting the
/// inputs).
///
/// Returns 0 on success and writes the next difficulty target into
/// `*out_next_difficulty`; returns a negative error code per the
/// `SHEKYL_DIFFICULTY_ERR_*` macros below otherwise.
int32_t shekyl_difficulty_lwma1_next(
    const uint64_t* timestamps,
    const struct shekyl_u128* cum_difficulties,
    size_t count,
    uint64_t chain_height,
    struct shekyl_u128* out_next_difficulty);

/// PoW-target predicate: does `hash` satisfy `difficulty`?
///
/// Wraps the `shekyl-difficulty` crate's `check_hash` — the unified
/// port of the inherited C++ `cryptonote::check_hash`/`_64`/`_128`
/// family. Passes iff the 32-byte `hash`, read as a 256-bit
/// little-endian integer, satisfies `hash * difficulty < 2^256`. The
/// `_64`/`_128` split was a speed optimization; both produced the
/// identical boolean (proven over the differential corpus in
/// `rust/shekyl-difficulty/tests/check_hash_vectors.rs`).
///
/// `hash` is a pointer to exactly 32 bytes; the fixed length is encoded
/// in the type as `const uint8_t (*)[32]` (same convention as the
/// RandomX v2 surface below) so a wrong-sized buffer is a compile error
/// rather than an out-of-bounds read. `difficulty` is the 128-bit
/// difficulty as a `struct shekyl_u128` — construct it at the call
/// site as `{ .lo = (uint64_t)v, .hi = (uint64_t)(v >> 64) }`; never
/// reinterpret-cast a native `uint128_t` (Round-5 ABI rationale
/// above). `difficulty == 0` always passes (matching the inherited
/// behaviour; not an error).
///
/// Returns 0 on success and writes the result into `*out_pass`;
/// returns `SHEKYL_DIFFICULTY_ERR_NULL_PTR` if `hash` or `out_pass`
/// is null (in which case `*out_pass` is untouched).
int32_t shekyl_difficulty_check_hash(
    const uint8_t (*hash)[32],
    struct shekyl_u128 difficulty,
    bool* out_pass);

// ---------------------------------------------------------------------------
// RandomX v2 light-cache PoW verification FFI surface
//
// Two functions wrap the `shekyl-pow-randomx` verifier crate (via
// `shekyl-ffi`'s `pow_randomx_ffi` module): the consensus PoW hash and
// the canonical-seedhash pin/eager-derive entry point. They replace the
// inherited C RandomX v1 path (`crypto::rx_slow_hash` /
// `rx_set_main_seedhash`) on the daemon's block-verification boundary
// per `docs/design/RANDOMX_V2_PHASE3_PLAN.md` §4 and `RANDOMX_V2_RUST.md`
// §5/§17/§18.
//
// The 32-byte `seedhash`/`out_hash` arguments use the pointer-to-array
// form `const uint8_t (*)[32]` / `uint8_t (*)[32]` rather than a decayed
// `const uint8_t*`: the fixed length is part of the type, so a
// wrong-sized buffer at a call site is a compile error rather than a
// silent out-of-bounds access (Round-5 hardening, `RANDOMX_V2_PLAN.md`
// §5; supersedes the decayed form in `RANDOMX_V2_RUST.md` §5).
//
// Under the Rust workspace's `panic = "abort"` profile,
// `SHEKYL_POW_RANDOMX_V2_ERR_CACHE_DERIVE_FAILED` and
// `SHEKYL_POW_RANDOMX_V2_ERR_INTERNAL` are reserved and never returned:
// a derivation OOM or panic aborts the process. They are declared for
// wire-stable ABI/taxonomy parity with `RANDOMX_V2_RUST.md` §17.
// ---------------------------------------------------------------------------

/// Compute the RandomX v2 PoW hash of `data[0..data_len]` under
/// `*seedhash`.
///
/// On success writes exactly 32 bytes to `*out_hash` and returns
/// `SHEKYL_POW_RANDOMX_V2_OK` (0). The per-seedhash 256 MiB cache is
/// derived lazily on first use and memoized internally; the daemon
/// removes first-use latency on the canonical seedhash by calling
/// `shekyl_pow_randomx_v2_set_canonical` at tip advance.
///
/// `seedhash` and `out_hash` must be non-null. The `data`/`data_len`
/// pairing follows `RANDOMX_V2_RUST.md` §17: `data == NULL` is valid iff
/// `data_len == 0` (empty input); `data == NULL && data_len > 0` returns
/// `SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR`. On any non-zero return
/// `*out_hash` is untouched and must not be read.
int32_t shekyl_pow_randomx_v2_hash(
    const uint8_t (*seedhash)[32],
    const uint8_t* data,
    size_t data_len,
    uint8_t (*out_hash)[32]);

/// Pin `*seedhash` as the canonical verification cache and eagerly
/// derive it.
///
/// Called at tip advance (replacing `crypto::rx_set_main_seedhash`).
/// Performs the synchronous ~150-200 ms / 256 MiB cache derivation
/// off the per-block validation hot path, then pins the result so a
/// flood of transient-seedhash lookups cannot evict it (the DoS
/// protection of `RANDOMX_V2_PHASE2C_PLAN.md` §5.11.7). Idempotent:
/// re-pinning the already-canonical seedhash is a no-op.
///
/// `seedhash` must be non-null. Returns `SHEKYL_POW_RANDOMX_V2_OK` (0)
/// on success, `SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR` (-1) if null.
int32_t shekyl_pow_randomx_v2_set_canonical(
    const uint8_t (*seedhash)[32]);

/// RandomX seed-epoch schedule: the height whose block hash seeds the
/// cache used to verify `height` (2048-block epochs, 64-block lag;
/// SEEDHASH_EPOCH_* env overrides are the regtest lever). Pure
/// arithmetic; replaces the retired crypto::rx_seedheight.
uint64_t shekyl_pow_randomx_v2_seedheight(uint64_t height);
/// seedheight(height + lag) — the upcoming seed height (the second
/// output of the retired crypto::rx_seedheights).
uint64_t shekyl_pow_randomx_v2_next_seedheight(uint64_t height);
/// The effective seed-epoch length in blocks (2048, or the clamped
/// SEEDHASH_EPOCH_BLOCKS override) — the single source for consumers
/// needing the epoch length itself (block-sync sizing).
uint64_t shekyl_pow_randomx_v2_seed_epoch_blocks(void);
/// True iff a SEEDHASH_EPOCH_* override is active (schedule differs
/// from the mainnet defaults); the daemon logs a startup warning.
bool shekyl_pow_randomx_v2_seed_epoch_overridden(void);

// ── Dandelion++ stem embargo (RP-4, DAEMON_RELAY_PRIVACY.md sec 17) ─────────
//
// There is no embargo constant in C++ any more, and that is the point. The
// inherited CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE = 39 did not follow from the
// derivation printed beside it (its own formula gives 16.61 s; 39 s reproduces
// only if log10 is read for ln), and it was drawn from a Poisson under a
// derivation assuming exponential survival, so the backstop never fired. Value
// and distribution now both come from shekyl-relay-privacy's EmbargoTimer,
// whose integer table *is* the distribution: reviewable, identical on every
// platform, golden-vector pinned — none of which holds for the
// implementation-defined std::poisson_distribution.
//
// Do not reintroduce a C++-side embargo constant or multiplier. If a number is
// needed here, derive it in the crate and export it, so the number and its
// reason cannot drift apart again.

/// One embargo duration in seconds, drawn from the adopted memoryless
/// distribution (mean 144 s). A 0 s draw is legitimate and rare (~0.17 %): the
/// geometric support includes 0 and the table is not clamped at the boundary,
/// so what ships is what was derived and tested. A zero draw does not mean "fire
/// this instant" — deadlines are whole seconds, so it resolves to the earliest
/// one that does not under-provision (the next second boundary; see
/// cryptonote::detail::embargo_deadline). Rounding it down instead would put the
/// deadline up to ~999 ms in the past, which shortens an embargo, and a shorter
/// embargo is the privacy-losing direction at every draw value including zero.
uint64_t shekyl_dandelionpp_embargo_draw_seconds(void);

/// How long to wait before judging a still-unseen transaction failed, in
/// seconds — a quantile of the embargo distribution (at most 1 in 100 embargoes
/// still running), not a multiple of its mean. On the adopted table that is
/// exactly 664 s (`ADOPTED_PROPAGATION_TIMEOUT_SECS` in shekyl-relay-privacy),
/// pinned so the wait cannot drift from the distribution. A stem transaction is
/// invisible to its sender until it fluffs, so a shorter deadline declares
/// healthy transactions dead while their backstop is still running, and the
/// sender then releases the inputs it had reserved.
uint64_t shekyl_dandelionpp_propagation_timeout_seconds(void);


// ── Live relay zone (RP-3a, DAEMON_RELAY_PRIVACY.md sec 18) ────────────────
//
// The Dandelion++ scheduler: epoch role, stem routing, and per-peer fluff
// batching. `levin_notify` forwards here and keeps transport — epee framing,
// padding, the socket — so transaction bodies cross only as opaque blobs.
//
// RP-3a adds NO reactor. Rust owns the state and every timing DECISION; the
// existing boost::asio timer is armed from shekyl_relay_zone_next_wake() and
// owns the SLEEP. That is what the crate's reason-2 seal prescribes, so this
// boundary is seal-consistent rather than seal-breaking.
//
// Effects are delivered through per-variant CALLBACKS rather than a marshalled
// enum: dispatch happens in Rust where the compiler checks the match, so the
// C++ side has no tag, no offsets and no decoding to get wrong (sec 18.4a).
//
// Rust twins: rust/shekyl-ffi/src/relay_zone_ffi/mod.rs.

struct RelayZoneHandle;

//! One transaction blob, borrowed for the duration of the call.
struct ShekylRelayBlob
{
  const std::uint8_t* ptr;
  std::size_t len;
};
static_assert(sizeof(ShekylRelayBlob) == sizeof(const std::uint8_t*) + sizeof(std::size_t),
              "ShekylRelayBlob must be two packed words to match Rust's #[repr(C)]");

//! A released fluff batch: one call carrying a peer's WHOLE batch, already
//! sorted and de-duplicated by the zone (receive order is an observable). It
//! becomes a single levin notification — delivered blob-by-blob it would become
//! N notifications, leaking the batch size as a per-peer message count.
typedef void (*ShekylRelayFluffCb)(void* ctx, const std::uint8_t* peer,
                                   const ShekylRelayBlob* blobs, std::size_t n);
//! Covert channel `channel` came due with its stem slot unbound: clear it —
//! nil the binding, discard buffers — on the channel's own strand. The other
//! half of the deleted slot array: the binding itself travels with each covert
//! send, and the LOSS of a binding travels here, because an unbound channel
//! emits no sends. One index crosses -- no array, no slot order, no width to
//! reconcile. Fires at EVERY due tick while the slot stays unbound (derived
//! from the map at each poll, never pushed once at a transition), so the
//! receiver must be idempotent and a lost clear self-heals one covert interval
//! later. Must not throw across the FFI boundary.
typedef void (*ShekylRelayCovertUnbindCb)(void* ctx, std::size_t channel);
//! Supply the outbound connection set on demand: write the id count through
//! `out_n` and return a pointer to `*out_n` x 16 bytes valid until the poll
//! returns (nullptr with `*out_n == 0` for none). shekyl_relay_zone_poll calls
//! this ONLY at an epoch boundary, so a fluff-release wake never pays for the
//! connection scan. Must not throw across the FFI boundary.
typedef const std::uint8_t* (*ShekylRelayOutboundCb)(void* ctx, std::size_t* out_n);

//! Covert channel `channel` is due to send.
//!
//! Carries NO payload discriminant, and that is deliberate (CV-4): whether the
//! send is a dummy or drains a queued real fragment is a queue question, and the
//! queue is C++. Rust decides WHEN and WHICH CHANNEL; C++ decides WHAT. Adding a
//! kind or a "has real pending" flag here would let the cadence react to traffic,
//! and that change would look like a latency optimisation rather than the
//! covert-channel leak it is. Must not throw across the FFI boundary.
//! `peer` is the 16-byte connection id the channel's stem slot is bound to --
//! never nil, since an unbound slot emits nothing (CV-2). The binding travels
//! with the send (§20.3's inversion) rather than as a pushed slot array.
typedef void (*ShekylRelayCovertSendCb)(void* ctx, std::size_t channel, const std::uint8_t* peer);

//! Forward to the successor written into `out_dest`.
#define SHEKYL_RELAY_PLAN_STEM        0
//! Stem-eligible, but nothing routes yet — refresh connections and re-plan.
#define SHEKYL_RELAY_PLAN_NO_ROUTE    1
//! Settled for this epoch: fluff. Retrying cannot change the answer.
#define SHEKYL_RELAY_PLAN_FLUFF_EPOCH 2

//! Zone-shape flags for `shekyl_relay_zone_new`.
//!
//! Named bits rather than two `bool` parameters, deliberately. Adjacent bools
//! in a C signature transpose silently — and transposing THESE two swaps the
//! i2p/tor outbound-only fluff rule with the covert enable, which is the exact
//! regression RP-3a's first pass shipped (caught only because eight `private_*`
//! gtests happened to cover it). Function *signatures* on this surface are
//! gated by `scripts/ci/check_relay_ffi_signatures.sh` (conflicting-declaration
//! TU over a cbindgen-generated header). Flag *values* are not: the ABI pin
//! `zone_flag_bits_do_not_transpose` owns those, and a bitmask removes the
//! ordering question the signature gate cannot see.
//!
//! The i2p/tor rule follows the NETWORK, not covert mode: a hidden-service zone
//! with covert disabled still needs it. That is why the bits are independent.
//! Keep these values in sync with `SHEKYL_RELAY_ZONE_*` in `relay_zone_ffi`.
#define SHEKYL_RELAY_ZONE_OUTBOUND_FLUFF_ONLY 1u
#define SHEKYL_RELAY_ZONE_COVERT_ENABLED 2u

//! Open a zone with the caller's epoch length (public 600/30, noise 300/30).
//! `flags` is a mask of the `SHEKYL_RELAY_ZONE_*` bits above.
//! Null when a zone cannot be built: SIZE_MAX stems, or a zero epoch — which
//! would expire at every wake and spin the relay timer. Treat null as fatal.
RelayZoneHandle* shekyl_relay_zone_new(std::uint64_t now_ms, std::size_t stems,
                                       std::uint32_t min_epoch_secs,
                                       std::uint32_t epoch_jitter_secs,
                                       std::uint32_t flags);
//! Whether this zone runs covert (noise) channels.
//! The single owner of a fact this side used to re-derive at nine sites from
//! `!zone::noise.empty()` — a byte payload doubling as its own enable flag.
//! Frozen at construction, so this is a plain read. False for a null handle.
bool shekyl_relay_zone_covert_enabled(const RelayZoneHandle* handle);

//! The outbound floor the embargo provisioning assumes (F-8b): counts below
//! this put real fluff first-passage above the provisioned value.
std::uint32_t shekyl_relay_zone_min_provisioned_out_peers();

//! Record `n` packed 32-byte CANONICAL tx hashes stemmed to `successor`
//! (16-byte uuid); `source` is the arriving peer's uuid or null for local
//! origin. Canonical, not blob-derived — blob bytes are not a stable identity
//! across relay hops (F-9). The observation deadline is drawn Rust-side from
//! the adopted embargo at `now_ms`.
void shekyl_relay_zone_record_stem(RelayZoneHandle* handle,
    const std::uint8_t* hashes, std::size_t n,
    const std::uint8_t* successor, const std::uint8_t* source,
    std::uint64_t now_ms);

//! Record `n` arrived canonical tx hashes (any peer, any path). Unknown
//! hashes are ignored; call on EVERY zone's handle, since a stem placed on
//! one zone can return through another.
void shekyl_relay_zone_record_arrival(RelayZoneHandle* handle,
    const std::uint8_t* hashes, std::size_t n);

//! Stem observations still pending resolution (0 for null handle) — the
//! liveness read a wiring witness needs.
std::size_t shekyl_relay_zone_stem_in_flight(const RelayZoneHandle* handle);
//! Free a zone. Null is a no-op; free exactly once.
void shekyl_relay_zone_free(RelayZoneHandle* handle);
//! A peer completed its handshake.
void shekyl_relay_zone_on_handshake(RelayZoneHandle* handle, const std::uint8_t* id, bool is_income);
//! A peer disconnected.
void shekyl_relay_zone_on_close(RelayZoneHandle* handle, const std::uint8_t* id);
//! Stem slots backed by a live peer — the inherited `connection_count`. Reads a
//! single-writer atomic, so it is safe from any thread.
std::size_t shekyl_relay_zone_live_stems(const RelayZoneHandle* handle);
//! Configured stem width (slot count). When covert is enabled this is also the
//! channel count (channel i follows slot i). Size the C++ channel deque from
//! this so the two widths cannot silently diverge.
std::size_t shekyl_relay_zone_stem_width(const RelayZoneHandle* handle);
//! Earliest time the zone has work; what the asio timer is armed against.
std::uint64_t shekyl_relay_zone_next_wake(const RelayZoneHandle* handle);
//! One of the SHEKYL_RELAY_PLAN_* codes. Three-way, not a bool: a transient
//! routing failure (retry after a refresh) and a settled fluff epoch (do not)
//! also report different relay_method events. Deciding between them in C++
//! would mean a second copy of the RD-4 predicate `!fluffing || local_origin`.
//! A null handle reports NO_ROUTE. Pure plan — production notify prefers
//! shekyl_relay_zone_plan_relay_with_refresh, which owns the one NoRoute
//! refresh; keep this for a forced refresh already performed (send-failure
//! retry) and for tests.
std::int32_t shekyl_relay_zone_plan_relay(RelayZoneHandle* handle, const std::uint8_t* source,
                                          bool local_origin, std::uint8_t* out_dest);
//! Plan a relay; on NO_ROUTE merge `outbound` once and re-plan. Settled fluff
//! epochs do not refresh. This is the production notify path: the refresh
//! policy lives in Rust with the zone. No callback — commands return nothing;
//! a covert channel the refresh leaves unbound clears at its next due tick
//! through shekyl_relay_zone_poll's on_unbind.
std::int32_t shekyl_relay_zone_plan_relay_with_refresh(
    RelayZoneHandle* handle, const std::uint8_t* source, bool local_origin,
    const std::uint8_t* outbound, std::size_t n, std::uint8_t* out_dest);
//! Merge the current outbound set into the stem map mid-epoch. Used for
//! connection churn, covert-send recovery, and the forced refresh after a stem
//! send failure. No callback — see plan_relay_with_refresh.
void shekyl_relay_zone_update_stems(RelayZoneHandle* handle, const std::uint8_t* outbound,
                                    std::size_t n);
//! Accept a batch for fluffing to every peer but `source`. Returns how many
//! peers took it — zero means nothing is connected to fluff to, or a blob span
//! was invalid (null ptr with non-zero len). Empty blobs (`len == 0`) are valid
//! and may pass a null ptr; non-empty spans require a live readable ptr.
std::size_t shekyl_relay_zone_queue_fluff(RelayZoneHandle* handle, std::uint64_t now_ms,
                                          const ShekylRelayBlob* blobs, std::size_t n,
                                          const std::uint8_t* source);
//! Run every step due at now_ms, delivering results through the callbacks. The
//! outbound set is not passed in: `gather_outbound` is called back only when a
//! wake crosses an epoch boundary and the stem map is rebuilt, so a fluff
//! release never triggers the connection scan.
void shekyl_relay_zone_poll(RelayZoneHandle* handle, std::uint64_t now_ms, void* ctx,
                            ShekylRelayOutboundCb gather_outbound,
                            ShekylRelayFluffCb on_fluff, ShekylRelayCovertUnbindCb on_unbind,
                            ShekylRelayCovertSendCb on_covert);
//! Release every pending fluff batch — what notify::run_fluff() drives.
void shekyl_relay_zone_force_fluff(RelayZoneHandle* handle, std::uint64_t now_ms,
                                   void* ctx, ShekylRelayFluffCb on_fluff);
//! Start a new epoch immediately — what notify::run_epoch() drives. No
//! callback — the rollover's covert consequences ride the schedule, exactly
//! as a deadline-crossing rollover's do.
void shekyl_relay_zone_force_epoch(RelayZoneHandle* handle, std::uint64_t now_ms,
                                   const std::uint8_t* outbound, std::size_t n);

} // extern "C"

/// `shekyl_difficulty_lwma1_next` returned successfully and
/// `*out_next_difficulty` carries the next-block difficulty target.
#define SHEKYL_DIFFICULTY_OK                  0
/// A required pointer was null. `out_next_difficulty` must always be
/// non-null; `timestamps` and `cum_difficulties` must be non-null when
/// `count > 0` (they may be null when `count == 0`, the genesis short-
/// circuit case where `chain_height < SHEKYL_DAA_WINDOW_N`).
#define SHEKYL_DIFFICULTY_ERR_NULL_PTR       -1
/// `count` disagrees with `chain_height` per `DAA_LWMA1.md` §5.3 step 1.
#define SHEKYL_DIFFICULTY_ERR_INVALID_COUNT  -2
/// Consensus invariant violation (non-monotonic cumulative difficulty)
/// or `u128` arithmetic overflow inside the algorithm.
#define SHEKYL_DIFFICULTY_ERR_OVERFLOW       -3
/// Reserved for unexpected internal failure. Not currently emitted; the
/// Rust workspace runs `panic = "abort"` so any panic terminates the
/// process before reaching the return path.
#define SHEKYL_DIFFICULTY_ERR_INTERNAL       -4

/// `shekyl_pow_randomx_v2_hash` wrote `*out_hash`, or
/// `shekyl_pow_randomx_v2_set_canonical` pinned the seedhash.
#define SHEKYL_POW_RANDOMX_V2_OK                       0
/// A required pointer (`seedhash`/`out_hash`, or `data` when
/// `data_len > 0`) was null. `*out_hash` is not written.
#define SHEKYL_POW_RANDOMX_V2_ERR_NULL_PTR            -1
/// `data_len` exceeds the verifier's hashing-blob bound (2 MiB).
/// `*out_hash` is not written.
#define SHEKYL_POW_RANDOMX_V2_ERR_DATA_TOO_LARGE      -2
/// Reserved for a structured cache-derivation failure. Not currently
/// emitted: cache derivation uses infallible allocation that aborts on
/// OOM under `panic = "abort"`. See `RANDOMX_V2_RUST.md` §17.
#define SHEKYL_POW_RANDOMX_V2_ERR_CACHE_DERIVE_FAILED -3
/// Reserved for a panic crossing the FFI boundary. Not currently
/// emitted; `panic = "abort"` terminates the process first.
#define SHEKYL_POW_RANDOMX_V2_ERR_INTERNAL            -4

/// Secure memory primitives are declared in shekyl/shekyl_secure_mem.h
/// (C-compatible header used by both memwipe.c and mlocker.cpp).
