// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

/// @file shekyl_ffi.h
/// @brief C declarations for the Rust FFI surface.
///
/// This header is the C ABI between C++ and Rust. Every function is
/// exported from `rust/shekyl-ffi` (`libshekyl_ffi.a`).
///
/// ## Linking
///
/// Every C++ binary — the tests and the debug utilities — links
/// `libshekyl_ffi.a`, the one Rust archive, so each process holds one
/// Rust image with one `tracing-core` dispatcher (see
/// `cmake/BuildRust.cmake`). `shekyld` is a Rust binary that links no
/// C++ (P2P_3_REMNANT_CUTOVER_BRIEF.md §1) and does not include this
/// header.
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

/// m_pqc_public_key canonical layout: X25519_pub[32] || ML-KEM-768_ek[1184].
#define SHEKYL_PQC_PUBLIC_KEY_BYTES 1216
#define SHEKYL_X25519_PK_BYTES 32
#define SHEKYL_ML_KEM_768_EK_BYTES 1184
#define SHEKYL_ML_KEM_768_DK_BYTES 2400

/// Uniform master seed produced by `shekyl_seed_normalize`.
#define SHEKYL_MASTER_SEED_BYTES 64
/// Raw 32-byte seed accepted by testnet/fakechain generate flows.
#define SHEKYL_RAW_SEED_BYTES 32
/// Full classical address payload in `ShekylAllKeysBlob.classical_address_bytes`
/// and Rust `account::CLASSICAL_ADDRESS_BYTES`:
/// `version || spend_pk || view_pk || msg_sign_pk[48]` (113).
/// Must match the Rust constant exactly; a drift corrupts every later
/// field of the `#[repr(C)]` blob.
///
/// This is the FULL field. The `version || spend || view` prefix alone is
/// `SHEKYL_CLASSICAL_ADDRESS_PREFIX_BYTES` (65); the difference
/// between them is `msg_sign_pk`, which is why the two are pinned together.
#define SHEKYL_CLASSICAL_ADDRESS_BYTES 113

/// SLH-DSA-192s message-signing public key — the fourth classical field.
/// Matches Rust `shekyl_address::MSG_SIGN_PK_LEN`.
#define SHEKYL_MSG_SIGN_PK_BYTES 48

/// The classical address PREFIX: version(1) || spend(32) || view(32) = 65.
/// Equivalently, the byte offset of `msg_sign_pk` inside the `#[repr(C)]`
/// blob's classical address field, which is how its one consumer uses it —
/// `populate_account_from_blob` (`cryptonote_basic/account.cpp`).
///
/// The `static_assert` below is what makes that offset arithmetic safe: it
/// pins the full field as prefix + `msg_sign_pk`, so a drift in either
/// constant fails the build rather than silently shifting the read.
#define SHEKYL_CLASSICAL_ADDRESS_PREFIX_BYTES 65
static_assert(
    SHEKYL_CLASSICAL_ADDRESS_BYTES
        == SHEKYL_CLASSICAL_ADDRESS_PREFIX_BYTES + SHEKYL_MSG_SIGN_PK_BYTES,
    "blob classical bytes are the classical prefix plus msg_sign_pk");

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

/// TEST-SUPPORT ONLY (F-7): generates a fresh, NON-derived hybrid keypair for
/// the FFI test suite. Real wallets derive their keys — do NOT call from
/// production code. Free both buffers with shekyl_buffer_free; wipe secret_key.
ShekylPqcKeypair shekyl_pqc_keypair_generate();

/// Sign a message with a canonical-encoded hybrid (Ed25519 + ML-DSA-65) secret
/// key on the **tx per-input PQC auth surface**: the Rust side binds the
/// surface domain (SCHEME_DOMAIN_PQC_AUTH_TX, SA-R-2) internally — C++ never
/// carries a domain string — so signatures from this export verify ONLY as tx
/// per-input auth (shekyl_pqc_verify scheme 1). Do not reach for it from any
/// other signing surface; each surface gets its own export with its own
/// Rust-owned domain (see shekyl_pqc_sign_multisig_participant).
/// secret_key_ptr/len: canonical hybrid secret key bytes. Production keys are
/// wallet-derived and Rust-held (rule 36) — production C++ never holds one;
/// tests source keys from the TEST-SUPPORT shekyl_pqc_keypair_generate.
/// Returns signature blob. Caller frees with shekyl_buffer_free.
ShekylPqcSignatureResult shekyl_pqc_sign(
    const uint8_t* secret_key_ptr,
    size_t secret_key_len,
    const uint8_t* message_ptr,
    size_t message_len);

/// TEST-SUPPORT ONLY (F-7): sign a message as a multisig participant (scheme 2),
/// under the multisig-specific domain. A participant signature is NOT
/// interchangeable with a shekyl_pqc_sign (single-signer) signature over the
/// same message. Use this — not shekyl_pqc_sign — to assemble multisig
/// containers in tests. Production multisig participant signing is unbuilt; do
/// not call from production code. Returns signature blob; free with
/// shekyl_buffer_free.
ShekylPqcSignatureResult shekyl_pqc_sign_multisig_participant(
    const uint8_t* secret_key_ptr,
    size_t secret_key_len,
    const uint8_t* message_ptr,
    size_t message_len);

/// Verify a hybrid PQC signature. The scheme-level domain is Rust-owned
/// (SA-R-2): scheme_id 1 verifies under the tx per-input auth surface
/// (SCHEME_DOMAIN_PQC_AUTH_TX — the shekyl_pqc_sign twin), scheme_id 2 under
/// the multisig participant domain (the shekyl_pqc_sign_multisig_participant
/// twin). C++ passes no domain string.
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

/// Release multiplier from demand pacing:
/// clamp(tx_volume / baseline, RELEASE_MIN, RELEASE_MAX), fixed-point
/// SCALE. The volume operand crosses as the exact window
/// (tx_count_sum, window_blocks) -- FL-R24: Rust forms
/// tx_count_sum / (baseline * window_blocks) in one division; C++ counts and
/// never divides (shekyl/tx_volume_window.h). Since FL-R12' the PAID
/// composition applies this Rust-side inside shekyl_block_reward; this
/// export remains for observability (RPC get_info's release_multiplier
/// field).
uint64_t shekyl_calc_release_multiplier(
    uint64_t tx_count_sum,
    uint64_t window_blocks,
    uint64_t tx_volume_baseline,
    uint64_t release_min,
    uint64_t release_max);

/// Free-parameter burn percentage. Not the consensus burn: consensus uses
/// shekyl_compute_fee_burn / shekyl_calc_burn_pct_at, which derive the
/// supply. The relay-floor ring still calls this with gross
/// already_generated_coins (FL-R16c: no per-height burn fold). Volume
/// operand as for shekyl_calc_release_multiplier.
uint64_t shekyl_calc_burn_pct(
    uint64_t tx_count_sum,
    uint64_t window_blocks,
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

// --- the composed owners (E6 slice 4 precursor, CHAIN_RULES_SLICE_4.md §3.1) --
//
// The composed owners. C++ passes parent-state facts; Rust derives the
// supply, the percentage, and the split. shekyl_calc_burn_pct stays the
// free-parameter entry: the relay-floor ring still calls it with gross
// already_generated_coins, because the ring walks historical heights and
// no per-height burn fold is stored (FL-R16c). That entry is not the
// consensus burn.

/// Status codes for the composed fee-burn entries.
#define SHEKYL_ECONOMICS_OK                 0
#define SHEKYL_ECONOMICS_NULL_OUT          (-1)
/// total_burned > coins_generated: a store-invariant violation (every burned
/// unit was first emitted). Nothing is written; the caller halts — it does
/// not proceed on a zero supply, which the burn would read as "nothing
/// emitted" and answer with a burn of 0 (FL-R16c).
#define SHEKYL_ECONOMICS_SUPPLY_INVARIANT  (-2)

/// The fee burn from the store facts (CEN-F17). coins_generated is the
/// PARENT's already_generated_coins and total_burned the destroyed-fee fold
/// at the same state; Rust derives circulating_supply = coins_generated −
/// total_burned (checked), the percentage from the shipped EconomicParams,
/// the D2-escalated split at frozen_segment_count, and the zero-fee arm.
/// Same parent-state read-point obligation for all three facts.
int32_t shekyl_compute_fee_burn(
    uint64_t total_fees,
    uint64_t tx_count_sum,
    uint64_t window_blocks,
    uint64_t coins_generated,
    uint64_t total_burned,
    uint64_t frozen_segment_count,
    ShekylBurnSplit *out);

/// The burn percentage the info RPC reports, from the same two store facts
/// as shekyl_compute_fee_burn. The relay floor does not call this — see
/// shekyl_calc_burn_pct. Same status codes.
int32_t shekyl_calc_burn_pct_at(
    uint64_t tx_count_sum,
    uint64_t window_blocks,
    uint64_t coins_generated,
    uint64_t total_burned,
    uint64_t *out_pct);

/// Effective block-weight median: short_term bounded to
/// [long_term, S * long_term], S from consensus_constants.json.
/// Cannot fail. C++ gathers the window medians; Rust owns the clamp.
uint64_t shekyl_effective_block_weight_median(
    uint64_t long_term_effective,
    uint64_t short_term_median);

/// Bound a block's long-term-median contribution to [LTEM/1.7, LTEM*1.7].
/// Cannot fail. C++ gathers LTEM; Rust owns the bound.
uint64_t shekyl_long_term_block_weight(
    uint64_t long_term_effective,
    uint64_t block_weight);

/// Base block subsidy before weight penalty and release multiplier (0h KAT export).
uint64_t shekyl_base_block_reward(uint64_t already_generated_coins);

// Admit iff fee >= weight * min(floors) rounded up to the fee lattice
// (shekyl_economics::FEE_QUANTIZATION_MASK), less the admission slack
// (RELAY_ADMISSION_SLACK_BP, 0); both are the predicate's own constants.
// floors is at most shekyl_relay_floor_lookback()+1 values; only the
// minimum is read. A short window is stricter; empty refuses.
// Returns 1 admit, 0 refuse, -1 bad pointer/length.
int32_t shekyl_relay_floor_admits(
    uint64_t fee,
    uint64_t weight,
    const uint64_t* floors,
    size_t floors_len);

// F = R*C*w_ref/M^2, floored at 1. Same function as the ladder's economy
// rung. w_ref is shekyl_economics::RELAY_FLOOR_REFERENCE_TX_WEIGHT, not an
// argument — the same move the lattice and the slack made on
// shekyl_relay_floor_admits. The penalty-free zone is
// EconomicParams::full_reward_zone, not an argument.
// Returns 0 written, -1 null out_floor, -2 out of u128 domain.
int32_t shekyl_relay_fee_floor(
    uint64_t base_reward,
    uint64_t median,
    uint64_t c_scaled,
    uint64_t* out_floor);

// Raw C = (1-sigma)*M_r/(1-b) in SCALE units. Cannot fail.
uint64_t shekyl_fee_correction(
    uint64_t tx_count_sum,
    uint64_t window_blocks,
    uint64_t sigma_scaled,
    uint64_t burn_pct_scaled);

// G — lookback depth. Rust is the owner.
uint64_t shekyl_relay_floor_lookback(void);

// Three-slot ladder [economy, standard, priority]. Economy is the relay
// floor at the same operands. w_ref is
// shekyl_economics::RELAY_FLOOR_REFERENCE_TX_WEIGHT, not an argument.
// The penalty-free zone is EconomicParams::full_reward_zone, not an
// argument. Returns 0 written, -1 null, -2 out of domain.
int32_t shekyl_corrected_fee_ladder(
    uint64_t base_reward,
    uint64_t median,
    uint64_t c_scaled,
    uint64_t *out_fees);

/// shekyl_block_reward status codes. Rejection is POSITIVE, caller misuse
/// NEGATIVE, so "the block is invalid" is never confused with "the call was".
#define SHEKYL_BLOCK_REWARD_OK             0
#define SHEKYL_BLOCK_REWARD_BLOCK_TOO_BIG  1
#define SHEKYL_BLOCK_REWARD_INVALID       (-1)

/// The PAID block reward — the one owner of the FL-R12' signed composition
/// max(M_r*curve(remaining), TAIL) * penalty(x): release multiplier on the
/// curve, tail floor on the modulated result, quadratic penalty applied LAST
/// (floors belong to emission; penalties apply to the paid quantity). The
/// only fallible entry in the economics family: BLOCK_TOO_BIG is a consensus
/// rejection, not an internal error. The limit is INCLUSIVE — a block at
/// exactly 2 * effective median is accepted and earns zero; only
/// current_block_weight > 2 * effective median is rejected. out_weight_limit
/// receives that doubled effective median on EVERY path so a caller can
/// report the limit it was rejected against without recomputing the clamp.
/// A past-asymptote already_generated_coins is a legitimate perpetual-tail
/// state, not an error. INVALID covers a null out-pointer and an input
/// beyond the exact arithmetic domain (medians around 2^43 and above, where
/// the product leaves 128 bits) — fail-closed rather than wrapping.
/// Neither out-pointer may be null. The penalty-free zone is NOT an
/// argument: it is EconomicParams::full_reward_zone, generated from
/// config/consensus_constants.json for both languages (E6 slice 4 §3.1 S8) —
/// the C++ macro CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 is now defined
/// from the same generated header, and a caller can no longer pass a
/// different one.
int32_t shekyl_block_reward(
    uint64_t median_weight,
    uint64_t current_block_weight,
    uint64_t already_generated_coins,
    uint64_t tx_count_sum,
    uint64_t window_blocks,
    uint64_t *out_reward,
    uint64_t *out_weight_limit);


/// Advance already_generated_coins by a block reward. Under FL-R12' the
/// accumulator passes the emission-curve asymptote (perpetual tail); the
/// only saturation is the u64 rail (FL-R14). One entry point for both
/// C++ connect paths.
uint64_t shekyl_advance_already_generated(
    uint64_t already_generated_coins,
    uint64_t block_reward);

/// The staker emission share in force at height, in SCALE units: zero at
/// genesis, the shipped share decayed from block 1 after it (CEN-F21). The
/// epoch and the share constants are shekyl-economics', not arguments.
uint64_t shekyl_emission_share_at(uint64_t height);

struct ShekylEmissionSplit {
    uint64_t miner_emission;
    uint64_t staker_emission;
};

ShekylEmissionSplit shekyl_split_block_emission(
    uint64_t block_emission,
    uint64_t effective_share);

/// The emission split (CEN-F16) as ONE owner: the share in force at
/// current_height (shekyl_emission_share_at), the split, and the
/// zero-emission arm, all Rust. Genesis pays no staker share. Infallible.
ShekylEmissionSplit shekyl_compute_emission_split(
    uint64_t block_emission,
    uint64_t current_height);

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

/// Compute the verifier-side PQC key scalar k = H_l(hybrid_pk) for a revealed
/// PQC public key (PL-D3): the per-input value shekyl_fcmp_verify /
/// shekyl_fcmp_membership_only_verify take. The verifier derives K = k*G_k
/// from it and the FCMP++ circuit opens the spent leaf's commitment to K. A
/// function of the revealed key only -- never the leaf value. Writes 32 bytes.
bool shekyl_fcmp_pqc_key_scalar(
    const uint8_t* pqc_pk_ptr,
    size_t pqc_pk_len,
    uint8_t* out_ptr);

/// Derive the output's 64-byte tx_extra 0x07 entry CM || record (PL-D3 /
/// PL-D3a) from combined KEM shared secret and output index. Secret key and
/// blinds stay on the Rust side; never returned.
/// combined_ss_ptr: 64 bytes. leaf_entry_out: 64-byte caller-provided buffer.
bool shekyl_derive_pqc_leaf_entry(
    const uint8_t* combined_ss_ptr,
    uint64_t output_index,
    uint8_t* leaf_entry_out); // 64 bytes: the output's 0x07 entry CM || record (PL-D3)

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

/// Verify FCMP++ proof with batch verification.
///
/// pqc_pk_hashes_ptr: pqc_hash_count * 32 bytes, one PQC key scalar k per input
/// (shekyl_fcmp_pqc_key_scalar over the input's revealed hybrid_public_key).
/// A non-canonical scalar encoding is refused with code 1, never reduced.
///
/// Returns 0 on success, or a nonzero VerifyError discriminant on failure:
///   1 = DeserializationFailed   4 = KeyImageCountMismatch  7 = TreeDepthTooLarge
///   2 = InvalidTreeRoot         5 = UpstreamError          9 = PqcKeyCountMismatch
///   6 = BatchVerificationFailed
///   (3 retired 2026-09-14, PL-D3 fix pass: the arm could not fire -- K is
///   computed directly. Retired-in-place; never reassign.)
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
/// path is the emission per-epoch dedup, not a key image; the hybrid leaf-gated
/// auth check ran as step 8 of the C++ emission verify that `DEL-008` deleted; the
/// Rust rule is `shekyl_chain_rules::rules::tx_emission`.
/// po_count must equal pqc_hash_count.
/// po_count must be in 1..=MAX_INPUTS (= 8); 0 or larger is rejected up front.
/// Returns 0 on success, else the VerifyError discriminant:
///   1 = Deserialization (also: null ptr; po_count == 0 or > MAX_INPUTS;
///       po_count*32 usize overflow; a non-canonical PQC key scalar k)
///   2 = InvalidTreeRoot
///   5 = UpstreamError     6 = BatchVerificationFailed   7 = TreeDepthTooLarge
///   8 = InputCountMismatch (po_count != pqc_hash_count)
///   (3 retired 2026-09-14, PL-D3 fix pass: the arm could not fire -- K is
///   computed directly. Retired-in-place; never reassign.)
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
/// msg_sign_pk_ptr: 48 bytes (SLH-DSA-192s message-signing public key,
/// the fourth classical field since the fork-(ii) layout). REQUIRED —
/// null returns a null buffer, because no valid address exists without
/// it. Callers holding only an `account_public_address` (no msg_sign_pk)
/// cannot re-encode; live daemon paths carry the original address string.
ShekylBuffer shekyl_address_encode(
    uint8_t network,
    const uint8_t* spend_key_ptr,
    const uint8_t* view_key_ptr,
    const uint8_t* msg_sign_pk_ptr,
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
    /// The output's 64-byte tx_extra 0x07 entry CM || record (PL-D3).
    uint8_t pqc_leaf[64];
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

// ─── Merged scan + key image (PR-wallet Phase 1b) ────────────────────────────

/// Scan an output, recover all secrets, and compute the key image — all in one
/// call. Secret outputs are written into caller-provided buffers. Production
/// scan does not use this export (`shekyl-scanner` calls the Rust functions);
/// the remaining callers are tests. `transfer_details` left with the C++ wallet.
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
    uint8_t* leaf_entry_out); // 64 bytes: the output's 0x07 entry CM || record (PL-D3)

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
///   per output, derived via shekyl_crypto_pq::output::derive_proof_secrets.
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

// ---------------------------------------------------------------------------
// Curve-tree replica (rust/shekyl-ffi/src/curve_tree_replica_ffi.rs)
//
// An ephemeral Rust CurveTreeClient the C++ test generator
// (tests/core_tests/chaingen.cpp) drives to compute the curve_tree_root every
// generated block header must carry, now that the admission-time header-root
// check (CEN-B5) runs on every nettype. The client's parity with the daemon's
// store is KAT-pinned (shekyl-curve-tree/tests/recon_kat.rs); every generated
// block that connects is a live parity check between the two.
//
// Contract: heights strictly consecutive from 0; transactions in block order,
// coinbase first; `next_block_root` is the state at chain height tip + 1 (what
// a block built on the tip commits to; the empty-tree sentinel for a fresh
// replica). `rollback_to_fork(h)` keeps heights 0..=h. Every failure returns
// false and logs; nothing is substituted. Test-generator surface only.
// ---------------------------------------------------------------------------

typedef struct ShekylCurveTreeReplica ShekylCurveTreeReplica;

/// One output's leaf-relevant facts (vout[i] + ct_signatures.outPk[i].mask).
/// Layout mirrors the Rust `#[repr(C)]` definition field-for-field.
typedef struct ShekylCurveTreeReplicaOutput {
    uint8_t output_key[32];
    uint8_t commitment[32];
    uint8_t has_commitment;  // 0 when i >= outPk.size() (leaf-ineligible)
    uint8_t target_kind;     // 0 txout_to_tagged_key, 1 txout_to_key, 2 other
} ShekylCurveTreeReplicaOutput;

/// One transaction's leaf inputs in vout order.
typedef struct ShekylCurveTreeReplicaTx {
    uint8_t is_miner;
    uint8_t has_leaf_entry_blob;     // tx_extra 0x07 tag present
    const uint8_t* leaf_entry_blob;  // raw 0x07 payload, leaf_entry_blob_len bytes
    size_t leaf_entry_blob_len;
    const ShekylCurveTreeReplicaOutput* outputs;
    size_t n_outputs;
} ShekylCurveTreeReplicaTx;

// Layout pins (rule 40): a drift here is silent -- wrong roots, a block
// rejected sixty heights later, no pointer back. The Rust module carries the
// same assertions.
static_assert(offsetof(ShekylCurveTreeReplicaOutput, output_key) == 0, "replica output layout");
static_assert(offsetof(ShekylCurveTreeReplicaOutput, commitment) == 32, "replica output layout");
static_assert(offsetof(ShekylCurveTreeReplicaOutput, has_commitment) == 64, "replica output layout");
static_assert(offsetof(ShekylCurveTreeReplicaOutput, target_kind) == 65, "replica output layout");
static_assert(sizeof(ShekylCurveTreeReplicaOutput) == 66, "replica output layout");
static_assert(offsetof(ShekylCurveTreeReplicaTx, is_miner) == 0, "replica tx layout");
static_assert(offsetof(ShekylCurveTreeReplicaTx, has_leaf_entry_blob) == 1, "replica tx layout");
static_assert(offsetof(ShekylCurveTreeReplicaTx, leaf_entry_blob) == sizeof(void*), "replica tx layout");
static_assert(offsetof(ShekylCurveTreeReplicaTx, leaf_entry_blob_len) == 2 * sizeof(void*), "replica tx layout");
static_assert(offsetof(ShekylCurveTreeReplicaTx, outputs) == 3 * sizeof(void*), "replica tx layout");
static_assert(offsetof(ShekylCurveTreeReplicaTx, n_outputs) == 4 * sizeof(void*), "replica tx layout");
static_assert(sizeof(ShekylCurveTreeReplicaTx) == 5 * sizeof(void*), "replica tx layout");

/// Create an empty replica; null if the ephemeral store cannot be opened.
ShekylCurveTreeReplica* shekyl_curve_tree_replica_new(void);
/// Destroy a replica (null tolerated).
void shekyl_curve_tree_replica_free(ShekylCurveTreeReplica* replica);
/// Ingest one block at `height` (tip + 1, or 0 for a fresh replica).
bool shekyl_curve_tree_replica_ingest_block(
    ShekylCurveTreeReplica* replica,
    uint64_t height,
    const ShekylCurveTreeReplicaTx* txs,
    size_t n_txs);
/// Keep heights 0..=fork_height. On the client's poisoned failure mode the
/// handle is unusable and must be freed.
bool shekyl_curve_tree_replica_rollback_to_fork(
    ShekylCurveTreeReplica* replica,
    uint64_t fork_height);
/// Ingested tip height; false when nothing is ingested (out untouched).
bool shekyl_curve_tree_replica_tip_height(
    const ShekylCurveTreeReplica* replica,
    uint64_t* out_height);
/// The curve_tree_root a block built on the current tip must carry (32 bytes).
bool shekyl_curve_tree_replica_next_block_root(
    const ShekylCurveTreeReplica* replica,
    uint8_t* out_root);

// ---------------------------------------------------------------------------
// tx_extra shape rule codes (rust/shekyl-ffi/src/tx_extra_ffi.rs). CEN-I19
// (GENESIS_TX_WIRE_FORMAT.md §9.6a as ruled 2026-09-05): with n = vout.size(),
// exactly one 0x06 KEM-ciphertext field of 1120·n bytes and exactly one 0x07
// leaf-entry field of 64·n bytes when n > 0, neither when n == 0, and (PL-D3
// content rule) every 0x07 entry's leading 32 bytes a canonical prime-order
// non-identity Ed25519 point. Returned by shekyl_tx_extra_shape_of and the
// codec reads below, which parse the extra themselves; the daemon never
// parses it (TX_EXTRA_RUST_CUTOVER.md). Consensus: applied from
// core::check_tx_semantic, Blockchain::prevalidate_miner_transaction and the
// DB collector through check_tx_extra_shape.
// ---------------------------------------------------------------------------
#define SHEKYL_TX_EXTRA_PQC_SHAPE_OK                           0
#define SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR                 1
#define SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS  2
#define SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING                  3
#define SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_DUPLICATE                4
#define SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH                   5
#define SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_PRESENT_WITHOUT_OUTPUTS 6
#define SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING                 7
#define SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE               8
#define SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH                  9
#define SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT                   10
// 11 was ERR_MARSHALLING (the retired lengths-taking form's caller-bug
// verdict); not re-minted.
/// Buffer size for out_msg, NUL included.
#define SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP                      256
/// Write the conforming 64-byte 0x07 leaf entry (shekyl-wire's
/// conforming_pqc_leaf_entry: the compressed PQC_LEAF_COMMITMENT_J generator
/// followed by the fixed opaque record) to out (64 bytes; null tolerated).
/// Exists for the C++ unit-test fixtures (tests/unit_tests/pqc_spend_fixture.h)
/// so no fixture hand-copies the point's bytes; test-support surface, not
/// consensus.
void shekyl_test_conforming_pqc_leaf_entry(uint8_t* out);

/* ── tx_extra codec (TX_EXTRA_RUST_CUTOVER.md §3; rule 40) ─────────────────
 * shekyl-wire parses and builds tx_extra; the daemon transports. Every call
 * below receives a fixed-size value or an opaque payload; C++ never reads
 * inside an `extra` again.
 *
 * Codes: shape verdicts keep their SHEKYL_TX_EXTRA_PQC_SHAPE_* /
 * SHEKYL_TX_EXTRA_SHAPE_* values (0 OK, 1..=20) and are returned unchanged
 * by the leaf read and the coinbase writer when the rule refuses; this
 * family's own outcomes start at 100 so the two cannot collide. A null
 * pointer is SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR everywhere.
 *
 * The shape rule (shekyl_wire::tx_extra::check_tx_extra_shape) is CEN-I19 on
 * every transaction plus, on a coinbase, the closed coinbase grammar
 * (TXE-Q6', consensus; amended 2026-10-10, SO-D12i): the extra is exactly
 * [0x01 pubkey, 0x02 nonce of SHEKYL_COINBASE_NONCE_BYTES, 0x0C draw
 * commitment of 32 bytes, 0x06 KEM(1120*n), 0x07 leaf(64*n)] in that order
 * and nothing else; off the coinbase, no 0x02 and no 0x0C at all. The draw
 * commitment never crosses this boundary as a value: Rust draws it inside
 * shekyl_coinbase_extra and judges it inside shekyl_tx_extra_shape_of, so
 * C++ has no name for its tag, its width or its refusal codes (18..=20). */
/// Per-output widths of the two PQC fields (shekyl_wire::tx_extra::
/// HYBRID_KEM_CT_BYTES = X25519 ct(32) + ML-KEM-768 ct(1088), and
/// PQC_LEAF_ENTRY_LEN = CM(32) ‖ record(32)); a 0x06 field is 1120·n bytes
/// and a 0x07 field 64·n for n outputs (CEN-I19).
#define SHEKYL_HYBRID_KEM_CT_BYTES            1120
#define SHEKYL_PQC_LEAF_ENTRY_BYTES           64
/// Fixed width of the coinbase 0x02 nonce. 2^32 / 120 s ~= 36 MH/s exhausts
/// the header nonce in one interval; each byte here multiplies that by 256,
/// so 8 never binds and matches the pool convention (reserve_size: 8).
#define SHEKYL_COINBASE_NONCE_BYTES           8
/// Bytes from the first byte of the coinbase tx pubkey to the nonce payload.
/// The grammar fixes the distance (shekyl_wire::tx_extra::COINBASE_NONCE_OFFSET_FROM_PUBKEY);
/// the template adds it to the pubkey's offset in the block blob rather than
/// re-encoding the 0x02 tag and the length byte.
size_t shekyl_coinbase_nonce_offset_from_pubkey(void);
/// Coinbase grammar refusals C++ names (12..=17), beside the CEN-I19 codes
/// (1..=11). The draw-commitment refusals (18..=20) have no define: no C++
/// branches on one, and the rule's own sentence is what gets logged.
#define SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_MISSING   12
#define SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_LENGTH    13
#define SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_DUPLICATE 14
#define SHEKYL_TX_EXTRA_SHAPE_COINBASE_FOREIGN_TAG     15
#define SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT          16
#define SHEKYL_TX_EXTRA_SHAPE_NONCE_OUTSIDE_COINBASE   17
#define SHEKYL_TX_EXTRA_OK                    0
/// The extra parsed and holds no such field — the committed empty set.
#define SHEKYL_TX_EXTRA_ABSENT                100
/// The extra does not parse. Never the same fact as ABSENT.
#define SHEKYL_TX_EXTRA_MALFORMED             101
/// The caller named a tag with no payload (padding, a retired/reserved byte).
#define SHEKYL_TX_EXTRA_UNKNOWN_TAG           102
/// The writer's input exceeds a wire cap; nothing was built.
#define SHEKYL_TX_EXTRA_UNSERIALIZABLE        103

/// The tag bytes a C++ caller may name to shekyl_tx_extra_field. The table
/// of record is `shekyl_wire::tx_extra::TX_EXTRA_TAG_*`; a value here that
/// drifts from it is answered with SHEKYL_TX_EXTRA_UNKNOWN_TAG or the wrong
/// field, which the archival_credit_wire and mining_parity round trips pin.
#define SHEKYL_TX_EXTRA_TAG_PUBKEY               0x01
#define SHEKYL_TX_EXTRA_TAG_NONCE                0x02
#define SHEKYL_TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT   0x06
#define SHEKYL_TX_EXTRA_TAG_PQC_LEAF_ENTRIES     0x07
#define SHEKYL_TX_EXTRA_TAG_ARCHIVAL_ATTESTATION 0x0B

/// The `index`th field of `tag` in `extra`, as its payload bytes, in `out`
/// (free with shekyl_buffer_free). OK / ABSENT / MALFORMED / UNKNOWN_TAG;
/// `out` holds the payload on OK and the null buffer otherwise. A present
/// tag with an empty payload is OK with len 0 — present-empty and absent are
/// different facts (the 0x0B reader's contract, now a return code).
int32_t shekyl_tx_extra_field(
    const uint8_t* extra,
    size_t extra_len,
    uint8_t tag,
    size_t index,
    ShekylBuffer* out);

/// The transaction public key (0x01, first occurrence) written into out32.
/// OK / ABSENT / MALFORMED; out32 is written only on OK.
int32_t shekyl_tx_extra_tx_pubkey(
    const uint8_t* extra,
    size_t extra_len,
    uint8_t* out32);

/// The shape rule over the extra's own parse (is_coinbase selects the
/// coinbase grammar), then the 0x07 blob in `out` (len 0 when n_outputs ==
/// 0). A shape code with the rule's sentence in out_msg on refusal;
/// MALFORMED when the extra does not parse. One read where the DB add path
/// had three passes.
int32_t shekyl_tx_extra_leaf_entries(
    const uint8_t* extra,
    size_t extra_len,
    size_t n_outputs,
    bool is_coinbase,
    ShekylBuffer* out,
    char* out_msg,
    size_t out_msg_cap);

/// The shape rule over the extra's own parse — verdict and sentence only;
/// is_coinbase selects the coinbase grammar. check_tx_extra_shape adapts it;
/// MALFORMED when the extra does not parse (out_msg carries the admission
/// sentence).
int32_t shekyl_tx_extra_shape_of(
    const uint8_t* extra,
    size_t extra_len,
    size_t n_outputs,
    bool is_coinbase,
    char* out_msg,
    size_t out_msg_cap);

// ---------------------------------------------------------------------------
// The transaction id (rust/shekyl-ffi/src/txid_ffi.rs). There is one txid
// mixer and it is Rust's (shekyl-wire `TxidSegments::txid`, SHT-Q2);
// cryptonote::calculate_transaction_hash is its only C++ caller.
//
// The caller hands over the four byte ranges of a serialized v2+ transaction
// -- prefix, ct base, tx-level pqc_auths, prunable -- cut at the offsets its
// serializer recorded, plus the two facts about them that are not bytes. Rust
// hashes the ranges, measures the archival length from the last two, and
// mixes. There is no length parameter on purpose: the txid binds the length,
// so a length the caller supplied would be a second measurement of a
// consensus operand.
//
// The ranges are opaque here -- nothing is parsed -- so no content can make
// the call fail. It returns false, writing nothing, only for a pointer that
// cannot be the range it claims: a null out_txid, or a range with a non-zero
// length that is null or longer than PTRDIFF_MAX bytes. A null pointer is
// accepted for an empty range. out_txid receives 32 bytes.
// ---------------------------------------------------------------------------
bool shekyl_txid_from_segments(
    const uint8_t* prefix,
    size_t prefix_len,
    const uint8_t* ct_base,
    size_t ct_base_len,
    const uint8_t* pqc_auths,
    size_t pqc_auths_len,
    size_t pqc_auth_count,
    bool first_input_is_spend,
    const uint8_t* prunable,
    size_t prunable_len,
    uint8_t* out_txid);

/// The prunable digest of a serialized transaction: keccak256 of its prunable
/// range, by the function the txid mixer uses (shekyl-wire `prunable_hash_of`).
/// It is the value stored as `txs_prunable_hash` and served beside a pruned
/// body, which a wallet mixes into the txid it checks that body against -- so
/// it is computed where the mixer is, and C++ holds no hash of its own for it.
///
/// One byte range, nothing parsed, and no archival length: that operand is
/// the txid mixer's to measure. An empty range (a body with no prunable
/// region) is valid and may be a null pointer. Returns false, writing
/// nothing, only for a pointer that cannot be the range it claims: a null
/// out_hash, or a prunable with a non-zero length that is null or longer
/// than PTRDIFF_MAX bytes. out_hash receives 32 bytes.
bool shekyl_tx_prunable_hash(
    const uint8_t* prunable,
    size_t prunable_len,
    uint8_t* out_hash);

/// Build the coinbase extra in the grammar's one layout: [PubKey(tx_pubkey
/// [32]), Nonce(nonce[SHEKYL_COINBASE_NONCE_BYTES]), DrawCommitment,
/// PqcKemCiphertext(kem), PqcLeafEntries(leaf)] — [PubKey, Nonce,
/// DrawCommitment] when n_outputs == 0 — judged by the coinbase grammar
/// before it is handed back in `out`. The draw commitment is not an input:
/// each call draws a fresh witness key and seed in Rust, commits to them
/// and writes the commitment, so two calls with the same arguments return
/// different bytes and the caller holds no secret (rule 36). If the OS
/// random source or key generation fails the call returns 104 with a
/// message and builds nothing; there is no fallback value. kem is
/// 1120·n_outputs bytes and leaf 64·n_outputs, as shekyl_construct_output
/// produced them; anything else is refused with the shape code naming the
/// field, so a template that could not pass admission is refused at
/// construction, not at the miner.
int32_t shekyl_coinbase_extra(
    const uint8_t* tx_pubkey,
    const uint8_t* nonce,
    const uint8_t* kem,
    size_t kem_len,
    const uint8_t* leaf,
    size_t leaf_len,
    size_t n_outputs,
    ShekylBuffer* out,
    char* out_msg,
    size_t out_msg_cap);

/// shekyl_coinbase_extra without the key generation, for C++ TESTS that lay
/// a coinbase by hand: the production writer generates a key on every call,
/// which a test building tens of thousands of blocks cannot pay. It writes
/// the fixture commitment Rust's own fixtures carry and draws nothing. Same
/// signature, grammar, layout and refusals. Test-support surface, not
/// consensus, as shekyl_test_conforming_pqc_leaf_entry is; no production
/// code calls it.
int32_t shekyl_test_coinbase_extra(
    const uint8_t* tx_pubkey,
    const uint8_t* nonce,
    const uint8_t* kem,
    size_t kem_len,
    const uint8_t* leaf,
    size_t leaf_len,
    size_t n_outputs,
    ShekylBuffer* out,
    char* out_msg,
    size_t out_msg_cap);

/// The PQC signing preimage (FCMP_SPEND_SIGNING_PREIMAGE.md §1.1; CEN-I17),
/// derived by shekyl-wire — the one derivation the wallet signs over and the
/// daemon verifies against (E6 slice 6 commit 7 retired the C++ assembly in
/// tx_pqc_verify.cpp). Every input's signed hash, 32 bytes each in input
/// order, written into `out` (room for `out_cap` hashes — the input count,
/// since an admitted body carries one authentication per input);
/// `*out_count` is how many were written (0 for a body with no per-input
/// authentication: a coinbase, the serve-credit form, a storage-pruned spend).
#define SHEKYL_TX_SIGNING_OK           0
/// A required pointer was null.
#define SHEKYL_TX_SIGNING_ERR_NULL_PTR 1
/// The bytes are not a transaction (do not parse, or not exactly); nothing
/// is derived from bytes that are not one. out_msg carries the parser's
/// sentence.
#define SHEKYL_TX_SIGNING_MALFORMED    2
/// More per-input authentications than out_cap hashes fit; nothing written.
#define SHEKYL_TX_SIGNING_CAPACITY     3
int32_t shekyl_tx_pqc_signing_payload_hashes(
    const uint8_t* tx,
    size_t tx_len,
    uint8_t* out,
    size_t out_cap,
    size_t* out_count,
    char* out_msg,
    size_t out_msg_cap);

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

/// Construct a 128-byte curve tree leaf from output pubkey, commitment, and the
/// output's PQC leaf commitment point.
/// output_key_ptr: 32 bytes compressed Ed25519 output public key (O).
/// commitment_ptr: 32 bytes compressed Ed25519 amount commitment (C).
/// cm_point_ptr: 32 bytes, the commitment point CM at the front of the
///   output's 0x07 entry (PL-D3). No placeholder: an output without an
///   admissible entry is not a leaf (admission refuses its transaction).
/// leaf_out_ptr: 128 bytes output for {O.x, I.x, C.x, CM.x}.
/// Returns true on success.
bool shekyl_construct_curve_tree_leaf(
    const uint8_t* output_key_ptr,
    const uint8_t* commitment_ptr,
    const uint8_t* cm_point_ptr,
    uint8_t* leaf_out_ptr);

// ─── Transaction Builder ─────────────────────────────────────────────────────
/// Single-call FCMP++ proof generation: BP+, membership proof, pseudo-outs.
/// Rust owns all witness assembly. C++ never touches ephemeral spend secrets.

/// Result of shekyl_sign_fcmp_transaction.
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
///   {ki, combined_ss (hex, 128 chars), output_index, amount,
///    commitment_mask, commitment, output_key,
///    leaf_chunk, c1_layers, c2_layers}
/// The input's own PQC leaf commitment and blind (PL-D3) are re-derived by
/// Rust from combined_ss + output_index and checked against leaf_chunk before
/// proving (a mismatch is the received-but-unspendable refusal, code -32).
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

// ---------------------------------------------------------------------------
// Archival serve-credit verification (ARCHIVAL_RETENTION_GATE2.md §5.3)
// ---------------------------------------------------------------------------

#define SHEKYL_ARCHIVAL_VERIFY_OK                    0
#define SHEKYL_ARCHIVAL_VERIFY_ERR_NULL_PTR        1
#define SHEKYL_ARCHIVAL_VERIFY_ERR_WIRE              2

/// Empty-set archival attestation root (`attestation_root(&[])`). Writes 32
/// bytes to `out_ptr`. Returns true on success. Not the all-zero null hash —
/// see ARCHIVAL_CREDIT_WIRE.md §3.
bool shekyl_attestation_root_empty(uint8_t* out_ptr);

/// Extract `(P, shard, E)` from a serve-credit vin's opaque `canonical_bytes`
/// (tag byte INCLUDED). The Rust codec is the only parser of those bytes
/// (RF-D1 / rule 40): C++ indexes by these three fields and reads nothing
/// else. Returns SHEKYL_ARCHIVAL_VERIFY_OK or a wire error code. Empty
/// length is a wire failure, not ERR_NULL_PTR.
uint8_t shekyl_archival_serve_credit_extract(
    const uint8_t* vin_ptr,
    size_t vin_len,
    uint8_t* out_p_canonical_id,
    uint64_t* out_shard_id,
    uint64_t* out_settlement_epoch);

// Bond-post CT balance (ARCHIVAL_BOND_GATE4.md §3.2)
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_OK                    0
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_NULL_PTR        1
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_BOTH_TERMS      2
/// Invalid point, non-32-byte-aligned flat buffer, or count*32 overflow.
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_INVALID_POINT   3
#define SHEKYL_ARCHIVAL_BOND_CT_BALANCE_ERR_SUM_MISMATCH    4
/// Retired-assigned: (credit, debit) = (0, 0) is Unmoved (Reinstate), not an error.
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
// shape for verCtSemanticsSimple / verCtSemanticsFeeOnly. Canonical prime-order
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
/// outPk.size() != vout.size() (or, for a coinbase, the amount count differs):
/// one mask per output (E6 slice 4 §3.1 S25 — was an uncensused C++ gate).
#define SHEKYL_OUTPUT_POINTS_ERR_MASK_COUNT    5
/// The CT type byte is neither CTTypeNull nor CTTypeFcmpPlusPlusPqc: no
/// subject for the mask check.
#define SHEKYL_OUTPUT_POINTS_ERR_CT_TYPE       6

/// Flattened `num_keys x 32` output public keys; `keys_ptr` may be null when
/// `num_keys` is zero. Zero keys is vacuously OK.
uint8_t shekyl_check_output_keys(
    const uint8_t* keys_ptr,
    size_t num_keys);

/// The commitment-mask gate, FACTS in: the tx's CT type byte, its vout
/// count, the flattened `num_masks x 32` outPk masks, and every
/// vout[i].amount (exactly num_outputs values; a spend's are zero on the
/// wire). Rust derives the subject from ct_type — CTTypeNull is a coinbase
/// and the zeroCommit(amount) fingerprint gate applies; the FCMP++ type is a
/// spend and it does not — and refuses a mask count that is not the output
/// count. Until E6 slice 4 (§3.1 S25/S27) the C++ caller made both decisions
/// before calling; it makes neither now. Pointers may be null when their
/// counts are zero.
uint8_t shekyl_check_commitment_masks(
    uint8_t ct_type,
    size_t num_outputs,
    const uint8_t* masks_ptr,
    size_t num_masks,
    const uint64_t* amounts_ptr);


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

/// C2-R3 block-timestamp consensus rule
/// (docs/completed/CONSENSUS_C2_R3_TIMESTAMPS.md §4.3, ratified
/// 2026-09-01): the candidate timestamp is valid iff it is at most
/// `local_clock + 540` (saturating arithmetic) AND strictly greater
/// than sorted-index-5 of the 11 timestamps immediately preceding it,
/// the window right-padded with `genesis_ts` when fewer than 11
/// predecessors exist. Wraps the `shekyl-difficulty` crate's
/// `check_timestamp_rule` — the ONE implementation of the ruled
/// sentence; `Blockchain::check_block_timestamp` is a marshaling shim
/// over this entry point (rule 20), as `shekyl_difficulty_lwma1_next`
/// above serves the difficulty half.
///
/// `window` holds the <= 11 newest predecessor timestamps in any order
/// (callers with deeper history truncate to the newest 11 first —
/// C2-R3-Q1 sub-a); it may be null only when `window_len == 0` (block 1:
/// full genesis padding). `*out_median` receives the padded window's
/// median on every verdict except WINDOW_TOO_WIDE (which writes 0); the
/// miner-template caller reads it unconditionally. Returns a
/// `SHEKYL_TIMESTAMP_RULE_*` verdict code (>= 0: the rule's answer), or
/// `SHEKYL_TIMESTAMP_RULE_ERR_NULL_PTR` on pointer misuse.
int32_t shekyl_difficulty_check_timestamp_rule(
    uint64_t candidate_ts,
    const uint64_t* window,
    size_t window_len,
    uint64_t genesis_ts,
    uint64_t local_clock,
    uint64_t* out_median);

/// Verdict codes for `shekyl_difficulty_check_timestamp_rule` (mirrors
/// of the Rust `TimestampRuleVerdict` discriminants; renumbering is an
/// FFI break).
#define SHEKYL_TIMESTAMP_RULE_OK               INT32_C(0)
#define SHEKYL_TIMESTAMP_RULE_WINDOW_TOO_WIDE  INT32_C(1)
#define SHEKYL_TIMESTAMP_RULE_ABOVE_FTL        INT32_C(2)
#define SHEKYL_TIMESTAMP_RULE_NOT_ABOVE_MEDIAN INT32_C(3)
#define SHEKYL_TIMESTAMP_RULE_ERR_NULL_PTR     INT32_C(-1)

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
/// derived lazily on first use and memoized internally. The C++ parity
/// gates are its callers; the daemon's PoW is the Rust ingest's.
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


// ---------------------------------------------------------------------------
// DRS-P0d logical-state digest v0
// (`docs/design/DAEMON_REDB_STORE.md` §7.1). One coarse call: C++ has
// already collected height-ordered block hashes, the spent-key set, and
// the live curve-tree root from production LMDB. Archival journals are
// not inputs (named exclusion, §7.1.1).
//
// `block_hashes` / `spent_keys` may be NULL only when the corresponding
// count is 0. `curve_root` and `out_digest` are always 32-byte buffers
// and must be non-NULL.
// ---------------------------------------------------------------------------
int32_t shekyl_logical_state_digest_v0(
    const uint8_t* block_hashes,
    uint64_t n_blocks,
    const uint8_t* spent_keys,
    uint64_t n_spent,
    const uint8_t* curve_root,
    uint8_t* out_digest);


} // extern "C"

/// Owns a Rust-allocated ShekylBuffer for one C++ scope and returns it to
/// Rust with shekyl_buffer_free on exit. The null buffer (ptr == nullptr,
/// len == 0) is the valid empty value every out-parameter starts as, so a
/// call that refused leaves nothing to free. Not copyable: two owners of one
/// allocation is the double free this type exists to make unwritable.
struct ShekylOwnedBuffer {
  ShekylBuffer buf{nullptr, 0};
  ShekylOwnedBuffer() = default;
  ShekylOwnedBuffer(const ShekylOwnedBuffer&) = delete;
  ShekylOwnedBuffer& operator=(const ShekylOwnedBuffer&) = delete;
  ~ShekylOwnedBuffer() { if (buf.ptr) shekyl_buffer_free(buf.ptr, buf.len); }
  const uint8_t* data() const { return buf.ptr; }
  size_t size() const { return buf.len; }
};


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
/// A window precondition the difficulty crate refuses.
#define SHEKYL_DIFFICULTY_ERR_WINDOW         -5

/// `shekyl_pow_randomx_v2_hash` wrote `*out_hash`.
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

/// `shekyl_logical_state_digest_v0` wrote `*out_digest`.
#define SHEKYL_CHAIN_DIGEST_V0_OK                      0
/// A required pointer was null. `curve_root` and `out_digest` are
/// always required; `block_hashes` / `spent_keys` may be null only
/// when the corresponding count is 0.
#define SHEKYL_CHAIN_DIGEST_V0_ERR_NULL_PTR           -1
/// `n_blocks` or `n_spent` overflowed `size_t` when widened to bytes.
#define SHEKYL_CHAIN_DIGEST_V0_ERR_OVERFLOW           -2


/// Secure memory primitives are declared in shekyl/shekyl_secure_mem.h
/// (C-compatible header used by both memwipe.c and mlocker.cpp).
