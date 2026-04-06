# Shekyl Changelog

## Unreleased

### 🔒 Security

- **Base58 overflow and non-canonical encoding fix (monero-oxide fork).**
  `shekyl-base58::decode()` now uses `checked_add` to prevent integer overflow
  during character accumulation, and rejects non-canonical encodings where
  unused high bytes of the decoded sum are non-zero. Defense-in-depth measure;
  Shekyl production addresses use Bech32m.

- **Cargo profile hardening (both Rust workspaces).** All profiles (dev,
  release, test, bench) now enforce `overflow-checks = true` in both the
  monero-oxide fork `Cargo.toml` and the Shekyl `rust/Cargo.toml`. Dev and
  release profiles additionally set `panic = "abort"`.

### ✨ Added

- **FROST SAL threshold signing for FCMP++ multisig.** New `frost_sal`
  module in `shekyl-fcmp` wraps upstream `SalAlgorithm<Ed25519T>` for
  threshold Spend-Auth-and-Linkability proofs. `FrostSalSession` manages
  per-input FROST state; `prove_with_sal()` constructs FCMP++ proofs from
  pre-aggregated SAL pairs. FFI functions (`shekyl_frost_sal_session_new`,
  `_get_rerand`, `_aggregate_and_prove`, `_session_free`) expose the session
  lifecycle to C++. The `multisig` feature flag enables FROST dependencies
  (`modular-frost`, `transcript`, `rand_chacha`).

- **FROST DKG key management.** New `frost_dkg` module in `shekyl-fcmp`
  provides `SerializedThresholdKeys` for `ThresholdKeys<Ed25519T>`
  serialization/deserialization, group key extraction, and parameter
  validation. FFI functions (`shekyl_frost_keys_import`, `_export`,
  `_group_key`, `_validate`, `_free`) manage threshold keys from C++.

- **Variable-length FCMP++ witness wire format.** `shekyl_fcmp_prove` FFI
  now accepts a single `witness_ptr`/`witness_len` blob containing per-input
  fixed headers, leaf chunk Ed25519 output data, and Helios/Selene branch
  layers. `genRctFcmpPlusPlus` in `rctSigs.cpp` serializes the full witness.

- **Daemon RPC `chunk_outputs_blob`.** `get_curve_tree_path` response now
  includes per-chunk compressed Ed25519 output data (O, I=Hp(O), C,
  H(pqc_pk)) enabling the wallet to pass full output points to the prover.

- **C++ wallet FROST multisig integration.** `prepare_multisig_fcmp_proof`
  creates FROST SAL sessions when threshold keys are present (defers proof).
  `export_multisig_signing_request` emits v3 format with FROST round data.
  `import_multisig_signatures` aggregates FROST shares via FFI and produces
  the final FCMP++ proof. New methods: `import_frost_threshold_keys`,
  `export_frost_threshold_keys`, `clear_frost_sessions`.

- **16 new Rust tests for FROST.** 4 `frost_sal` unit tests (session
  creation, pseudo-out distinctness, identity rejection, field roundtrip),
  4 `frost_dkg` unit tests (serialization roundtrip, group key extraction,
  parameter validation, byte-level roundtrip), 8 FFI lifecycle tests (null
  safety, invalid data rejection, session handle management).

- **FCMP++ prove/verify round-trip test.** `prove_verify_roundtrip()` in
  `rust/shekyl-fcmp/src/proof.rs` exercises the full stack: random key
  generation, single-leaf tree root computation, `prove()`, `verify()`, and
  negative tests (tampered key image, wrong tree root).

### 🐛 Fixed

- **Stale fuzz targets updated.** `fuzz_fcmp_proof_deserialize` and
  `fuzz_tx_deserialize_fcmp_type7` now pass the required `signable_tx_hash`
  7th argument to `verify()`. `fuzz_block_header_tree_root` rewritten for the
  current `ProveInput` struct and 4-arg `prove()` signature.

- **`prune_tx_data` miner output lookup.** When storing output-pruning metadata,
  RCT coinbase outputs are keyed under amount `0` in LMDB (same as
  `add_transaction`); pruning now uses that amount for `get_output_key` instead
  of the plaintext `vout.amount`, avoiding `OUTPUT_DNE` during prune for
  miner transactions.

### 🔄 Changed

- **Tx-data prune watermark.** `prune_tx_data` now stores `tx_prune_next_block`
  (exclusive next height) instead of ambiguous `last_pruned_tx_data_height`
  values; legacy keys migrate on read/write. LMDB unit tests live in
  `tests/unit_tests/tx_data_pruning_lmdb.cpp` (minimal block builder only; does
  not link `tests/core_tests/chaingen.cpp` into `unit_tests`, avoiding duplicate
  object code and macOS linker unwind/diagnostic issues in CI).

- **FCMP++ Rust dependency source moved in-repo.** `shekyl-fcmp` now consumes
  vendored `shekyl-oxide` crates via path dependencies under
  `rust/shekyl-oxide/` instead of git dependencies plus local absolute-path
  `[patch]` overrides. This removes host-specific Cargo path failures in CI and
  keeps builds fully repo-local.

- **Upstream sync and portability guardrails.** Added vendored snapshot metadata
  at `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`, a divergence workflow
  (`.github/workflows/shekyl-oxide-divergence.yml`), and build workflow checks
  that fail on absolute local paths in Cargo manifests/config.

### ✨ Added

- **`--prune-blockchain` transaction-data pruning.** LMDB v6 adds `txs_pqc_auths`
  (split from `txs_pruned` at `pqc_auths_offset`), implements `prune_tx_data`
  (batch 256 blocks, output metadata, watermark, TOCTOU height check), default
  depth `CRYPTONOTE_TX_PRUNE_DEPTH` (5000), `pop_block` guard when verification
  data is gone, continuous pruning via `update_blockchain_pruning`, RPC
  `get_transactions.pruned` and `get_info.tx_prune_height`.

- **Staking FFI and config-driven tier parameters.** `shekyl-staking` now
  generates tier lock durations, yield multipliers, and max stake-claim range
  from `config/economics_params.json` at build time (aligned with
  `shekyl-economics`). New FFI: `shekyl_calc_per_block_staker_reward` (128-bit
  division with optional overflow flag), `shekyl_stake_tier_count`,
  `shekyl_stake_tier_name`, `shekyl_stake_max_claim_range`. C++ uses these in
  `blockchain.cpp`, `core_rpc_server.cpp`, and `simplewallet` instead of
  duplicating tier strings or inline `mul128`/`div128_64` reward math.

- **FCMP++ transaction construction helper (`construct_fcmp_tx`).** New chaingen
  helper in `tests/core_tests/chaingen.cpp` that builds fully valid FCMP++
  transactions during core test replay: tree path assembly from the live LMDB
  curve tree, `genRctFcmpPlusPlus` proof generation, KEM decapsulation for
  per-input PQC keypair derivation, and PQC auth signing. This unblocks 30+
  disabled core tests that relied on the old `construct_tx_rct` stub.

- **FCMP++ core test generators (Phase 7).** Five new tests in
  `tests/core_tests/fcmp_tests.cpp`:
  - `gen_fcmp_tx_valid`: end-to-end FCMP++ transaction construction and pool
    acceptance during replay
  - `gen_fcmp_tx_double_spend`: second FCMP++ spend of the same output rejected
  - `gen_fcmp_tx_reference_block_too_old`: stale referenceBlock rejected
  - `gen_fcmp_tx_reference_block_too_recent`: too-recent referenceBlock rejected
  - `gen_fcmp_tx_timestamp_unlock_rejected`: timestamp-based `unlock_time` rejected

- **Verification caching unit tests.** Six new GTest cases in
  `tests/unit_tests/fcmp.cpp` validating `compute_fcmp_verification_hash`
  determinism, sensitivity to proof/referenceBlock/key-image changes, null return
  for non-FCMP++ types, and multi-input handling.

- **Deferred insertion boundary tests.** New `tests/unit_tests/deferred_insertion.cpp`
  with tests for: outputs not drainable before maturity, coinbase maturity window
  (60 blocks), regular tx maturity window (10 blocks), drain journal atomicity
  round-trip, and insertion ordering determinism across two DB instances.

- **Pending tree add/pop stress test.** New `tests/unit_tests/pending_tree_fuzz.cpp`
  with randomized stress test (100 random leaves, multi-height draining),
  add/remove round-trip, drain journal CRUD, and leaf removal correctness.

- **`fuzz_tx_deserialize_fcmp_type7` Rust fuzz target.** New cargo-fuzz target in
  `rust/shekyl-fcmp/fuzz/` that exercises FCMP++ proof verification with
  transaction-structured random inputs: pseudoOuts, proof blobs, PQC hashes,
  corrupted type bytes, empty proofs, and mismatched input counts.

- **Comprehensive staking test suite.** New test coverage across C++ and Rust:
  - `tests/unit_tests/staking.cpp`: 20+ GTest unit tests covering
    `txin_stake_claim` and `txout_to_staked_key` serialization round-trips,
    reward integer math (including `mul128`/`div128_64` vs `double` divergence
    at large values), helper function coverage (`get_inputs_money_amount`,
    `check_inputs_overflow`, `check_inputs_types_supported`,
    `get_output_staking_info`, `set_staked_tx_out`), stake weight/tier FFI
    validation, and variant type handling.
  - `tests/core_tests/staking.cpp` + `staking.h`: 18 chaingen core tests
    covering staking lifecycle (stake output creation), invalid claim
    rejection (inverted range, oversized range, future height, wrong
    watermark, wrong amount, non-staked output, output not in tree), lock
    period enforcement (invalid tier, wrong lock_until, zero lock), rollback
    correctness (pool balance, watermark), txpool handling, sorted-input
    enforcement, and multi-tier staking.
  - `rust/shekyl-staking/src/tiers.rs`: 10 edge-case tests including
    exhaustive invalid tier ID rejection, ordering invariants for yield
    multiplier and lock blocks, contiguous ID verification, and positive
    parameter assertions.
  - `rust/shekyl-staking/fuzz/fuzz_targets/fuzz_claim_reward.rs`: cargo-fuzz
    target that generates random accrual records and verifies reward
    computation invariants (no overflow, reward <= pool, weight monotonicity,
    cumulative bounds).

### 🔄 Changed

- **Universal deferred curve-tree insertion (Decision 15).** All outputs
  (coinbase, regular, staked) now enter the `pending_tree_leaves` table at
  creation and drain into the curve tree only after their type-specific
  maturity height (coinbase: +60, regular: +10, staked: max(lock_until, +10)).
  The `pending_staked_*` identifiers were renamed to `pending_tree_*` across
  all database interfaces. The drain journal (`pending_tree_drain`) now stores
  full 136-byte entries (maturity_height + leaf_data) for exact `pop_block`
  reversal instead of just a drain count. `pop_block` restores drained leaves
  to pending and removes the popped block's own pending entries.

- **FCMP_REFERENCE_BLOCK_MIN_AGE reduced to 5 (Decision 14).** With maturity
  enforced by deferred tree insertion, MIN_AGE now serves only as a reorg
  safety margin (5 blocks ≈ 10 minutes). The old static_asserts tying
  MIN_AGE to unlock windows have been removed.

- **Timestamp-based `unlock_time` rejected (Decision 13).** Transactions
  with `unlock_time >= CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL` (500M) are now
  rejected in `check_tx_outputs`. Only height-based lock times are accepted.

- **`prune_tx_data` status clarification.** The output-metadata pruning loop
  in `db_lmdb.cpp` is a plumbing-only stub (`TODO(phase6f)`). The
  `store_output_metadata`, `get_output_metadata`, and `is_output_pruned`
  interfaces are live, but the block-iteration pruning loop does not execute.

### 🗑️ Removed

- **Vestigial hard fork constants.** Removed `HF_VERSION_CLSAG` and
  `HF_VERSION_MIN_V2_COINBASE_TX` from `cryptonote_config.h`. All test
  references replaced with literal `1`.

- **Legacy tests incompatible with FCMP++ consensus.** Disabled 30+ core
  and unit tests that relied on Monero-era transaction construction
  (`RCTTypeBulletproofPlus`, CLSAG ring signatures, v1/v2 transactions):
  - `tests/core_tests/chaingen_main.cpp`: Disabled `gen_simple_chain_001`,
    `gen_simple_chain_split_1`, `gen_chain_switch_1`, `gen_ring_signature_1`,
    `gen_ring_signature_2`, all `txpool_*` tests, all `gen_double_spend_*`
    tests, `gen_block_reward`, all `gen_bpp_*` Bulletproofs+ tests, and
    several `gen_tx_*` tests whose setup required valid user transactions.
    These tests construct transactions via `MAKE_TX`/`construct_tx_rct`
    which produce `RCTTypeFcmpPlusPlusPqc` stubs with empty `pqc_auths`,
    rejected by `check_tx_inputs` even in FAKECHAIN mode.
  - `tests/unit_tests/bulletproofs.cpp`: All three weight tests
    (`weight_equal`, `weight_more`, `weight_pruned`) prefixed with
    `DISABLED_` and hex blobs removed. Shekyl's `rctSigBase` serialization
    rejects any type other than `RCTTypeFcmpPlusPlusPqc` (type 7), so old
    `RCTTypeBulletproofPlus` (type 6) blobs fail to deserialize.
  - Re-enabling requires a chaingen FCMP++ transaction generator that
    produces valid PQC auth signatures and curve-tree membership proofs.

### 🔄 Changed

- **Upstream monero-oxide dependencies renamed to shekyl-oxide.** Updated
  `shekyl-fcmp/Cargo.toml` and all Rust source files to use the renamed
  packages from the monero-oxide fork (`monero-fcmp-plus-plus` →
  `shekyl-fcmp-plus-plus`, `monero-generators` → `shekyl-generators`).
  `Cargo.lock` advanced from pin `92af05e` to `416d8d1` which includes the
  complete `monero-oxide/` → `shekyl-oxide/` directory and package rename.

- **`shekyl-fcmp` crate cleanup.** Removed unused `sha2` and `shekyl-crypto-pq`
  dependencies from `rust/shekyl-fcmp/Cargo.toml`. Renamed the misleading
  `ProveError::InputCountMismatch` variant to `ProveError::PqcHashMismatch`
  with a clear `input_index` field indicating which input has a mismatched
  leaf `h_pqc` vs `pqc_auth` commitment.

### 🐛 Fixed

- **Private member access in pending tree unit tests.** Fixed 18 compile
  errors in `pending_tree_fuzz.cpp` and 4 in `deferred_insertion.cpp` on
  macOS CI where calls to `add_pending_tree_leaf`, `drain_pending_tree_leaves`,
  `add_pending_tree_drain_entry`, `get_pending_tree_drain_entries`,
  `remove_pending_tree_drain_entries`, and `remove_pending_tree_leaf` were
  calling private overrides on `BlockchainLMDB`. Changed all test methods
  to use `BlockchainDB&` references, accessing the public base class interface.

- **CI compile errors across all platforms.** Fixed compilation failures in
  the new staking and FCMP++ test suites:
  - `tests/core_tests/staking.cpp`: Added missing `fill_tx_sources`
    declaration to `chaingen.h` and moved `Blockchain::check_stake_claim_input`
    from the private section to the public API so core tests can call it
    without `IN_UNIT_TESTS`.
  - `tests/unit_tests/fcmp.cpp`: Fixed serialization calls to use
    `do_serialize(ar, v)` instead of non-existent `v.serialize(ar)` member;
    replaced `binary_archive<false>(istringstream&)` with the correct
    `binary_archive<false>(span<const uint8_t>)` constructor; fixed
    `shekyl_pqc_verify` call to include the required `scheme_id` first
    argument and corrected parameter order.
  - `tests/unit_tests/staking.cpp`: Same `binary_archive<false>` constructor
    fix — replaced `istringstream` with `epee::span<const uint8_t>` in all
    four serialization round-trip tests.
  - macOS CI: Added `zstd` to Homebrew dependencies and fixed CMake to use
    `PkgConfig::ZSTD` imported target instead of bare library name, resolving
    `ld: library 'zstd' not found` on macOS Homebrew where the library lives
    in a non-standard path (`/opt/homebrew/lib`).

- **RPC estimate_claim_reward floating-point precision bug.** The
  `on_estimate_claim_reward` RPC handler used `double`-precision arithmetic
  for reward estimation, which diverges from the consensus `mul128`/`div128_64`
  path when `total_weighted_stake > 2^53`. Fixed to use identical 128-bit
  integer math, ensuring wallet reward estimates always match consensus.

### 🐛 Fixed

- **FCMP++ wallet precompute metadata and input consistency checks.**
  `transfer_selected_rct` and multisig proof prep now read tree depth from
  RPC metadata (`tree_depth`) instead of `path_blob[0]`, enforce that all
  selected inputs share the same reference block/depth snapshot, and reject
  empty precomputed paths. This fixes silent spend-construction failures.

- **Stake-claim input routing in consensus verification.**
  `Blockchain::check_tx_inputs` now routes pure `txin_stake_claim`
  transactions through the claim-specific input checks before generic FCMP++
  `txin_to_key` validation, preventing incorrect rejection of valid
  stake-claim transactions that use `RCTTypeFcmpPlusPlusPqc`.

- **Stake-claim reward math overflow defense.** Added a defensive `q_hi != 0`
  check after `div128_64` in claim reward computation, rejecting impossible
  overflow states instead of silently truncating.

- **Claim transaction PQC signing correctness/performance.** Removed wallet
  master-key fallback for claim input signing and now require per-output
  shared-secret rederivation for all claim inputs. Claim signing keypairs are
  derived once per input and reused for both `pqc_auths` public key and
  signature generation.

- **Curve-tree path RPC returns spendable reference block.**
  `get_curve_tree_path` now returns a `reference_block` at least
  `FCMP_REFERENCE_BLOCK_MIN_AGE + 1` behind tip, avoiding immediate mempool
  rejection of freshly built transactions that used a too-recent tip anchor.

- **PQC derivation index correctness and duplicate derivation overhead.**
  Spend-path and multisig PQC key derivation now use
  `m_internal_output_index` (matching KEM encapsulation/decapsulation) and
  derive each per-input keypair once per transaction, reusing it for both
  `H(pqc_pk)` and signing.

- **Staked-output FCMP++ path precompute filtering.**
  Wallet precompute/incremental updates now skip still-locked staked outputs
  (`m_stake_lock_until > current_height`) to avoid daemon path lookup errors.

- **Stake-claim rollback completeness.** `BlockchainDB::remove_transaction`
  now fully reverses `txin_stake_claim` state on reorg: watermark is restored
  to its pre-claim value (or removed for first-time claims) and the claimed
  amount is credited back into the staker reward pool. Previously only the
  spent key was removed, leaving claim-progress accounting permanently
  advanced after a reorg.

- **Txpool key-image handling for stake claims.** All six txpool functions
  that walk transaction inputs (`insert_key_images`,
  `remove_transaction_keyimages`, `have_tx_keyimges_as_spent`,
  `have_key_images`, `append_key_images`, `mark_double_spend`) now handle
  `txin_stake_claim` inputs alongside `txin_to_key`. Previously they used
  `CHECKED_GET_SPECIFIC_VARIANT(..., txin_to_key, ...)` which caused
  immediate false-return on any stake-claim input, breaking mempool
  bookkeeping for claim transactions.

- **`remove_transaction_keyimages` no longer returns early on error.**
  The function now continues removing remaining key images instead of
  aborting at the first mismatch, eliminating the partial-cleanup semantics
  noted by the long-standing FIXME.

- **Core helper support for `txin_stake_claim`.** `get_inputs_money_amount`
  and `check_inputs_overflow` now handle both `txin_to_key` and
  `txin_stake_claim` input variants instead of failing on the latter. These
  are called unconditionally for all transactions (via `check_money_overflow`),
  so the old hard-cast to `txin_to_key` would reject any transaction
  containing a stake claim.

### 🔒 Security

- **FFI buffer zeroization before free.** `shekyl_buffer_free` now wipes
  buffer contents prior to deallocation, reducing secret-key residue risk in
  allocator-managed memory.

- **Wallet KEM key management fix.** `generate_pqc_key_material()` now
  generates `HybridX25519MlKem` KEM keypairs via `shekyl_kem_keypair_generate()`
  instead of `HybridEd25519MlDsa` signing keypairs. The wallet-level PQC
  keys (`m_pqc_public_key` / `m_pqc_secret_key`) are encapsulation/decapsulation
  keys; per-output ML-DSA-65 signing keys are always derived from the KEM
  shared secret at spend time.

- **Full hybrid ciphertext storage in tx_extra tag 0x06.** All KEM
  encapsulation sites (coinbase, claim, regular transfers) now store the
  complete 1120-byte hybrid ciphertext (`x25519_ephemeral_pk[32] || ml_kem_ct[1088]`)
  instead of only the ML-KEM portion. This enables correct hybrid
  decapsulation during wallet scanning and seed restore.

### ✨ Added

- **FCMP++ wallet transaction construction (Phase 5).** `transfer_selected_rct`
  now builds transactions using full-chain membership proofs instead of ring
  signatures:
  - Inputs contain only the real output (no decoy selection).
  - `genRctFcmpPlusPlus` generates the combined Bulletproofs+ and FCMP++
    membership proof.
  - Per-input PQC auth signatures use ML-DSA-65 keypairs derived from the
    KEM shared secret and output index.
  - `construct_tx_with_tx_key` adds KEM encapsulation (tag 0x06) and
    `H(pqc_pk)` leaf hashes (tag 0x07) for each output, and skips
    wallet-level PQC signing.

- **KEM decapsulation during wallet scanning.** `process_new_transaction`
  now extracts hybrid KEM ciphertexts from `tx_extra` tag 0x06, calls
  `shekyl_kem_decapsulate` with the wallet's KEM secret keys, and stores
  the resulting 64-byte combined shared secret in `transfer_details::m_combined_shared_secret`.
  This enables per-output PQC key derivation at spend time.

- **FCMP++ fee estimation.** `estimate_rct_tx_size` now accounts for the
  FCMP++ membership proof size (`shekyl_fcmp_proof_len`), per-input PQC
  auth envelopes (~5400 bytes each), and per-output KEM ciphertexts and
  leaf hashes.

- **GUI wallet QR code.** Receive page now renders a real QR code encoding
  the full FCMP++ Bech32m address via `qrcode.react`.

- **GUI wallet fee preview.** Send page shows an estimated transaction fee
  before submission, debounced as the user types.

### 🗑️ Removed

- **CLSAG device interface methods.** Removed `clsag_prepare`, `clsag_hash`,
  and `clsag_sign` virtual methods from `device.hpp` and all implementations
  (`device_default.cpp`, `device_ledger.cpp`). Shekyl never supported CLSAG;
  the device interface now only exposes FCMP++ methods.

- **`get_outs` / `get_outs.bin` RPC endpoints.** Removed the ring member
  fetching endpoints from the C++ daemon (`core_rpc_server`), the FFI dispatch
  tables (`core_rpc_ffi.cpp`), and the Rust daemon RPC (`shekyl-daemon-rpc`).
  FCMP++ uses full-chain membership proofs; there is no decoy selection.

- **Dead hard fork constants.** Removed `HF_VERSION_MIN_MIXIN_4/6/10/15`,
  `HF_VERSION_SAME_MIXIN`, `HF_VERSION_ENFORCE_MIN_AGE`,
  `HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY`,
  `HF_VERSION_REJECT_SIGS_IN_COINBASE`, `HF_VERSION_ENFORCE_RCT`,
  `HF_VERSION_DETERMINISTIC_UNLOCK_TIME` from `cryptonote_config.h`. These
  were defined but never referenced in production code. `HF_VERSION_CLSAG`
  and `HF_VERSION_MIN_V2_COINBASE_TX` are retained for test compilation
  until Phase 7 rewrites the legacy tests.

### ✨ Added

- **Zstd compression for Levin P2P relay (Phase 6e).** P2P payloads above
  256 bytes are transparently compressed with zstd (level 1) before relay.
  A new `LEVIN_PACKET_COMPRESSED` flag (0x10) in the Levin header marks
  compressed frames. Peers negotiate compression via
  `P2P_SUPPORT_FLAG_ZSTD_COMPRESSION` (0x02) in the handshake support flags.
  Reduces relay bandwidth by ~10-20% for FCMP++ transactions, especially
  important for Tor/I2P connections. Compression is optional at compile time
  (requires libzstd); decompression always succeeds if the flag is set.

### 📚 Documentation

- **Updated `DAEMON_RPC_RUST.md`.** Fixed stale references to `get_outs.bin`
  and `get_curve_tree_root`; corrected endpoint counts and cutover test steps.

### 🐛 Fixed

- **`rct::key` missing `operator!=`.** Added `operator!=` to the `key`
  struct in `rctTypes.h`. The operator was present for cross-type
  comparisons (`rct::key` vs `crypto::public_key`) but not for
  `rct::key` vs `rct::key`, causing compilation failures on all
  platforms when comparing pseudo-outs to expected zero-commitments in
  the stake claim verification path.

- **MSVC `binary_archive` constructor mismatch.** Fixed `wallet2.cpp`
  to use `epee::strspan<std::uint8_t>` instead of `std::istringstream`
  for constructing `binary_archive<false>`, which MSVC could not resolve.

- **Memory leak on exception in PQC auth signing.** Added RAII scope
  guard for `ShekylPqcKeypair` buffers in `transfer_selected_rct`
  Phase C, ensuring Rust-allocated key material is freed even if
  `THROW_WALLET_EXCEPTION_IF` throws mid-loop.

- **Secret key material not wiped on KEM decapsulation failure.** The
  stack buffer in `process_new_transaction` KEM decapsulation is now
  wiped unconditionally (success or failure), preventing partial key
  material from lingering on the stack.

- **Shadowed `tx_extra_fields` variable in KEM decapsulation.** Removed
  redundant inner `tx_extra_fields` reference that shadowed the outer
  one in `process_new_transaction`, using the already-resolved outer
  reference instead.

### 🔄 Changed

- **Decoy selection functions are dead code.** `get_outs`,
  `tx_add_fake_output`, and `light_wallet_get_outs` in `wallet2.cpp` are
  no longer called from the active transfer path. They remain in the
  codebase for reference and will be removed in a follow-up cleanup.

- **Claim transaction indistinguishability (Phase 4 — CRITICAL).** Rewrote
  `wallet2::create_claim_transaction()` to produce privacy-preserving claim
  transactions that blend into the anonymity set:
  - Uses `RCTTypeFcmpPlusPlusPqc` with Bulletproofs+ range proofs instead
    of `RCTTypeNull` with plaintext amounts.
  - Adds a dummy change output (amount = 0) to match the standard 2-output
    transaction structure, preventing structural fingerprinting.
  - Performs hybrid KEM derivation (X25519 + ML-KEM-768) via
    `shekyl_fcmp_derive_pqc_keypair()` for per-output PQC keys instead of
    reusing the wallet master PQC key.
  - Embeds ML-KEM ciphertexts in `tx_extra` under tag `0x06` and
    `H(pqc_pk)` leaf hashes under new tag `0x07`.
  - Signs with per-output KEM-derived PQC keys, not the wallet-level key.
  - Sets deterministic pseudo-outs (`zeroCommit(claim_amount)`) for each
    stake claim input to satisfy the Bulletproofs+ balance check.

- **Consensus rejects `RCTTypeNull` for non-coinbase v3 transactions.**
  `check_tx_inputs` now enforces that only coinbase (`txin_gen`) may use
  `RCTTypeNull`. All other v3 transactions (including stake claims) must
  use `RCTTypeFcmpPlusPlusPqc` with confidential amounts. Claim
  transactions are validated within the FCMP++ handler with their own
  sub-path that verifies pseudo-out determinism, PQC ownership, and pool
  balance while skipping the membership proof (which is not applicable to
  `txin_stake_claim` inputs).

### ✨ Added

- **`TX_EXTRA_TAG_PQC_LEAF_HASHES` (`0x07`).** New `tx_extra` field
  (`tx_extra_pqc_leaf_hashes`) stores per-output `H(pqc_pk)` values —
  the 32-byte Blake2b-512 hashes of each output's derived ML-DSA-65
  public key. Used by curve tree insertion to commit the correct PQC
  ownership hash to each leaf instead of a zero placeholder.

- **Curve tree leaves use actual `H(pqc_pk)` from `tx_extra`.** The
  `collect_outputs` / `make_leaf` path in `blockchain_db.cpp` now extracts
  `H(pqc_pk)` values from the `0x07` tag, replacing the zero placeholder
  that was previously committed to the 4th leaf scalar. This enables the
  PQC ownership cross-check for stake claim verification.

- **Coinbase transactions emit `H(pqc_pk)` leaf hashes.** `construct_miner_tx`
  now derives per-output PQC keypairs via KEM shared secrets and includes
  their `H(pqc_pk)` values in the `0x07` `tx_extra` field alongside the
  existing KEM ciphertexts in `0x06`.

### 🔒 Security

- **Integer-only stake reward computation.** Replaced floating-point
  arithmetic (`(double)total_reward * weight / total_weighted_stake`) with
  128-bit integer math (`mul128`/`div128_64`) in `check_stake_claim_input`
  to eliminate rounding errors that could cause determinism mismatches
  across platforms.

- **Batch pool balance validation for stake claims.** Moved the staker
  pool balance check from per-claim (`check_stake_claim_input`) to a
  batch check in `check_tx_inputs` that sums all claim amounts first.
  Prevents multiple claims in the same block from independently passing
  the balance check and overdrawing the pool.

- **PQC ownership cross-check on stake claims.** Each `txin_stake_claim`
  now verifies that the `H(pqc_pk)` stored in the curve tree leaf (bytes
  96–128) matches `shekyl_fcmp_pqc_leaf_hash(pqc_auths[i].hybrid_public_key)`,
  preventing reward claims for outputs the claimer does not own the PQC
  key for.

### 🐛 Fixed

- **Stake claim key image cleanup on reorg.** `remove_transaction` in
  `blockchain_db.cpp` now handles `txin_stake_claim` key images in
  addition to `txin_to_key`, preventing stale key images from persisting
  after block pops.

### 🔄 Changed

- **Sorted input enforcement extended to stake claims.** The
  sorted-inputs check in `check_tx_inputs` now covers both `txin_to_key`
  and `txin_stake_claim` key images, ensuring consistent ordering rules
  across all input types.

- **Third-party headers treated as SYSTEM includes.** `external/`, `external/rapidjson`,
  `external/easylogging++`, and `external/supercop` are now `-isystem` in CMake,
  suppressing `-Wsuggest-override` and other warnings from third-party code while
  keeping strict warnings for first-party code.

### 🗑️ Removed

- **Dead `check_ring_signature` function.** Removed unused ring signature
  verification from `blockchain.cpp` and its declaration from
  `blockchain.h`. Shekyl uses FCMP++ from genesis; ring signatures are
  never validated.

- **Dead `expand_transaction_2` function.** Removed the no-op transaction
  expansion function from `blockchain.cpp` and its declaration from
  `blockchain.h`. FCMP++ does not use mixRing expansion.

- **Dropped `serde_json` dev-dependency from `shekyl-fcmp`.** Replaced the JSON
  round-trip test with a byte-level serialization check, reducing the dev-dep
  surface.

### 📚 Documentation

- Synced `docs/FCMP_PLUS_PLUS.md` curve-tree text with consensus: outputs are
  indexed at creation; maturity is enforced via `referenceBlock` and other
  rules, not by delaying leaf insertion.
- Clarified `docs/POST_QUANTUM_CRYPTOGRAPHY.md` to use `pqc_auths` (per-input)
  terminology consistently.
- Documented mempool FCMP verification-cache id: `compute_fcmp_verification_hash`
  binds proof + `referenceBlock` + key images (comment in `blockchain.cpp`).
- Noted the monero-oxide commit pin in `rust/shekyl-fcmp/Cargo.toml` comments
  (lockfile remains authoritative).
- Updated `docs/STAKER_REWARD_DISBURSEMENT.md` with integer arithmetic, batch
  pool check, PQC cross-check, and sorted input consensus rules.

### ✨ Added

- **Block-inclusion FCMP++ cache fast path.** When a transaction was previously
  verified in the mempool and arrives in a block, `check_tx_inputs` skips the
  expensive `shekyl_fcmp_verify` FFI call (~35ms/input) while still running all
  structural checks (referenceBlock, depth, key images, PQC auth).

- **`construct_leaf` now accepts PQC key hash parameter.** The Rust FFI
  function `shekyl_construct_curve_tree_leaf` takes a 4th `h_pqc_ptr` argument
  (32 bytes) to set the 4th leaf scalar.  Callers pass zero bytes until
  per-output PQC commitments are wired in Phase 3.

- **Deferred staked leaf insertion infrastructure.**
  Added `pending_staked_leaves` (LMDB DUPSORT/DUPFIXED table keyed by
  `lock_until_height` with 128-byte leaf values) and `pending_staked_drain`
  (block_height → drain count) tables to the blockchain database layer.
  Five new methods on `BlockchainDB`: `add_pending_staked_leaf`,
  `drain_pending_staked_leaves`, `set_pending_staked_drain_count`,
  `get_pending_staked_drain_count`, and `remove_pending_staked_drain_count`.
  This enables staked outputs whose `lock_until > block_height` to be parked
  in a pending table and batch-inserted into the curve tree when they mature.

- **Comprehensive FCMP++ test suite and fuzz targets (Phase 7).**
  Added 6 `cargo-fuzz` targets across `rust/shekyl-fcmp/fuzz/` (proof
  deserialization, curve tree leaf hashing, block header tree root mismatch)
  and `rust/shekyl-crypto-pq/fuzz/` (Bech32m address decoding, KEM
  decapsulation with corrupted ciphertexts). Extended Rust unit tests in
  `proof.rs`, `tree.rs`, `leaf.rs`, `kem.rs`, `address.rs`, and
  `derivation.rs` covering prove/verify round-trips, hash grow/trim inverse
  properties, boundary values, and cross-crate consistency. Extended C++ unit
  tests in `tests/unit_tests/fcmp.cpp` with RCTTypeFcmpPlusPlusPqc
  serialization round-trip, key image y-normalization, referenceBlock
  staleness constants, and empty proof rejection. Added PQC rederivation
  criterion benchmark (`rust/shekyl-crypto-pq/benches/pqc_rederivation.rs`)
  targeting < 100ms per output for the full ML-KEM-768 decapsulation +
  HKDF-SHA-512 + ML-DSA-65 keygen pipeline.

- **Stressnet tooling for FCMP++ pre-audit gate (Phase 7.7).**
  Added `tests/stressnet/` with configuration, load generator, and monitoring
  scripts for a 4-week sustained-load testnet. The stressnet exercises curve
  tree growth, verification caching, wallet restore correctness, pruned vs.
  full node storage, staking lifecycle, and block validation latency under
  near-block-weight-limit load. Includes `config.yaml` with load profiles,
  `load_generator.py` for synthetic transaction submission, and `monitor.py`
  for real-time metric collection, consensus checking, and daily report
  generation.

- **Security audit scope document (Phase 9).**
  Added `docs/AUDIT_SCOPE.md` defining the scope for a third-party security
  review of the 4-scalar leaf circuit modification. Covers soundness,
  zero-knowledge, and completeness verification for the `H(pqc_pk)` extension,
  Shekyl fork modifications to monero-fcmp-plus-plus, PQC commitment binding,
  and the FFI verification boundary. Includes materials list, auditor guidance
  questions, success criteria, and timeline.

- **Mainnet gate: stressnet and audit prerequisites in release checklist.**
  Updated `docs/RELEASE_CHECKLIST.md` with "Stressnet stable for 4 consecutive
  weeks" and "4-scalar leaf circuit audit completed" as hard prerequisites
  for mainnet launch.

### 🔄 Changed

- **Renamed `src/ringct/` to `src/fcmp/` for naming consistency.**
  Shekyl does not use ring signatures; the directory now reflects the actual
  FCMP++ confidential transaction system.  CMake targets renamed from
  `ringct`/`ringct_basic` to `fcmp`/`fcmp_basic`.  All `#include "ringct/..."`
  paths updated across 44 source and test files.  Log categories, user-facing
  strings ("RingCT" → "FCMP"), JSON keys, and documentation updated.
  The `rct::` namespace is preserved for now as a separate future rename.

- **Unified coinbase transaction version to v3.**
  `construct_miner_tx` and `build_genesis_coinbase_from_destinations` now emit
  `tx.version = 3`, matching regular FCMP++ transactions.  All `miner_tx &&
  tx.version == 2` checks have been widened to `>= 2` across `blockchain_db`,
  `blockchain`, `wallet2`, and test infrastructure.  The `pqc_auths`
  serialization gate (`!txin_gen`) already excluded coinbase, so v3 coinbase
  serializes identically to v2 minus the version byte.

### 🐛 Fixed

- **Fixed wallet API compilation errors after ring-signature removal.**
  `wallet/api/wallet.cpp` still referenced the undefined `fake_outs_count`
  variable and called `estimate_fee` with the old 12-argument signature.
  Replaced `fake_outs_count` with `0` (FCMP++ has no decoys) and updated
  `estimateTransactionFee` to use the simplified 8-argument `estimate_fee`
  signature with hardcoded `use_per_byte_fee=true`, `use_rct=true`,
  `use_view_tags=true`.

- **Fixed CI build failure from removed legacy RCT types in test files.**
  Stripped all references to removed `rct::Bulletproof`, `rct::RCTConfig`,
  `rct::RangeProofType`, `rct::RCTTypeBulletproofPlus`, `rct::clsag`,
  `rct::proveRctCLSAGSimple`/`verRctCLSAGSimple`, and `rct::genRctSimple`
  from: `chaingen.h`/`.cpp`, `bulletproof_plus.cpp`/`.h`, `chain_switch_1.cpp`,
  `wallet_tools.h`/`.cpp`, `bulletproofs.cpp` (unit), `ringct.cpp` (unit),
  `serialization.cpp` (unit), `ver_rct_non_semantics_simple_cached.cpp`,
  `json_serialization.cpp`, `fuzz/bulletproof.cpp`, and all performance test
  headers.  Removed legacy-only test cases; updated shared test helpers to drop
  `RangeProofType`/`bp_version` parameters.

### 🗑️ Removed

- **Dead verification cache code (`verRctNonSemanticsSimple`, `ver_rct_non_semantics_simple_cached`).**
  Removed the stub `verRctNonSemanticsSimple` from `rctSigs.cpp/.h` (returned `true`
  unconditionally), the `ver_rct_non_semantics_simple_cached` wrapper and its
  `ver_rct_non_sem` helper from `tx_verification_utils.cpp/.h`, the unused
  `rct_ver_cache_t` type alias and `m_rct_ver_cache` member from `Blockchain`,
  and the dead `RCT_CACHE_TYPE` constant from `check_tx_inputs`.  Real FCMP++
  verification lives in `check_tx_inputs` (blockchain.cpp) and the mempool
  uses `compute_fcmp_verification_hash` for caching.

### 🔒 Security

- **CRITICAL: PQC signed payload now binds to prunable FCMP++ data (Phase 4c).**
  `get_transaction_signed_payload` now includes `H(serialize(RctSigPrunable))`
  in the signed payload, binding PQC signatures to the FCMP++ proof, pseudoOuts,
  curve_trees_tree_depth, and Bulletproofs+.  Without this, an attacker could
  substitute different prunable data without invalidating PQC signatures,
  breaking the dual-layer security model.

- **CRITICAL: Wired stake claim validation in `check_tx_inputs` (Phase 4e audit fix).**
  The non-FAKECHAIN gate in `check_tx_inputs` rejected all `RCTTypeNull`
  transactions, which includes pure stake-claim txs.  The gate now allows
  `RCTTypeNull` transactions through when all inputs are `txin_stake_claim`.
  Additionally, the `RCTTypeNull` switch case now calls `check_stake_claim_input`
  for each claim input and checks key image double-spend — previously it
  `break`ed without any validation.

- **HIGH: Bound all inputs' H(pqc_pk) hashes into PQC signed payload.**
  `get_transaction_signed_payload` now appends `H(pqc_pk_0) || ... || H(pqc_pk_{N-1})`
  after the per-input header blob, preventing key-substitution attacks where an
  attacker replaces one input's PQC key without invalidating other signatures.

- **MEDIUM: Stake claim curve tree leaf verification (Phase 4e).**
  `check_stake_claim_input` now verifies the staked output's leaf is present
  in the curve tree by checking `staked_output_index < get_curve_tree_leaf_count()`
  and reading the leaf with `get_curve_tree_leaf()`.  Previously, only the
  `lock_until` check was performed, which didn't guarantee the leaf had been
  inserted into the tree.

- **MEDIUM: PQC `auth_version` and `flags` consensus enforcement.**
  `verify_transaction_pqc_auth` now rejects `auth_version != 1` and
  `flags != 0`, enforcing spec steps 6a/6c. Previously these fields were
  serialized and signed over but never validated.

- **LOW: Single-signer `hybrid_public_key` size enforcement.**
  `verify_transaction_pqc_auth` now verifies single-signer key blobs are
  exactly `HYBRID_SINGLE_KEY_LEN` (1996 bytes). Previously only multisig
  keys had size bounds checks; single-signer keys relied solely on the FFI
  call to reject malformed keys.

- **LOW: Added deserialization size bounds for `pqc_authentication` blobs.**
  `hybrid_public_key` and `hybrid_signature` vectors are now rejected during
  deserialization if they exceed `PQC_MAX_PUBLIC_KEY_BLOB` or
  `PQC_MAX_SIGNATURE_BLOB`, preventing memory-exhaustion attacks via
  oversized PQC fields.

### 🐛 Fixed

- **HIGH: Fixed `pop_block()` off-by-one for staked-output curve tree removal.**
  The height used for staked-output eligibility checking was captured *after*
  `remove_block()`, using the post-pop height instead of the removed block's
  height.  This caused a mismatch with `add_block()`'s logic: outputs added at
  the exact lock boundary were inserted during add but not removed during pop,
  leaving orphaned leaves in the curve tree.

- **HIGH: Fixed `pseudoOuts` serialization mismatch in generic `rctSigBase`.**
  The generic `BEGIN_SERIALIZE_OBJECT()` path in `rctSigBase` unconditionally
  included `pseudoOuts`, even for `RCTTypeFcmpPlusPlusPqc` where pseudo-outs
  live in the prunable section.  Now gated with
  `if (type != RCTTypeFcmpPlusPlusPqc)` to match the custom serializer.

- **MEDIUM: `get_curve_tree_path` RPC now fails on missing layer hashes.**
  Previously, a failed `get_curve_tree_layer_hash()` silently inserted zeros
  into the proof path, potentially generating invalid proofs from inconsistent
  DB state.  Now returns `CORE_RPC_ERROR_CODE_INTERNAL_ERROR`.



- **CRITICAL: Fixed incorrect existing_child in internal layer hash propagation**
  (`grow_curve_tree`).  When updating an existing child chunk's hash, the
  parent's Pedersen commitment was computed with `existing_child = 0` instead of
  the previous cycle-scalar.  This produced wrong chunk hashes for any block
  that updated (rather than created) a child chunk.  The fix tracks both old and
  new hashes through `updated_chunk_t` and passes the previous cycle-scalar to
  `hash_grow`.

- **CRITICAL: Replaced O(N) `trim_curve_tree` with incremental `hash_trim`.**
  Reorgs previously read all remaining leaves, cleared the tree, and rebuilt
  from scratch — a liveness risk at scale.  The new implementation uses
  `hash_trim_selene`/`hash_trim_helios` FFI to surgically update only the
  affected chunks, then propagates the old→new deltas up through internal layers.
  Complexity is now O(removed × log N).

- **CRITICAL: Enforced output maturity via `FCMP_REFERENCE_BLOCK_MIN_AGE`.**
  Outputs enter the curve tree at creation time (maximising the anonymity set).
  Maturity is enforced at spending time by requiring the reference block to be
  at least `CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW` (60) blocks behind the tip.
  Added `static_assert`s in `cryptonote_config.h` to prevent regression.

- **HIGH: Validated meta reads in `save_curve_tree_checkpoint`.**  The function
  now checks that root, depth, and leaf_count were all successfully read from
  meta before storing a checkpoint.  If any value is missing or leaf_count is 0,
  the checkpoint is skipped with a log warning instead of storing a corrupt
  zero-valued checkpoint.

### 🔄 Changed

- **Consensus: `curve_trees_tree_depth` validation now accepts `<= current`.**
  The referenceBlock's tree may have fewer layers than the current tip (depth
  is monotonically non-decreasing).  The strict `!=` check was replaced with a
  range check `(0, current_depth]`, and the FCMP++ proof verifier provides the
  authoritative depth validation.

- **Consensus: Removed ring-based validation path from `check_tx_inputs`.**
  Shekyl starts at genesis with FCMP++; the legacy ring-signature per-input
  validation is unreachable dead code.  The `else` branch now immediately
  rejects non-FCMP++ transactions with a clear error message.

- **Coinbase KEM: Added warning when miner address lacks PQC public key.**
  If a miner's address has no PQC key at the FCMP++ hard fork, a warning is
  logged noting that the output will have `H(pqc_pk) = 0` in the curve tree —
  a distinguishable pattern.

- **RPC: Replaced hardcoded chunk widths with FFI calls.**
  `get_curve_tree_path` now calls `shekyl_curve_tree_selene_chunk_width()` and
  `shekyl_curve_tree_helios_chunk_width()` instead of using static constants.

- **RPC: Added `reference_height` and `leaf_count` to `get_curve_tree_path`
  response.**  Wallets can now verify response freshness and detect stale paths
  without parsing the reference block hash.

- **RPC: Added `MAX_OUTPUTS_PER_RPC_REQUEST` (64) rate limit** to
  `get_curve_tree_path` to prevent abuse from unbounded requests.

### ✨ Added

- **RPC: `get_curve_tree_info` endpoint** returns root hash, depth, leaf count,
  and chain height for the current curve tree state.

- **RPC: `get_curve_tree_checkpoint` endpoint** retrieves a stored checkpoint
  (root, depth, leaf_count) at a given block height, needed for fast-sync.

### 📚 Documentation

- Documented `verRctNonSemanticsSimple` stub status: the FCMP++ membership
  proof is verified in the main consensus path (`check_tx_inputs`), not in the
  verification-caching path.  Added TODO for Phase 5 unification.
- ~~Documented coinbase `tx.version = 2` rationale~~ — superseded: coinbase
  is now version 3, unified with regular transactions.
- Documented LMDB post-delete cursor contract (`MDB_GET_CURRENT` after
  `mdb_cursor_del` returns the next item) in pruning and GC loops.
- Added `ct_layer_chunk_key` bit-layout comment explaining the 8-bit layer /
  56-bit chunk index encoding for LMDB integer keys.
- Documented `construct_leaf` zero 4th scalar (H(pqc_pk)) and the tree rebuild
  requirement when PQC per-output keys are activated.
- Documented depth tracking semantics (root layer index, not layer count) and
  root detection invariant in `grow_curve_tree`.
- Added TODO for async/batched checkpoint+pruning in `add_block`.
- Documented `get_curve_tree_root` empty-tree return semantics (returns
  `hash_init`, callers should check `leaf_count`).

### 🗑️ Removed

- **Legacy RCT and mixin references stripped from wallet layer.** Completed
  the wallet-side refactor removing all references to legacy ring sizes,
  `adjust_mixin`, `default_mixin`, `m_default_mixin`, `RCTConfig`, and
  mixin-count parameters:
  - `wallet2.h`: Removed `estimate_fee` mixin/bulletproof/clsag params,
    `adjust_mixin()`, `default_mixin()` getter/setter, `m_default_mixin`
    member, `rct_config` from `pending_tx` and `transfer_selected_rct`.
  - `wallet2.cpp`: Removed mixin from `estimate_rct_tx_size`,
    `estimate_tx_size`, `estimate_tx_weight`, `estimate_fee` signatures
    and all call sites. Removed `adjust_mixin()` definition, JSON
    serialization of `default_mixin`, constructor initialization. Removed
    `const bool clsag/bulletproof/bulletproof_plus = true` patterns.
  - `wallet_errors.h`: Removed `mixin_count` field from
    `not_enough_outs_to_mix` error struct.
  - `wallet2_ffi.cpp`: Replaced `adjust_mixin` calls with constant `0`.
  - `wallet_rpc_server.cpp`: Replaced `adjust_mixin` calls with constant `0`.
  - `wallet2_api.h`, `wallet.h`, `wallet.cpp`: Removed `mixin_count`
    parameter from `createTransaction` and `createTransactionMultDest`.
  - `unsigned_transaction.cpp`: Simplified `mixin()` and `minMixinCount()`
    to always return 0 (FCMP++ has no explicit mixin).
  - `simplewallet.cpp`: Removed ring-size parsing, `adjust_mixin` calls,
    and `default_mixin` display. All fake_outs_count set to 0.
- **Legacy RCT references stripped from all src/ files.** Removed all
  remaining references to CLSAG, legacy RCT types, `RCTConfig`, `mixRing`,
  and `low_mixin` from device drivers, Trezor protocol, RPC handlers,
  blockchain verification, transaction utilities, wallet, and serialization:
  - `device_ledger.cpp`: Removed `INS_CLSAG` define, legacy type branches
    in `mlsag_prehash`, replaced `clsag_prepare`/`clsag_hash`/`clsag_sign`
    with FCMP++ TODO stubs.
  - `protocol.cpp`/`protocol.hpp` (Trezor): Removed `rct::Bulletproof`
    variant, `is_simple()`/`is_req_bulletproof()`/`is_bulletproof()`/
    `is_clsag()` helpers, `mixRing` resize, CLSAG deserialization in
    `step_final_ack`. Added `is_fcmp_pp()` helper.
  - `core_rpc_server.cpp`/`core_rpc_server_commands_defs.h`: Removed
    `low_mixin` field and its assignment from send_raw_tx response.
  - `daemon_handler.cpp`: Removed `m_low_mixin` error branch.
  - `verification_context.h`: Removed `m_low_mixin` from
    `tx_verification_context`.
  - `blockchain.cpp`: Replaced legacy mixin-checking branch with a reject
    gate for non-FCMP++ transactions (Shekyl only supports FCMP++).
  - `cryptonote_tx_utils.h`/`.cpp`: Removed `rct::RCTConfig` parameter
    from `construct_tx_with_tx_key` and `construct_tx_and_get_tx_key`.
    Replaced `genRctSimple` call with FCMP++ proof generation stub.
    Removed `mixRing` construction.
  - `cryptonote_format_utils.cpp`: Removed `is_rct_bulletproof`/
    `is_rct_clsag` calls, simplified BP+ weight calculations.
  - `cryptonote_boost_serialization.h`: Removed serialization functions
    for `rct::rangeSig`, `rct::Bulletproof`, `rct::mgSig`, `rct::clsag`,
    `rct::RCTConfig`, `rct::boroSig`. Simplified `rctSigBase` and
    `rctSigPrunable` serialization to only handle FCMP++.
  - `tx_verification_utils.h`/`.cpp`: Removed `mix_ring` parameter from
    `ver_rct_non_semantics_simple_cached`. Removed `expand_tx_and_ver_rct_non_sem`,
    `calc_tx_mixring_hash`, and `is_canonical_bulletproof_layout`.
  - `json_object.h`/`.cpp`: Removed JSON serialization for `rct::rangeSig`,
    `rct::Bulletproof`, `rct::boroSig`, `rct::mgSig`, `rct::clsag`.
    Removed legacy prunable fields from `rctSig` JSON output.
  - `wallet2.h`: Removed `rct_config` field from `tx_construction_data`
    serialization and the version-gated `RangeProofPaddedBulletproof`
    defaults in Boost serialization.
  - `wallet2.cpp`: Fixed `construct_tx_and_get_tx_key` call site that
    still passed `{}` where the removed `rct_config` parameter was.
  - `bulletproofs.h`/`.cc`: Gutted non-plus Bulletproof PROVE/VERIFY
    functions — the `rct::Bulletproof` struct was already removed from
    `rctTypes.h`, making these 1000+ lines of dead code.
- **Legacy RCT types stripped from core.** Removed `RCTTypeFull` (1),
  `RCTTypeSimple` (2), `RCTTypeBulletproof` (3), `RCTTypeBulletproof2` (4),
  `RCTTypeCLSAG` (5), and `RCTTypeBulletproofPlus` (6) from the enum.
  Only `RCTTypeNull` (0) and `RCTTypeFcmpPlusPlusPqc` (7) remain.
- Deleted structs: `mgSig`, `clsag`, `rangeSig`, `Bulletproof` (non-plus),
  `RangeProofType` enum, and `RCTConfig`.
- Removed `mixRing` member from `rctSigBase` and `mixin` parameter from
  `serialize_rctsig_prunable`.
- Removed from `rctSigPrunable`: `rangeSigs`, `bulletproofs` (non-plus),
  `MGs`, `CLSAGs` vectors and their serialization blocks.
- Removed functions: `CLSAG_Gen`, `proveRctCLSAGSimple`,
  `verRctCLSAGSimple`, `genRctSimple` (both overloads),
  `populateFromBlockchainSimple`, `getKeyFromBlockchain`,
  `is_rct_simple`, `is_rct_bulletproof`, `is_rct_borromean`, `is_rct_clsag`,
  `proveRangeBulletproof`, `verBulletproof`, `make_dummy_bulletproof`,
  `make_dummy_clsag`.
- Removed `HASH_KEY_CLSAG_ROUND`, `HASH_KEY_CLSAG_AGG_0`,
  `HASH_KEY_CLSAG_AGG_1`, and `HASH_KEY_TXHASH_AND_MIXRING` from
  `cryptonote_config.h`.
- Removed VARIANT_TAG entries for `mgSig`, `rangeSig`, `Bulletproof`,
  and `clsag`.
- Simplified `get_pre_mlsag_hash` to only handle `RCTTypeFcmpPlusPlusPqc`.
- Simplified `verRctSemanticsSimple` and `verRctNonSemanticsSimple` to
  only accept FCMP++ transactions (no CLSAG/ring verification path).

### 🔄 Changed

- **FCMP++ Phase 3: Per-input PQC authorization vector.** Replaced
  `std::optional<pqc_authentication> pqc_auth` with
  `std::vector<pqc_authentication> pqc_auths` on `cryptonote::transaction`
  (one `pqc_authentication` per input). Updated binary, Boost, and JSON
  serialization, transaction hash (`cn_fast_hash` of serialized
  `pqc_auths`), per-input PQC verification, and wallet/RPC signing paths.

### ✨ Added

- **FCMP++ (Full-Chain Membership Proofs): complete implementation across
  Phases 1–6.**
  Shekyl replaces ring signatures (CLSAG) with FCMP++ from genesis. Every
  spend proves membership in the entire UTXO set via a Helios/Selene curve
  tree, giving every transaction full-chain anonymity instead of 16-decoy
  ring ambiguity. Combined with hybrid post-quantum spend authorization
  (Ed25519 + ML-DSA-65), this makes Shekyl the first cryptocurrency to offer
  full-UTXO-set anonymity with quantum-resistant ownership.

  Key components delivered:
  - **Rust foundation (Phase 1):** `shekyl-fcmp` crate wrapping upstream
    `monero-fcmp-plus-plus` with 4-scalar leaf type `{O.x, I.x, C.x,
    H(pqc_pk)}`. Hybrid X25519 + ML-KEM-768 KEM with HKDF-SHA-512.
    Bech32m segmented address encoding. Per-output PQC key derivation.
    15 FFI exports. Security audit (zero vulnerabilities, zero unsafe in
    first-party code). Reproducible builds with pinned Cargo.lock.
  - **Transaction format (Phase 3):** `RCTTypeFcmpPlusPlusPqc = 7` with
    `referenceBlock`, `curve_trees_tree_depth`, and `fcmp_pp_proof` fields.
    `curve_tree_root` commitment in every block header.
  - **Consensus verification (Phase 4):** 7-step verification order in
    `check_tx_inputs` — referenceBlock age, tree depth, key image
    y-normalization, FCMP++ proof via Rust FFI, PQC signature verification,
    BP+ range proofs. Mempool verification caching (`fcmp_verification_hash`
    in `txpool_tx_meta_t`). Staked output curve-tree leaves.
  - **Curve tree database (Phase 2):** Full `get_curve_tree_path` RPC
    implementation assembling real Merkle paths (leaf scalars + per-layer
    sibling hashes with position encoding). Selective pruning of
    intermediate tree layers between checkpoints, wired into `add_block`
    after `save_curve_tree_checkpoint`. Old checkpoint garbage collection.
  - **Wallet integration (Phase 5):** `genRctFcmpPlusPlus()` proof
    construction. `get_curve_tree_path` RPC. Tree-path precomputation
    and incremental update in wallet refresh loop. PQC key rederivation from
    stored shared secret. Restore-from-seed PQC rederivation.
  - **Infrastructure (Phase 6):** Hardware device FCMP++ stubs. CI pipeline
    for Rust workspace build, FCMP crate, determinism check, Bech32m tests.
    `output_pruning_metadata_t` and `m_output_metadata` LMDB table for
    transaction pruning. LMDB curve tree schema (leaves, layers, meta,
    checkpoints). Checkpoint every 10,000 blocks for fast-sync resumption.

  See `docs/FCMP_PLUS_PLUS.md` for the full specification.

- **FCMP++ Phase 3: KEM ciphertext `tx_extra` and coinbase self-encapsulation.**
  - `tx_extra_pqc_kem_ciphertext` with tag `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`
    (`0x06`): payload `blob` is the concatenation of N ML-KEM-768 ciphertexts
    (1088 bytes each), one per output in order.
  - **Coinbase:** When the miner address has a PQC key and the hard-fork
    version is at least `HF_VERSION_FCMP_PLUS_PLUS_PQC`, `construct_miner_tx`
    performs KEM self-encapsulation to the miner’s own address per coinbase
    output (same tag and derivation semantics as normal transfers), then
    wipes the shared secret after use.

- **FCMP++ Phase 5e: Wallet precomputation of curve tree paths.**
  - Added `fcmp_precomputed_path` struct to `wallet2.h` caching per-output
    tree path, root hash at precompute time, and precompute height.
  - Added `m_fcmp_precomputed_paths` runtime cache (not serialized) and
    `m_fcmp_last_precompute_height` watermark to `wallet2`.
  - `precompute_fcmp_paths()` fetches tree paths for all unspent outputs
    via the `get_curve_tree_path` daemon RPC endpoint.
  - `update_fcmp_paths_incremental(new_height)` extends existing paths
    and adds newly discovered outputs, pruning paths for spent outputs.
  - Incremental path update is hooked into the wallet refresh loop,
    triggering after sync catches up if blocks were fetched.
  - Progress callbacks (`on_fcmp_path_precompute_progress`) fire during
    both initial and incremental precomputation.
- **FCMP++ Phase 5.5: Wallet sync and restore-from-seed PQC support.**
  - `transfer_details::m_combined_shared_secret` (64 bytes) stores the
    hybrid KEM shared secret needed to rederive per-output PQC keys.
  - `rederive_pqc_keys_for_output(td)` calls `shekyl_fcmp_derive_pqc_keypair`
    via FFI to validate keypair derivation from stored shared secret.
  - `rederive_all_pqc_keys()` iterates all transfers with stored shared
    secrets and rederives PQC keys, with progress callback
    `on_pqc_rederivation_progress`.
  - Restore-from-seed triggers full PQC key rederivation on first refresh
    after sync completes.

### 🐛 Fixed

- **Curve tree pop_block over-trim:** `pop_block` previously counted all
  `tx.vout` entries when computing how many leaves to trim, but `add_block`
  skips outputs that fail type checks (unknown target types), locked staked
  outputs, and outputs whose FFI leaf construction fails. The trim count now
  mirrors the same filtering logic used in the grow path, preventing tree
  desynchronization during reorgs.
- **Curve tree pruning correctness:** `prune_curve_tree_intermediate_layers`
  was deleting all intermediate layer entries instead of selectively pruning
  only chunks fully below the previous checkpoint boundary. Fixed to compute
  the chunk boundary from the previous checkpoint's `leaf_count` and only
  remove sealed entries. Also added garbage collection of stale checkpoint
  records (only the two most recent are kept).
- **LMDB output metadata: removed undefined behavior in cursor macros.**
  - `store_output_metadata` now uses `mdb_put` directly with `m_write_txn`
    instead of the `CURSOR()` macro which required `m_cursors` to be in
    scope.
  - `get_output_metadata` and `prune_tx_data` now use `m_txn` (from
    `TXN_PREFIX_RDONLY`) instead of `txn_ptr` (from `TXN_PREFIX`).
  - Removed unused `m_txc_output_metadata` cursor field and
    `m_cur_output_metadata` macro from `db_lmdb.h`.
- **Wallet FCMP++ path precomputation: fixed undefined behavior.**
  - Replaced `reinterpret_cast<std::string&>` on `std::vector<uint8_t>` with
    a proper intermediate `std::string` copy in both `precompute_fcmp_paths`
    and `update_fcmp_paths_incremental`.

- **FCMP++ Phase 6c: CI pipeline updates.**
  - Added x86_64 architecture verification step to the `rust-audit-and-test`
    CI job in `.github/workflows/build.yml`.
  - Added explicit `cargo build --locked -p shekyl-fcmp` step to verify the
    FCMP++ crate builds as part of the Rust workspace.
  - Added dedicated Bech32m address encoding test step that runs
    `shekyl-crypto-pq` address tests with visible CI output.
  - The monero-oxide git dependency is cached via `~/.cargo/git` in the
    existing Cargo cache key (`rust-${{ hashFiles('rust/Cargo.lock') }}`).
  - Determinism check (build twice, diff `libshekyl_ffi.a` hashes) and
    `cargo audit` remain in place.
- **FCMP++ Phase 6f: Transaction pruning mode (skeleton).**
  - Added `output_pruning_metadata_t` packed struct to `blockchain_db.h`
    storing per-output scan data (pubkey, commitment, unlock_time, height,
    pruned flag) for wallet scanning after transaction pruning.
  - Added abstract interface in `BlockchainDB`: `store_output_metadata()`,
    `get_output_metadata()`, `is_output_pruned()`, `prune_tx_data()`.
  - Added `m_output_metadata` LMDB table (keyed by `global_output_index`)
    in `db_lmdb.h` and `db_lmdb.cpp` with cursor, rflag, and DBI member.
  - LMDB implementation: `store_output_metadata` and `get_output_metadata`
    are fully wired; `is_output_pruned` delegates to `get_output_metadata`;
    `prune_tx_data` validates depth against `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`
    and reads/writes a `last_pruned_tx_data_height` watermark in the
    properties table to skip already-processed blocks on subsequent runs.
    The block-iteration pruning loop is documented as a TODO skeleton.
  - `--prune-blockchain` CLI flag now also triggers `prune_tx_data()` in
    `cryptonote_core.cpp`, running output-metadata pruning alongside
    Monero's existing stripe-based pruning.
  - Test DB (`testdb.h`) updated with no-op stubs for all four new methods.
- **FCMP++ Phase 4b: Mempool verification caching.**
  - Added `fcmp_verification_hash` (32-byte `crypto::hash`) and
    `fcmp_verified` (1-bit flag) to `txpool_tx_meta_t` in
    `src/blockchain_db/blockchain_db.h`, carved from the existing
    76-byte padding (now 44 bytes).  Struct stays 192 bytes.
  - New `Blockchain::compute_fcmp_verification_hash()` computes a
    deterministic cache key from `hash(proof || referenceBlock || key_images)`.
  - `tx_memory_pool::add_tx` stores the cache hash on successful FCMP++
    verification.
  - `tx_memory_pool::is_transaction_ready_to_go` checks the cached hash
    via `is_fcmp_verification_cached()` and seeds `m_input_cache` to
    skip re-running `shekyl_fcmp_verify()` for previously-verified
    mempool transactions.
  - Added `static_assert` guards at the `memcmp` site on
    `txpool_tx_meta_t` (tx_pool.cpp line 1656) enforcing
    trivially-copyable layout and 192-byte struct size.
  - All padding and new fields are zero-initialized at every meta
    construction site.
- **FCMP++ Phase 4e: Staking consensus rules for FCMP++.**
  - `collect_outputs` in `blockchain_db.cpp::add_block` now handles
    `txout_to_staked_key` outputs using the same 4-scalar leaf format
    `{O.x, I.x, C.x, H(pqc_pk)}`.
  - Deferred insertion: staked outputs only enter the curve tree when
    `block_height >= lock_until`.  Outputs still within their lock
    period are stored in the `pending_staked_leaves` DB table and
    inserted into the curve tree when they mature (see deferred
    staked leaf insertion entry below).
  - `check_stake_claim_input` now rejects claims on outputs whose
    `lock_until > current_height`, ensuring claimability only after
    the lock period expires.
- **FCMP++ Phase 5: Wallet transaction construction skeleton.**
  - Added `rct::genRctFcmpPlusPlus()` in `src/fcmp/rctSigs.cpp` — builds
    an FCMP++ `rctSig` with `RCTTypeFcmpPlusPlusPqc`, Bulletproofs+ range
    proofs, balanced pseudo-outputs, and invokes `shekyl_fcmp_prove()` via
    FFI to generate the membership proof.
  - Declared the new function in `src/fcmp/rctSigs.h`.
  - Added `COMMAND_RPC_GET_CURVE_TREE_PATH` RPC command in
    `src/rpc/core_rpc_server_commands_defs.h` — accepts output indices and
    returns Merkle paths from the curve tree (stub handler for now).
  - Wired `get_curve_tree_path` JSON-RPC endpoint in
    `src/rpc/core_rpc_server.h` and `src/rpc/core_rpc_server.cpp`.
  - Added TODO scaffolding in `src/wallet/wallet2.cpp` at the decoy
    selection (`get_outs`), transaction construction
    (`construct_tx_and_get_tx_key`), and fee estimation
    (`estimate_tx_weight`) sites, documenting how FCMP++ replaces ring
    signatures in the wallet transfer flow.
- **FCMP++ Phase 6a: Hardware device stubs.**
  - Added `fcmp_prepare`, `fcmp_proof_start`, and `fcmp_proof_add_input`
    virtual methods to `hw::device` (base class) with default `return false`
    implementations for unsupported devices.
  - Software device (`device_default`) returns `true` (scaffolding for Rust
    FFI delegation).
  - Ledger device (`device_ledger`) logs an informative error and returns
    `false`, guiding users to software wallets until Ledger firmware gains
    FCMP++ support.
  - Trezor inherits the base-class defaults (unsupported) without code changes.
  - Updated `RELEASE_CHECKLIST.md` to document hardware wallet readiness status.
- **FCMP++ Phase 4a: Verification in `check_tx_inputs`.**
  - Added `RCTTypeFcmpPlusPlusPqc` verification path in
    `Blockchain::check_tx_inputs` (`src/cryptonote_core/blockchain.cpp`).
  - `referenceBlock` age validation: confirmed within
    `[tip - MAX_AGE, tip - MIN_AGE]` using DB block lookup.
  - `curve_trees_tree_depth` validated against the current tree state.
  - Key offsets verified empty for all FCMP++ inputs.
  - Key image y-normalization enforced (sign bit of byte 31 cleared).
  - Input count bounded by `FCMP_MAX_INPUTS_PER_TX`.
  - `shekyl_fcmp_verify()` FFI call wired up with key images, pseudo
    outputs, and proof blob.
  - Per-input `pqc_auths` verification left as documented TODO pending
    the per-input auth field migration.
- **FCMP++ Phase 4a-pre: PQC auth binding specification.**
  - New `docs/FCMP_PLUS_PLUS.md` formally documents the dual-layer
    binding model, per-input signed payload layout, and 7-step consensus
    verification order for `RCTTypeFcmpPlusPlusPqc` transactions.
- **FCMP++ Phase 3.5: Curve tree root in block header (consensus-critical).**
  - Added `curve_tree_root` (`crypto::hash`) field to `block_header` in
    `src/cryptonote_basic/cryptonote_basic.h`, initialized to `null_hash`.
  - Field is always serialized (genesis-native, no version gating) in both
    the binary archive (`BEGIN_SERIALIZE`) and Boost serialization.
  - Block template creation (`Blockchain::create_block_template`) snapshots
    the current DB curve tree root into the header.
  - Block validation (`Blockchain::handle_block_to_main_chain`) verifies
    `curve_tree_root` matches the locally-computed tree root after
    `add_block` grows the tree; rejects the block on mismatch.
  - RPC `block_header_response` now includes `curve_tree_root` hex string.
  - Test generator (`chaingen.cpp`) sets `curve_tree_root` to `null_hash`
    in `construct_block` and `construct_block_manually`.
- **FCMP++ Phase 3: Transaction format for FCMP++ PQC.**
  - Added `RCTTypeFcmpPlusPlusPqc = 7` to the RCT type enum in
    `src/fcmp/rctTypes.h` — Shekyl's only non-coinbase transaction type.
  - Added `referenceBlock` (block hash anchoring the curve tree snapshot)
    to `rctSigBase`, serialized only for the new type.
  - Added `curve_trees_tree_depth` and `fcmp_pp_proof` (opaque FCMP++ proof
    blob) to `rctSigPrunable`, replacing CLSAG ring signatures for the new type.
  - Added `TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT` (0x06) to `tx_extra.h` for
    per-output ML-KEM-768 ciphertexts.
  - Added `key_image_y_normalize()` to `crypto.h`/`crypto.cpp` — clears the
    sign bit of a key image's y-coordinate as required by FCMP++.
  - Added `is_rct_fcmp_pp_pqc()` helper to `rctTypes.h`/`rctTypes.cpp`.
  - Updated serialization helpers (`serialize_rctsig_base`,
    `serialize_rctsig_prunable`) and type classifier functions
    (`is_rct_simple`, `is_rct_bulletproof_plus`) to handle the new type.
- **FCMP++ Phase 2e: Curve tree checkpoint strategy.**
  - New `BlockchainDB` virtual methods: `save_curve_tree_checkpoint`,
    `get_curve_tree_checkpoint`, `get_latest_curve_tree_checkpoint_height`,
    `prune_curve_tree_intermediate_layers`.
  - LMDB implementation with `curve_tree_checkpoints` table (MDB_INTEGERKEY),
    storing root[32] + depth[1] + leaf_count[8] per checkpoint.
  - Automatic checkpoint every `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` (10 000)
    blocks during `add_block`, enabling fast-sync resumption.
  - Configurable interval via `cryptonote_config.h` constant.
- **FCMP++ Phase 2f: Curve tree pruning strategy.**
  - `prune_curve_tree_intermediate_layers` removes recomputable internal hash
    layers between checkpoints, preserving leaves and the root layer to reduce
    storage overhead.
- **FCMP++ Phase 1: Rust foundation crates.**
  - New `rust/shekyl-fcmp/` crate wrapping upstream `monero-fcmp-plus-plus`
    (from `Shekyl-Foundation/monero-oxide` fork, `fcmp++` branch) with
    4-scalar curve tree leaf type `{O.x, I.x, C.x, H(pqc_pk)}`.
  - Implemented `HybridX25519MlKem` (X25519 + ML-KEM-768 FIPS 203) in
    `shekyl-crypto-pq/src/kem.rs` with HKDF-SHA-512 shared-secret
    combination and master-seed key derivation.
  - Implemented Bech32m segmented address encoding
    (`shekyl1<classical>/skpq1<pqc_a>/skpq21<pqc_b>`) in
    `shekyl-crypto-pq/src/address.rs`, keeping each segment within
    Bech32m's proven checksum range.
  - Implemented per-output PQC keypair derivation (HKDF-Expand → ML-DSA-65
    deterministic keygen) in `shekyl-crypto-pq/src/derivation.rs`.
  - Added 15 new FFI exports to `shekyl-ffi` for FCMP++ proofs, KEM
    operations, address encoding, and seed derivation.
  - Added FCMP++ consensus constants to `cryptonote_config.h`:
    `HF_VERSION_FCMP_PLUS_PLUS_PQC`, `FCMP_REFERENCE_BLOCK_MAX_AGE` (100),
    `FCMP_REFERENCE_BLOCK_MIN_AGE` (2), `FCMP_MAX_INPUTS_PER_TX` (8).
  - Updated `BuildRust.cmake` with `--locked` flag for reproducible builds.
- **FCMP++ Phase 1a.1: Security review of forked monero-oxide crates.**
  - `cargo audit`: 226 crate dependencies scanned, zero vulnerabilities found.
  - `unsafe` block audit: zero `unsafe` in first-party monero-oxide workspace
    code (helioselene, ec-divisors, generalized-bulletproofs, fcmps,
    monero-oxide). Only 4 `unsafe` blocks exist in helioselene benchmarks
    (`_rdtsc()` for cycle counting, not in library code). `dalek-ff-group`
    (crates.io dependency) also has zero `unsafe` blocks.
  - Veridise audit status: FCMPs circuit audited by Veridise (June 2025);
    Generalized Bulletproofs security proofs by Cypher Stack; Divisor proofs
    reviewed by both Veridise and Cypher Stack. Pinned commit `92af05e0` is
    post-audit. Helioselene and ec-divisors are not yet independently audited.
    Multi-phase integration audit (seraphis-migration/monero#294) is in
    planning.
- **FCMP++ Phase 1a.2: Rust reproducible builds.**
  - `Cargo.lock` pins all git dependencies to exact commit hash `92af05e0`.
  - Double-build determinism verified: `libshekyl_ffi.a` hash identical across
    consecutive builds on x86_64.
  - Added CI job `rust-audit-and-test` to `.github/workflows/build.yml` with
    cargo audit, workspace tests, and determinism check (build twice, diff).
  - Documented x86_64-only build requirement and Guix integration status in
    `docs/COMPILING_DEBUGGING_TESTING.md`.

### 🔄 Changed

- **P2P reorg functional test uses deadline-based polling.** Replaced three
  fixed-sleep polling sites in `test_p2p_reorg()` (`time.sleep(10)` x2,
  `loops = 100` counter) with 240 s deadline + 0.25 s interval polling,
  matching the pattern already used in `test_p2p_tx_propagation()`.
  Adapted from upstream Monero #9795.

### ✨ Added

- **Extra compiler warnings and hardening flags.** Added `-Wredundant-decls`,
  `-Wdate-time`, `-Wimplicit-fallthrough`, `-Wunreachable-code` (common);
  `-Woverloaded-virtual`, `-Wsuggest-override` (C++ only); `-Wgnu`,
  `-Wshadow-field`, `-Wthread-safety`, `-Wloop-analysis`,
  `-Wconditional-uninitialized`, `-Wdocumentation`, `-Wself-assign` (Clang);
  `-Wduplicated-branches` (GCC). Added security protections:
  `-fno-extended-identifiers`, `-fstack-reuse=none`, and ARM64 branch
  protection (`-mbranch-protection=bti` on macOS, `standard` elsewhere).
  Adapted from upstream Monero #9858.
- **Linker dead-code stripping.** Added `-ffunction-sections -fdata-sections`
  to compile flags and `-Wl,--gc-sections` (Linux) / `-Wl,-dead_strip`
  (macOS) to linker flags, enabling the linker to strip unreferenced
  functions and data. Inspired by upstream Monero #9898 author's findings
  (~14 MiB reduction in Docker images).

### 📚 Documentation

- **Upstream Monero PR triage.** Replaced the stale "To be done (and merged)"
  section in `COMPILING_DEBUGGING_TESTING.md` with a structured triage table
  covering applied PRs (#6937, #9762, #9795, #9858, #9898) and tracked-for-
  future-work PRs (#10157, #10084, #9801) with STRUCTURAL_TODO.md cross-refs.
- **FCMP++ documentation rework (Phase 0.5a).** Reworked all core documentation
  to reflect FCMP++ as the membership proof system from genesis. Replaced CLSAG
  and ring signature references with FCMP++ full-chain membership proof language.
  Updated PQC spec for per-input pqc_auths, per-output KEM derivation, Bech32m
  addresses, and curve tower architecture. Retired V4 lattice ring signature
  roadmap. Updated V3_ROLLOUT.md size estimates for ~23 KB typical transactions.
  Added FCMP++ items to RELEASE_CHECKLIST.md.

### 🐛 Fixed

- **Re-enabled `gen_block_reward` core test with Shekyl economics.**
  Rewrote `check_block_rewards()` in `block_reward.cpp` to verify miner
  outputs against Shekyl's four-component economics formula (release
  multiplier + emission split + fee burn) instead of legacy Monero fixed
  expectations. Updated `construct_miner_tx_by_weight` to pass explicit
  economics parameters. Fixed `construct_block` and
  `construct_block_manually` in `chaingen.cpp` to pass
  `circulating_supply=already_generated_coins` to `construct_miner_tx`,
  preventing parameter mismatch between test generator and validator.
  80 core_tests now pass (was 79).

- **MSVC C4334: 23 `1 << n` sites widened to `1ULL << n` in consensus
  code.** Fixed potential undefined behavior (signed 32-bit overflow if
  shift amount ever reaches 32) in `cryptonote_format_utils.cpp` (3),
  `bulletproofs.cc` (6), `bulletproofs_plus.cc` (6), `rctTypes.cpp` (5),
  `rctSigs.cpp` (2), and `multiexp.cc` (2).

- **MSVC C4333 right-shift warning in UTF-8 helpers.** Changed `wint_t cp` to
  `uint32_t cp` in `src/common/util.cpp` `get_string_prefix_by_width()`, and
  added an explicit `static_cast<uint32_t>` on the transform result in
  `src/common/utf8.h` `utf8canonical()`. On MSVC, `wint_t` is 16-bit
  `unsigned short`, so `cp >> 18` shifted by more than the type's width.

- **Remaining HF17 references corrected to HF1.** Fixed stale Monero-era
  `HF17` / `HF_VERSION_SHEKYL_NG = 17` references in `POST_QUANTUM_CRYPTOGRAPHY.md`
  (scheme registry, rollout notes, V4 roadmap), `PQC_MULTISIG.md` (V3 heading,
  V4 scheme table, activation target), `V3_ROLLOUT.md` (title, consensus gate,
  node checklist), and `STAKER_REWARD_DISBURSEMENT.md`. Also corrected `HF18`
  references to `HF2` in multisig V4 rollout tables. The source code constant
  `HF_VERSION_SHEKYL_NG` was already correctly defined as `1` in
  `cryptonote_config.h`; only documentation was affected.

- **CMake Boost detection on CMake 3.30+**: The built-in `FindBoost.cmake`
  module was removed in CMake 3.30. Restructured Boost detection to try
  CONFIG mode first (finding `BoostConfig.cmake` installed by b2), falling
  back to MODULE on older CMake. Fixes `contrib/depends` builds on Ubuntu
  24.04 runners with CMake ≥ 3.30.

### 🗑️ Removed

- **Classical multisig wallet RPC commands.** Removed all 9 Monero-inherited
  multisig RPC endpoints (`is_multisig`, `prepare_multisig`, `make_multisig`,
  `export_multisig_info`, `import_multisig_info`, `finalize_multisig`,
  `exchange_multisig_keys`, `sign_multisig`, `submit_multisig`) from the
  wallet RPC server. Removed `multisig_txset` fields from transfer and sweep
  response structs. Removed the `CHECK_MULTISIG_ENABLED` macro and
  `multisig/multisig.h` dependency. Classical secret-splitting multisig is
  replaced by PQC-only authorization (`scheme_id = 2`); see
  `docs/PQC_MULTISIG.md`.
- **Classical multisig simplewallet CLI commands.** Removed all multisig and
  MMS (Multisig Messaging System) commands from `simplewallet`: `prepare_multisig`,
  `make_multisig`, `exchange_multisig_keys`, `export_multisig_info`,
  `import_multisig_info`, `sign_multisig`, `submit_multisig`,
  `export_raw_multisig_tx`, and all `mms` subcommands. Removed
  `--generate-from-multisig-keys` and `--restore-multisig-wallet` CLI flags.
  Removed `enable-multisig-experimental` wallet setting. Removed
  `wallet/message_store.h` dependency. The `transfer_main`/`called_by_mms`
  indirection was collapsed into a single `transfer` method.
- **Classical multisig test and device_trezor remnants.** Removed stale
  multisig references from test infrastructure: `m_multisig*` wallet resets
  in `wallet_tools.cpp`, `multisig_sigs.clear()` in Trezor tests,
  `multisig_txset` assertion in `cold_signing.py`, and deleted
  `tests/functional_tests/multisig.py`. Removed `multisig` from the
  functional test default list. Cleaned up device_trezor protocol:
  removed `translate_klrki`, `MoneroMultisigKLRki` alias, `m_multisig`
  member, and multisig cout decryption in `Signer::step_final_ack`.
  Removed `mms_error`, `no_connection_to_bitmessage`, and
  `bitmessage_api_error` error classes from `wallet_errors.h`.
- **Classical multisig wallet API layer.** Removed all classical multisig
  code from the public wallet API: `MultisigState` struct, virtual multisig
  declarations (`multisig`, `getMultisigInfo`, `makeMultisig`,
  `exchangeMultisigKeys`, `exportMultisigImages`, `importMultisigImages`,
  `hasMultisigPartialKeyImages`, `restoreMultisigTransaction`,
  `publicMultisigSignerKey`, `signMultisigParticipant`,
  `multisigSignData`, `signMultisigTx`). Removed multisig helper functions
  and multisig threshold check from PendingTransaction commit path.
  Removed multisig guard from the background-sync validation macro.
- **Classical multisig wallet core (`wallet2.cpp`).** Removed all classical
  multisig code from the wallet core: `#include "multisig/..."` headers,
  `MULTISIG_UNSIGNED_TX_PREFIX`/`MULTISIG_EXPORT_FILE_MAGIC`/`MULTISIG_SIGNATURE_MAGIC`
  constants, `m_multisig`/`m_multisig_threshold`/`m_multisig_rounds_passed`/
  `m_enable_multisig`/`m_message_store`/`m_mms_file` member initializations,
  `num_priv_multisig_keys_post_setup`, `get_multisig_seed`, multisig restore
  path in `generate()`, `make_multisig`, `exchange_multisig_keys`,
  `get_multisig_first_kex_msg`, `multisig()`, `has_multisig_partial_key_images`,
  `frozen(multisig_tx_set)`, all `save/parse/load/sign_multisig_tx` overloads,
  the multisig transaction builder path in `transfer_selected_rct`,
  `export_multisig`, `import_multisig`, `update_multisig_rescan_info`,
  `get_multisig_signer_public_key`, `get_multisig_signing_public_key`,
  `get_multisig_k`, `get_multisig_kLRki`, `get_multisig_composite_kLRki`,
  `get_multisig_composite_key_image`, `get_multisig_wallet_state`,
  `sign_multisig_participant`, JSON serialization/deserialization of multisig
  fields, MMS file handling, and all scattered `m_multisig` guard branches.
- **Classical multisig `m_key_image_partial` remnants.** Removed the
  `m_key_image_partial` bitfield from `exported_transfer_details` and all
  code references in `wallet2.cpp` and `simplewallet.cpp`. Since classical
  multisig was removed, partial key images can never exist; all guard
  conditions (`!known || partial`, `known && !partial`, standalone partial
  checks) were simplified to reference only `m_key_image_known`. Removed
  the dead `old_mms_file` cleanup block from `wallet2::store_to`.

### ✨ Added

- **Daemon RPC migrated to Rust/Axum (Phase 1).** The daemon HTTP RPC transport
  is now served by the `shekyl-daemon-rpc` Rust crate using Axum, replacing
  `epee::http_server_impl_base`. All 90 endpoints (33 JSON REST, 9 binary,
  48 JSON-RPC 2.0) are routed through Axum with PQC-ready 10 MiB body limits,
  CORS, and restricted-mode enforcement. The C++ `core_rpc_server` handler
  logic is unchanged and accessed via a `core_rpc_ffi` C ABI facade. Enabled
  by default; `--no-rust-rpc` falls back to the legacy epee HTTP server.
  JSON REST endpoints accept both GET and POST (matching epee). Binary
  endpoints return 400 on parse failure (matching epee's MAP_URI_AUTO_BIN2).
  Validated on live testnet: 23/25 pass, 2 expected diffs
  (`rpc_connections_count`), 2 binary skips (empty-POST → 400 on both).
  Validation harness at `tests/rpc_comparison/compare_rpc.sh`;
  test data in `shekyl-dev/data/rpc_comparison/`.
- **PQC multisig core (scheme_id=2).** Implemented M-of-N hybrid Ed25519 +
  ML-DSA-65 multisig in Rust. Includes `MultisigKeyContainer`,
  `MultisigSigContainer`, `multisig_group_id`, and a 10-check adversarial
  verification pipeline. Maximum 7 participants (consensus constant). Domain
  separator: `shekyl-multisig-group-v1`.
- **PQC multisig FFI bridge.** Extended `shekyl_pqc_verify` to accept
  `scheme_id` and dispatch between single-signer (1) and multisig (2) paths.
  Added `shekyl_pqc_verify_debug` for diagnostic error codes and
  `shekyl_pqc_multisig_group_id` for group identity computation.
- **Scheme downgrade protection.** New `tx_extra_pqc_ownership` tag (0x05)
  records the expected PQC scheme and group ID for each output, preventing
  attackers from spending multisig-protected outputs with single-signer
  transactions.
- **Wallet multisig coordination.** New wallet2 methods for PQC multisig:
  `create_pqc_multisig_group`, `export_multisig_signing_request`,
  `sign_multisig_partial`, `import_multisig_signatures`. File-based JSON
  signing protocol. Wallet serialization version bumped to 32.
- **Cargo-fuzz harnesses.** 4 fuzz targets for multisig deserialization and
  verification (`fuzz_multisig_key_blob`, `fuzz_multisig_sig_blob`,
  `fuzz_multisig_verify`, `fuzz_group_id`), each validated at 10M iterations
  with zero panics.
- **PQC multisig subset-signing test.** Added `valid_subset_signing_3_of_5`
  test to `shekyl-crypto-pq` verifying that any valid 3-of-5 signer subset
  produces a valid multisig through the full 10-check verification pipeline.
- **PQC multisig test vectors.** Published
  `docs/PQC_TEST_VECTOR_002_MULTISIG.json` with canonical encoding sizes,
  wire-format sizes, verification pipeline checks, the 10-check pipeline,
  size regression data, and adversarial test cases for `scheme_id = 2`.
- **MSVC wallet-core build path**: `BuildRust.cmake` now selects the
  `x86_64-pc-windows-msvc` Rust target when CMake is driven by MSVC,
  enabling the Tauri GUI wallet to link against shekyl-core on Windows.
  The existing MinGW cross-compilation path for headless binaries is
  unchanged.
- **CI: Windows MSVC wallet-core job** (`build-windows-msvc`): New CI
  lane builds the wallet-core static libraries with Visual Studio / MSVC
  via vcpkg, validating the MSVC portability patches on every push.
- **Unified Gitian release pipeline.** The `gitian` workflow is now the sole
  release pipeline, replacing the separate `release-tagged` workflow. Gitian
  builds produce reproducible binaries; a new `package-and-publish` job
  creates `.deb`/`.rpm` packages, a Windows NSIS installer, source archive,
  and `SHA256SUMS`, then publishes the GitHub Release. Eliminates duplicate
  cross-compilation and host-toolchain issues.
- **Source archive in GitHub Releases.** The packaging job produces
  `shekyl-vX.Y.Z-source.tar.gz` containing the full source tree with all
  submodules, attached to each release alongside the binaries.

### 🔄 Changed

- **`shekyl_pqc_verify` FFI signature change.** Now requires `scheme_id` as
  first parameter for scheme dispatch.
- **`depends.yml` demoted to PR-only.** The cross-compilation CI workflow now
  runs only on pull requests (and manual dispatch), not on every push. Saves
  significant CI minutes; Gitian catches cross-platform issues at release time.
- **`release-tagged.yml` disabled.** The Gitian pipeline now handles all
  release artifacts. The old workflow is preserved as `.disabled` for one
  release cycle.
- **Gitian reproducible builds: migrated from Ubuntu 18.04 (Bionic) to 22.04
  (Jammy).** All five build descriptors (`gitian-linux.yml`, `gitian-win.yml`,
  `gitian-osx.yml`, `gitian-android.yml`, `gitian-freebsd.yml`),
  `gitian-build.py`, and `dockrun.sh` now target Jammy. Drops GCC 7 and
  Python 2 dependencies in favour of the distro-default GCC 11 and Python 3.
  Upgrades FreeBSD cross-compiler from Clang 8 to Clang 14. Removes
  Bionic-specific workarounds (i686 asm symlink hack, glibc `math-finite.h`
  hack). Adds `linux-libc-dev:i386` for native i686 headers. C++17 is now
  fully supported by the Gitian toolchain.

### 🐛 Fixed

- **Comprehensive compiler warning cleanup across all CI platforms.** Eliminated
  ~30 unique warnings inherited from Monero across Linux, macOS, Windows, and
  Arch Linux CI builds:
  - Removed dead code: `add_public_key` (format_utils), `keys_intersect`
    (wallet2), unused `addressof` template specialization (crypto test),
    unused `max_block_height` variable (protocol_handler).
  - Fixed `oaes_lib.c`: replaced deprecated `ftime()` with `gettimeofday()`,
    corrected transposed `calloc` argument order (5 call sites).
  - Fixed `rx-slow-hash.c`: added `(void)` to K&R-style function definitions.
  - Suppressed GCC false positive `-Wstringop-overflow` in `tree-hash.c`.
  - Replaced deprecated `strand::wrap()` with `boost::asio::bind_executor()`
    in `levin_notify.cpp`.
  - Suppressed GCC `-Wuninitialized` for safe circular-reference constructors
    in `cryptonote_core.cpp` and `long_term_block_weight.cpp`.
  - Added default member initializers to `BulletproofPlus` (rctTypes.h),
    `transfer_details` and `payment_details` (wallet2.h) to silence
    `-Wmaybe-uninitialized`.
  - Fixed Windows: removed unused variables in `windows_service.cpp`,
    eliminated `-Wcast-function-type` in `util.cpp` via `void*` intermediate
    cast, fixed `-Wtype-limits` in `utf8.h` by using `uint32_t` instead of
    `wint_t` for code points.
  - Suppressed intentional uninitialized read in `memwipe.cpp` test.
  - Set `MACOSX_DEPLOYMENT_TARGET` for native Darwin Cargo builds in
    `BuildRust.cmake` to eliminate 672 linker warnings from `ring` crate.
- **CI link errors: separated `shekyl-daemon-rpc` from `shekyl-ffi`.** The daemon
  RPC Axum crate was bundled into `libshekyl_ffi.a`, causing `undefined reference
  to core_rpc_ffi_*` on non-daemon targets (gen-ssl-cert, wallet-crypto-bench,
  etc.) across all 5 CI platforms. Moved FFI exports (`shekyl_daemon_rpc_start`,
  `shekyl_daemon_rpc_stop`) into a new `ffi_exports.rs` within the daemon-rpc
  crate, which now produces its own `libshekyl_daemon_rpc.a` staticlib. Only the
  daemon target links both libraries. `BuildRust.cmake` updated with a second
  cargo build step and `SHEKYL_DAEMON_RPC_LINK_LIBS`.
- **Wallet: `--daemon-port` help text referenced Monero port 18081.** Updated to
  Shekyl's default RPC port 11029.
- **Wallet: `account_public_address` equality after PQC.** Destination and
  change-address checks used `memcmp` on the whole struct; `m_pqc_public_key`
  is a `std::vector`, so equality was wrong when keys matched but allocations
  differed. All such sites now use `operator==` / `!=`. Added a
  `static_assert` that the type is not trivially copyable to discourage raw
  `memcmp` regressions.
- **Wallet / Ledger: constant-time comparison for 32-byte secrets.**
  `wallet2::is_deterministic` and Ledger HMAC secret lookup now use
  `crypto_verify_32` instead of `memcmp`.
- **MSVC: add `<io.h>` and POSIX guards in `util.cpp`.** Added `<io.h>`
  for `_open_osfhandle`/`_close`, expanded MinGW conditionals to cover
  MSVC for `setenv`→`putenv`, `mode_t`/`umask`, and `closefrom`→no-op.
- **MSVC: replace `__thread` with `thread_local` in `perf_timer.cpp` and
  `threadpool.cpp`.** GCC's `__thread` is not supported by MSVC.
- **MSVC: rename `xor` parameter in `slow-hash.c` to `xor_pad`.** MSVC
  treats `xor` as a reserved keyword in C mode. Both the x86/SSE and
  ARM/NEON variants of `aes_pseudo_round_xor()` were affected.
- **MSVC: fix iterator-to-pointer cast in `http_auth.cpp`.** MSVC
  `boost::as_literal()` iterator is a class, not a raw pointer. Used
  `&*data.begin()` to obtain the address.
- **MSVC: guard `unbound.h` include and usage in `util.cpp`.** The
  include and `unbound_built_with_threads()` function/call were not
  wrapped in `HAVE_DNS_UNBOUND`, causing a missing-header error.
- **MSVC: guard `unistd.h` in easylogging++.** The third-party logging
  library unconditionally included `<unistd.h>` which does not exist on
  MSVC.
- **MSVC: add `<io.h>` include for `_isatty` in `mlog.cpp`.** The WIN32
  code path uses `_isatty`/`_fileno` which require `<io.h>` on MSVC.
- **MSVC: fix `boost::iterator_range` conversion in `http_auth.cpp`.**
  Boost 1.90 `as_literal()` returns an iterator type that does not
  implicitly convert to `iterator_range<const char*>` on MSVC. Changed to
  `auto` deduction.
- **MSVC: add `<cwctype>` include for `std::towlower` in
  `language_base.h`.** MSVC does not transitively include wide-character
  utilities through other Boost headers.
- **MSVC: fix rvalue binding in portable_storage serialization.** Changed
  `array_entry_t::insert_first_val` and `insert_next_value` from strict
  rvalue-reference parameters (`t_entry_type&&`) to pass-by-value, allowing
  lvalue forwarding from `portable_storage::insert_first_value` /
  `insert_next_value` to work correctly under MSVC template deduction.
- **MSVC: force-include `<iso646.h>` for C++ alternative tokens.** The
  codebase uses `not`, `and`, `or` extensively (hundreds of sites). MSVC
  does not recognise these as keywords by default. Added `/FIiso646.h` to
  the MSVC compile definitions so they are defined in every translation
  unit.
- **MSVC: enable conformant preprocessor (`/Zc:preprocessor`).** MSVC's
  traditional preprocessor breaks nested `__VA_ARGS__` forwarding in the
  `THROW_ON_RPC_RESPONSE_ERROR` macro chain, causing `throw_wallet_ex`
  template deduction failures. Added `/Zc:preprocessor` to MSVC compile
  flags and removed the obsolete Boost.Preprocessor-based `throw_wallet_ex`
  fallback in favour of the standard variadic template version.
- **Gitian: enable `universe` repository and remove apt proxy in Docker base
  image.** The `ubuntu:jammy` Docker image only enables `main restricted` by
  default; `gitian-build.py` now patches the base image after `make-base-vm`
  to add `universe` and remove the `apt-cacher-ng` proxy configuration
  (`/etc/apt/apt.conf.d/50cacher`). The proxy routes all apt traffic through
  `172.17.0.1:3142` which is unreliable on ephemeral CI runners, causing
  persistent 503 failures during package installation. Uses `docker build`
  (not run+commit) to preserve the image's CMD/USER metadata.
- **Gitian Linux: fix i386-dependent package installation.** The i386
  architecture is now enabled in the Docker base image (via `gitian-build.py`'s
  `docker build` step) along with passwordless `sudo` for the `ubuntu` user,
  allowing `linux-libc-dev:i386`, `gcc-multilib`, and `g++-multilib` to be
  installed normally via the descriptor's `packages:` section.
- **Gitian macOS: add `libtinfo5` and `python-is-python3`, remove `python`
  from `FAKETIME_PROGS`.** The pre-built Clang 9 cross-compiler requires
  `libtinfo.so.5`. The `python` faketime wrapper broke CMake's
  `FindPythonInterp` version detection in the `native_libtapi` build (empty
  `PYTHON_VERSION_STRING`); removing `python` from the faketime wrappers
  fixes this while preserving timestamp reproducibility for `ar`, `ranlib`,
  `date`, `dmg`, and `genisoimage`.
- **Gitian Android: add `python-is-python3`.** Android NDK r17b scripts use
  `#!/usr/bin/env python` which does not exist on Jammy without this package.
- **Gitian macOS: fix Rust `ring` crate cross-compilation.** `BuildRust.cmake`
  incorrectly overrode the macOS cross-compiler with the Linux system `clang`
  when cross-compiling for Darwin, causing the `ring` crate to include
  Linux-only `cet.h`. Now only uses system clang on native macOS builds.
- **Gitian Windows: drop i686 (32-bit) target.** The i686-pc-windows-gnu Rust
  target has an unresolved `GetHostNameW@8` symbol against MinGW's `ws2_32`.
  Since the release workflow only targets x86_64, the 32-bit Gitian build is
  removed.
- **macOS cross-build: exclude `-fcf-protection=full`.** Intel CET is x86
  Linux only; the flag defines `__CET__` which triggers `#include <cet.h>` in
  the `ring` crate's assembly, but `cet.h` does not exist in the macOS SDK.
  Now excluded for all Apple targets.
- **macOS aarch64 cross-build: set `MACOSX_DEPLOYMENT_TARGET=10.16`.**
  Clang 9 (depends cross-compiler) does not recognise macOS version 11.0+.
  Apple aliases 10.16 == 11.0; the `cc-rs` crate respects this env var, fixing
  the `ring` build for `aarch64-apple-darwin`.
- **Gitian Docker base image: install `sudo` before creating sudoers entry.**
  The `/etc/sudoers.d/` directory does not exist in the minimal Ubuntu image
  until the `sudo` package is installed.

### 🔄 Changed

- **Replace all `BOOST_FOREACH` / `BOOST_REVERSE_FOREACH` with range-for
  loops.** 31+ call sites across test and utility code replaced with standard
  C++11 range-based for. Adds `/DNOMINMAX` to MSVC definitions to prevent
  Windows `min`/`max` macro collisions.
- **Replace hardcoded `-fPIC` with `POSITION_INDEPENDENT_CODE`.** The CMake
  property works across all compilers (GCC, Clang, MSVC). Applied to
  `liblmdb` and `easylogging++` CMakeLists.
- **Guard/remove unguarded `#include <unistd.h>`.** POSIX header guarded
  behind `#ifndef _WIN32` in `blockchain_import.cpp`; unused include removed
  from `crypto.cpp`.
- **Replace C++20 designated initializers with C++17-compatible member
  assignment.** Rewrote 10 call sites in `cryptonote_core.cpp`,
  `blockchain.cpp`, `levin_notify.cpp`, `multisig_tx_builder_ringct.cpp`, and
  `wallet2.cpp`. GCC/Clang accepted these as extensions; MSVC rejects them.
- **Replace all `__thread` with `thread_local`.** Covers `easylogging++.cc`,
  `perf_timer.cpp`, and `threadpool.cpp`. The `__thread` qualifier is
  GCC/Clang-specific; `thread_local` (C++11) is
  portable across GCC, Clang, and MSVC.
- **Centralize `ssize_t` typedef in `src/common/compat.h`.** Replaces
  duplicate `#if defined(_MSC_VER)` guards in `util.h` and `download.h`
  with a single include.

### 🗑️ Removed

- **Classical multisig code removed from wallet2.h.** Removed all classical
  Monero-style multisig types (`multisig_info`, `multisig_sig`,
  `multisig_kLR_bundle`, `multisig_tx_set`), public/private multisig API
  methods, multisig private members, MMS (message store) integration, and
  associated Boost serialization functions. The `src/multisig/` directory and
  `src/wallet/message_store.h` are deleted; `wallet2.h` no longer depends on
  those headers. All multisig uses PQC-only authorization (`scheme_id = 2`)
  via the `pqc_auth` layer.
- **Gitian Android build.** Removed from the Gitian matrix since there is no
  Android wallet. The Android NDK r17b is also incompatible with Ubuntu Jammy.
- **Gitian Linux: drop i686-linux-gnu (32-bit x86) target.** Eliminates the
  need for `linux-libc-dev:i386`, `gcc-multilib`, `g++-multilib`, `sudo`,
  and the `dpkg --add-architecture i386` workaround. Simplifies the Docker
  base image patching to only enable the `universe` repository.

### 📚 Documentation

- **`docs/RELEASING.md`: document all release artifacts.** Updated the
  artifact table to list all 13 files produced per release (was 6),
  including cross-platform tarballs, aarch64 `.deb`/`.rpm`, and source
  archive. Updated "Future Platforms" to reflect that macOS tarballs are
  now shipping and `.dmg`/AppImage remain planned.

## [3.0.3-RC1] - 2026-03-31

### Known Limitations

- **Multisig not yet implemented.** Multisig wallets are restricted to v2
  transactions (no PQC authentication). PQC-enabled multisig is planned for
  a future release. See `docs/PQC_MULTISIG.md` for the design.

### ✨ Added

- **Rust wallet RPC server (`shekyl-wallet-rpc`)**: New Rust crate that
  replaces the C++ `wallet_rpc_server` with an axum-based JSON-RPC server.
  Calls the existing C++ `wallet2` library through a new C FFI facade
  (`wallet2_ffi.cpp/.h`). Supports all 98 RPC methods with full parity.
  Can run as a standalone binary (`shekyl-wallet-rpc-rs`) or be embedded
  as a library in the Tauri GUI wallet. See `docs/WALLET_RPC_RUST.md`.

- **C++ wallet2 FFI facade (`wallet2_ffi.cpp/.h`)**: Opaque-handle C API
  over `wallet2` with JSON serialization at the boundary. Includes a
  generic `wallet2_ffi_json_rpc()` dispatcher that routes all RPC methods
  to the underlying wallet2 implementation. Covers lifecycle, queries,
  transfers, sweeps, proofs, accounts, address book, import/export,
  multisig, staking, mining, background sync, and daemon management.

- **GUI wallet direct FFI integration**: The Tauri GUI wallet now calls
  wallet2 directly through the Rust FFI bridge (`wallet_bridge.rs`)
  instead of spawning a child `shekyl-wallet-rpc` process and
  communicating via HTTP. Eliminates process management, port allocation,
  and HTTP overhead. Removed `wallet_process.rs` and `wallet_rpc.rs`.

### v3-First Core Test Adaptation

- **Enforced min_tx_version=3 for non-coinbase transactions**: All user
  transactions in the test suite now construct v3 with PQC authentication
  (hybrid Ed25519 + ML-DSA-65). Coinbase transactions remain v2.
- **Adapted chaingen framework for RCT-from-genesis**: Transaction
  construction helpers (`construct_tx_to_key`, `construct_tx_rct`) thread
  `hf_version=1` and `use_view_tags=true`. Coinbase outputs are indexed
  under `amount=0` for correct RCT spending. Fixed difficulty is injected
  for FAKECHAIN replay. Mixin checks are relaxed for FAKECHAIN.
- **Added RCT-aware balance verification**: Pool transaction balance checks
  in `gen_chain_switch_1` now decrypt ecdhInfo amounts using the recipient's
  view key instead of relying on the plaintext `o.amount` field (always 0
  for RCT outputs).
- **Recalibrated economic constants for Shekyl**: Test constants
  (`TESTS_DEFAULT_FEE`, `FIRST_BLOCK_REWARD`, `MK_COINS`) match Shekyl's
  `COIN = 10^9`, `EMISSION_SPEED_FACTOR = 21`, and staker/burn splits.
  `construct_miner_tx_manually` in block validation tests uses Shekyl's
  reward distribution.
- **Fixed Bulletproofs+ test suite**: Dynamically discover miner output
  amounts, set HF to 1 for all block construction, correctly flag coinbase
  outputs as RCT. All 15 BP+ tests pass.
- **Fixed txpool tests**: Adjusted key image count assertions for
  multi-input RCT transactions and corrected unlock_time handling.
- **Fixed double-spend tests**: Modified output selection to pick the
  largest decomposed output, avoiding underflow on fee subtraction.
- **Disabled legacy-incompatible tests**: `gen_block_invalid_binary_format`
  (hours-long), `gen_block_invalid_nonce`, `gen_block_late_v1_coinbase_tx`,
  `gen_uint_overflow_1`, `gen_block_reward`,
  `gen_bpp_tx_invalid_before_fork`, `gen_bpp_tx_invalid_clsag_type`,
  `gen_ring_signature_big`. These rely on pre-RCT economics, legacy
  fork transitions, or are prohibitively slow.
- **All 79 core_tests pass with 0 failures.**

### Test suite cleanup for Shekyl HF1

- **Removed 96 dead Borromean ringct tests**: All tests in
  `tests/unit_tests/ringct.cpp` that exercised legacy Borromean range
  proofs were removed. Shekyl HF1 rejects Borromean proofs at the
  `genRctSimple` level. Retained 9 non-Borromean tests (CLSAG, HPow2,
  d2h, d2b, key_ostream, zeroCommit, H, mul8).
- **Updated transaction construction helpers to Bulletproofs+**: The
  `test::make_transaction` helper (used by JSON serialization and ZMQ
  tests) now constructs transactions with
  `{ RangeProofPaddedBulletproof, 4 }` (BP+/CLSAG) instead of the
  removed Borromean or unsupported BP v2 configs. Removed the obsolete
  `bulletproof` parameter. Consolidated three JSON serialization tests
  (RegularTransaction, RingctTransaction, BulletproofTransaction) into
  one `BulletproofPlusTransaction` test. Fixes all 8 zmq_pub/zmq_server
  test failures.
- **Updated serialization round-trip test to BP+**: Changed
  `Serialization.serializes_ringct_types` from `bp_version 2` (throws
  "Unsupported BP version") to `bp_version 4` (Bulletproofs+). Updated
  assertions from MGs to CLSAGs and from `bulletproofs` to
  `bulletproofs_plus`.
- **Removed legacy Monero-era core/perf test executions**: Stopped running
  deprecated Borromean/pre-RCT/fork-transition test generators in
  `core_tests` and removed Borromean/MLSAG/range-proof performance test
  invocations and defaults, so CI validates HF1-era behavior only.
- **Hardened block-weight test contract for HF1 semantics**: `block_weight`
  comparison now enforces deterministic `H/BW/LTBW` parity and EMBW floor
  invariants instead of byte-identical legacy model output, preventing
  false failures from non-consensus median implementation details.
- **Fixed block_reward test expected values**: Updated emission curve
  expectations to match Shekyl's `EMISSION_SPEED_FACTOR = 21` (120s
  blocks) and per-block tail floor of
  `FINAL_SUBSIDY_PER_MINUTE * target_minutes`.
- **Rewrote mining_parity release multiplier test**: Replaced legacy
  pre-Shekyl-NG equality assertion (which tested a non-existent version
  0) with a test that verifies the release multiplier correctly scales
  rewards above and below the tx volume baseline.
- **Fixed Ubuntu 24.04 CI test runner**: Replaced `pip install` with
  `apt install python3-*` packages to comply with PEP 668
  (externally-managed-environment).

### 🐛 Fixed

- **macOS cross-compilation (depends CI)**: Fixed multiple build failures
  for Cross-Mac x86_64 and Cross-Mac aarch64 targets:
  - Raised macOS minimum deployment target from 10.8 (Mountain Lion, 2012)
    to 10.15 (Catalina, 2019) to enable `std::filesystem` support in the
    cross-compiled libc++.
  - Fixed Boost discovery in depends builds by setting `Boost_NO_BOOST_CMAKE`
    and forcing MODULE mode, preventing `BoostConfig.cmake` variant-check
    failures on cross-compiled Darwin libraries.
  - Made `boost_locale` a conditional dependency (Windows only), since it
    is only used within `#ifdef WIN32` blocks and was unavailable for
    Darwin cross-builds.
  - Added per-target `CC_<triple>/AR_<triple>/CFLAGS_<triple>` environment
    variables in `BuildRust.cmake` so the `ring` crate can locate the
    cross-compiler for C/assembly code.
  - Used system clang (instead of the depends-bundled Clang 9) for Rust
    crate C compilation on Darwin, since `ring` 0.17 requires clang
    features unavailable in Clang 9 (macOS 11 version strings,
    `-fno-semantic-interposition`).
  - Guarded `-fno-semantic-interposition` behind `check_c_compiler_flag()`
    so it is only added when the compiler supports it (Clang 9 does not).
  - Fixed OSX SDK cache key in `depends.yml` to include the SDK version
    and skip the cache step for non-macOS builds.

- **FreeBSD cross-compilation (depends CI)**: Fixed multiple build failures
  for the x86_64 FreeBSD target:
  - Switched Boost's b2 toolset from `gcc` to `clang` for FreeBSD, fixing
    C++ standard library header resolution (`<cstddef>` not found).
  - Embedded `-stdlib=libc++` in the FreeBSD clang++ wrapper script so all
    depends packages automatically use the correct C++ standard library,
    regardless of whether their own `$(package)_cxxflags` overrides the
    host flags (previously broke zeromq, sodium, and other packages).
  - Fixed compiler wrapper argument quoting: replaced the broken
    `echo "...$$$$""@"` pattern with `printf '..."$$$$@"'` so `"$@"`
    passes through correctly to the generated wrapper, preventing argument
    mangling for flags containing quotes (e.g. `-DPACKAGE_VERSION="1.0.20"`).
  - Added `-D_LIBCPP_ENABLE_CXX17_REMOVED_UNARY_BINARY_FUNCTION` to both
    Boost's FreeBSD cxxflags and the CMake toolchain, restoring
    `std::unary_function` compatibility needed by Boost 1.74's
    `container_hash/hash.hpp` under FreeBSD's strict C++17 libc++.
  - Removed the unsupported `no-devcrypto` option from OpenSSL's FreeBSD
    configure flags (the devcrypto engine was removed in OpenSSL 3.0).
  - Added `threadapi=pthread runtime-link=shared` to Boost's FreeBSD
    config options for correct threading and linking behavior.

- **Linux static release build (libudev linking)**: Added `libudev-dev` to
  the `release-tagged.yml` CI package list. Static `libusb-1.0.a` and
  `libhidapi-libusb.a` depend on `libudev` for USB hotplug support;
  without the dev package installed, `find_library(udev)` failed and the
  final link produced undefined `udev_*` references, preventing the
  "Publish GitHub Release" step from running.
- **Win64 build failure (ICU generator expression)**: Replaced broken CMake
  generator expressions `$<$<BOOL:${WIN32}>:${ICU_LIBRARIES}>` with
  `if(WIN32)` blocks in `simplewallet`, `wallet_api`, and
  `libwallet_api_tests` CMakeLists. Generator expressions cannot contain
  semicolon-separated lists; the old pattern passed literal fragments like
  `$<1:icuio` to the linker on MinGW cross-compilation.
- **Linux static build (libunbound linking)**: Fixed `FindUnbound.cmake`
  scoping bug where `list(APPEND UNBOUND_LIBRARIES ...)` created a local
  variable shadowing the `find_library` cache entry. The transitive static
  deps (libevent, libnettle, libhogweed, libgmp) were silently dropped,
  causing undefined reference errors in `release-static-linux-x86_64`
  builds.
- **JSON serialization of v3 (PQC) transactions**: Added missing
  `pqc_auth` field to the RapidJSON `toJsonValue`/`fromJsonValue`
  roundtrip for `cryptonote::transaction`. V3 transactions created
  under `HF_VERSION_SHEKYL_NG` include a `pqc_authentication`
  envelope; without JSON support the field was silently dropped,
  causing `get_transaction_hash` to fail with "Inconsistent
  transaction prefix, unprunable and blob sizes" after a JSON
  roundtrip. Fixes the `JsonSerialization.BulletproofPlusTransaction`
  unit test failure.

### GUI Wallet

- New project: Shekyl GUI Wallet (`shekyl-gui-wallet`) at
  [Shekyl-Foundation/shekyl-gui-wallet](https://github.com/Shekyl-Foundation/shekyl-gui-wallet).
  Built with Tauri 2 (Rust backend) + Vite + React 19 + TypeScript + Tailwind CSS 4.
  Initial scaffold includes 6 pages (Dashboard, Send, Receive, Staking,
  Transactions, Settings), stub Tauri commands, Shekyl gold/purple design system,
  and verified production builds for Linux (.deb, .rpm, .AppImage).
  Phase 2 will add the C++ FFI bridge to `wallet2_api.h` for real wallet operations.
- Added testing infrastructure: Vitest + React Testing Library for frontend
  (20 tests across 6 suites), cargo test for Rust backend (10 tests), with
  Tauri IPC mocking for isolated component testing.
- Added CI/CD via GitHub Actions: `ci.yml` runs ESLint, TypeScript type-check,
  Vitest, Rustfmt, Clippy, and cargo test on every PR; `release.yml` builds
  multi-platform binaries (Linux x64, Windows x64, macOS ARM64 + Intel) via
  `tauri-action` and creates draft GitHub releases.

### Consensus timing alignment (HF1)

- Fixed remaining runtime paths that still derived timing from legacy `DIFFICULTY_TARGET_V1` (`60s`) so active Shekyl HF1 behavior consistently uses `DIFFICULTY_TARGET_V2` (`120s`) for difficulty target selection, block reward minute-scaling, unlock-time leeway checks, sync ETA reporting, and wallet lock-time display.
- Updated `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` to mark the 120s block-time drift item as resolved (`code_fix_required` completed).

### 📚 Documentation

- Updated `docs/V3_ROLLOUT.md` to reflect HF1 (genesis) activation instead
  of the stale HF17 references. Added v3-first test strategy section.
- Updated `docs/POST_QUANTUM_CRYPTOGRAPHY.md` scheme_id status table and
  deferred-items section from HF17 to HF1.
- Updated `docs/PQC_MULTISIG.md` V3 signature list heading from HF17 to HF1.
- Updated `docs/STAKER_REWARD_DISBURSEMENT.md` to reference HF1 activation.
- Updated `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` HF naming drift label
  from `doc_correction` to resolved.
- Added `core_tests` section to `docs/COMPILING_DEBUGGING_TESTING.md`
  documenting the v3-from-genesis test approach and how to run/filter tests.

### Genesis initialization compatibility

- Regenerated `GENESIS_TX` for mainnet, testnet, and stagenet to modern coinbase format (`tx.version = 2`) with tagged outputs.
- Removed all legacy genesis compatibility exceptions and enforced strict coinbase version checks (`tx.version > 1`) across all network types, including `FAKECHAIN`.
- Fixed genesis reward validation to accept the hardcoded `GENESIS_TX` amount at `height == 0` while leaving post-genesis reward accounting unchanged.
- Fixed startup edge case where long-term weight median calculations could evaluate with zero historical blocks during genesis initialization (`count == 0`), causing daemon boot failure on empty data dirs.
- Updated genesis-construction helper (`build_genesis_coinbase_from_destinations`) to emit `tx.version = 2` with view-tagged outputs for current HF1 expectations.
- Added canonical root build command `make genesis-builder` (using the main release build dir with `GENESIS_TOOL_SRC_DIR`) to avoid split/ambiguous genesis-builder binaries across multiple build trees.

### Testnet economy readiness checks

- Added `docs/ECONOMY_TESTNET_READINESS_MATRIX.md` to track design-vs-code status for economy testnet rehearsal with explicit drift tags (`doc_correction`, `code_fix_required`, `needs_decision`).
- Added `scripts/check_testnet_genesis_consensus.py` to verify multi-node testnet tuple consistency (`height 0 block hash`, `miner tx hash`, `tx hex`) and optional economy field presence in `get_info`.
- Added Rust parity/invariant tests:
  - `shekyl-economics-sim`: validates `SimParams::default()` against `config/economics_params.json`.
  - `shekyl-economics`: added release monotonicity, burn bounds, and emission-share monotonicity tests.
  - `shekyl-ffi`: added direct FFI-vs-Rust consistency tests for burn pct and emission share.
- Added functional RPC test `tests/functional_tests/economy_info.py` and included it in `functional_tests_rpc.py` default test list to assert required economy fields are exposed by `get_info`.
- Corrected documentation errors without changing design intent:
  - Clarified `DESIGN_CONCEPTS.md` Section 2 as historical baseline.
  - Removed duplicate heading in `GENESIS_TRANSPARENCY.md`.
  - Linked `RELEASE_CHECKLIST.md` testnet section to the rehearsal runbook/checklist and deterministic tuple check command.

### BREAKING: Second-pass rebrand (wallet, URI, serialization)

- **URI scheme**: Wallet URI generation and parsing now use `shekyl:` only.
  The legacy `monero:` scheme is no longer accepted. QR codes and payment
  links generated by previous builds will fail to parse. Regenerate all
  payment URIs before upgrading wallets.
- **Wallet/export/cache magic strings**: All file-format magic prefixes have
  been rewritten from `Monero` to `Shekyl`:
  - `UNSIGNED_TX_PREFIX` → `"Shekyl unsigned tx set\005"`
  - `SIGNED_TX_PREFIX` → `"Shekyl signed tx set\005"`
  - `MULTISIG_UNSIGNED_TX_PREFIX` → `"Shekyl multisig unsigned tx set\001"`
  - `KEY_IMAGE_EXPORT_FILE_MAGIC` → `"Shekyl key image export\003"`
  - `MULTISIG_EXPORT_FILE_MAGIC` → `"Shekyl multisig export\001"`
  - `OUTPUT_EXPORT_FILE_MAGIC` → `"Shekyl output export\004"`
  - `ASCII_OUTPUT_MAGIC` → `"ShekylAsciiDataV1"`
  - Wallet cache magic → `"shekyl wallet cache"`
  Old wallet caches, exported key images, multisig exports, signed/unsigned
  tx sets, and output exports are **incompatible** and must be re-exported
  after upgrading.
- **Message signing domain**: `HASH_KEY_MESSAGE_SIGNING` changed from
  `"MoneroMessageSignature"` to `"ShekylMessageSignature"`. Messages signed
  with the old domain separator will fail verification.
- **i18n domain**: Translation catalogue domain changed from `"monero"` to
  `"shekyl"`.
- **Daemon stdout redirect**: Daemonized output file changed from
  `bitmonero.daemon.stdout.stderr` to `shekyl.daemon.stdout.stderr`.
- **Log file names**: All blockchain utility log files renamed from
  `monero-blockchain-*` to `shekyl-blockchain-*`.
- **DNS seed/checkpoint domains**: Replaced `moneroseeds.*` and
  `moneropulse.*` lookups with 5-domain consensus set: `shekyl.org`,
  `shekyl.net`, `shekyl.com`, `shekyl.biz`, `shekyl.io`. Majority
  threshold is 3 of 5. See `shekyl-dev/docs/DNS_CONFIG.md` for the full
  infrastructure reference.
- **Update check**: Software name comparison for macOS `.dmg` extension
  switched from `monero-gui` to `shekyl-gui`.
- **Hardware wallet**: Ledger app error message now references "Shekyl Ledger
  App" instead of "Monero Ledger App". Trezor protobuf namespaces are
  unchanged (third-party protocol dependency).
- **Intentionally preserved**: Trezor/Ledger protobuf includes and protocol
  namespaces (`hw.trezor.messages.monero.*`), Esperanto mnemonic word
  `"monero"` (means "money"), academic paper citations, copyright headers,
  `MONERO_DEFAULT_LOG_CATEGORY` build-internal macros, and `MakeCryptoOps.py`
  build artifacts.

#### Operator migration checklist

1. Delete old wallet cache files (`.keys` files are unaffected).
2. Re-export any key-image, multisig, or output export files.
3. Re-export and re-sign any unsigned/signed transaction sets.
4. Regenerate all `monero:` QR codes/payment URIs as `shekyl:` URIs.
5. Update any scripts or integrations that parse URI scheme or file magic.
6. Verify message signatures were not created with the old signing domain.
7. Update log rotation configs if they reference `monero-blockchain-*` paths.
8. Update DNS infrastructure to serve records under all 5 TLDs (`.org`,
   `.net`, `.com`, `.biz`, `.io`). See `shekyl-dev/docs/DNS_CONFIG.md`.

### Dead Monero legacy code removal

- **Dead HF branch cleanup**: Collapsed all always-true / always-false hard fork
  version branches across `blockchain.cpp` (~25 sites), `wallet2.cpp` (~22 sites),
  `cryptonote_basic_impl.cpp` (2 sites), and `cryptonote_core.cpp` (2 sites).
  Since all `HF_VERSION_*` constants are 1, every `hf_version >= HF_VERSION_*`
  was always true and every `hf_version < HF_VERSION_*` was always false.
  Collapsed fee algorithms, ring size ladders, tx version ladders, difficulty
  target selection, sync block size selection, BP/CLSAG/BP+ gating, dynamic
  fee scaling, long-term block weight calculations, and `use_fork_rules()` call
  sites. Removed ~500-800 lines of dead conditional logic.

- **Dropped v1 transaction support entirely**:
  - **Consensus**: `check_tx_outputs` now rejects `tx.version == 1` outright.
    `check_tx_inputs` sets `min_tx_version = 2` unconditionally; unmixable
    output counting and ring-size exemptions removed. v1 ring signature
    verification code and threaded v1 signature checking removed from
    `check_tx_inputs`. `expand_transaction_2` only handles CLSAG and
    BulletproofPlus; old RCTTypeFull/Simple/Bulletproof/Bulletproof2 branches
    removed.
  - **RingCT** (`rctSigs.cpp`/`.h`): Removed ~770 lines of dead crypto code:
    `genBorromean`, `verifyBorromean`, `MLSAG_Gen`, `MLSAG_Ver`, `proveRange`,
    `verRange`, `proveRctMG`, `proveRctMGSimple`, `verRctMG`, `verRctMGSimple`,
    `populateFromBlockchain`, `genRct` (both overloads), `verRct`, `decodeRct`
    (both overloads). `genRctSimple`, `verRctSemanticsSimple`,
    `verRctNonSemanticsSimple`, and `decodeRctSimple` only accept
    `RCTTypeCLSAG` and `RCTTypeBulletproofPlus`. Header reduced from 144 to
    87 lines.
  - **Transaction construction** (`cryptonote_tx_utils.cpp`): Removed v1
    ring signature generation block and non-simple RCT construction
    (`genRct`). All transactions now use `genRctSimple` (CLSAG path).
  - **Tx verification utils**: Removed `RCTTypeSimple`, `RCTTypeFull`,
    `RCTTypeBulletproof`, `RCTTypeBulletproof2` from batch semantics
    verification.
  - **Test fixups**: Updated all test files under `tests/` to match the
    removed RCT primitives. Stubbed performance benchmarks for MLSAG
    (`rct_mlsag.h`, `sig_mlsag.h`) and Borromean range proofs
    (`range_proof.h`). Replaced `verRct` with `verRctNonSemanticsSimple`
    in `check_tx_signature.h`. Removed `decodeRct` else-branches from
    `rct.cpp`, `rct2.cpp`, `bulletproofs.cpp`, `bulletproof_plus.cpp`.
    In `unit_tests/ringct.cpp`: removed Borromean, MLSAG, and
    RCTTypeFull-only tests; rewrote `make_sample_rct_sig` to use
    `genRctSimple`; replaced all `verRct` calls with `verRctSimple`.

- **Wallet v1 cleanup**: Removed unmixable sweep functions, v1 fee/amount
  paths, v1 coinbase optimization, dead non-RCT creation branches, and
  replaced `RangeProofBorromean` defaults with `RangeProofPaddedBulletproof`.
  `sweep_dust` RPC returns error; `createSweepUnmixableTransaction` API
  returns empty result with error status.

- **Trezor Shekyl rebrand**: Renamed all include guard macros from
  `MONERO_*_H` to `SHEKYL_*_H` in 8 `device_trezor/` headers. Updated
  derivation path comment and HTTP Origin URL. Protobuf message types and
  wire protocol identifiers intentionally preserved (must match Trezor
  firmware definitions).

### Epee Phase 1: Rust replacement for security-critical primitives

- **SSL certificate generation migrated to Rust (`rcgen`)**: Replaced the
  deprecated OpenSSL RSA/EC_KEY certificate generation in `net_ssl.cpp` with
  Rust's `rcgen` crate (ECDSA P-256) via FFI. Eliminates all `RSA_new`,
  `RSA_generate_key_ex`, `EC_KEY_new`, `EC_KEY_generate_key`, and other
  OpenSSL 3.0-deprecated API calls. The `create_rsa_ssl_certificate` and
  `create_ec_ssl_certificate` functions are replaced by a single
  `create_ssl_certificate` that delegates to `shekyl_generate_ssl_certificate`
  in the Rust FFI, returning PEM-encoded key+cert for loading into OpenSSL's
  SSL_CTX via non-deprecated BIO APIs.
- **Post-quantum hybrid key exchange enabled**: TLS context configuration now
  prefers `X25519MLKEM768` (FIPS 203 ML-KEM-768 hybrid) key exchange groups,
  falling back to classical `X25519:P-256:P-384` when the OpenSSL build lacks
  PQ support. Also added explicit TLS 1.3 ciphersuite configuration. Removed
  deprecated `SSL_CTX_set_ecdh_auto` call.
- **Secure memory wiping migrated to Rust (`zeroize`)**: Replaced the
  platform-specific `memwipe.c` implementation (memset_s / explicit_bzero /
  compiler-barrier fallback) with a single call to the Rust `zeroize` crate
  via `shekyl_memwipe` FFI. The `zeroize` crate uses `write_volatile` which
  is guaranteed not to be optimized away, replacing the fragile compiler
  barrier tricks.
- **Memory locking migrated to Rust (`libc`)**: Replaced the GNUC-only
  `mlock`/`munlock`/`sysconf` calls in `mlocker.cpp` with Rust FFI functions
  (`shekyl_mlock`, `shekyl_munlock`, `shekyl_page_size`) backed by the `libc`
  crate. Adds Windows `VirtualLock`/`VirtualUnlock` support that was
  previously missing (`#warning Missing implementation`). The `mlocked<T>` and
  `scrubbed<T>` C++ template wrappers are preserved unchanged.
- **New Rust FFI dependencies**: Added `rcgen = "0.14"`, `zeroize = "1"`,
  `libc = "0.2"` to `shekyl-ffi/Cargo.toml`.
- **C-compatible FFI header**: Added `src/shekyl/shekyl_secure_mem.h` with
  C-linkage declarations for the secure memory primitives, usable from both
  C (`memwipe.c`) and C++ (`mlocker.cpp`) translation units.
- **CMake wiring**: `epee` library now links `${SHEKYL_FFI_LINK_LIBS}` and
  includes `${CMAKE_SOURCE_DIR}/src` for the FFI headers.

### Build fixes

- **Boost CONFIG-mode compatibility shim**: When Boost is found via cmake
  CONFIG mode (Boost 1.85+), old-style `${Boost_XXX_LIBRARY}` variables may
  resolve to versioned `.so` paths that don't exist on rolling-release distros
  (e.g. Arch Linux with Boost 1.90). Added a shim in the root `CMakeLists.txt`
  that remaps all `Boost_*_LIBRARY` variables to `Boost::*` imported targets
  when CONFIG mode is active. Fixes linker failures on Arch.
- **Removed duplicate `parse_amount` test**: Two identical
  `TEST_pos(18446744073709551615, ...)` entries in
  `tests/unit_tests/parse_amount.cpp` caused a redefinition error on macOS
  Clang. Removed the duplicate.
- **Boost CONFIG-mode validation**: Added a cmake-configure-time check that
  verifies Boost imported-target `IMPORTED_LOCATION` files exist on disk.
  Gives a clear `FATAL_ERROR` with remediation steps instead of a cryptic
  linker failure minutes into the build.
- **Arch Linux CI**: Added `boost-libs` to the Arch pacman install to
  provide shared `.so` files alongside the `boost` headers/cmake-config
  package.
- **Ubuntu 24.04 test matrix**: Added Ubuntu 24.04 to the `test-ubuntu`
  CI matrix (previously only 22.04 was tested).

### Depends system updates

- **FreeBSD sysroot updated to 14.4-RELEASE**: The cross-compilation
  sysroot was stuck at FreeBSD 11.3 (EOL Sept 2021), whose `base.txz`
  had been removed from FreeBSD mirrors (404). Updated to 14.4-RELEASE
  (March 2026), updated SHA256 hash, and fixed clang wrapper scripts
  from clang-8 to clang-14 to match `hosts/freebsd.mk`. Added
  `-stdlib=libc++` to CXXFLAGS and LDFLAGS since FreeBSD uses libc++
  and the Ubuntu host's clang-14 defaults to libstdc++. Also added
  `libc++-14-dev` and `libc++abi-14-dev` to CI packages for the FreeBSD
  cross-build so the host compiler can find libc++ headers when
  `-stdlib=libc++` is specified.
- **Boost: skip CONFIG mode for depends builds**: The depends-built Boost
  1.74.0 installs CMake config files whose variant detection fails for
  darwin cross-builds (`boost_locale` reports "No suitable build variant").
  `find_package(Boost ... CONFIG)` is now skipped when `DEPENDS` is true
  (set by the depends toolchain), falling back to the more robust MODULE
  mode (`FindBoost.cmake`).
- **OpenSSL: disabled `devcrypto` engine for FreeBSD**: Added
  `no-devcrypto` to FreeBSD OpenSSL configure options. The `/dev/crypto`
  engine requires the `crypto/cryptodev.h` kernel header which is not
  available in a cross-compilation sysroot.
- **libsodium updated to 1.0.20**: The 1.0.18 tarball was removed from
  `download.libsodium.org` (404). Updated to 1.0.20 with new SHA256 hash.
  Removed the 1.0.18-specific patches (`fix-whitespace.patch`,
  `disable-glibc-getrandom-getentropy.patch`) which no longer apply.

### Warning cleanup and dead code removal

- **Removed dead fork helpers**: Deleted unused `get_bulletproof_fork()`,
  `get_bulletproof_plus_fork()`, and `get_clsag_fork()` from `wallet2.cpp`.
  These Monero-era version ladders had no call sites; Shekyl activates all
  features from HF1.
- **Removed dead variable**: Deleted unused `bool refreshed` in
  `wallet2::refresh()`.
- **Removed legacy `result_type` typedefs**: Deleted `using result_type = void`
  from `add_input` and `add_output` visitor structs in `json_object.cpp`. These
  were required by `boost::static_visitor` but are unused by `std::visit`.
- **Fixed uninitialized-variable warning**: Zero-initialized `local_blocks_to_unlock`
  and `local_time_to_unlock` in `wallet2::unlocked_balance_all()`.
- **Fixed aliasing cast in wallet serialization**: Replaced C-style cast of
  `m_account_tags` from `pair<serializable_map, vector>` to `pair<map, vector>&`
  with direct `.parent()` accessor, eliminating formal undefined behavior.
- **Suppressed epee warnings**: Added targeted `#pragma GCC diagnostic` guards
  for `-Wclass-memaccess` (memcpy into `mlocked<scrubbed<>>` in
  `keyvalue_serialization_overloads.h`) and `-Wstring-compare` (type_info
  comparisons in `portable_storage.h`).
- **Renamed test target**: `monero-wallet-crypto-bench` renamed to
  `shekyl-wallet-crypto-bench`.
- **Trezor Protobuf fixes**: Added `std::string()` wrapping for
  `GetDescriptor()->name()` calls in `messages_map.cpp/.hpp` to handle
  Protobuf 22+ returning `absl::string_view`/`std::string_view`. Added
  missing `<cstdint>` include to `exceptions.hpp`.

### Rust crypto infrastructure

- **New `shekyl-crypto-hash` crate**: Implements `cn_fast_hash` (Keccak-256
  with original padding, not SHA3) and `tree_hash` (Merkle tree) in Rust
  using `tiny-keccak`. Both functions produce byte-identical output to the
  C implementations in `src/crypto/hash.c` and `src/crypto/tree-hash.c`.
- **FFI exports**: `shekyl_cn_fast_hash` and `shekyl_tree_hash` exposed
  through `shekyl-ffi` with C-ABI declarations in `shekyl_ffi.h`. The C++
  side can now call Rust hashing alongside or instead of the C path.
- **Rust-preferred development rule**: Added `.cursor/rules/rust-preferred.mdc`
  establishing policy for gradual C++ to Rust migration: new modules in Rust,
  crypto primitives via RustCrypto crates, computational extraction to Rust
  behind FFI when modifying existing C++ modules.

### Hardfork reboot and testnet wallet readiness

- **Hardfork schedule rebooted**: All `HF_VERSION_*` constants collapsed to 1.
  The chain starts with all features active from genesis -- no legacy migration
  gates. Hardfork tables reduced to single-entry `{ 1, 1, 0, timestamp }` for
  all three networks (mainnet, testnet, stagenet).
- Removed all raw numeric HF version gates (`hf_version <= 3`, `>= 7`, `< 8`,
  `> 8`, etc.) from consensus and transaction construction code, replacing them
  with named `HF_VERSION_*` constants. Legacy Monero-era transition logic
  (borromean proofs, bulletproofs v1, grandfathered txs) removed.
- Coinbase transactions always v2 RCT with single output, zero dust threshold.
- **Staked outputs excluded from spendable balance**: `is_transfer_unlocked()`
  now returns false for staked outputs, preventing them from being selected
  during normal transfers. `balance_per_subaddress` and
  `unlocked_balance_per_subaddress` skip staked outputs.
- **Unstake transaction fixed**: `create_unstake_transaction` now passes matured
  staked output indices directly to `create_transactions_from`, properly using
  the actual staked UTXOs as transaction inputs with standard ring signatures.
- **Claim reward validation fixed**: `check_stake_claim_input` now looks up the
  real staked output from the blockchain DB to get the actual amount and tier,
  replacing the hardcoded `shekyl_stake_weight(0, 0)` placeholder.
- **New daemon RPC `estimate_claim_reward`**: computes per-output reward
  server-side using the accrual database, returning reward amount, tier, and
  staked amount. Wallet `estimate_claimable_reward` now calls this RPC instead
  of returning a hardcoded zero.
- **CLI improvements**: `balance` command now shows staked balance alongside
  liquid and unlocked balances. New `staking_info` command shows wallet staking
  overview (locked/matured output counts with tier and remaining lock blocks).
  `stake`, `unstake`, and `claim_rewards` commands now include daemon
  connectivity guards.
- **Wallet RPC fixes**: `unstake` response changed from single `tx_hash` to
  `tx_hash_list` array to support multi-transaction unstaking. `stake` request
  now accepts `account_index` parameter. New `get_staked_balance` RPC returns
  staked balance with locked/matured output counts.

### Post-quantum cryptography

- **Phase 4 wallet/core PQC wiring completed**: all v3 transaction construction
  paths now include hybrid Ed25519 + ML-DSA-65 signing via `pqc_auth`. Fixed
  `create_claim_transaction` (staking reward claims) which previously built v3
  transactions without PQC authentication, causing consensus rejection.
- PQC verification enforced in both mempool acceptance and block validation for
  all non-coinbase v3 transactions.
- Multisig wallets intentionally restricted to v2 transactions (no PQC); the
  PQC secret key is cleared on multisig creation with a documented design note.
- Aligned `POST_QUANTUM_CRYPTOGRAPHY.md` field naming: `hybrid_ownership_material`
  renamed to `hybrid_public_key` to match the canonical code implementation.
- Added three negative PQC test vectors (`docs/PQC_TEST_VECTOR_002–004`) covering
  tampered ownership material, wrong scheme_id, and oversized/truncated signature
  blobs. Each vector is generated and verified by integration tests in
  `rust/shekyl-crypto-pq/tests/negative_vectors.rs`.
- Reconciled `POST_QUANTUM_CRYPTOGRAPHY.md` Open Items: resolved Rust crate
  selection, `RctSigningBody` layout, ownership binding, and max tx size;
  only `scheme_id` registry extension remains open.
- Added tentative V4 PQC Privacy Roadmap to `POST_QUANTUM_CRYPTOGRAPHY.md`
  with four phases (V4-A Research, V4-B Prototype, V4-C Testnet,
  V4-D Activation) and explicit KEM composition decision milestone
  (`X25519 + ML-KEM-768` via `HKDF-SHA-512`).
- Added payload limit guidance section to `V3_ROLLOUT.md` with recommended
  minimum mempool/ZMQ/relay buffer sizes for post-PQC transactions.

### Economics and simulation

- Added `rust/shekyl-economics-sim` workspace crate: reproducible 8-scenario
  simulation harness driven from `config/economics_params.json`. Scenarios
  cover baseline, boom-bust, sustained growth, stuffing attack, stake
  concentration, mass unstaking, chain bootstrap, and late-chain tail state.
  Results archived in `docs/economics_sim_results.json`.
- Provisionally locked `tx_baseline` (50) and `FINAL_SUBSIDY_PER_MINUTE`
  (300,000,000) in `DESIGN_CONCEPTS.md` after simulation validation; pending
  final testnet confirmation.
- Wired live chain-health RPC fields in `get_info`: `release_multiplier` now
  computed from rolling `tx_volume_avg`, `burn_pct` from current chain state,
  `total_burned` persisted in LMDB and accumulated per block.
- Wired `total_staked` in `get_staking_info` via new
  `Blockchain::get_total_staked()` accessor backed by existing stake cache.
- Added `total_burned` LMDB persistence: `set_total_burned`/`get_total_burned`
  on `BlockchainDB`, with rollback support via extended `staker_accrual_record`
  (`actually_destroyed` field).

### Privacy and anonymity networks

- Updated `ANONYMITY_NETWORKS.md` with measured v3 payload impact analysis
  (cell/fragment counts for Tor and I2P), known leak vectors vs mitigations
  matrix, and recommended pre-mainnet testing checklist.
- Extended `LEVIN_PROTOCOL.md` wire inventory with per-command PQC size
  impact, anonymity sensitivity ratings, and a summary table covering all
  P2P and Cryptonote protocol commands.
- Added privacy considerations section to `STAKER_REWARD_DISBURSEMENT.md`
  covering claim timing, amount correlation, and staked output visibility.
- Added reward-driven privacy/mixing research appendix to
  `DESIGN_CONCEPTS.md` evaluating random maturation delay, claim batching,
  and reward output shaping with adversarial analysis and go/no-go criteria.

### C++17 and Boost migration

- **C++17 standard bump**: `CMAKE_CXX_STANDARD` changed from 14 to 17 in both
  the main `CMakeLists.txt` and the macOS cross-compilation toolchain
  (`contrib/depends/toolchain.cmake.in`). This unblocks `std::filesystem`,
  `std::optional`, and other modern C++ features. Upstream Monero cherry-picks
  that required C++14-to-C++17 back-ports now compile without shims.
- **`boost::optional` → `std::optional` (complete)**:
  Migrated ~486 use sites across ~93 files in `src/`, `contrib/epee/`, and
  `tests/`. Replaced `boost::optional<T>` with `std::optional<T>`,
  `boost::none` with `std::nullopt`, `boost::make_optional` with
  `std::make_optional`, and `.get()` accessor calls with `*` / `->`.
  Added a `std::optional` Boost.Serialization adapter in
  `cryptonote_boost_serialization.h` so PQC auth fields serialize correctly.
  Replaced `BOOST_STATIC_ASSERT`/`boost::is_base_of` with
  `static_assert`/`std::is_base_of` in Trezor `messages_map.hpp`.
- **`boost::filesystem` → `std::filesystem` (wallet/RPC layer)**:
  Migrated `wallet_manager.cpp`, `wallet_rpc_server.cpp`,
  `core_rpc_server.cpp`, and `wallet_args.cpp` from `boost::filesystem` to
  `std::filesystem`. Combined with the earlier utility-file migration, this
  covers all filesystem usage outside of `net_ssl.cpp` (epee, deferred due to
  permissions API coupling).
- **`boost::format` removal (wallet/RPC layer)**:
  Replaced all `boost::format` calls in `wallet2.cpp` (4), `wallet_rpc_server.cpp`
  (8), and `wallet_args.cpp` (1) with stream output or string concatenation.
  `simplewallet.cpp` (106 uses, i18n-sensitive) remains deferred.
- **`boost::chrono`/`boost::this_thread` in daemonizer**: Replaced with
  `std::chrono`/`std::this_thread` in `windows_service.cpp` (PR #9544 equivalent).
- **Medium-effort Boost removals (completed earlier)**:
  - `boost::algorithm::string` (trim, to_lower, iequals, join) replaced with
    `tools::string_util` helpers in `src/common/string_util.h`.
  - `boost::format` replaced with `snprintf`, stream output, or string
    concatenation in `util.cpp`, `message_store.cpp`, `gen_ssl_cert.cpp`,
    `gen_multisig.cpp`.
  - `boost::regex` replaced with `std::regex` in `simplewallet.cpp` and
    `wallet_manager.cpp`.
  - `boost::mutex`, `boost::lock_guard`, `boost::unique_lock`, and
    `boost::condition_variable` replaced with `std::mutex`, `std::lock_guard`,
    `std::unique_lock`, and `std::condition_variable` in `util.h`, `util.cpp`,
    `threadpool.h`, `threadpool.cpp`, and `rpc_payment.h`/`rpc_payment.cpp`.
  - `boost::thread::hardware_concurrency()` replaced with
    `std::thread::hardware_concurrency()`.
- **Filesystem migration (utility files, completed earlier)**:
  - `boost::filesystem` replaced with `std::filesystem` in
    `blockchain_export.cpp`, `blockchain_import.cpp`, `cn_deserialize.cpp`,
    `util.cpp`, `bootstrap_file.h`/`.cpp`, and `blocksdat_file.h`/`.cpp`.
  - Eliminated `BOOST_VERSION` preprocessor conditional in `copy_file()`.
- **Upstream Monero cherry-pick verification**: Confirmed PRs #9628 (ASIO
  `io_service` → `io_context`), #6690 (serialization overhaul), and #9544
  (daemonizer chrono/thread) are already absorbed in our tree.
- **`boost::variant` → `std::variant` (complete)**:
  Full migration from `boost::variant` to C++17 `std::variant` across the
  entire codebase (~100+ replacements in ~40 files):
  - **Serialization layer rewrite** (`serialization/variant.h`): Replaced
    Boost.MPL type-list iteration with C++17 `if constexpr` recursion for
    deserialization and `std::visit` lambda for serialization. Removed all
    `boost::mpl`, `boost::static_visitor`, and `boost::apply_visitor` usage.
  - **Archive headers**: Replaced `boost::mpl::bool_<B>` with
    `std::bool_constant<B>` in `binary_archive.h`, `json_archive.h`, and
    `serialization.h`. Replaced `boost::true_type`/`false_type` and
    `boost::is_integral` with `std` equivalents.
  - **Core typedefs**: Changed `txin_v`, `txout_target_v`, `tx_extra_field`,
    `transfer_view::block`, and Trezor `rsig_v` from `boost::variant` to
    `std::variant`.
  - **Boost.Serialization shim**: Added a local ~45-line `std::variant`
    serialization adapter in `cryptonote_boost_serialization.h` (save/load
    with index + payload, wire-compatible with old `boost::variant` format).
    Removed dependency on `<boost/serialization/variant.hpp>`.
  - **Mechanical replacements** across all `src/` and `tests/` files:
    `boost::get<T>(v)` → `std::get<T>(v)`,
    `boost::get<T>(&v)` → `std::get_if<T>(&v)`,
    `v.type() == typeid(T)` → `std::holds_alternative<T>(v)`,
    `v.which()` → `v.index()`,
    `boost::apply_visitor(vis, v)` → `std::visit(vis, v)`.
  - **P2P layer**: Updated `net_peerlist_boost_serialization.h` to use
    `std::false_type`/`std::true_type` instead of `boost::mpl` equivalents.
  - `tests/unit_tests/net.cpp` retains `boost::get<N>` for `boost::tuple`
    access via `boost::combine` (not variant-related).
- **Remaining deferred Boost areas**: ASIO deep plumbing,
  multi-index containers, Spirit parser, multiprecision, `net_ssl.cpp` filesystem,
  `simplewallet.cpp` format strings, `boost::thread::attributes` (stack size).
  Tagged with `TODO(shekyl-v4)` in source. See `DOCUMENTATION_TODOS_AND_PQC.md`
  section 1.11 for the full backlog.

### CI/CD and build system

- **Boost minimum bumped to 1.74**: `BOOST_MIN_VER` in `CMakeLists.txt` raised
  from 1.62 to 1.74. The `contrib/depends` system now pins Boost 1.74.0
  (previously 1.69.0) and builds with `-std=c++17`. Removed legacy Boost 1.64
  patches (`fix_aroptions.patch`, `fix_arm_arch.patch`) that do not apply to 1.74.
- **CI containers updated to Ubuntu 22.04 minimum**: Dropped Debian 11 and
  Ubuntu 20.04 build jobs from `build.yml`, `depends.yml`, and
  `release-tagged.yml`. Ubuntu 22.04 is now the lowest-common-denominator Linux
  build environment (ships Boost 1.74+ and GCC 11+). Added Ubuntu 24.04 build
  matrix entry.
- Migrated version identifiers from legacy `MONERO_*` symbols to canonical
  `SHEKYL_*` names (`SHEKYL_VERSION`, `SHEKYL_VERSION_TAG`,
  `SHEKYL_RELEASE_NAME`, `SHEKYL_VERSION_FULL`, `SHEKYL_VERSION_IS_RELEASE`)
  in `src/version.h` and `src/version.cpp.in`. The old `MONERO_*` names are
  retained as preprocessor aliases so existing call sites and future Monero
  upstream cherry-picks continue to compile unchanged. The aliases will be
  removed in a single cleanup after v4 RingPQC stabilises.
- Fixed Gitian deterministic build pipeline: replaced all hardcoded Monero
  repository URLs and internal package names with Shekyl equivalents across
  `gitian-build.py`, all 5 gitian descriptor YAMLs, `dockrun.sh`, and the
  `gitian.yml` GitHub Actions workflow. The workflow now passes `--url` to
  ensure the correct repository is cloned. Added checkout error handling with
  an actionable message when a tag/branch is missing.
- Tag-driven versioning: `GitVersion.cmake` now extracts the version string
  from git tags (e.g. `v3.0.2-RC1` → `3.0.2-RC1`). The hardcoded version in
  `version.cpp.in` is replaced with the CMake-substituted `@SHEKYL_VERSION@`;
  a default (`3.1.0`) is used for development builds not on a tag.
  `Version.cmake` centralises the fallback default in `SHEKYL_VERSION_DEFAULT`.
- Updated RPC version string validator (`rpc_version_str.cpp`) from Monero's
  four-number format to Shekyl's three-number semver with optional pre-release
  suffix (e.g. `3.0.2-RC1-release`).
- Updated gitian descriptor names from Monero's `0.18` to Shekyl `3` series.
- Added `release/tagged` GitHub Actions workflow: builds static Linux x86_64
  binaries, cross-compiles Windows x64 via MinGW, and produces `.tar.gz`,
  `.deb`, `.rpm`, `.zip`, and NSIS `.exe` installer artifacts on every `v*` tag.
- Added `BuildRust.cmake` cross-compilation support: detects `CMAKE_SYSTEM_NAME`
  and `CMAKE_SYSTEM_PROCESSOR` to derive Rust target triples for Windows, macOS,
  Android, FreeBSD, and Linux cross-targets (ARM, aarch64, i686, RISC-V);
  automatically configures the MinGW linker for Windows cross-compilation.
- Added Rust toolchain installation to all CI workflows (`build.yml`,
  `depends.yml`, `release-tagged.yml`) and all 5 Gitian deterministic build
  descriptors with appropriate cross-compilation targets; required for
  `libshekyl_ffi.a` linking.
- Fixed Gitian `gitian-build.py` to fetch tags explicitly (`--tags`) during
  repository setup, preventing checkout failures for tag-based builds.
- Enhanced `gitian-build.py` error handling: robust `lsb_release` detection,
  auto-correction of stale clone origins when `--url` changes, and detailed
  diagnostics on checkout failure (lists available remote tags and suggests
  the push command).
- Added `workflow_dispatch` trigger to `gitian.yml` with configurable `tag` and
  `repo_url` inputs, allowing manual re-runs and testing against forks without
  retagging.
- Fixed Doxygen project name from `Monero` to `Shekyl` in `cmake/Doxyfile.in`.
- Replaced bundled Google Test 1.7.0 (2013) with CMake `FetchContent` for
  GoogleTest v1.16.0. Fixes `GTEST_SKIP` compilation errors on all platforms
  without a system gtest. Removes 34k lines of vendored source.
- Upgraded all GitHub Actions workflows to Node.js 24: bumped `actions/checkout`
  to v5, `actions/cache` to v5, `actions/upload-artifact` to v6, and
  `actions/download-artifact` to v7 to resolve the Node.js 20 deprecation
  warnings.
- Trimmed `depends.yml` cross-compilation matrix: dropped i686 Win and i686
  Linux (32-bit targets are dead); deferred RISCV 64-bit and ARM v7 until
  user demand materialises. Active matrix is now ARM v8, Win64, x86_64 Linux,
  Cross-Mac x86_64, Cross-Mac aarch64, and x86_64 FreeBSD (6 targets, down
  from 10). Added Cross-Mac aarch64 to the artifact upload filter.
- Added Linux packaging files: `contrib/packaging/linux/shekyld.service`
  (systemd unit) and `contrib/packaging/windows/shekyl.nsi` (NSIS installer).

### Upstream Monero sync (March 2026)

Cherry-picked 62 upstream Monero commits (from `monero-project/monero` master)
across five risk-phased integration rounds. Key improvements absorbed:

- **Wallet**: Fee priority refactoring (`fee_priority` enum + utility functions),
  improved subaddress lookahead logic, `set_subaddress_lookahead` RPC endpoint
  (no longer requires password), incoming transfers without daemon connection,
  HTTP body size limit, fast refresh checkpoint fix, ring index sanity checks,
  `find_and_save_rings()` deprecation, pool spend identification during scan.
- **Daemon/RPC**: Dynamic `print_connections` column width, ZMQ IPv6 support,
  dynamic base fee estimates via ZMQ, `getblocks.bin` start height validation,
  CryptoNight v1 error reporting, batch key image existence check, blockchain
  prune DB version handling, removed `COMMAND_RPC_SUBMIT_RAW_TX` (light wallet
  deprecated).
- **P2P/Network**: Removed `state_idle` connection state, fixed inverted peerlist
  ternary, removed `#pragma pack` from protocol defs, connection patches for
  reliability, dynamic block sync span limits.
- **Crypto/Serialization**: Fixed invalid `constexpr` on hash functions, added
  `hash_combine.h`, aligned container pod-as-blob serialization, fixed
  `apply_permutation()` for `std::vector<bool>`.
- **Build system**: Removed iwyu/MSVC/obsolete CMake targets, added
  `MANUAL_SUBMODULES` cache option, Trezor protobuf 30 compatibility, fixed
  `FetchContent`/`ExternalProject` cmake usage.
- **Tests**: New unit tests for format utils, threadpool, varint, logging,
  serialization static asserts, cold signing functional test fixes.
- **Misc**: Boost ASIO 1.87+ compatibility, fixed Trezor temporary binding,
  fixed multisig key exchange intermediate message update, `constexpr`
  `cn_variant1_check`, extra nonce length fix, removed redundant BP consensus rule.

Skipped commits (deferred to future integration): input verification caching
(conflicts with `txin_stake_claim`/PQC), `wallet_keys_unlocker` refactoring,
`get_txids_loose` DB API (missing prerequisite), complex subaddress lookahead
fixes, and several CMake/depends version bumps that conflict with Shekyl's
build system divergences.

Cherry-picked code was initially adapted to C++14 compatibility; with the
subsequent C++17 standard bump, many of those back-ports are now unnecessary
and can use native `std::optional`, `std::string_view`, etc.

### Documentation

- Added `docs/EXECUTABLES.md`: comprehensive reference for all 17 build
  artifacts covering usage, CLI options, interactive commands, and examples
  for `shekyld`, `shekyl-wallet-cli`, `shekyl-wallet-rpc`, blockchain
  utilities, and debug tools.

### Operations

- Added `utils/systemd/shekyld.service` for Shekyl-native daemon service
  deployment (`/usr/local/bin/shekyld` + `/etc/shekyl/shekyld.conf`).
- Updated `docs/INSTALLATION_GUIDE.md` related-doc references to include seed
  operations documentation in the companion `shekyl-dev` docs set.
- Added `docs/BLOCKCHAIN_NETWORKS.md` with a deep-dive comparison of network
  models across Bitcoin, Ethereum, Monero, Solana, Polkadot, and Avalanche,
  and mapped those patterns to Shekyl's mainnet/testnet/stagenet/fakechain
  usage guidance.
- Migrated Shekyl stagenet defaults from legacy Monero ports to
  `13021` (P2P), `13029` (RPC), and `13025` (ZMQ), and aligned test/docs
  references so `--testnet` workflows use `12029` while scripts support
  overrideable network/daemon variables.
- Updated libwallet API helper scripts to call `shekyl-wallet-cli` (not
  `monero-wallet-cli`) so test tooling matches Shekyl binary names.

### Staking (end-to-end claim-based system)

- Added `txout_to_staked_key` output target type for locking coins at a chosen
  tier (short/medium/long). Outputs carry `lock_tier` and `lock_until` fields
  enforced at the consensus layer.
- Added `txin_stake_claim` input type for claiming accrued staking rewards.
  Claims specify a height range and are validated against deterministic per-block
  accrual records.
- Extended LMDB schema with `staker_accrual` and `staker_claims` tables plus a
  `staker_pool_balance` property for on-chain reward pool accounting.
- Per-block accrual logic computes staker emission share and fee pool allocation
  at block insertion time, with full reversal on reorg (block pop).
- Consensus validation: `lock_until` enforcement on staked outputs, claim amount
  verification against accrual records, watermark-based anti-double-claim,
  maximum claim range (10,000 blocks), pool balance sufficiency checks.
- Pure claim transactions (`txin_stake_claim`-only inputs) use `RCTTypeNull`
  signatures, cleanly separated from ring-signature transaction validation.
- Extended `tx_destination_entry` with `is_staking`, `stake_tier`, and
  `stake_lock_until` fields. `construct_tx_with_tx_key` emits
  `txout_to_staked_key` outputs when `is_staking` is set.
- Extended `transfer_details` with `m_staked`, `m_stake_tier`, and
  `m_stake_lock_until` for wallet-side staking metadata tracking.
- Implemented wallet2 methods: `create_staking_transaction`,
  `create_unstake_transaction`, `create_claim_transaction`,
  `get_matured_staked_outputs`, `get_locked_staked_outputs`,
  `get_claimable_staked_outputs`, `get_staked_balance`,
  `estimate_claimable_reward`.
- Added simplewallet commands: `stake <tier> <amount>`, `unstake`,
  `claim_rewards`.
- Added wallet RPC endpoints: `stake`, `unstake`, `get_staked_outputs`,
  `claim_rewards`.
- Added daemon RPC endpoint: `get_staking_info` returning current staking
  metrics (height, stake ratio, pool balance, emission share, tier lock blocks).
- Wired `stake_ratio` and `staker_pool_balance` in `/get_info` to live
  blockchain state.
- No minimum stake amount enforced (matches design doc).
- Fixed compilation errors from `txin_stake_claim` missing in exhaustive
  `boost::static_visitor` patterns: added `operator()` overloads to the
  double-spend visitor (`blockchain.cpp`) and the JSON serialization visitor
  (`json_object.cpp`), added JSON deserialization branch for `"stake_claim"`
  inputs, added `toJsonValue`/`fromJsonValue` declarations and implementations
  for `txin_stake_claim`, and added Boost.Serialization `serialize()` free
  function for wallet binary archive support (`cryptonote_boost_serialization.h`).

### Consensus and mining economics

- Wired Four-Component economics to live chain-state inputs for miner reward
  paths:
  - block template construction now passes rolling `tx_volume_avg`,
    `circulating_supply`, and `stake_ratio` to `construct_miner_tx`
  - miner transaction validation now uses the release-multiplier reward path
    and non-placeholder fee-burn inputs
  - tx pool block template estimation now uses the same rolling
    `tx_volume_avg` reward path for consistency
- Added `Blockchain::get_tx_volume_avg(height)` and
  `Blockchain::get_stake_ratio(height)` (stubbed to `0` until staking state is
  consensus-tracked).

### Modular PoW

- Added pluggable PoW schema abstractions:
  - `IPowSchema` interface
  - `RandomX` and `Cryptonight` schema implementations
  - PoW registry-based selection preserving existing behavior by block version
- Refactored `get_block_longhash` to route through the PoW schema registry while
  keeping existing RandomX seed handling and the historical block 202612
  workaround.
- Updated miner thread preparation to call schema-level
  `prepare_miner_thread(...)` (RandomX prepares thread context; Cryptonight is
  a no-op).
