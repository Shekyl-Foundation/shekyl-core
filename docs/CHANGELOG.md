# Shekyl Changelog

## Unreleased

### Post-quantum cryptography

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

### CI/CD and build system

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
- Fixed Doxygen project name from `Monero` to `Shekyl` in `cmake/Doxyfile.in`.
- Replaced bundled Google Test 1.7.0 (2013) with CMake `FetchContent` for
  GoogleTest v1.16.0. Fixes `GTEST_SKIP` compilation errors on all platforms
  without a system gtest. Removes 34k lines of vendored source.
- Upgraded all GitHub Actions workflows to Node.js 24 via
  `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` ahead of the June 2026 deprecation.
- Added Linux packaging files: `contrib/packaging/linux/shekyld.service`
  (systemd unit) and `contrib/packaging/windows/shekyl.nsi` (NSIS installer).

### Documentation and operations

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
