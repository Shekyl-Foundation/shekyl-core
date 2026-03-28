# Shekyl Changelog

## Unreleased

### CI/CD and build system

- Added `release/tagged` GitHub Actions workflow: builds static Linux x86_64
  binaries, cross-compiles Windows x64 via MinGW, and produces `.tar.gz`,
  `.deb`, `.rpm`, `.zip`, and NSIS `.exe` installer artifacts on every `v*` tag.
- Added `BuildRust.cmake` cross-compilation support: detects `CMAKE_SYSTEM_NAME`
  and `CMAKE_SYSTEM_PROCESSOR` to derive Rust target triples for Windows, macOS,
  Android, and FreeBSD; automatically configures the MinGW linker for Windows
  cross-compilation.
- Added Rust toolchain installation to all CI workflows (`build.yml`,
  `depends.yml`, `release-tagged.yml`); required for `libshekyl_ffi.a` linking.
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
