# Shekyl Changelog

## Unreleased

### Documentation and operations

- Added `utils/systemd/shekyld.service` for Shekyl-native daemon service
  deployment (`/usr/local/bin/shekyld` + `/etc/shekyl/shekyld.conf`).
- Updated `docs/INSTALLATION_GUIDE.md` related-doc references to include seed
  operations documentation in the companion `shekyl-dev` docs set.

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
