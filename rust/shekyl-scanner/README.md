# shekyl-scanner

Transaction scanner for the Shekyl protocol with FCMP++, PQC, and staking
support.

## Overview

This crate provides output scanning functionality adapted from the
monero-oxide wallet library, extended with Shekyl-specific features:

- **FCMP++**: Only `RCTTypeFcmpPlusPlusPqc` transactions (no legacy ring
  signatures, no decoy selection)
- **Hybrid KEM scanning**: Full X25519 + ML-KEM-768 decapsulation pipeline
  with view-tag pre-filtering for fast output rejection
- **PQC extra field parsing**: Parses tx_extra tag 0x06 (KEM ciphertext)
  and 0x07 (FCMP++ leaf hashes)
- **Staking detection**: Identifies staked outputs with tier and lock period
- **Balance breakdown**: Staking-aware balance computation (total, unlocked,
  timelocked, staked matured/locked, frozen)

The scanner is a pure scanning library: block fetch, daemon polling,
reorg handling, and wallet-state mutation are owned by
`shekyl-wallet-core::Wallet::refresh` (Phase 2a snapshot-merge driver).

## Architecture

```
shekyl-scanner
├── scan.rs          # Block/tx/output scanning pipeline (Scanner)
│                    # Hybrid KEM: parse 0x06, view-tag pre-filter,
│                    # scan_output_recover, subaddress lookup, key image
├── extra.rs         # Transaction extra field parsing (extended with PQC tags)
├── view_pair.rs     # ViewPair with X25519 + ML-KEM decapsulation keys
├── output.rs        # WalletOutput representation
├── transfer.rs      # Re-export shim for shekyl_wallet_state::TransferDetails
│                    # (canonical type, with staking + PQC + FCMP++ fields)
├── ledger_ext.rs    # Scanner-side extension traits for LedgerBlock + LedgerIndexes
│                    # (TransferDetailsExt, LedgerIndexesExt, LedgerBlockExt). The
│                    # canonical persisted/runtime split lives in shekyl-wallet-state.
├── balance.rs       # Balance computation with staking categories
├── coin_select.rs   # Coin selection for transaction building
├── staker_pool.rs   # Staker pool accrual data for reward estimation
├── claim.rs         # Claimable reward info for staked outputs
└── subaddress.rs    # SubaddressIndex type
```

## Dependencies

- `shekyl-oxide` — Transaction/block types, FCMP module, IO primitives
- `shekyl-rpc` — `ScannableBlock` type, daemon RPC traits
- `shekyl-crypto-pq` — Hybrid KEM operations (X25519 + ML-KEM-768),
  `scan_output_recover`, `compute_output_key_image`
- `shekyl-staking` — Staking tier definitions
- `shekyl-address` — Bech32m address encoding
- `shekyl-generators` — `hash_to_point` for key image computation

## Usage

The scanner is consumed by `shekyl-wallet-core::Wallet::refresh` (the
production refresh driver), `shekyl-wallet-rpc` (behind its
`rust-scanner` feature flag, slated for retirement in Phase 4b), and the
GUI wallet's `wallet_bridge.rs`. It is not intended to be used directly
by end users.

```rust
use shekyl_scanner::{
    LedgerBlock, LedgerBlockExt, LedgerIndexes, LedgerIndexesExt,
    Scanner, ViewPair,
};

// Create a scanner from wallet keys (includes KEM secret keys for hybrid scanning)
let view_pair = ViewPair::new(
    view_public, spend_public, view_secret,
    x25519_sk, ml_kem_dk, subaddresses,
);
let scanner = Scanner::new(view_pair, spend_secret);

// Scan a block (from daemon RPC)
let outputs = scanner.scan(scannable_block)?;

// Track outputs in the (LedgerBlock, LedgerIndexes) pair: persisted state
// in `ledger`, runtime-only derived indexes in `indexes`.
let mut ledger = LedgerBlock::empty();
let mut indexes = LedgerIndexes::empty();
indexes.process_scanned_outputs(&mut ledger, block_height, block_hash, outputs);

// Detect spends from block inputs
indexes.detect_spends(&mut ledger, block_height, &key_images_from_block);

// Query balance (read-only against the persisted ledger)
let balance = ledger.balance(current_height);
```

### Driving sync

The block-fetch / poll / reorg-detect / wallet-state-mutate loop is owned
by `shekyl-wallet-core::Wallet::refresh`, which calls
`produce_scan_result` against a borrowed `LedgerSnapshot` and merges via
`Wallet::apply_scan_result` under a brief `&mut self` window. See the
Phase 2a refresh-driver decision-log entries (2026-04-25 / 2026-04-26)
in `docs/V3_WALLET_DECISION_LOG.md` for the snapshot-merge rationale.
This crate intentionally provides no top-level driver of its own —
running two sync loops over the same daemon connection (one in the
scanner, one in the wallet) was the inconsistency surface the
refresh-driver split was designed to remove.

## Feature Status

| Feature | Status |
|---------|--------|
| Core scanning pipeline | ✅ Complete |
| Hybrid KEM decapsulation (X25519 + ML-KEM-768) | ✅ Integrated |
| PQC extra field parsing (0x06, 0x07) | ✅ Complete |
| View-tag pre-filtering | ✅ Inside `scan_output_recover` |
| Native Rust key image computation | ✅ Via `compute_output_key_image` |
| Transfer details with staking + PQC secrets | ✅ Complete, ZeroizeOnDrop |
| Wallet state management | ✅ Complete with reorg handling |
| Balance computation | ✅ Complete with staking breakdown |
| Coin selection | ✅ Complete |
| FCMP++ path precompute | ⬜ Needs daemon RPC for `/get_curve_tree_path` |
