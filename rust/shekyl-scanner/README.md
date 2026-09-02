# shekyl-scanner

Transaction scanner for the Shekyl protocol with FCMP++ and hybrid PQC.

## Overview

This crate provides output scanning. Types it scans *into* live in
`shekyl-engine-state`; this crate re-exports them and adds scanner-only
extension traits. Further work here is Shekyl-native (FCMP++, hybrid PQC)
— do not add oxide-shaped APIs.

- **FCMP++**: Only `CTTypeFcmpPlusPlusPqc` transactions (no legacy ring
  signatures, no decoy selection)
- **Hybrid KEM scanning**: Full X25519 + ML-KEM-768 decapsulation pipeline
  with view-tag pre-filtering for fast output rejection
- **PQC extra field parsing**: Parses tx_extra tag 0x06 (KEM ciphertext)
  and 0x07 (FCMP++ leaf hashes)
- **Balance breakdown**: total, unlocked, timelocked, frozen, awaiting
  confirmation. Staking accounting lives in `shekyl-engine-core`
  (`StakeFacade` / sealed pscan), not here — `TransferDetails` does not
  carry stake fields.

The scanner is a pure scanning library: block fetch, daemon polling,
reorg handling, and wallet-state mutation are owned by
`shekyl-engine-core::Engine::refresh`.

## Architecture

```
shekyl-scanner
├── scan.rs          # Block/tx/output scanning pipeline (Scanner)
│                    # Hybrid KEM: parse 0x06, view-tag pre-filter,
│                    # scan_output_recover, primary spend-key claim, key image
├── extra.rs         # Transaction extra field parsing (extended with PQC tags)
├── view_pair.rs     # ViewPair with X25519 + ML-KEM decapsulation keys
├── output.rs        # WalletOutput representation
├── transfer.rs      # Re-export shim for shekyl_engine_state::TransferDetails
│                    # (canonical type; PQC + FCMP++ fields, no stake fields)
├── ledger_ext.rs    # Scanner-side extension traits for LedgerBlock + LedgerIndexes
│                    # (TransferDetailsExt, LedgerIndexesExt, WalletLedgerExt). The
│                    # canonical persisted/runtime split lives in shekyl-engine-state.
├── balance.rs       # Balance computation (timelock / frozen / awaiting confirmation)
└── coin_select.rs   # Coin selection for transaction building
```

## Dependencies

- `shekyl-wire` — canonical genesis block/tx wire types + parsing
- `shekyl-curve-io` / `shekyl-curve-primitives` — IO primitives + `Commitment`
- `shekyl-rpc-client` — daemon RPC `Rpc` trait / `RpcError` / `FeeRate`
- `shekyl-crypto-pq` — Hybrid KEM operations (X25519 + ML-KEM-768),
  `scan_output_recover`, `compute_output_key_image`
- `shekyl-types` — `Timelock` and foundational domain newtypes
- `shekyl-address` — Bech32m address encoding
- `shekyl-curve-generators` — `hash_to_point` for key image computation

## Usage

The scanner is consumed by `shekyl-engine-core::Engine::refresh` (the
production refresh driver), `shekyl-wallet-rpc` (behind its
`rust-scanner` feature flag, slated for retirement in Phase 4b), and the
GUI wallet's `wallet_bridge.rs`. It is not intended to be used directly
by end users.

```rust
use shekyl_scanner::{LedgerIndexes, LedgerIndexesExt, Scanner, ViewPair, WalletLedgerExt};
use shekyl_engine_state::WalletLedger;

// Create a scanner from wallet keys (includes KEM secret keys for hybrid scanning)
let view_pair = ViewPair::new(
    spend_public,
    view_scalar,
    x25519_sk,
    ml_kem_dk,
)?;
let scanner = Scanner::new(view_pair, spend_secret);

// Scan a block (from daemon RPC)
let outputs = scanner.scan(scannable_block)?;

// Track outputs in the (LedgerBlock, LedgerIndexes) pair: persisted state
// in `wallet.ledger`, runtime-only derived indexes in `indexes`.
let mut wallet = WalletLedger::empty();
let mut indexes = LedgerIndexes::empty();
indexes.process_scanned_outputs(&mut wallet.ledger, block_height, block_hash, outputs);

// Detect spends from block inputs
indexes.detect_spends(&mut wallet.ledger, block_height, &key_images_from_block);

// Query balance. Whole-wallet, not ledger-only: an output whose spend is
// already on the wire is locked by the send journal, a sibling block the
// scan-derived `LedgerBlock` cannot see (C7). `WalletLedger` owns both, so
// there is no lock map to thread — or to forget.
let balance = wallet.balance();          // at the wallet's synced height
let historical = wallet.balance_at(current_height);
```

### Driving sync

The block-fetch / poll / reorg-detect / wallet-state-mutate loop is owned
by `shekyl-engine-core::Engine::refresh`, which calls
`produce_scan_result` against a borrowed `LedgerSnapshot` and merges via
`Engine::apply_scan_result` under a brief `&mut self` window. See the
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
| Transfer details with PQC secrets | ✅ Complete, ZeroizeOnDrop |
| Wallet state management | ✅ Complete with reorg handling |
| Balance computation | ✅ Complete (no staking bucket; that is engine-core) |
| Coin selection | ✅ Complete |
| FCMP++ path precompute | ⬜ Needs daemon RPC for `/get_curve_tree_path` |
