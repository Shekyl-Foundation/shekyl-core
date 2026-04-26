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
- **Background sync loop**: Polls daemon for new blocks, scans, detects
  spends, handles reorgs, and emits progress events

## Architecture

```
shekyl-scanner
├── scan.rs          # Block/tx/output scanning pipeline (Scanner)
│                    # Hybrid KEM: parse 0x06, view-tag pre-filter,
│                    # scan_output_recover, subaddress lookup, key image
├── sync.rs          # Background sync loop with reorg detection,
│                    # retry-with-backoff, cancellation, flush strategy
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

The scanner is consumed by `shekyl-wallet-rpc` (behind the `rust-scanner`
feature flag) and the GUI wallet's `wallet_bridge.rs`. It is not intended
to be used directly by end users.

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

### Background sync loop

With the `rust-scanner` feature, a full background sync loop is available:

```rust
use shekyl_scanner::sync::{run_sync_loop, LiveLedger};

// `state` is `Arc<Mutex<LiveLedger>>`, where
// `pub type LiveLedger = (LedgerBlock, LedgerIndexes);`
run_sync_loop(
    rpc,
    scanner,
    state,
    cancel_token,
    poll_interval,
    flush_every_block,   // true on mobile, false on desktop
    |progress| { /* update UI */ },
    |state| { /* persist `state.0` (LedgerBlock) to disk */ },
).await?;
```

The sync loop:
- Fetches blocks with retry and exponential backoff
- Detects chain reorgs by comparing parent hashes and rolls back
- Emits `SyncProgress` events per block
- Flushes every 100 blocks (desktop) or every block (mobile)
- Shuts down cleanly via `CancellationToken`

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
| Background sync loop | ✅ With reorg detection, retry, cancellation |
| Coin selection | ✅ Complete |
| FCMP++ path precompute | ⬜ Needs daemon RPC for `/get_curve_tree_path` |
