# shekyl-scanner

Transaction scanner for the Shekyl protocol with FCMP++, PQC, and staking
support.

## Overview

This crate provides output scanning functionality adapted from the
monero-oxide wallet library, extended with Shekyl-specific features:

- **FCMP++**: Only `RCTTypeFcmpPlusPlusPqc` transactions (no legacy ring
  signatures, no decoy selection)
- **PQC KEM decapsulation**: Parses tx_extra tag 0x06 for hybrid X25519 +
  ML-KEM-768 ciphertext
- **PQC leaf hashes**: Parses tx_extra tag 0x07 for FCMP++ binding verification
- **Staking detection**: Identifies staked outputs with tier and lock period
- **Balance breakdown**: Staking-aware balance computation (total, unlocked,
  timelocked, staked matured/locked, frozen)

## Architecture

```
shekyl-scanner
├── scan.rs          # Block/tx/output scanning pipeline (Scanner, GuaranteedScanner)
├── shared_key.rs    # ECDH shared key derivation (view tags, amount decryption)
├── extra.rs         # Transaction extra field parsing (extended with PQC tags)
├── view_pair.rs     # ViewPair / GuaranteedViewPair key handling
├── output.rs        # WalletOutput representation
├── transfer.rs      # TransferDetails with staking + PQC + FCMP++ fields
├── wallet_state.rs  # In-memory state management (key images, spend tracking)
├── balance.rs       # Balance computation with staking categories
└── subaddress.rs    # SubaddressIndex type
```

## Dependencies

- `shekyl-oxide` — Transaction/block types, FCMP module, IO primitives
- `shekyl-rpc` — `ScannableBlock` type from daemon RPC
- `shekyl-crypto-pq` — Hybrid KEM operations (X25519 + ML-KEM-768)
- `shekyl-staking` — Staking tier definitions
- `shekyl-address` — Bech32m address encoding

## Usage

The scanner is consumed by `shekyl-wallet-rpc` (behind the `rust-scanner`
feature flag) and the GUI wallet's `wallet_bridge.rs`. It is not intended
to be used directly by end users.

```rust
use shekyl_scanner::{Scanner, ViewPair, WalletState};

// Create a scanner from wallet keys
let scanner = Scanner::new(view_pair);

// Scan a block (from daemon RPC)
let outputs = scanner.scan(scannable_block)?;

// Track outputs in wallet state
let mut state = WalletState::new();
state.process_scanned_outputs(block_height, block_hash, outputs);

// Query balance
let balance = state.balance(current_height);
```

## Feature Status

| Feature | Status |
|---------|--------|
| Core scanning pipeline | ✅ Ported from monero-oxide |
| PQC extra field parsing (0x06, 0x07) | ✅ Parse support |
| Transfer details with staking | ✅ Complete |
| Wallet state management | ✅ Complete |
| Balance computation | ✅ Complete with staking breakdown |
| KEM decapsulation (runtime) | ⬜ Needs `shekyl-crypto-pq` integration |
| PQC key rederivation | ⬜ Post-scan validation |
| FCMP++ path precompute | ⬜ Needs daemon RPC for `/get_curve_tree_path` |
| Background sync loop | ⬜ Future work |
