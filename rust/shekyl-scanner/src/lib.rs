// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Transaction scanner for the Shekyl protocol.
//!
//! This crate provides output scanning with Shekyl-native extensions:
//! - FCMP++ as the sole transaction proof type
//! - Hybrid PQC key derivation via KEM decapsulation (tag 0x06)
//! - PQC key rederivation and verification (tag 0x07)
//! - FCMP++ curve-tree path precomputation
//!
//! Staking classification and accounting live in `shekyl-engine-core`
//! (`StakeFacade` / sealed pscan), not in this crate. `TransferDetails` does
//! not carry stake fields.
//!
//! Runtime-state types (`TransferDetails`, `LedgerBlock`, …) are owned by
//! [`shekyl_engine_state`]; this crate re-exports them and adds scanner-only
//! extension traits. Further scanner work is Shekyl-native — do not add
//! oxide-shaped APIs.
//!
//! Historical note: the original scan loop was adapted from monero-oxide
//! wallet code. That is lineage, not the present architecture.
//!
//! ### Runtime-state types
//!
//! [`TransferDetails`], [`LedgerBlock`], [`LedgerIndexes`],
//! [`PaymentId`], [`FcmpPrecomputedPath`], and [`SPENDABLE_AGE`] are owned by the
//! [`shekyl_engine_state`] crate; this crate re-exports them explicitly (no glob)
//! so existing `use shekyl_scanner::…` imports keep resolving. Scanner-only
//! methods on those types (`TransferDetails::from_wallet_output`,
//! `LedgerIndexes::process_scanned_outputs`, `WalletLedger::balance`)
//! are provided by the extension traits in [`ledger_ext`] and require the
//! trait to be in scope at the call site:
//!
//! ```ignore
//! use shekyl_scanner::{LedgerIndexesExt, TransferDetailsExt, WalletLedgerExt};
//! use shekyl_engine_state::WalletLedger;
//!
//! let mut wallet = WalletLedger::empty();
//! let mut indexes = LedgerIndexes::empty();
//! indexes.process_scanned_outputs(&mut wallet.ledger, h, block_hash, outputs);
//! // Balance is a whole-wallet query: the journal-derived F14 locks
//! // come from the same value, so there is no lock map to forget.
//! let balance = wallet.balance();
//! ```
//!
//! The pair `(LedgerBlock, LedgerIndexes)` replaces the `RuntimeWalletState`
//! shape used through commit 2m. See `docs/V3_WALLET_DECISION_LOG.md`
//! ("`RuntimeWalletState` audit", 2026-04-25) for the rationale and the
//! invariant that pins the split.

pub mod balance;
pub mod coin_select;
pub mod extra;
pub mod ledger_ext;
pub mod output;
pub mod scan;
pub mod transfer;
pub mod view_pair;

/// Bench fixture helpers for the [`scan::Scanner::scan`] per-output
/// cost measurement (PR 4 §3.1 / F11-S substrate). Gated behind
/// `#[cfg(any(test, feature = "test-utils"))]` so the production
/// crate surface stays free of bench-only constructors; the two
/// `benches/scan_transaction*.rs` harnesses both consume this
/// module via the existing self-dep with `features = ["test-utils"]`.
#[cfg(any(test, feature = "test-utils"))]
pub mod bench_fixtures;

#[cfg(test)]
pub(crate) mod tests;

pub use balance::BalanceSummary;
pub use extra::{Extra, ExtraField};
pub use ledger_ext::{LedgerIndexesExt, TransferDetailsExt, WalletLedgerExt};
pub use output::WalletOutput;
pub use scan::{
    GuaranteedScanner, RecoveredWalletOutput, ScanError, ScanOutcome, ScannableBlock, Scanner,
    Timelocked, MAX_OUTPUTS,
};
pub use view_pair::{GuaranteedViewPair, ViewPair, ViewPairError};

// ── Explicit (non-glob) re-exports of types moved to `shekyl-engine-state`. ──
//
// Listing them by name (rather than `pub use shekyl_engine_state::*;`) pins the
// scanner's public API surface in commit-diffable form: adding a new type in
// `shekyl-engine-state` does NOT silently expand the scanner's API.
pub use shekyl_engine_state::{
    FcmpPrecomputedPath, LedgerBlock, LedgerIndexes, PaymentId, TransferDetails, SPENDABLE_AGE,
};
