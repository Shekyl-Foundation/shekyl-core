// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Transaction scanner for the Shekyl protocol.
//!
//! This crate provides output scanning with Shekyl-specific extensions:
//! - FCMP++ as the sole transaction proof type
//! - Hybrid PQC key derivation via KEM decapsulation (tag 0x06)
//! - Staking output detection and balance tracking
//! - PQC key rederivation and verification (tag 0x07)
//! - FCMP++ curve-tree path precomputation
//!
//! The scanner core is adapted from the monero-oxide wallet library,
//! extended to handle Shekyl's 3-key HKDF model and staking economy.
//!
//! ### Runtime-state types
//!
//! [`TransferDetails`], [`LedgerBlock`], [`LedgerIndexes`],
//! [`SubaddressIndex`], [`PaymentId`], [`StakerPoolState`], [`AccrualRecord`],
//! [`FcmpPrecomputedPath`], and [`SPENDABLE_AGE`] are owned by the
//! [`shekyl_wallet_state`] crate; this crate re-exports them explicitly (no glob)
//! so existing `use shekyl_scanner::…` imports keep resolving. Scanner-only
//! methods on those types (`TransferDetails::from_wallet_output`,
//! `LedgerIndexes::process_scanned_outputs`, `LedgerBlock::balance`,
//! `LedgerBlock::claimable_rewards_summary`) are provided by the extension
//! traits in [`ledger_ext`] and require the trait to be in scope at the
//! call site:
//!
//! ```ignore
//! use shekyl_scanner::{LedgerBlockExt, LedgerIndexesExt, TransferDetailsExt};
//! use shekyl_wallet_state::{LedgerBlock, LedgerIndexes};
//!
//! let mut ledger = LedgerBlock::empty();
//! let mut indexes = LedgerIndexes::empty();
//! indexes.process_scanned_outputs(&mut ledger, h, block_hash, outputs);
//! let balance = ledger.balance(ledger.height());
//! ```
//!
//! The pair `(LedgerBlock, LedgerIndexes)` replaces the `RuntimeWalletState`
//! shape used through commit 2m. See `docs/V3_WALLET_DECISION_LOG.md`
//! ("`RuntimeWalletState` audit", 2026-04-25) for the rationale and the
//! invariant that pins the split.

pub mod balance;
pub mod claim;
pub mod coin_select;
pub mod extra;
pub mod ledger_ext;
pub mod output;
pub mod scan;
pub mod shared_key;
pub mod staker_pool;
pub mod subaddress;
pub mod transfer;
pub mod view_pair;

#[cfg(test)]
pub(crate) mod tests;

pub use balance::BalanceSummary;
pub use claim::ClaimableInfo;
pub use extra::{Extra, ExtraField};
pub use ledger_ext::{LedgerBlockExt, LedgerIndexesExt, TransferDetailsExt};
pub use output::WalletOutput;
pub use scan::{GuaranteedScanner, RecoveredWalletOutput, ScanError, Scanner, Timelocked};
pub use shared_key::SharedKeyDerivations;
pub use view_pair::{GuaranteedViewPair, ViewPair, ViewPairError};

// ── Explicit (non-glob) re-exports of types moved to `shekyl-wallet-state`. ──
//
// Listing them by name (rather than `pub use shekyl_wallet_state::*;`) pins the
// scanner's public API surface in commit-diffable form: adding a new type in
// `shekyl-wallet-state` does NOT silently expand the scanner's API.
pub use shekyl_wallet_state::{
    AccrualRecord, ConservationCheck, FcmpPrecomputedPath, LedgerBlock, LedgerIndexes, PaymentId,
    StakerPoolState, SubaddressIndex, TransferDetails, SPENDABLE_AGE,
};
