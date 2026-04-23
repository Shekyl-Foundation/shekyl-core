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
//! [`TransferDetails`], [`RuntimeWalletState`] (aliased as [`WalletState`]),
//! [`SubaddressIndex`], [`PaymentId`], [`StakerPoolState`], [`AccrualRecord`],
//! [`FcmpPrecomputedPath`], and [`SPENDABLE_AGE`] are owned by the
//! [`shekyl_wallet_state`] crate; this crate re-exports them explicitly (no glob)
//! so existing `use shekyl_scanner::…` imports keep resolving during the
//! migration. Scanner-only methods on those types
//! (`TransferDetails::from_wallet_output`, `WalletState::{process_scanned_outputs,
//! balance, claimable_rewards_summary}`) are provided by the extension traits in
//! [`runtime_ext`] and require the trait to be in scope at the call site:
//!
//! ```ignore
//! use shekyl_scanner::{TransferDetailsExt, WalletStateExt, WalletState};
//! let mut ws = WalletState::new();
//! ws.process_scanned_outputs(h, block_hash, outputs);
//! ```
//!
//! The transitional `WalletState` alias and the `*Ext` traits disappear in
//! Commit 2n once every caller uses `RuntimeWalletState` directly.

pub mod balance;
pub mod claim;
pub mod coin_select;
pub mod extra;
pub mod output;
pub mod runtime_ext;
pub mod scan;
pub mod shared_key;
pub mod staker_pool;
pub mod subaddress;
pub mod sync;
pub mod transfer;
pub mod view_pair;
pub mod wallet_state;

#[cfg(test)]
pub(crate) mod tests;

pub use balance::BalanceSummary;
pub use claim::ClaimableInfo;
pub use extra::{Extra, ExtraField};
pub use output::WalletOutput;
pub use runtime_ext::{TransferDetailsExt, WalletStateExt};
pub use scan::{GuaranteedScanner, RecoveredWalletOutput, ScanError, Scanner, Timelocked};
pub use shared_key::SharedKeyDerivations;
pub use view_pair::{GuaranteedViewPair, ViewPair, ViewPairError};

// ── Explicit (non-glob) re-exports of types moved to `shekyl-wallet-state`. ──
//
// Listing them by name (rather than `pub use shekyl_wallet_state::*;`) pins the
// scanner's public API surface in commit-diffable form: adding a new type in
// `shekyl-wallet-state` does NOT silently expand the scanner's API.
pub use shekyl_wallet_state::{
    AccrualRecord, ConservationCheck, FcmpPrecomputedPath, PaymentId, RuntimeWalletState,
    StakerPoolState, SubaddressIndex, TransferDetails, SPENDABLE_AGE,
};

// Transitional alias: `WalletState` resolves to `RuntimeWalletState` so every
// `use shekyl_scanner::WalletState` and `WalletState::new()` call site in the
// workspace keeps building. Removed in Commit 2n.
pub use shekyl_wallet_state::RuntimeWalletState as WalletState;
