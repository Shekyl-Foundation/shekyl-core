// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Shekyl wallet core: transaction builders for staking operations.
//!
//! Provides Rust-native builders for:
//! - Claim transactions (reward withdrawal)
//! - Stake transactions (creating staked outputs)
//! - Unstake transactions (spending matured staked outputs)
//! - Combined claim-and-unstake workflow

pub mod claim_builder;
pub mod error;
#[cfg(feature = "multisig")]
pub mod multisig;
pub mod scan;
pub mod wallet;
pub mod workflow;

pub use claim_builder::{ClaimTxBuilder, ClaimTxPlan};
pub use error::WalletCoreError;
pub use scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult, StakeEvent};
pub use wallet::{
    Capability, CapabilityInput, Credentials, DaemonClient, FeePriority, IoError, KeyError,
    Network, OpenError, OpenedWallet, PendingTx, PendingTxError, RefreshError, ReservationId,
    SendError, SoloSigner, TxError, TxHash, TxRecipient, TxRecipientSummary, TxRequest, Wallet,
    WalletCreateParams, WalletSignerKind,
};
pub use workflow::ClaimAndUnstakePlan;

#[cfg(test)]
mod tests;

/// **Not part of the public API.** Re-exports otherwise-`pub(crate)`
/// types so external Criterion benchmarks (`benches/*.rs`) can measure
/// internal data structures without weakening their crate-local
/// visibility for production callers. Gated behind the
/// `bench-internals` feature; consumers must not depend on it.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod __bench_internals {
    pub use crate::wallet::refresh::LedgerSnapshot;
}
