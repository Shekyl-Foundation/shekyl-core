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
    Capability, DaemonClient, IoError, KeyError, Network, OpenError, PendingTxError, RefreshError,
    SendError, SoloSigner, TxError, Wallet, WalletSignerKind,
};
pub use workflow::ClaimAndUnstakePlan;

#[cfg(test)]
mod tests;
