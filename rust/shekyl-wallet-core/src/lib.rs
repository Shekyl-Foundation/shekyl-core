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

pub mod error;
pub mod claim_builder;
pub mod workflow;
#[cfg(feature = "multisig")]
pub mod multisig;

pub use error::WalletCoreError;
pub use claim_builder::{ClaimTxBuilder, ClaimTxPlan};
pub use workflow::ClaimAndUnstakePlan;

#[cfg(test)]
mod tests;
