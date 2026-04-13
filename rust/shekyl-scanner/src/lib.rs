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

pub mod balance;
pub mod claim;
pub mod coin_select;
pub mod extra;
pub mod output;
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
pub use extra::{Extra, ExtraField, PaymentId};
pub use output::WalletOutput;
pub use scan::{GuaranteedScanner, RecoveredWalletOutput, ScanError, Scanner, Timelocked};
pub use shared_key::SharedKeyDerivations;
pub use staker_pool::{AccrualRecord, ConservationCheck, StakerPoolState};
pub use subaddress::SubaddressIndex;
pub use transfer::TransferDetails;
pub use view_pair::{GuaranteedViewPair, ViewPair, ViewPairError};
pub use wallet_state::WalletState;
