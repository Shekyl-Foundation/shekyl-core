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

pub mod subaddress;
pub mod extra;
pub mod view_pair;
pub mod output;
pub mod shared_key;
pub mod scan;
pub mod transfer;
pub mod wallet_state;
pub mod balance;

pub use subaddress::SubaddressIndex;
pub use extra::{PaymentId, Extra, ExtraField};
pub use view_pair::{ViewPairError, ViewPair, GuaranteedViewPair};
pub use output::WalletOutput;
pub use shared_key::SharedKeyDerivations;
pub use scan::{Timelocked, ScanError, Scanner, GuaranteedScanner};
pub use transfer::TransferDetails;
pub use wallet_state::WalletState;
pub use balance::BalanceSummary;
