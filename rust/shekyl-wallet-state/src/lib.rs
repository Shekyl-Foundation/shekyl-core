// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Canonical Shekyl wallet state types.
//!
//! This crate owns the types that make up the persistent wallet ledger and the
//! live-mutating runtime state used by the scanner:
//!
//! - [`SubaddressIndex`] — `(account, address)` tuple, `(0, 0)` reserved for primary.
//! - [`PaymentId`] — 8-byte encrypted payment ID (Shekyl V3 rejects the legacy
//!   unencrypted form at parse time).
//! - [`FcmpPrecomputedPath`] — daemon-provided FCMP++ curve-tree path attached to a transfer.
//! - [`TransferDetails`] — extended transfer record with PQC/HKDF-derived secrets.
//! - [`StakerPoolState`] / [`AccrualRecord`] — local per-block accrual data for reward
//!   estimation.
//! - [`RuntimeWalletState`] — the scanner's live, mutating wallet state. Serializable
//!   via typed blocks (ledger, bookkeeping, tx_meta, sync_state), added in later commits.
//!
//! The serialization-format policy for this crate is pinned by
//! `.cursor/rules/42-serialization-policy.mdc` (added in Commit 2n): the ledger blocks
//! defined here use `postcard` for on-disk storage; metadata (identity + settings) lives
//! in [`shekyl_crypto_pq::wallet_state`] and uses JSON.

pub mod error;
pub mod ledger_block;
pub mod payment_id;
pub mod runtime_state;
pub mod serde_helpers;
pub mod staker_pool;
pub mod subaddress;
pub mod transfer;

pub use error::WalletLedgerError;
pub use ledger_block::{
    BlockchainTip, LedgerBlock, ReorgBlocks, DEFAULT_REORG_BLOCKS_CAPACITY, LEDGER_BLOCK_VERSION,
};
pub use payment_id::PaymentId;
pub use runtime_state::RuntimeWalletState;
pub use staker_pool::{AccrualRecord, ConservationCheck, StakerPoolState};
pub use subaddress::SubaddressIndex;
pub use transfer::{FcmpPrecomputedPath, TransferDetails, SPENDABLE_AGE};
