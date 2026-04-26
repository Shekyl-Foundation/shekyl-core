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
//! - [`LedgerBlock`] — the persisted scanner-derived ledger (transfers, tip, reorg
//!   window). Inherent methods supply read-only queries plus the small set of
//!   mutators that touch only transfer state.
//! - [`LedgerIndexes`] — runtime-only lookup indexes plus the staker-pool aggregate.
//!   Rebuilt at wallet open from `LedgerBlock` + scanner replay; never persisted.
//!   See [`ledger_indexes`] for the full surface and the invariant that pins it
//!   there.
//!
//! The serialization-format policy for this crate is pinned by
//! `.cursor/rules/42-serialization-policy.mdc` (added in Commit 2n): the ledger blocks
//! defined here use `postcard` for on-disk storage; metadata (identity + settings) lives
//! in [`shekyl_crypto_pq::wallet_state`] and uses JSON.

pub mod bookkeeping_block;
pub mod error;
pub mod invariants;
pub mod ledger_block;
pub mod ledger_indexes;
pub mod local_label;
pub mod payment_id;
pub mod safety_constants;
pub mod schema_snapshot;
pub mod serde_helpers;
pub mod staker_pool;
pub mod subaddress;
pub mod sync_state_block;
pub mod transfer;
pub mod tx_meta_block;
pub mod wallet_ledger;

pub use bookkeeping_block::{
    AddressBookEntry, BookkeepingBlock, SubaddressLabels, BOOKKEEPING_BLOCK_VERSION,
};
pub use error::WalletLedgerError;
pub use ledger_block::{
    BlockchainTip, LedgerBlock, ReorgBlocks, DEFAULT_REORG_BLOCKS_CAPACITY, LEDGER_BLOCK_VERSION,
};
pub use ledger_indexes::LedgerIndexes;
pub use local_label::{LocalLabel, SecretStr};
pub use payment_id::PaymentId;
pub use safety_constants::NetworkSafetyConstants;
pub use staker_pool::{AccrualRecord, ConservationCheck, StakerPoolState};
pub use subaddress::SubaddressIndex;
pub use sync_state_block::{SyncStateBlock, SYNC_STATE_BLOCK_VERSION};
pub use transfer::{FcmpPrecomputedPath, TransferDetails, SPENDABLE_AGE};
pub use tx_meta_block::{
    ScannedPoolTx, TxMetaBlock, TxSecretKey, TxSecretKeys, TX_META_BLOCK_VERSION,
};
pub use wallet_ledger::{WalletLedger, WALLET_LEDGER_FORMAT_VERSION};
