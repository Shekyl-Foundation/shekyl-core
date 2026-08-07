// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Send journal — dispatch-authored outgoing history (`WALLET_SEND_RECORD.md`).
//!
//! Sixth `.wallet`-side ledger block (after [`LedgerBlock`],
//! [`BookkeepingBlock`], [`TxMetaBlock`], [`SyncStateBlock`], and
//! [`StakingBlock`]). Lives **outside** [`LedgerBlock`] by construction
//! (C7): rescan rebuilds only scan-derived state and never needs to
//! "remember" to preserve these rows.
//!
//! Rows are written at dispatch beside [`WalletLedger::record_retained_tx_key`]
//! and flip through the append-only [`SendJournalState`] machine as
//! refresh / watchdog / user edges fire. [`SendJournalState`] is
//! **append-only** (A4 clause-(2)): a future `ExportedUnsigned` variant
//! (and its field) must land as a new enum arm — old files read forward
//! with no version break.
//!
//! [`LedgerBlock`]: crate::ledger_block::LedgerBlock
//! [`BookkeepingBlock`]: crate::bookkeeping_block::BookkeepingBlock
//! [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
//! [`SyncStateBlock`]: crate::sync_state_block::SyncStateBlock
//! [`StakingBlock`]: crate::staking_block::StakingBlock
//! [`WalletLedger::record_retained_tx_key`]: crate::wallet_ledger::WalletLedger::record_retained_tx_key

use serde::{Deserialize, Serialize};
use shekyl_types::TxHash;
use shekyl_units::AtomicUnits;

use crate::error::WalletLedgerError;

/// Schema version of the send-journal block. PR-SJ-1 ships version `1`.
pub const SEND_JOURNAL_BLOCK_VERSION: u32 = 1;

/// Marker: types that may live inside [`crate::ledger_block::LedgerBlock`].
///
/// C7 (`WALLET_SEND_RECORD.md`): `LedgerBlock` holds only scan-derived
/// types. Dispatch-authored journal rows deliberately do **not**
/// implement this trait — putting one in `LedgerBlock` is a compile
/// error at any site that requires `T: ScanDerived`.
pub trait ScanDerived {}

impl ScanDerived for crate::transfer::TransferDetails {}
impl ScanDerived for crate::ledger_block::BlockchainTip {}

/// One payee of a dispatched send (SJ-DQ-1: full row, addresses stored).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SendRecipient {
    /// Encoded destination address as the wallet built it.
    pub address: String,
    /// Amount in atomic units (realized).
    pub amount: AtomicUnits,
}

/// Append-only lifecycle of a journal row.
///
/// **Append-only encoding pin (A4 clause-(2)):** new variants (e.g. a
/// future `ExportedUnsigned { .. }`) MUST be added at the end. Existing
/// discriminants are stable; renaming or reordering is a version break.
/// The discriminant-stability KAT in this module's tests pins the
/// currently-shipped arms.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum SendJournalState {
    /// Bytes left for the daemon; network exposure may have begun.
    Dispatched,
    /// Refresh observed the spend on-chain at `height`.
    Confirmed {
        /// Confirming height (refresh-authored).
        height: u64,
    },
    /// Definite daemon refusal — never relayed under single-egress.
    TerminalRejected,
    /// Watchdog confirmed-absent horizon (display / abandon precursor).
    PresumedDead,
    /// User abandoned; I-2 live reference migrates onto this row (PR-SJ-3).
    Abandoned,
}

/// Durable outgoing-send record (SJ-DQ-1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SendJournalRow {
    /// Canonical txid of the dispatched bytes.
    pub txid: TxHash,
    /// Lifecycle state.
    pub state: SendJournalState,
    /// Payees as built (addresses + amounts).
    pub recipients: Vec<SendRecipient>,
    /// Realized fee of the built tx (never an estimator prediction).
    pub fee: AtomicUnits,
    /// Change amount (atomic); address excluded (re-randomizes).
    pub change: AtomicUnits,
    /// Key images of the inputs at dispatch (stable identity across
    /// rescan — P3-1 re-application joins on these, not transfer indices).
    pub input_key_images: Vec<[u8; 32]>,
    /// Wallet height when the row was written.
    pub dispatched_at_height: u64,
    /// Optional FA-10 request rid echoed on an outbound label, if any.
    pub echoed_request_rid: Option<u64>,
}

/// Dispatch-authored send journal. Preserved across rescan by living
/// outside [`crate::ledger_block::LedgerBlock`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SendJournalBlock {
    /// Per-block schema version. Always [`SEND_JOURNAL_BLOCK_VERSION`].
    pub block_version: u32,
    /// Rows keyed by txid order of insertion (BTreeMap for stable postcard).
    pub rows: std::collections::BTreeMap<[u8; 32], SendJournalRow>,
}

impl Default for SendJournalBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl SendJournalBlock {
    /// Empty journal pinned to the current version.
    pub fn empty() -> Self {
        Self {
            block_version: SEND_JOURNAL_BLOCK_VERSION,
            rows: std::collections::BTreeMap::new(),
        }
    }

    /// Insert or replace a row keyed by its txid bytes.
    pub fn upsert(&mut self, row: SendJournalRow) {
        self.rows.insert(row.txid.to_bytes(), row);
    }

    /// Borrow the row for a txid, if any.
    pub fn get(&self, txid: &[u8; 32]) -> Option<&SendJournalRow> {
        self.rows.get(txid)
    }

    /// Mutable borrow of the row for a txid, if any.
    pub fn get_mut(&mut self, txid: &[u8; 32]) -> Option<&mut SendJournalRow> {
        self.rows.get_mut(txid)
    }

    /// Iterate rows in txid order.
    pub fn iter(&self) -> impl Iterator<Item = &SendJournalRow> {
        self.rows.values()
    }

    /// True when any row is still in a non-terminal (in-flight) state.
    ///
    /// Used by rescan re-application (P3-1); the `-29202` unconfirmed
    /// half retires in favor of this journal-carried set.
    pub fn has_unconfirmed(&self) -> bool {
        self.rows.values().any(|r| {
            matches!(
                r.state,
                SendJournalState::Dispatched | SendJournalState::PresumedDead
            )
        })
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize and refuse version mismatch.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let block: Self = postcard::from_bytes(bytes)?;
        block.check_version()?;
        Ok(block)
    }

    /// Version gate for the aggregator fan-out.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        if self.block_version != SEND_JOURNAL_BLOCK_VERSION {
            return Err(WalletLedgerError::UnsupportedBlockVersion {
                block: "send_journal",
                file: self.block_version,
                binary: SEND_JOURNAL_BLOCK_VERSION,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_types::TxHash;

    fn sample_row() -> SendJournalRow {
        SendJournalRow {
            txid: TxHash::from_bytes([0x11; 32]),
            state: SendJournalState::Dispatched,
            recipients: vec![SendRecipient {
                address: "SkTestAddr".into(),
                amount: AtomicUnits::from_raw(1_000),
            }],
            fee: AtomicUnits::from_raw(50),
            change: AtomicUnits::from_raw(100),
            input_key_images: vec![[0xAA; 32], [0xBB; 32]],
            dispatched_at_height: 42,
            echoed_request_rid: None,
        }
    }

    #[test]
    fn empty_block_roundtrips_and_pins_version() {
        let b = SendJournalBlock::empty();
        assert_eq!(b.block_version, SEND_JOURNAL_BLOCK_VERSION);
        assert!(b.rows.is_empty());
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = SendJournalBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_roundtrips() {
        let mut b = SendJournalBlock::empty();
        b.upsert(sample_row());
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = SendJournalBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
        assert!(back.has_unconfirmed());
    }

    #[test]
    fn wrong_version_is_refused() {
        let mut b = SendJournalBlock::empty();
        b.block_version = 999;
        let bytes = b.to_postcard_bytes().expect("serialize");
        match SendJournalBlock::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "send_journal");
                assert_eq!(file, 999);
                assert_eq!(binary, SEND_JOURNAL_BLOCK_VERSION);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A4 clause-(2): shipped discriminants stay stable so a future
    /// `ExportedUnsigned` arm can append without a version break.
    #[test]
    fn send_journal_state_discriminants_are_stable() {
        // postcard encodes external enums as a varint discriminant then
        // fields. Pin the leading byte of each shipped arm.
        let cases: &[(SendJournalState, u8)] = &[
            (SendJournalState::Dispatched, 0),
            (SendJournalState::Confirmed { height: 1 }, 1),
            (SendJournalState::TerminalRejected, 2),
            (SendJournalState::PresumedDead, 3),
            (SendJournalState::Abandoned, 4),
        ];
        for (state, want) in cases {
            let bytes = postcard::to_allocvec(state).expect("ser");
            assert_eq!(
                bytes[0], *want,
                "discriminant drift for {state:?}: got {bytes:02x?}",
            );
        }
    }

    #[test]
    fn confirmed_clears_unconfirmed_flag() {
        let mut b = SendJournalBlock::empty();
        let mut row = sample_row();
        row.state = SendJournalState::Confirmed { height: 99 };
        b.upsert(row);
        assert!(!b.has_unconfirmed());
    }
}
