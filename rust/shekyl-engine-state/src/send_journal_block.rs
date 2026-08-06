// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Send-journal block — the wallet's dispatch-authored record of its own
//! sends (`docs/design/WALLET_SEND_RECORD.md`, ratified R1 passes 1–3).
//!
//! Sixth `.wallet`-side ledger block, and the first whose whole purpose is
//! **dispatch-authored** state: everything in here was written by this
//! wallet at or after tx dispatch and is *not* rebuildable from a chain
//! replay (recipients and the per-recipient split are cryptographically
//! unrecoverable under CT — §1 recoverability table). It therefore lives
//! outside [`LedgerBlock`](crate::ledger_block::LedgerBlock) and survives
//! `reset_scan_derived_state` **by construction** (C6/C7): rescan
//! reconstructs `LedgerBlock`; nothing needs to remember to preserve this.
//!
//! # Ownership (C2)
//!
//! The journal **owns** the dispatch facts: the selected input set, the
//! realized recipients, the realized fee (the wire tx's cleartext fee —
//! never an estimator output, roadmap R-4), and the lock baseline. The F14
//! awaiting-confirmation state on
//! [`TransferDetails`](crate::transfer::TransferDetails) is a **derived
//! cache** of these facts (the `LedgerIndexes` precedent): PR-SJ-1 keeps
//! the live field and proves equivalence
//! ([`crate::invariants`] `send-journal-lock-equivalence`); PR-SJ-1b
//! (pre-committed) retires the field.
//!
//! # State machine (append-only)
//!
//! [`SendState`] is **append-only**: variants are never removed, renamed,
//! or reordered — new states (the A4 clause-(2) `ExportedUnsigned`, the
//! PR-SJ-3 `Abandoned`) are appended after the last variant, so old files
//! read forward with no version break and no migration. The
//! discriminant-stability KAT below pins this; treat a KAT failure as a
//! broken promise, not a snapshot to refresh.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Current send-journal block schema version.
pub const SEND_JOURNAL_BLOCK_VERSION: u32 = 1;

/// One recipient of a recorded send, exactly as realized in the built
/// transaction (SJ-DQ-1: full row, addresses stored, no knob — settled by
/// the envelope frame, C1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SendRecipient {
    /// Shekyl-encoded destination address.
    pub address: String,
    /// Amount sent to this recipient, in atomic units.
    pub amount: u64,
}

/// One carried input of a recorded send — the wipe-stable identifier the
/// rescan re-derivation joins on (SJ-DQ-4 / P3-1: `global_output_index`
/// survives a `LedgerBlock` reconstruction; row indices do not).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SendInputRef {
    /// The input's global output index on chain.
    pub gindex: u64,
    /// The input's amount in atomic units (change derivation +
    /// display; our own output, already known to this wallet).
    pub amount: u64,
}

/// Lifecycle state of a recorded send.
///
/// **Append-only** (see module docs): `Abandoned` (PR-SJ-3) and
/// `ExportedUnsigned` (A4 reopen) append after the current tail.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum SendState {
    /// Dispatched to the daemon; not yet observed on chain. The F14
    /// lock exists iff [`SendRecord::lock_baseline`] is `Some`.
    Dispatched,
    /// Refresh observed the spend on chain at `height`
    /// (refresh-authoritative — never set from a daemon verdict, C3).
    Confirmed {
        /// Height the spend was observed at.
        height: u64,
    },
    /// The daemon definitively refused the dispatch (terminal verdict);
    /// the tx never relayed (single-egress). Kept as failed-send
    /// history (rule 82).
    TerminalRejected,
    /// The watchdog's confirmed-absent horizon released the F14 locks:
    /// the tx is presumed dead. **Display state** (P3-1/P3-4): keys and
    /// the I-2 reference are retained; a late confirmation flips this
    /// to [`Self::Confirmed`] loudly.
    PresumedDead,
}

/// One recorded send, keyed by canonical txid in
/// [`SendJournalBlock::rows`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SendRecord {
    /// Wallet synced height at dispatch.
    pub dispatched_at_height: u64,
    /// Realized fee of the built transaction, in atomic units — parsed
    /// from the wire tx (the same cleartext value the chain sees),
    /// never an estimator output (roadmap R-4).
    pub fee: u64,
    /// Realized recipients, in transaction order.
    pub recipients: Vec<SendRecipient>,
    /// Change returned to this wallet, in atomic units
    /// (`Σ inputs − Σ recipients − fee`, computed at dispatch).
    pub change_amount: u64,
    /// The dispatched input set — carried across a rescan wipe so the
    /// F14 locks re-derive (SJ-DQ-4 inversion).
    pub inputs: Vec<SendInputRef>,
    /// F14 lock baseline: `Some(height)` once an accepting verdict
    /// placed the lock (fresh accept → wallet height at accept;
    /// `AlreadyInChain` → the daemon-claimed height, F40 §2.5(a));
    /// `None` before any accepting verdict and after a watchdog
    /// release. Lock re-derivation applies iff `Some`.
    pub lock_baseline: Option<u64>,
    /// Lifecycle state.
    pub state: SendState,
}

/// The send-journal block: dispatch-authored send records keyed by
/// canonical txid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SendJournalBlock {
    /// Per-block schema version. Always [`SEND_JOURNAL_BLOCK_VERSION`]
    /// on construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Send records by canonical txid.
    #[serde(default = "BTreeMap::new")]
    pub rows: BTreeMap<[u8; 32], SendRecord>,
}

impl SendJournalBlock {
    /// Fresh, empty block at the current version.
    pub fn empty() -> Self {
        Self {
            block_version: SEND_JOURNAL_BLOCK_VERSION,
            rows: BTreeMap::new(),
        }
    }

    /// Enforce the block version gate at load.
    pub fn check_version(&self) -> Result<(), crate::error::WalletLedgerError> {
        if self.block_version != SEND_JOURNAL_BLOCK_VERSION {
            return Err(crate::error::WalletLedgerError::UnsupportedBlockVersion {
                block: "send_journal",
                file: self.block_version,
                binary: SEND_JOURNAL_BLOCK_VERSION,
            });
        }
        Ok(())
    }

    /// Birth a dispatch-authored row (pin-1 form: before the bytes can
    /// leave for the daemon). `change_amount` is the exact remainder
    /// `Σ inputs − Σ recipients − fee`; a wallet-built send that does
    /// not balance is a build-path defect, not a runtime condition.
    pub fn record_dispatched(
        &mut self,
        txid: [u8; 32],
        dispatched_at_height: u64,
        fee: u64,
        recipients: Vec<SendRecipient>,
        inputs: Vec<SendInputRef>,
    ) {
        let sent = recipients
            .iter()
            .map(|r| r.amount)
            .try_fold(0u64, u64::checked_add)
            .expect("recipient amounts sum without overflow");
        let input_total = inputs
            .iter()
            .map(|i| i.amount)
            .try_fold(0u64, u64::checked_add)
            .expect("input amounts sum without overflow");
        let change_amount = input_total
            .checked_sub(sent)
            .and_then(|v| v.checked_sub(fee))
            .expect("wallet-built send balances: inputs >= recipients + fee");
        self.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height,
                fee,
                recipients,
                change_amount,
                inputs,
                lock_baseline: None,
                state: SendState::Dispatched,
            },
        );
    }

    /// Record the F14 lock baseline on the owning row. Returns `false`
    /// when no row exists (dispatch always births one first).
    pub fn stamp_lock_baseline(&mut self, txid: &[u8; 32], baseline: u64) -> bool {
        let Some(row) = self.rows.get_mut(txid) else {
            return false;
        };
        row.lock_baseline = Some(baseline);
        true
    }

    /// Terminal refusal: keep the row as failed-send history (rule 82).
    pub fn mark_terminal_rejected(&mut self, txid: &[u8; 32]) {
        if let Some(row) = self.rows.get_mut(txid) {
            row.state = SendState::TerminalRejected;
        }
    }

    /// Retryable refusal: the dispatch is undone — row removed, re-born
    /// on the next submit (mirrors the retention record).
    pub fn undo_dispatch(&mut self, txid: &[u8; 32]) {
        self.rows.remove(txid);
    }

    /// Watchdog confirmed-absent release: display-state flip and clear
    /// the baseline so re-derivation never re-locks a deliberately
    /// released tx. No-op for non-`Dispatched` rows.
    pub fn mark_presumed_dead(&mut self, txid: &[u8; 32]) {
        if let Some(row) = self.rows.get_mut(txid) {
            if row.state == SendState::Dispatched {
                row.state = SendState::PresumedDead;
                row.lock_baseline = None;
            }
        }
    }
}

impl Default for SendJournalBlock {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(state: SendState, lock_baseline: Option<u64>) -> SendRecord {
        SendRecord {
            dispatched_at_height: 42,
            fee: 700,
            recipients: vec![SendRecipient {
                address: "shekyl1example".to_owned(),
                amount: 7_000,
            }],
            change_amount: 22_300,
            inputs: vec![SendInputRef {
                gindex: 11,
                amount: 30_000,
            }],
            lock_baseline,
            state,
        }
    }

    /// Round-trip through postcard preserves every field of every state.
    #[test]
    fn postcard_round_trips_all_states() {
        for (i, state) in [
            SendState::Dispatched,
            SendState::Confirmed { height: 99 },
            SendState::TerminalRejected,
            SendState::PresumedDead,
        ]
        .into_iter()
        .enumerate()
        {
            let key = u8::try_from(i).expect("four variants fit in u8");
            let mut block = SendJournalBlock::empty();
            block.rows.insert([key; 32], sample_record(state, Some(43)));
            let bytes = postcard::to_allocvec(&block).expect("serialize");
            let back: SendJournalBlock = postcard::from_bytes(&bytes).expect("deserialize");
            assert_eq!(back, block);
        }
    }

    /// Discriminant-stability KAT — the concrete form of the A4
    /// clause-(2) append-only pin. postcard encodes enum variants by
    /// declaration index (varint); these bytes are the on-disk promise
    /// that existing variants never move. Appending a new variant after
    /// the tail leaves every pinned encoding untouched; a KAT failure
    /// here means a reorder/removal — a broken promise, not a snapshot
    /// to refresh.
    #[test]
    fn send_state_discriminants_are_pinned() {
        let pins: [(SendState, &[u8]); 4] = [
            (SendState::Dispatched, &[0]),
            // variant index 1, then height 99 as a varint
            (SendState::Confirmed { height: 99 }, &[1, 99]),
            (SendState::TerminalRejected, &[2]),
            (SendState::PresumedDead, &[3]),
        ];
        for (state, expected) in pins {
            let bytes = postcard::to_allocvec(&state).expect("serialize");
            assert_eq!(
                bytes.as_slice(),
                expected,
                "SendState discriminant moved for {state:?} — append-only violated"
            );
        }
    }

    /// A v1 block with no rows deserializes from its minimal encoding —
    /// the forward-compat floor old files rest on.
    #[test]
    fn empty_block_round_trips() {
        let block = SendJournalBlock::empty();
        let bytes = postcard::to_allocvec(&block).expect("serialize");
        let back: SendJournalBlock = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(back.block_version, SEND_JOURNAL_BLOCK_VERSION);
        assert!(back.rows.is_empty());
    }

    /// Dispatch birth records the exact remainder as change; baseline
    /// starts unset so re-derivation stays off until an accepting verdict.
    #[test]
    fn record_dispatched_computes_change_and_starts_unlocked() {
        let mut block = SendJournalBlock::empty();
        let txid = [7u8; 32];
        block.record_dispatched(
            txid,
            42,
            700,
            vec![SendRecipient {
                address: "shekyl1example".to_owned(),
                amount: 7_000,
            }],
            vec![SendInputRef {
                gindex: 11,
                amount: 30_000,
            }],
        );
        let row = &block.rows[&txid];
        assert_eq!(row.change_amount, 22_300);
        assert_eq!(row.lock_baseline, None);
        assert_eq!(row.state, SendState::Dispatched);
        assert!(block.stamp_lock_baseline(&txid, 43));
        assert_eq!(block.rows[&txid].lock_baseline, Some(43));
        block.mark_presumed_dead(&txid);
        assert_eq!(block.rows[&txid].state, SendState::PresumedDead);
        assert_eq!(block.rows[&txid].lock_baseline, None);
        // PresumedDead is terminal for the release path; a late confirm
        // un-presumes via the reconciler, not by re-stamping here.
        block.mark_presumed_dead(&txid);
        assert_eq!(
            block.rows[&txid].state,
            SendState::PresumedDead,
            "mark_presumed_dead is a no-op once already released"
        );
        // Re-birth path: undo removes; a later dispatch inserts fresh.
        block.undo_dispatch(&txid);
        assert!(!block.rows.contains_key(&txid));
        assert!(!block.stamp_lock_baseline(&txid, 1));
    }

    #[test]
    fn mark_terminal_rejected_keeps_the_row() {
        let mut block = SendJournalBlock::empty();
        let txid = [8u8; 32];
        block.record_dispatched(
            txid,
            1,
            0,
            Vec::new(),
            vec![SendInputRef {
                gindex: 1,
                amount: 0,
            }],
        );
        block.mark_terminal_rejected(&txid);
        assert_eq!(block.rows[&txid].state, SendState::TerminalRejected);
        assert!(block.rows.contains_key(&txid));
    }
}
