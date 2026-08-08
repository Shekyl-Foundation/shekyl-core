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
//! or reordered — new states (the A4 clause-(2) `ExportedUnsigned`) are
//! appended after the last variant, so old files read forward with no
//! encoding migration. The discriminant-stability KAT below pins this;
//! treat a KAT failure as a broken promise, not a snapshot to refresh.
//! (`Abandoned` was the first such append, PR-SJ-3.)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Current send-journal block schema version.
///
/// Version `2` appends [`SendState::Abandoned`] (PR-SJ-3). The append is
/// wire-additive (the discriminant KAT pins every pre-existing encoding),
/// so the bump follows rule 42's snapshot pairing, not a byte-layout
/// break: pre-genesis, strict-equality gating stays the cheapest honest
/// policy, and the additive-read-forward load path is the A4 reopen's
/// concern (`docs/FOLLOWUPS.md` "A4 DECIDED").
pub const SEND_JOURNAL_BLOCK_VERSION: u32 = 2;

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
/// **Append-only** (see module docs): `ExportedUnsigned` (A4 reopen)
/// appends after the current tail.
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
    /// The user abandoned the send (`abandon_tx`, P3-4). Terminal for
    /// the display machine, with two deliberate non-terminal edges:
    /// a late confirmation still flips this to [`Self::Confirmed`]
    /// loudly (the reconciler's confirm edge — un-abandoned rather
    /// than staying wrong), and carried input locks stay re-derivable
    /// across a rescan wipe while [`SendRecord::lock_baseline`] is
    /// `Some` (P3-1: an abandoned-but-still-landable send keeps its
    /// self-link defence). Keys are retained (C2); after
    /// [`crate::WalletLedger::abandon_send`] migrates the
    /// `pending_tx_hashes` entry, this row **is** the I-2 live
    /// reference for the retained tx secret.
    Abandoned,
}

impl SendState {
    /// Whether a journal row in this state is itself an I-2 live
    /// reference for a retained `tx_keys` entry (P3-4): after
    /// `abandon_send` migrates the pending set, the journal row is what
    /// keeps the secret from being collected as an orphan.
    ///
    /// Distinct from [`Self::reapplies_f14_locks`]: `PresumedDead` still
    /// holds retention (keys / I-2) but never re-places F14 locks
    /// (baseline is cleared on the confirmed-absent release).
    #[must_use]
    pub const fn holds_tx_key_retention(self) -> bool {
        matches!(
            self,
            Self::Dispatched | Self::PresumedDead | Self::Abandoned
        )
    }

    /// Whether a journal row in this state re-derives carried-input F14
    /// locks when `lock_baseline` is `Some` (P3-1 re-application set:
    /// non-terminal-or-abandoned, minus states that have deliberately
    /// released).
    #[must_use]
    pub const fn reapplies_f14_locks(self) -> bool {
        matches!(self, Self::Dispatched | Self::Abandoned)
    }

    /// Whether the user-authored abandon edge may fire from this state
    /// (`Dispatched | PresumedDead → Abandoned`).
    #[must_use]
    pub const fn is_abandonable(self) -> bool {
        matches!(self, Self::Dispatched | Self::PresumedDead)
    }
}

/// Result of the user-authored abandon edge (`WALLET_SEND_RECORD.md`
/// P3-4 / SJ-DQ-8) on one journal row.
///
/// The edge is `Dispatched | PresumedDead → Abandoned`; everything else
/// is named rather than collapsed, because each shape is a different
/// user-facing answer (rule 82).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonEdge {
    /// The edge applied. `previous` is what a fail-closed rollback
    /// restores when the durable save of the abandon fails.
    Applied {
        /// State the row held before the edge.
        previous: SendState,
    },
    /// The row is already `Abandoned` — idempotent no-op (SJ-DQ-8).
    AlreadyAbandoned,
    /// No journal row exists for this txid.
    NotFound,
    /// The row's state forbids abandoning: `Confirmed` is on chain and
    /// `TerminalRejected` was never relayed — neither has anything left
    /// to give up on.
    Forbidden {
        /// The state that refused the edge.
        state: SendState,
    },
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

impl SendRecord {
    /// Σ recipient amounts — the row's sent total, excluding fee and
    /// change.
    ///
    /// The single owner of that definition: [`SendJournalBlock::record_dispatched`]
    /// enforces it at write time and read-side projections
    /// (`shekyl-wallet-rpc`'s OUTGOING `TransferView`) call it rather
    /// than re-implementing the fold, so the journal's sent total
    /// cannot acquire a second meaning.
    ///
    /// Returns `None` on overflow. A row written by `record_dispatched`
    /// can never overflow, so `None` means a row that did not come from
    /// the write path — a read side must surface that as an error, not
    /// panic on it (the wallet-rpc process is `panic = "abort"`).
    #[must_use]
    pub fn sent_amount(&self) -> Option<u64> {
        sum_recipient_amounts(&self.recipients)
    }
}

/// The one implementation of "Σ recipient amounts", shared by
/// [`SendRecord::sent_amount`] and the write path below so the sent
/// total cannot drift between writer and reader.
fn sum_recipient_amounts(recipients: &[SendRecipient]) -> Option<u64> {
    recipients
        .iter()
        .map(|r| r.amount)
        .try_fold(0u64, u64::checked_add)
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
        let sent =
            sum_recipient_amounts(&recipients).expect("recipient amounts sum without overflow");
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
    /// released tx.
    ///
    /// An `Abandoned` row keeps its user-authored state but the baseline
    /// clears the same way — the watchdog's confirmed-absent evidence is
    /// what releases an abandoned-from-`Dispatched` row's carried input
    /// locks, and without this arm the reconciler's re-derivation
    /// (P3-1's non-terminal-or-abandoned set) would re-place locks the
    /// release just cleared. No-op for every other state.
    pub fn mark_presumed_dead(&mut self, txid: &[u8; 32]) {
        if let Some(row) = self.rows.get_mut(txid) {
            match row.state {
                SendState::Dispatched => {
                    row.state = SendState::PresumedDead;
                    row.lock_baseline = None;
                }
                SendState::Abandoned => {
                    row.lock_baseline = None;
                }
                _ => {}
            }
        }
    }

    /// The user-authored abandon edge (`abandon_tx`, P3-4):
    /// `Dispatched | PresumedDead → Abandoned`, idempotent on an
    /// already-`Abandoned` row, refused from terminal states.
    ///
    /// State-edge only — the I-2 reference migration that pairs with it
    /// lives in [`crate::WalletLedger::abandon_send`], which is the
    /// production entry point. `lock_baseline` is deliberately
    /// **retained**: an abandoned-but-still-landable send keeps its
    /// carried-input locks (and their rescan re-derivation) until the
    /// watchdog's confirmed-absent evidence releases them
    /// ([`Self::mark_presumed_dead`]'s `Abandoned` arm) or a late
    /// confirmation supersedes them.
    pub fn mark_abandoned(&mut self, txid: &[u8; 32]) -> AbandonEdge {
        let Some(row) = self.rows.get_mut(txid) else {
            return AbandonEdge::NotFound;
        };
        if row.state.is_abandonable() {
            let previous = row.state;
            row.state = SendState::Abandoned;
            AbandonEdge::Applied { previous }
        } else if matches!(row.state, SendState::Abandoned) {
            AbandonEdge::AlreadyAbandoned
        } else {
            AbandonEdge::Forbidden { state: row.state }
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

    /// State-set predicates are the single owner of retention / lock /
    /// abandonability membership — keep them aligned with the design
    /// tables (I-2 vs I-5 vs P3-4 edge sources).
    #[test]
    fn send_state_set_predicates() {
        assert!(SendState::Dispatched.holds_tx_key_retention());
        assert!(SendState::PresumedDead.holds_tx_key_retention());
        assert!(SendState::Abandoned.holds_tx_key_retention());
        assert!(!SendState::Confirmed { height: 1 }.holds_tx_key_retention());
        assert!(!SendState::TerminalRejected.holds_tx_key_retention());

        assert!(SendState::Dispatched.reapplies_f14_locks());
        assert!(SendState::Abandoned.reapplies_f14_locks());
        assert!(
            !SendState::PresumedDead.reapplies_f14_locks(),
            "PresumedDead holds retention but never re-places locks"
        );
        assert!(!SendState::Confirmed { height: 1 }.reapplies_f14_locks());

        assert!(SendState::Dispatched.is_abandonable());
        assert!(SendState::PresumedDead.is_abandonable());
        assert!(!SendState::Abandoned.is_abandonable());
        assert!(!SendState::Confirmed { height: 1 }.is_abandonable());
        assert!(!SendState::TerminalRejected.is_abandonable());
    }

    /// Round-trip through postcard preserves every field of every state.
    #[test]
    fn postcard_round_trips_all_states() {
        for (i, state) in [
            SendState::Dispatched,
            SendState::Confirmed { height: 99 },
            SendState::TerminalRejected,
            SendState::PresumedDead,
            SendState::Abandoned,
        ]
        .into_iter()
        .enumerate()
        {
            let key = u8::try_from(i).expect("five variants fit in u8");
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
        let pins: [(SendState, &[u8]); 5] = [
            (SendState::Dispatched, &[0]),
            // variant index 1, then height 99 as a varint
            (SendState::Confirmed { height: 99 }, &[1, 99]),
            (SendState::TerminalRejected, &[2]),
            (SendState::PresumedDead, &[3]),
            // PR-SJ-3: appended after the v1 tail — the four pins above
            // are byte-identical to their v1 encodings, which is the
            // append-only promise this KAT exists to keep.
            (SendState::Abandoned, &[4]),
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

    /// The P3-4 abandon edge: applies from `Dispatched` and
    /// `PresumedDead`, is idempotent on `Abandoned`, refuses terminal
    /// states, and **retains** the lock baseline (the carried-input
    /// locks outlive the user's abandon until confirmed-absent evidence
    /// releases them).
    #[test]
    fn mark_abandoned_edges_and_idempotency() {
        let mut block = SendJournalBlock::empty();
        assert_eq!(block.mark_abandoned(&[9u8; 32]), AbandonEdge::NotFound);

        // From Dispatched, baseline retained.
        let dispatched = [1u8; 32];
        block
            .rows
            .insert(dispatched, sample_record(SendState::Dispatched, Some(43)));
        assert_eq!(
            block.mark_abandoned(&dispatched),
            AbandonEdge::Applied {
                previous: SendState::Dispatched
            }
        );
        assert_eq!(block.rows[&dispatched].state, SendState::Abandoned);
        assert_eq!(
            block.rows[&dispatched].lock_baseline,
            Some(43),
            "abandon retains the baseline — locks release on evidence, not intent"
        );
        assert_eq!(
            block.mark_abandoned(&dispatched),
            AbandonEdge::AlreadyAbandoned,
            "second abandon is an idempotent no-op (SJ-DQ-8)"
        );

        // From PresumedDead (the watchdog already cleared the baseline).
        let dead = [2u8; 32];
        block
            .rows
            .insert(dead, sample_record(SendState::PresumedDead, None));
        assert_eq!(
            block.mark_abandoned(&dead),
            AbandonEdge::Applied {
                previous: SendState::PresumedDead
            }
        );
        assert_eq!(block.rows[&dead].state, SendState::Abandoned);

        // Terminal states refuse.
        let confirmed = [3u8; 32];
        block.rows.insert(
            confirmed,
            sample_record(SendState::Confirmed { height: 99 }, None),
        );
        assert_eq!(
            block.mark_abandoned(&confirmed),
            AbandonEdge::Forbidden {
                state: SendState::Confirmed { height: 99 }
            }
        );
        let rejected = [4u8; 32];
        block
            .rows
            .insert(rejected, sample_record(SendState::TerminalRejected, None));
        assert_eq!(
            block.mark_abandoned(&rejected),
            AbandonEdge::Forbidden {
                state: SendState::TerminalRejected
            }
        );
    }

    /// The watchdog's confirmed-absent release on an `Abandoned` row
    /// clears the baseline (so the reconciler never re-locks released
    /// inputs) but never overwrites the user-authored display state.
    #[test]
    fn presumed_dead_release_clears_abandoned_baseline_keeps_state() {
        let mut block = SendJournalBlock::empty();
        let txid = [5u8; 32];
        block
            .rows
            .insert(txid, sample_record(SendState::Abandoned, Some(43)));
        block.mark_presumed_dead(&txid);
        assert_eq!(block.rows[&txid].state, SendState::Abandoned);
        assert_eq!(block.rows[&txid].lock_baseline, None);
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
