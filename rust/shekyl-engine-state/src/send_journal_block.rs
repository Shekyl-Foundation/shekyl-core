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
//! awaiting-confirmation lock set is a **derived view** of those facts
//! ([`SendJournalBlock::spend_locks`], PR-SJ-1b) — never a second
//! persisted representation on
//! [`TransferDetails`](crate::transfer::TransferDetails).
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

/// The wallet's own outputs that must not be spent again yet, keyed by
/// `global_output_index`: for each, a transaction spending it is already
/// on the wire and has not confirmed. Consumed by balance, spendability,
/// and selection in place of the retired
/// `TransferDetails::awaiting_confirmation` field.
///
/// Selecting a locked output would build a second transaction bearing
/// the same key image. Both would be publicly linkable as coming from
/// one wallet — the §7.1 self-link artifact — and only one could ever be
/// mined. This set is what stops that.
///
/// The design spec calls this the *F14 awaiting-confirmation lock*
/// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2.6). That tag is a
/// cross-reference and stays in prose; it is deliberately not the type
/// name, which has to say what is locked and why to a reader who has
/// never opened the spec — and which would start lying if the spec ever
/// renumbers.
///
/// **A newtype, deliberately, and with no `Default`** (PR-SJ-1b
/// review): while the lock rode on [`crate::TransferDetails`] every
/// consumer got the defence for free. Once it became a parameter, a
/// plain `BTreeMap` alias would have let any caller satisfy the type
/// with `&Default::default()` — a lock-blind map that compiles, reads as
/// innocuous, and silently re-offers an output whose spend is already on
/// the wire. Sealing the field so that
/// [`SendJournalBlock::spend_locks`] is the *only* way
/// to obtain a value makes "I forgot the locks" unrepresentable instead
/// of merely discouraged; a caller with no journal in scope must write
/// `SendJournalBlock::empty().spend_locks()` and say so
/// out loud.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InFlightSpendLocks(BTreeMap<u64, crate::transfer::AwaitingConfirmation>);

/// Every accessor is `#[inline]`, and that is load-bearing rather than
/// decorative. [`crate::WalletLedger::spendable_outputs`] and the
/// scanner's `BalanceSummary::compute` call [`InFlightSpendLocks::contains`]
/// **once per transfer row**, from a different crate. The `BTreeMap`
/// alias these replaced was generic, so its `contains_key` instantiated
/// in — and inlined into — the caller. A bare inherent method on a
/// concrete newtype does not: without the attribute each row pays a
/// real cross-crate call, and `hot_path_bench_balance_compute` measured
/// that at **+65% instructions** at every fixture size (the sizes scale,
/// so a constant setup cost cannot explain it). Sealing the type must
/// not cost anything at runtime; if a new accessor lands on the
/// per-row path, it is `#[inline]` too.
impl InFlightSpendLocks {
    /// Whether the output at `gindex` has a network-exposed spend
    /// awaiting confirmation — the §7.1 self-link check.
    #[inline]
    #[must_use]
    pub fn contains(&self, gindex: u64) -> bool {
        self.0.contains_key(&gindex)
    }

    /// The lock covering `gindex`, if any.
    #[inline]
    #[must_use]
    pub fn get(&self, gindex: u64) -> Option<&crate::transfer::AwaitingConfirmation> {
        self.0.get(&gindex)
    }

    /// How many outputs are locked.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no output is locked.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

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
    /// The input's amount in atomic units — part of the SJ-DQ-1 full row.
    /// Read only at write time (the `change_amount` derivation); no live
    /// reader consumes the persisted value yet, and there is no display
    /// path — it is retained so the row is complete for a future OUTGOING
    /// detail projection (the amount is our own output, already known to
    /// this wallet, so storing it leaks nothing new).
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
    /// The F14 locks were released without a confirmation: the tx is
    /// presumed dead. Two entry points, both via
    /// [`SendJournalBlock::mark_presumed_dead`] — the watchdog's
    /// confirmed-absent horizon, and the reconciler's evidence-bound
    /// release when the ledger refutes the send outright
    /// ([`crate::WalletLedger::reconcile_send_journal`] step 3).
    /// **Display state** (P3-1/P3-4): keys and the I-2 reference are
    /// retained; a late confirmation flips this to [`Self::Confirmed`]
    /// loudly.
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
    /// Distinct from [`Self::locks_carried_inputs`]: `PresumedDead` still
    /// holds retention (keys / I-2) but never locks inputs — its
    /// baseline was cleared by the release.
    #[must_use]
    pub const fn holds_tx_key_retention(self) -> bool {
        matches!(
            self,
            Self::Dispatched | Self::PresumedDead | Self::Abandoned
        )
    }

    /// Whether a row in this state locks the inputs it carried, given a
    /// stamped `lock_baseline` — i.e. whether its spend is still on the
    /// wire and unsettled, so re-selecting those inputs would build a
    /// same-key-image second transaction
    /// ([`InFlightSpendLocks`]). P3-1's set: non-terminal-or-abandoned,
    /// minus states that have deliberately released.
    #[must_use]
    pub const fn locks_carried_inputs(self) -> bool {
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
    /// (`Σ inputs − Σ recipients − fee`, computed at dispatch). Part of the
    /// SJ-DQ-1 full row: replay cannot recover the split, so it is stored —
    /// no live reader consumes it yet, awaiting the OUTGOING detail
    /// projection (SA-4 keeps it for that reason, not a dead-field delete).
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
        crate::version_gate::gate_version(
            self.block_version,
            "send_journal",
            SEND_JOURNAL_BLOCK_VERSION,
        )
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

    /// Release a send that will never confirm: display-state flip and
    /// clear the baseline, which drops the row's carried inputs from
    /// [`Self::spend_locks`] and from the watchdog's held
    /// projection.
    ///
    /// Two callers, one meaning — "the wait is over without a
    /// confirmation." The watchdog reaches here from its confirmed-absent
    /// horizon (`DAEMON_SUBMIT_VERDICT.md` §2.6 invariant 2); the merge
    /// reconciler reaches here when the ledger *refutes* the send
    /// ([`crate::WalletLedger::reconcile_send_journal`] step 3). Neither
    /// authorizes a rebuild (§2.6 invariant 3).
    ///
    /// An `Abandoned` row keeps its user-authored state but the baseline
    /// clears the same way: releasing evidence is what ends an
    /// abandoned-from-`Dispatched` row's carried input locks, and
    /// without this arm the derivation (P3-1's
    /// non-terminal-or-abandoned set) would keep re-placing locks the
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

    /// Derive the F14 awaiting-confirmation lock set from journal facts
    /// — the **single owner** of the lock-derivation rule (PR-SJ-1b,
    /// `WALLET_SEND_RECORD.md` C2/P3-1a): a carried input of any row in
    /// a [`SendState::locks_carried_inputs`] state with a stamped
    /// `lock_baseline` is locked, keyed by the input's
    /// `global_output_index`.
    ///
    /// Also the **only constructor** of [`InFlightSpendLocks`] — sole ownership of
    /// the rule is enforced by the type, not by convention (see the
    /// [`InFlightSpendLocks`] docs for why an empty map must be spelled
    /// `SendJournalBlock::empty().spend_locks()`).
    ///
    /// The map says nothing about spent-ness: confirmed evidence
    /// supersedes a lock, and every consumer checks `spent` first (the
    /// same precedence the merge reconciler applied when the field
    /// existed). Cost is `O(live sends × their inputs)` — in-flight
    /// sends are few, so consumers derive on demand rather than
    /// maintaining a second cache (the cache *was* the retired field).
    ///
    /// Determinism: rows iterate in `BTreeMap` txid order and the first
    /// claim on a gindex wins. Two live rows carrying the same input
    /// cannot arise from the build path (locked inputs are never
    /// selected — the SJ-DQ-4 self-link defence this map implements),
    /// so the tie-break is a determinism guarantee, not a policy.
    pub fn spend_locks(&self) -> InFlightSpendLocks {
        let mut locks: BTreeMap<u64, crate::transfer::AwaitingConfirmation> = BTreeMap::new();
        for (txid, row) in &self.rows {
            if !row.state.locks_carried_inputs() {
                continue;
            }
            let Some(accepted_at_height) = row.lock_baseline else {
                continue;
            };
            for inp in &row.inputs {
                locks
                    .entry(inp.gindex)
                    .or_insert(crate::transfer::AwaitingConfirmation {
                        tx_hash: shekyl_types::TxHash::from_bytes(*txid),
                        accepted_at_height,
                    });
            }
        }
        InFlightSpendLocks(locks)
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
    /// tables (I-2 retention vs F14 lock re-application vs P3-4 edge
    /// sources).
    #[test]
    fn send_state_set_predicates() {
        assert!(SendState::Dispatched.holds_tx_key_retention());
        assert!(SendState::PresumedDead.holds_tx_key_retention());
        assert!(SendState::Abandoned.holds_tx_key_retention());
        assert!(!SendState::Confirmed { height: 1 }.holds_tx_key_retention());
        assert!(!SendState::TerminalRejected.holds_tx_key_retention());

        assert!(SendState::Dispatched.locks_carried_inputs());
        assert!(SendState::Abandoned.locks_carried_inputs());
        assert!(
            !SendState::PresumedDead.locks_carried_inputs(),
            "PresumedDead holds retention but never re-places locks"
        );
        assert!(!SendState::Confirmed { height: 1 }.locks_carried_inputs());

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

    /// The derived F14 lock set contains exactly the carried inputs of
    /// baseline-stamped rows in re-application states: `Dispatched` and
    /// `Abandoned` lock; `PresumedDead` (released — baseline `None` by
    /// construction, planted here to prove the state predicate alone
    /// also excludes), `Confirmed`, `TerminalRejected`, and un-stamped
    /// rows do not.
    #[test]
    fn derive_in_flight_spend_locks_covers_exactly_the_locking_set() {
        let mut block = SendJournalBlock::empty();
        let dispatched = [1u8; 32];
        let abandoned = [2u8; 32];
        for (txid, state, baseline, gindex) in [
            (dispatched, SendState::Dispatched, Some(25), 100),
            (abandoned, SendState::Abandoned, Some(30), 101),
            ([3u8; 32], SendState::PresumedDead, Some(35), 102),
            (
                [4u8; 32],
                SendState::Confirmed { height: 40 },
                Some(20),
                103,
            ),
            ([5u8; 32], SendState::TerminalRejected, Some(20), 104),
            ([6u8; 32], SendState::Dispatched, None, 105), // pre-verdict
        ] {
            let mut record = sample_record(state, baseline);
            record.inputs = vec![SendInputRef { gindex, amount: 1 }];
            block.rows.insert(txid, record);
        }

        let locks = block.spend_locks();
        assert_eq!(
            locks.len(),
            2,
            "exactly the baseline-stamped re-application rows lock"
        );
        for (gindex, txid, baseline) in [(100, dispatched, 25), (101, abandoned, 30)] {
            let lock = locks
                .get(gindex)
                .unwrap_or_else(|| panic!("gindex {gindex} must be locked"));
            assert_eq!(lock.tx_hash.to_bytes(), txid);
            assert_eq!(lock.accepted_at_height, baseline);
        }
    }

    /// Derivation is deterministic and pure: two calls over the same
    /// block yield identical maps, and a multi-input row locks each of
    /// its carried inputs under its own txid.
    #[test]
    fn derive_in_flight_spend_locks_is_deterministic_and_covers_all_inputs() {
        let mut block = SendJournalBlock::empty();
        let txid = [7u8; 32];
        let mut record = sample_record(SendState::Dispatched, Some(50));
        record.inputs = vec![
            SendInputRef {
                gindex: 200,
                amount: 1,
            },
            SendInputRef {
                gindex: 201,
                amount: 2,
            },
        ];
        block.rows.insert(txid, record);

        let a = block.spend_locks();
        let b = block.spend_locks();
        assert_eq!(a, b, "derivation is pure");
        assert_eq!(a.len(), 2);
        for g in [200, 201] {
            let lock = a
                .get(g)
                .unwrap_or_else(|| panic!("gindex {g} must be locked"));
            assert_eq!(lock.tx_hash.to_bytes(), txid);
            assert_eq!(lock.accepted_at_height, 50);
        }
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
