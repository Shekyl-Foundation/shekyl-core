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
use shekyl_types::BlockHeight;

/// Current send-journal block schema version.
///
/// Version `2` appends [`SendState::Abandoned`] (PR-SJ-3). The append is
/// wire-additive (the discriminant KAT pins every pre-existing encoding),
/// so the bump follows rule 42's snapshot pairing, not a byte-layout
/// break: pre-genesis, strict-equality gating stays the cheapest honest
/// policy, and the additive-read-forward load path is the A4 reopen's
/// concern (`docs/FOLLOWUPS.md` "A4 DECIDED").
/// Version `3` (height-semantics Phase 2f): `dispatched_at_height` and
/// `SendState::Confirmed::height` are [`BlockHeight`]. Postcard bytes of
/// the transparent `u64` stay identical; the schema type-name change
/// still bumps.
/// Version `4` (2026-09-28): [`SendRecipient::rid`] — the payment request
/// a recipient's output answered, stored at dispatch as PR-SJ-1 ruled
/// (`WALLET_SEND_RECORD.md` §1), so "paid request #N" never needs the
/// trial re-derivation. A new field in a positional postcard struct;
/// strict-equality gating, pre-genesis, no migration.
/// Version `5` (2026-10-18): [`SendRecipient::destination`] replaces the
/// address string with [`SendDestination`], so a `stake_in` row records
/// that it funded this wallet's own persona; a persona has no address.
/// Strict-equality gating, pre-genesis, no migration.
/// Version `6` (2026-11-12, A19): [`SendRecord::tx_bytes`] — the signed,
/// network-exposed bytes, saved with the row at dispatch so a send whose
/// verdict a restart crossed can still be resent, by the user's decision
/// (`DAEMON_SUBMIT_VERDICT.md` §5.3). Strict-equality gating, pre-genesis,
/// no migration.
pub const SEND_JOURNAL_BLOCK_VERSION: u32 = 6;

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
pub struct InFlightSpendLocks(
    BTreeMap<shekyl_types::GlobalOutputIndex, crate::transfer::AwaitingConfirmation>,
);

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
    pub fn contains(&self, gindex: shekyl_types::GlobalOutputIndex) -> bool {
        self.0.contains_key(&gindex)
    }

    /// The lock covering `gindex`, if any.
    #[inline]
    #[must_use]
    pub fn get(
        &self,
        gindex: shekyl_types::GlobalOutputIndex,
    ) -> Option<&crate::transfer::AwaitingConfirmation> {
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

/// Where one output of a recorded send went — the counterparty fact the
/// journal alone holds (SJ-DQ-1). Persisted: variants are append-only, and
/// the discriminant KAT below pins each encoding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum SendDestination {
    /// The Shekyl-encoded address the user sent to.
    Address(String),
    /// This wallet funding its own active staking persona (`stake_in`).
    /// A persona has no address, and the row records the kind of
    /// destination, never the persona's keys.
    OwnPersonaFunding,
}

/// One recipient of a recorded send, exactly as realized in the built
/// transaction (SJ-DQ-1: full row, addresses stored, no knob — settled by
/// the envelope frame, C1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SendRecipient {
    /// Where this output went.
    pub destination: SendDestination,
    /// Amount sent to this recipient, in atomic units.
    pub amount: u64,
    /// The payment request this output answered — the `rid` echoed in its
    /// encrypted label (`TxRecipient::rid`) — or `None` for a sentinel
    /// label. Dispatch-authored like the rest of the row: the chain holds
    /// it only as ciphertext the payee can open.
    pub rid: Option<crate::PaymentRequestId>,
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
        height: BlockHeight,
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
    pub dispatched_at_height: BlockHeight,
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
    /// The signed transaction exactly as it left for the daemon, kept so
    /// the same bytes can be offered again: automatically within the
    /// session that dispatched them (the watchdog's resubmit-same-bytes
    /// probe), and only on the user's decision after a restart
    /// (`tx_resend`; `DAEMON_SUBMIT_VERDICT.md` §5.3).
    ///
    /// `Some` from dispatch while the send can still need them; `None`
    /// once the row has settled ([`SendJournalBlock::prune_settled_tx_bytes`])
    /// or the daemon refused it terminally. Deliberately not a load-time
    /// invariant: a `PresumedDead` row abandoned afterwards, or a reorg
    /// deeper than the margin, can leave a row that locks without bytes,
    /// and refusing to open the wallet over it would be worse than the
    /// watchdog's named alarm for it. The bytes are public once relayed;
    /// they sit in the sealed wallet file beside the tx secret, which is
    /// the more sensitive of the two.
    pub tx_bytes: Option<Vec<u8>>,
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
    /// `tx_bytes` are the signed bytes about to leave
    /// ([`SendRecord::tx_bytes`]).
    pub fn record_dispatched(
        &mut self,
        txid: [u8; 32],
        dispatched_at_height: BlockHeight,
        fee: u64,
        recipients: Vec<SendRecipient>,
        inputs: Vec<SendInputRef>,
        tx_bytes: Vec<u8>,
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
                tx_bytes: Some(tx_bytes),
            },
        );
    }

    /// The saved bytes of the send `txid`, while it still holds them.
    #[must_use]
    pub fn tx_bytes(&self, txid: &[u8; 32]) -> Option<&[u8]> {
        self.rows.get(txid)?.tx_bytes.as_deref()
    }

    /// Place the F14 lock on every `Dispatched` row that has none: a
    /// dispatch whose verdict was never recorded, because the process
    /// ended between the dispatch save and the verdict (a crash, a kill,
    /// or an ambiguous verdict nobody resolved before close).
    ///
    /// Called once when the wallet opens, before anything can submit, so
    /// no row stamped here is in flight in this session. The bytes may
    /// already be on the network, so the inputs are locked as an accept
    /// would have locked them (§2.6 fund safety first: no selectable
    /// window for a same-key-image second spend, §7.1), baselined at the
    /// row's own dispatch height. The watchdog then sees the row as held
    /// and, because it was dispatched before this session, asks the user
    /// rather than resending (§5.3). Returns the number of rows stamped.
    pub fn lock_unverdicted_dispatches(&mut self) -> usize {
        let mut stamped = 0;
        for row in self.rows.values_mut() {
            if matches!(row.state, SendState::Dispatched) && row.lock_baseline.is_none() {
                row.lock_baseline = Some(row.dispatched_at_height.to_raw());
                stamped += 1;
            }
        }
        stamped
    }

    /// Drop the saved bytes of every row that can no longer need them,
    /// returning how many were dropped.
    ///
    /// A row keeps its bytes while its state [locks its
    /// inputs](SendState::locks_carried_inputs) — `Dispatched` (in
    /// flight, held, or verdict unknown) and `Abandoned` (the probe that
    /// can release an abandoned row's locks needs them) — and while it is
    /// confirmed less than `reorg_margin` blocks deep, since a reorg past
    /// its block returns it to `Dispatched` ([`crate::WalletLedger::reconcile_send_journal`]).
    /// `TerminalRejected` and `PresumedDead` rows have a definite answer
    /// and drop them.
    ///
    /// The rule reads the row's state, never membership of a projection:
    /// a dispatched row has no baseline until its verdict lands, and a
    /// prune keyed on the held projection would drop the bytes of a send
    /// still awaiting its verdict.
    pub fn prune_settled_tx_bytes(&mut self, synced: BlockHeight, reorg_margin: u64) -> usize {
        let mut dropped = 0;
        for row in self.rows.values_mut() {
            if row.tx_bytes.is_none() {
                continue;
            }
            let settled = match row.state {
                SendState::Dispatched | SendState::Abandoned => false,
                SendState::Confirmed { height } => {
                    synced.to_raw().saturating_sub(height.to_raw()) >= reorg_margin
                }
                SendState::TerminalRejected | SendState::PresumedDead => true,
            };
            if settled {
                row.tx_bytes = None;
                dropped += 1;
            }
        }
        dropped
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
            // Refused and never relayed (single-egress): nothing will
            // ever offer these bytes again.
            row.tx_bytes = None;
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
        let mut locks: BTreeMap<
            shekyl_types::GlobalOutputIndex,
            crate::transfer::AwaitingConfirmation,
        > = BTreeMap::new();
        for (txid, row) in &self.rows {
            if !row.state.locks_carried_inputs() {
                continue;
            }
            let Some(accepted_at_height) = row.lock_baseline else {
                continue;
            };
            for inp in &row.inputs {
                locks
                    .entry(shekyl_types::GlobalOutputIndex::from_raw(inp.gindex))
                    .or_insert(crate::transfer::AwaitingConfirmation {
                        tx_hash: shekyl_types::TxHash::from_bytes(*txid),
                        accepted_at_height: shekyl_types::BlockHeight::from_raw(accepted_at_height),
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
#[path = "send_journal_block_tests.rs"]
mod tests;
