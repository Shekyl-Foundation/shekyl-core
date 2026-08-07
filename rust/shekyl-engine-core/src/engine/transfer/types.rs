// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transfer / pending-tx state types.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use shekyl_curve_tree::ReferenceBlock;
use shekyl_engine_state::{LedgerBlock, WalletLedger};
use shekyl_units::AtomicUnits;

use super::super::error::{SendError, TerminalErrorKind};
use super::super::local_ledger::LocalLedger;
use super::super::pending::{
    InFlightSubmit, ReservationId, SnapshotId, TxHash, TxRecipientSummary, TxRequest,
};
use super::super::traits::LedgerEngine;

/// Per-output identifier used as the `output_locks` map key.
///
/// **Stage 1 placeholder.** Stage 1 identifies outputs by their
/// `usize` transfer-index within `LedgerBlock::transfers()`. The
/// body extraction confirmed this alias matches the existing
/// `Reservation::selected_transfer_indices` semantics; if subsequent
/// work needs a richer identifier (e.g., a `(height, tx_index,
/// output_index)` triple), the alias is upgraded to a newtype with
/// a single grep-able rename.
pub(crate) type OutputId = usize;

/// Semantic, canonically-ordered fingerprint of a built tx's *authorized
/// content* — the `(fee, who-gets-how-much, change)` the consumer reviewed.
///
/// CT-5d ([`docs/design/CT5D_REANCHOR.md`] §4, F-G/F-G′): a re-anchor advances
/// [`ConsumerHeldEntry::content_gen`] **iff this fingerprint changes**, so it
/// must capture exactly what consent is over and nothing else:
///
/// - **Semantic, not byte-level** — a reprove re-derives a fresh one-time
///   *change address* every time; the fingerprint carries the change *amount*
///   only, never the address, or transparent reprove would spuriously bump
///   `content_gen` (F-G).
/// - **Canonically ordered** — CryptoNote-lineage txs shuffle outputs so the
///   change output is not positionally identifiable, and a reprove re-runs the
///   build internals → re-shuffles; the destinations are sorted here so the
///   fingerprint is invariant under that privacy permutation (F-G′).
///
/// Consent is over *who gets how much* and the fee — not the wallet's own change
/// address or the output order — so two builds that pay the same recipients the
/// same amounts with the same fee and change compare equal regardless of address
/// re-randomization or output shuffle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContentFingerprint {
    /// Fee in atomic units.
    fee: u64,
    /// Authorized destinations as `(address, amount)`, sorted canonically so an
    /// output reshuffle does not change the fingerprint (F-G′).
    dests: Vec<(String, u64)>,
    /// Change amount (atomic units). The change *address* is deliberately
    /// excluded — it re-randomizes on every reprove (F-G).
    change: u64,
}

impl ContentFingerprint {
    /// Build the canonical fingerprint from the realized `(fee, recipients,
    /// change)`. Sorts the destinations so the result is permutation-invariant.
    pub(super) fn from_parts(
        fee: AtomicUnits,
        recipients: &[TxRecipientSummary],
        change: AtomicUnits,
    ) -> Self {
        let mut dests: Vec<(String, u64)> = recipients
            .iter()
            .map(|r| (r.address.clone(), r.amount_atomic_units.to_raw()))
            .collect();
        dests.sort();
        Self {
            fee: fee.to_raw(),
            dests,
            change: change.to_raw(),
        }
    }

    /// Single-sourced fingerprint construction from the realized build amounts,
    /// with **checked** arithmetic (`change = total_covered − Σrecipients − fee`).
    ///
    /// The fingerprint gates consent (§4 F-G), so a balance that does not add up
    /// — `total_covered < Σrecipients + fee`, only reachable under corrupt state
    /// since `build` validates funding first — must fail loud rather than
    /// saturate to a wrong `change` that could mask a content change and skip a
    /// `content_gen` bump. Used by both the fresh-build commit and the re-anchor
    /// so the two derive the fingerprint identically.
    pub(super) fn from_build(
        fee: AtomicUnits,
        recipients: &[TxRecipientSummary],
        total_covered: AtomicUnits,
    ) -> Result<Self, SendError> {
        let paid = AtomicUnits::checked_sum(recipients.iter().map(|r| r.amount_atomic_units))
            .ok_or(SendError::CannotSign {
                reason: "recipient amount sum overflowed computing the content fingerprint",
            })?;
        let change = paid
            .checked_add(fee)
            .and_then(|spent| total_covered.checked_sub(spent))
            .ok_or(SendError::CannotSign {
                reason: "balance does not cover recipients + fee computing the content fingerprint",
            })?;
        Ok(Self::from_parts(fee, recipients, change))
    }
}

/// Per-reservation metadata while the rid lives in `consumer_held`.
///
/// The (γ) lean shape stores collection membership in
/// `consumer_held` / `in_flight` and keeps `output_locks` as the
/// single source of truth for per-output claims. `snapshot_id` is
/// still required for lazy-R5 submit-time staleness checks even
/// though V3.0's `consumer_held` map values are lighter than the
/// V3.x eager-discard `ConsumerHeldEntry { snapshot_id, created_at }`
/// substrate named in §5.6.7 P9.
///
/// CT-5d adds the substrate a submit-time re-anchor needs: a `consumer_held`
/// entry must carry enough to *rebuild* (the `request`), the anchor it was built
/// against (`reference`), and the consent state (`content_gen` + `fingerprint`).
/// `PendingTxState` is a runtime `Mutex` (not persisted — F-F, [`docs/design/CT5D_REANCHOR.md`]
/// §7), so these are runtime-only fields with no schema-migration cost.
///
/// **Not `Clone`** (WI-RPC-3 retention): `tx_key_secret` is
/// deliberately non-`Clone`, keeping the per-tx secret single-copy
/// while the entry moves `consumer_held → in_flight → finalize`.
/// Nothing needed the whole-entry clone anyway — the flip moves the
/// entry, and the watchdog retains only `tx_bytes`.
#[derive(Debug)]
pub(crate) struct ConsumerHeldEntry {
    /// Build-time [`Instant`] for the R8 TTL safety-net.
    //
    // `dead_code` allow: the C7 TTL sweep is the reader. The field lost its
    // interim reader when the `consumer_held → in_flight` flip started moving
    // the whole entry (verdict-cutover reshape) instead of projecting fields.
    #[allow(dead_code)]
    pub created_at: Instant,
    /// [`SnapshotId`] pinned at build for submit-time comparison.
    pub snapshot_id: SnapshotId,
    /// Engine `synced_height` at build (defense-in-depth checks).
    pub built_at_height: u64,
    /// `block_hash_at(built_at_height)` at build.
    pub built_at_tip_hash: [u8; 32],
    /// Serialized signed transaction for daemon broadcast.
    pub tx_bytes: Vec<u8>,
    /// CT-5d: the original build request (recipients + priority). Re-anchor
    /// re-runs the build pipeline from this, so the entry carries enough to
    /// rebuild, not just to submit `tx_bytes` (§3).
    pub request: TxRequest,
    /// CT-5d: the reference block this proof is anchored to. The submit
    /// pre-flight reads it for `should_reanchor` (age) and `reference_orphaned`
    /// (point query) (§5).
    pub reference: ReferenceBlock,
    /// CT-5d: consumer-visible content generation. Advances only when a
    /// re-anchor changes the realized content (`fingerprint`), never on a proof
    /// refresh; `submit(id, seen_gen)` compares against it (§4 F-G).
    pub content_gen: u64,
    /// CT-5d: the materialized content fingerprint `content_gen` advances
    /// against (§4 F-G/F-G′).
    pub fingerprint: ContentFingerprint,
    /// WI-RPC-3 retention: the per-tx secret scalar minted at signing,
    /// carried alongside `tx_bytes` to the dispatch-persist point in
    /// `submit_async`, which copies it into `TxMetaBlock.tx_keys`
    /// atomically with the `in_flight` flip — before the bytes can
    /// leave for the daemon (`docs/api/wallet_rpc.yaml` OUTBOUND
    /// PREREQUISITE pin 1, dispatch form). After that flip the
    /// persisted record is the durable holder; this runtime copy
    /// exists only so a §2.5 retryable restoration can re-dispatch.
    /// Zeroize-on-drop — a discard wipes it structurally with the
    /// entry, matching pin 1's "not at build" lifecycle (a never-
    /// submitted build leaves no orphan in the store).
    pub tx_key_secret: shekyl_engine_state::TxSecretKey,
}

#[cfg(test)]
impl ConsumerHeldEntry {
    /// Minimal entry for cross-module tests that only need a `consumer_held`
    /// member to exist (e.g. the close-refusal test in `lifecycle`). Re-anchor
    /// tests build through the real pipeline and never use this — the
    /// `request` / `reference` here are placeholders, not a re-anchorable tx.
    pub(crate) fn for_outstanding_test(tx_bytes: Vec<u8>) -> Self {
        Self {
            created_at: Instant::now(),
            snapshot_id: SnapshotId([0u8; 16]),
            built_at_height: 0,
            built_at_tip_hash: [0u8; 32],
            tx_bytes,
            request: TxRequest {
                recipients: Vec::new(),
                priority: crate::engine::pending::FeePriority::Standard,
            },
            reference: ReferenceBlock {
                height: shekyl_curve_tree::BlockHeight(0),
                curve_tree_root: [0u8; 32],
                block_hash: [0u8; 32],
            },
            content_gen: 0,
            fingerprint: ContentFingerprint::from_parts(AtomicUnits::ZERO, &[], AtomicUnits::ZERO),
            tx_key_secret: shekyl_engine_state::TxSecretKey::new(zeroize::Zeroizing::new(
                [0u8; 32],
            )),
        }
    }
}

/// Stage 1 ledger access for spendable-output enumeration.
///
/// `LedgerEngine` does not yet expose matured-output enumeration;
/// Stage 1's sole production implementor is [`LocalLedger`]. `LocalPendingTx`
/// reaches `LedgerBlock::spendable_outputs` through this trait rather
/// than widening the public `LedgerEngine` surface.
pub(super) trait Stage1LedgerSpendableAccess: LedgerEngine {
    fn with_ledger_block<R>(&self, f: impl FnOnce(&LedgerBlock) -> R) -> R;

    /// Whole-`WalletLedger` mutable access, for writes that span blocks
    /// (WI-RPC-3 retention: `tx_meta.tx_keys` + `sync_state.
    /// pending_tx_hashes` + the ledger-block F14 locks in one guard,
    /// so the I-2 invariant holds atomically under the write lock).
    ///
    /// Replaced the former ledger-block-only mutable accessor
    /// (`with_ledger_block_mut`): every mutating call site (the two
    /// finalize paths, the watchdog release) now writes across blocks,
    /// so the narrower method lost its last caller.
    fn with_wallet_ledger_mut<R>(&self, f: impl FnOnce(&mut WalletLedger) -> R) -> R;
}

impl Stage1LedgerSpendableAccess for LocalLedger {
    fn with_ledger_block<R>(&self, f: impl FnOnce(&LedgerBlock) -> R) -> R {
        let guard = self.read();
        f(&guard.ledger.ledger)
    }

    fn with_wallet_ledger_mut<R>(&self, f: impl FnOnce(&mut WalletLedger) -> R) -> R {
        let mut guard = self.write();
        f(&mut guard.ledger)
    }
}

impl<L> Stage1LedgerSpendableAccess for Arc<L>
where
    L: Stage1LedgerSpendableAccess,
{
    fn with_ledger_block<R>(&self, f: impl FnOnce(&LedgerBlock) -> R) -> R {
        self.as_ref().with_ledger_block(f)
    }

    fn with_wallet_ledger_mut<R>(&self, f: impl FnOnce(&mut WalletLedger) -> R) -> R {
        self.as_ref().with_wallet_ledger_mut(f)
    }
}

// ============================================================================
// PendingTxState (γ three-collection lean shape)
// ============================================================================

/// Engine-internal mutable state guarded by
/// [`LocalPendingTx::state`](super::engine::LocalPendingTx::state).
///
/// Segment-2h (γ) lean shape per
/// [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`] §5.6.8 (γ):
/// three collections, no `ReservationState` enum, collection
/// membership as ground truth.
///
/// # Field semantics
///
/// - `current_snapshot` — the engine's view of the latest
///   [`SnapshotId`]; Stage 1 refreshes this on every mutating call
///   from `self.ledger.snapshot()` (exact under the mutex guard).
///   Stage 4's `PendingTxActor` maintains this via
///   `LedgerDiagnostic::SnapshotMerged` events under mailbox-FIFO
///   semantics.
/// - `output_locks` — per-output lock map. Insert at `build` (one
///   entry per selected output); remove at `submit` success /
///   `discard` / `signal_mempool_evicted` (sweep all entries for
///   the rid). The key-by-output shape enforces the no-double-
///   spend P6 invariant by construction: a second `build` selecting
///   the same output collides at insert.
/// - `consumer_held` — reservations the engine has built and the
///   consumer has not yet submitted. Values carry the pinned
///   `snapshot_id` and build-time chain tags for submit checks.
/// - `in_flight` — reservations whose `submit` is mid-flight
///   (daemon round-trip outstanding) or whose daemon outcome is
///   `AmbiguousErrorKind` (R9 daemon-side-authority preserved).
///   The map value carries [`InFlightSubmit`] with the preserved
///   `created_at` from `consumer_held` plus the `submitted_at`
///   transition timestamp.
/// - `next_id` — monotone counter that mints fresh
///   [`ReservationId`]s at `build` entry.
#[derive(Debug)]
pub(crate) struct PendingTxState {
    /// Engine's current view of the ledger [`SnapshotId`].
    pub current_snapshot: SnapshotId,
    /// Per-output lock map. See struct rustdoc.
    pub output_locks: HashMap<OutputId, ReservationId>,
    /// Reservations built but not yet submitted.
    pub consumer_held: HashMap<ReservationId, ConsumerHeldEntry>,
    /// Reservations in the submit → daemon-resolution window.
    pub in_flight: HashMap<ReservationId, InFlightSubmit>,
    /// Monotone counter for fresh [`ReservationId`]s.
    pub next_id: u64,
    /// F28/F37 rebuild-loop circuit breaker. See [`SubmitLoopBreaker`].
    pub loop_breaker: SubmitLoopBreaker,
    /// In-memory serialized bytes of network-exposed txs, keyed by
    /// canonical txid, retained for the §5.3 watchdog's rung-1
    /// resubmit-same-bytes probe (`DAEMON_SUBMIT_VERDICT.md` §5.3
    /// decision 2). Populated at finalize-accept / finalize-already-in-
    /// chain from the in-flight entry about to be dropped; pruned by the
    /// driver when the txid leaves the held projection.
    ///
    /// **Ephemeral by design (decision 2).** Not persisted: a wallet
    /// restart drops these, degrading the probe rung to the operator-
    /// alarm rung — still satisfying §2.6's "every exit is verdict,
    /// confirmation, or operator alarm." Persistence's only real product
    /// would be a silent cross-restart re-broadcast of a signed key-image
    /// spend, which the ephemeral design correctly converts into a human
    /// decision.
    pub held_bytes: HashMap<TxHash, Vec<u8>>,
    /// F40 targeted re-scan requests awaiting the driver's next tick.
    /// `finalize_submit_already_in_chain` pushes here (alongside the
    /// observability diagnostic) whenever the daemon claims a confirming
    /// height at-or-below the wallet's synced height (§2.5(b)); the driver
    /// drains it and runs the cheap-check-then-escalate executor under the
    /// F40-R2 breaker.
    ///
    /// A dedicated queue rather than the diagnostic sink: diagnostics are
    /// observability-only (decision 3), so control flow does not ride the
    /// sink.
    pub rescan_queue: Vec<RescanRequest>,
}

/// A targeted re-scan request enqueued by
/// [`LocalPendingTx::finalize_submit_already_in_chain`](super::engine::LocalPendingTx::finalize_submit_already_in_chain)
/// and drained by
/// the submit lifecycle driver (`DAEMON_SUBMIT_VERDICT.md` §2.5(b) /
/// F40, decision 3).
///
/// Carries only the public facts the executor needs: the awaited txid
/// and the daemon-claimed confirming height. The executor re-checks the
/// fruitless-soundness guard (`claimed_height ≤ current synced_height`)
/// at execution time — the synced height may have advanced between
/// enqueue and drain (decision 1 refinement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RescanRequest {
    /// Canonical txid the daemon claims is already in the chain.
    pub tx_hash: TxHash,
    /// Daemon-claimed confirming-block height (F40, §2.2 carve-out).
    /// A **release-path discriminant** only, never settlement truth.
    pub claimed_height: u64,
}

/// The F28/F37 rebuild-loop circuit breaker
/// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2.5).
///
/// The §2.5 dispositions for `Rejected{Malformed}`, `Rejected{FeeTooLow}`,
/// and `Rejected{Unrecognized}` are *one-shot rebuild*: a second
/// consecutive rejection of the same kind is a systematic wallet/daemon
/// rule (or fee-model) disagreement, not a bad tx — a third silent build
/// burns fees and multiplies linking artifacts (§7.1 for `Malformed`;
/// for `FeeTooLow` the bound is privacy-load-bearing outright, since a
/// fee-driven rebuild can pull in an additional input, leaking
/// co-ownership per iteration — F30). The breaker mechanizes "never
/// loop":
///
/// - Each terminal rejection of a breaker-scoped kind extends that
///   kind's consecutive streak; any other definite submit outcome
///   (accept, or a terminal rejection of a different class) resets the
///   streak.
/// - The **second** consecutive same-kind rejection trips the breaker:
///   an operator alarm is emitted
///   ([`PendingTxDiagnostic::SubmitLoopBreakerTripped`](super::super::diagnostics::PendingTxDiagnostic::SubmitLoopBreakerTripped))
///   and further
///   `build` calls are refused with
///   [`SendError::SubmitLoopBreakerTripped`] until the operator
///   acknowledges via
///   [`LocalPendingTx::acknowledge_submit_loop_breaker`](super::engine::LocalPendingTx::acknowledge_submit_loop_breaker).
/// - An accepted submit while tripped resets the *streak* but not the
///   tripped state: acceptance of a different tx does not falsify the
///   systematic-disagreement hypothesis for the failing payment, and
///   auto-clearing would let an alternating pattern re-enter the loop
///   the breaker exists to break. Acknowledgment is the only reset.
#[derive(Debug, Default)]
pub(crate) struct SubmitLoopBreaker {
    /// The rejection kind of the current consecutive streak, if any.
    streak_kind: Option<TerminalErrorKind>,
    /// Consecutive same-kind rejections observed.
    streak: u8,
    /// Set when the breaker trips; cleared only by acknowledgment.
    tripped: Option<TerminalErrorKind>,
}

impl SubmitLoopBreaker {
    /// Consecutive same-kind rejections at which the breaker trips.
    /// §2.5: "one-shot rebuild" — the second consecutive rejection is
    /// the escalation point; there is never a third build.
    const TRIP_THRESHOLD: u8 = 2;

    /// Which terminal kinds the breaker scopes over. `DoubleSpend` is
    /// excluded: its disposition is terminal release with no rebuild
    /// prescription, so there is no loop to break.
    pub(super) fn in_scope(kind: TerminalErrorKind) -> bool {
        matches!(
            kind,
            TerminalErrorKind::Malformed
                | TerminalErrorKind::FeeTooLow
                | TerminalErrorKind::Unrecognized
        )
    }

    /// Record a definite non-rejection submit outcome (accept). Resets
    /// the streak; deliberately does **not** clear `tripped` (see type
    /// docs).
    pub(super) fn record_accept(&mut self) {
        self.streak_kind = None;
        self.streak = 0;
    }

    /// Record a terminal rejection. Returns `true` iff this rejection
    /// trips the breaker (exactly once — an already-tripped breaker
    /// does not re-alarm).
    pub(super) fn record_terminal(&mut self, kind: TerminalErrorKind) -> bool {
        if !Self::in_scope(kind) {
            self.streak_kind = None;
            self.streak = 0;
            return false;
        }
        if self.streak_kind == Some(kind) {
            self.streak = self.streak.saturating_add(1);
        } else {
            self.streak_kind = Some(kind);
            self.streak = 1;
        }
        if self.streak >= Self::TRIP_THRESHOLD && self.tripped.is_none() {
            self.tripped = Some(kind);
            return true;
        }
        false
    }

    /// The kind the breaker tripped on, if tripped.
    pub(crate) fn tripped(&self) -> Option<TerminalErrorKind> {
        self.tripped
    }

    /// Operator acknowledgment: clear the tripped state and streak.
    pub(super) fn acknowledge(&mut self) {
        *self = Self::default();
    }
}

/// Bounded retries for the re-anchor lock₂ TOCTOU (CT-5d [`docs/design/CT5D_REANCHOR.md`]
/// §3a): the tip/tree can move during the lock-free prover run, re-staling the
/// freshly-anchored reference. Retry the whole pre-phase→prover→commit loop a
/// few times; a tip moving faster than this is better surfaced as a clean
/// "resyncing, retry later" than spun on.
pub(super) const REANCHOR_MAX_RETRIES: u8 = 3;

/// Outcome of a successful in-place reprove (CT-5d §3 reprove path / §4 consent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReanchorOutcome {
    /// Reproved against a fresh reference; the realized `(fee, recipients,
    /// change)` is unchanged, so `content_gen` is unchanged and the swapped-in
    /// tx is transparent to broadcast (§4).
    Reproved { content_gen: u64 },
    /// Reproved, but the realized content changed (a fresh-depth fee shift, F-A),
    /// so `content_gen` advanced; the caller must **withhold broadcast** and
    /// return the new artifact for re-confirm (§4).
    ContentChanged { content_gen: u64 },
}

/// Why a re-anchor could not reprove in place (CT-5d §3).
//
// `dead_code` allow: the submit pre-flight maps these by *variant* to a
// `SubmitError`, so the `detail` / `SendError` payloads are carried for
// diagnostics (the `Debug` render) but not read on the mapping path. Kept as
// data so a future logging/telemetry hook surfaces the precise cause.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum ReanchorError {
    /// The fresh reference is not yet anchorable under the two-sided gate (§3b):
    /// the tree has not ingested far enough (still resyncing), or it lags the
    /// chain tip so far that a freshly-anchored reference would already be past
    /// the rebuild threshold. Retriable once the tree catches up.
    ReferenceResyncing { detail: &'static str },
    /// The proof cannot be content-preservingly reproved with the currently
    /// selected inputs: a selected output was orphaned (membership resolution
    /// failed at the fresh reference), or the fresh-depth fee exceeds what those
    /// inputs cover (F-I). Reselection is the CT-5d-deferred path
    /// (`docs/FOLLOWUPS.md` "CT-5d reselect"); the consumer discards and rebuilds.
    ReselectionRequired { detail: &'static str },
    /// A transient assembly/signing failure that leaves the reservation intact.
    Failed(SendError),
}
