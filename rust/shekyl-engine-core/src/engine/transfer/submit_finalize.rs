// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Submit-verdict disposition: what a daemon answer does to the
//! reservation, the F14 awaiting-confirmation lock, and the loop breaker.
//!
//! One finalizer per arm of the `DAEMON_SUBMIT_VERDICT.md` §2.5 partition,
//! plus the two dispatch entry points that both submit call sites route
//! through ([`LocalPendingTx::finalize_submit_success`] /
//! [`LocalPendingTx::finalize_submit_error`]). Carved out of
//! `transfer/engine.rs` so the disposition layer reads as one unit and the
//! composition root stays under the decomposition ratchet's file cap.
//!
//! The success finalizers are deliberately **kind-blind** — they take only
//! the facts a disposition depends on, so the inform-only
//! `Accepted`-vs-`AlreadyInPool` sub-fact cannot fork one. Projection to
//! the Engine-public `SubmitOutcome` happens in `finalize_submit_success`,
//! *after* the disposition completes.

use shekyl_types::TxHash;

use super::super::diagnostics::{emit_pending_tx_diagnostic, DiscardReason, PendingTxDiagnostic};
use super::super::dispatch_durability::VerdictEdit;
use super::super::error::{
    AmbiguousErrorKind, RetryableRejectCause, SubmitError, TerminalErrorKind,
};
use super::super::fee_estimator::FeeEstimator;
use super::super::fee_snapshot::FeeSnapshotSource;
use super::super::output_selector::OutputSelector;
use super::super::pending::{ReservationId, SubmitOutcome};
use super::super::signer::Signer;
use super::super::traits::LedgerEngine;
use super::super::transaction_submitter::{
    canonical_tx_id, SubmitSuccess, SubmitterError, TransactionSubmitter,
};
use super::engine::LocalPendingTx;
use super::support::release_output_locks_for;
use super::types::{PendingTxState, Stage1LedgerSpendableAccess};

/// `#[allow(private_bounds)]`: the where-bounds name crate-private traits
/// (`FeeSnapshotSource`, `TransactionSubmitter`,
/// `Stage1LedgerSpendableAccess`), exactly as the inherent impl in
/// `transfer/engine.rs` this block was carved from does.
#[allow(private_bounds)]
impl<S, O, F, FS, TS, L> LocalPendingTx<S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    /// Deliberately **kind-blind**: the `Accepted`-vs-`AlreadyInPool`
    /// sub-fact never enters this finalizer, so the one Broadcast
    /// disposition (§2.5) cannot fork on it — the caller projects the
    /// Engine-public outcome from the kind *after* this returns
    /// (`BroadcastKind::into_outcome`, the single mapping site).
    /// State half of an accept. The journal edit is [`VerdictEdit::LockAtSyncedHeight`];
    /// the caller commits it after releasing the pending-tx lock.
    pub(super) fn finalize_submit_accept(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        tx_hash: TxHash,
    ) -> VerdictEdit {
        // The network-exposed bytes the watchdog's rung-1 probe re-offers
        // were saved on the journal row at dispatch, so dropping the
        // in-flight entry loses nothing.
        //
        // WI-RPC-3 retention: nothing to write here — the record was
        // saved at dispatch (pin 1, dispatch form), keyed by the
        // canonical txid of the bytes; dropping the entry wipes the
        // runtime copy of the secret. (A daemon returning a hash that
        // differs from the canonical txid would leave the record
        // pending under the canonical key — safe direction, the proof
        // stays servable for the tx actually broadcast.)
        state.in_flight.remove(&id);
        release_output_locks_for(state, id);
        // F28/F37: a definite accept ends any consecutive-rejection streak
        // (it does not clear a tripped breaker — see `SubmitLoopBreaker`).
        state.loop_breaker.record_accept();

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitSucceeded {
                reservation_id: id,
                tx_hash,
            },
        );

        // F14 via the journal: the accepting verdict means the tx is
        // network-exposed, not settled. The baseline is the wallet's
        // synced height, read inside the save's guard.
        VerdictEdit::LockAtSyncedHeight {
            txid: tx_hash.to_bytes(),
        }
    }

    /// State half of an already-in-chain verdict (F40, §2.5).
    ///
    /// Refresh remains the settlement authority. The journal edit places
    /// the F14 lock in both height cases, baselined at the daemon-claimed
    /// height and clamped to a height this wallet has reached. `height`
    /// decides the release path, which the caller applies after the save:
    ///
    /// - `height` above the synced height: refresh reaches the confirming
    ///   block and settles the spend.
    /// - `height` at or behind the synced height: the caller enqueues a
    ///   targeted rescan. A failed rescan never releases (F40-R1); it
    ///   falls through to the watchdog, and fruitless rescans are
    ///   breaker-bounded (F40-R2).
    ///
    /// `spent` stays refresh-written. Nothing here releases the lock the
    /// edit places.
    pub(super) fn finalize_submit_already_in_chain(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        tx_hash: TxHash,
        height: u64,
    ) -> VerdictEdit {
        // The AlreadyInChain arm holds too, so a fruitless-re-scan
        // escalation can fall through to the F31 resubmit-as-status-query
        // with the original bytes — saved on the journal row at dispatch,
        // so dropping the in-flight entry loses nothing.
        //
        // WI-RPC-3 retention: as on the accept path, the record was
        // saved at dispatch — an AlreadyInChain verdict changes the
        // lock baseline, not the retention record.
        state.in_flight.remove(&id);
        release_output_locks_for(state, id);
        // F28/F37: a definite identity-bearing verdict ends any
        // consecutive-rejection streak, same as a fresh accept.
        state.loop_breaker.record_accept();

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitSucceeded {
                reservation_id: id,
                tx_hash,
            },
        );

        // F40 §2.5(a): the commit clamps the baseline to a height this
        // wallet has reached and, when the raw claim is at or behind
        // that height, tells the caller to enqueue the targeted rescan.
        // The R1 never-release property is structural: this edit places
        // the lock and does not clear it. The R2 breaker lives with the
        // re-scan executor.
        VerdictEdit::LockAtClaimedHeight {
            txid: tx_hash.to_bytes(),
            claimed_height: height,
        }
    }

    /// Finalize one submit success and project the public outcome — the
    /// **single** site where a `SubmitSuccess` becomes a [`SubmitOutcome`].
    ///
    /// Disposition first, projection after: both finalizers are kind-blind
    /// and return only `TxHash`, so the `Accepted`-vs-`AlreadyInPool`
    /// sub-fact cannot fork a disposition (§2.5 — the variant set is the
    /// disposition set). Success splits by lock lifecycle: `Broadcast`
    /// (fresh accept / pool-resident duplicate) places the F14
    /// awaiting-confirmation lock baselined at the current height;
    /// `AlreadyInChain` places it too (F40 — no selectable-input window in
    /// either height case), baselined at the claimed confirming height
    /// clamped to a height the wallet has reached, while the raw claim
    /// routes the release path. Refresh remains the settlement authority
    /// in both arms.
    ///
    /// Both dispatch sites — the test-injected reply and the production
    /// submitter reply — route here, so a test that certifies one is
    /// certifying the other.
    /// State half of one submit success, plus the journal edit the caller
    /// commits after releasing the pending-tx lock.
    pub(super) fn finalize_submit_success(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        success: SubmitSuccess,
    ) -> (SubmitOutcome, VerdictEdit) {
        match success {
            SubmitSuccess::Broadcast { hash, kind } => {
                let edit = self.finalize_submit_accept(state, id, hash);
                (kind.into_outcome(hash), edit)
            }
            SubmitSuccess::AlreadyInChain { hash, height } => {
                let edit = self.finalize_submit_already_in_chain(state, id, hash, height);
                (SubmitOutcome::AlreadyInChain { hash, height }, edit)
            }
        }
    }

    /// Finalize one submit failure — the single site mapping the
    /// reservation-unaware [`SubmitterError`] onto the reservation-bound
    /// [`SubmitError`]. The finalizers bind `id`, the reservation under
    /// submit; the closed three-variant enum makes the former
    /// pass-through-with-sentinel-rid arm unrepresentable. Shared by the
    /// injected and production dispatch sites, as with
    /// [`Self::finalize_submit_success`].
    /// State half of one submit failure, plus the journal edit when the
    /// refusal changed the dispatch record. An ambiguous verdict has no edit.
    pub(super) fn finalize_submit_error(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        err: &SubmitterError,
    ) -> (SubmitError, Option<VerdictEdit>) {
        match err {
            SubmitterError::RejectedTerminal { kind } => {
                self.finalize_submit_terminal(state, id, *kind)
            }
            SubmitterError::RejectedRetryable { cause } => {
                self.finalize_submit_retryable(state, id, *cause)
            }
            SubmitterError::Ambiguous { kind } => {
                (self.finalize_submit_ambiguous(state, id, *kind), None)
            }
        }
    }

    pub(super) fn finalize_submit_terminal(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        kind: TerminalErrorKind,
    ) -> (SubmitError, Option<VerdictEdit>) {
        let edit = if let Some(flight) = state.in_flight.remove(&id) {
            // WI-RPC-3 retention: a terminal verdict is a definite
            // refusal — the daemon did not relay (single-egress), so
            // exposure never began. The caller retires the dispatch
            // record under the save's guard. The journal row survives
            // as failed-send history; only the secret retires.
            let txid = canonical_tx_id(&flight.entry.tx_bytes);
            Some(VerdictEdit::TerminalRefusal {
                txid: txid.to_bytes(),
            })
        } else {
            None
        };
        release_output_locks_for(state, id);

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::Discarded {
                reservation_id: id,
                reason: DiscardReason::DaemonRejectedTerminal { kind },
            },
        );

        // F28/F37 loop-breaker (§2.5): a second consecutive same-kind
        // rejection is a systematic disagreement — alarm once and gate
        // further builds until the operator acknowledges.
        if state.loop_breaker.record_terminal(kind) {
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::SubmitLoopBreakerTripped {
                    reservation_id: id,
                    kind,
                },
            );
        }

        (SubmitError::DaemonRejectedTerminal { kind }, edit)
    }

    /// Restore a reservation whose daemon verdict was a §2.5 retryable
    /// rejection (`StaleRoot` / `ReferenceTooRecent` / `ReferenceNotFound`)
    /// to `consumer_held`.
    ///
    /// The verdict is definite (not in pool, not in chain — under
    /// single-egress, provably unrelayed), but the input selection remains
    /// sound, so the `output_locks` are **retained**: releasing them would
    /// let a competing build select the same inputs and broadcast a second
    /// same-key-image artifact (`DAEMON_SUBMIT_VERDICT.md` §7.1). The
    /// entry returns with its full re-anchor substrate, so the consumer's
    /// next `submit(rid, seen_gen)` reproves against a fresh reference
    /// where the pre-flight staleness check calls for it (the `StaleRoot`
    /// remedy) or simply re-offers the same bytes (`ReferenceTooRecent` /
    /// `ReferenceNotFound` after their per-cause waits).
    pub(super) fn finalize_submit_retryable(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        cause: RetryableRejectCause,
    ) -> (SubmitError, Option<VerdictEdit>) {
        let edit = if let Some(flight) = state.in_flight.remove(&id) {
            // WI-RPC-3 retention: §2.5 retryable is likewise definite
            // ("provably unrelayed"). The caller removes the dispatch
            // record under the save's guard. The next `submit(id, gen)`
            // re-persists at its own dispatch, possibly under a new
            // canonical txid after a re-anchor.
            let txid = canonical_tx_id(&flight.entry.tx_bytes);
            state.consumer_held.insert(id, flight.entry);
            Some(VerdictEdit::RetryableRefusal {
                txid: txid.to_bytes(),
            })
        } else {
            None
        };

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitRetryablyRejected {
                reservation_id: id,
                cause,
            },
        );

        (
            SubmitError::DaemonRejectedRetryable {
                cause,
                reservation_id: id,
            },
            edit,
        )
    }

    pub(super) fn finalize_submit_ambiguous(
        &self,
        state: &PendingTxState,
        id: ReservationId,
        kind: AmbiguousErrorKind,
    ) -> SubmitError {
        // `None` when the reservation is no longer in flight: there
        // are no bytes left to hash, and the reservation_id below
        // already correlates the event. Manufacturing a TxHash from
        // the id (the retired `phase1_tx_hash`) put a plausible,
        // nonexistent txid into a field consumers monitor.
        let tx_hash = state
            .in_flight
            .get(&id)
            .map(|flight| canonical_tx_id(&flight.entry.tx_bytes));

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitPendingResolution {
                reservation_id: id,
                tx_hash,
                kind,
            },
        );

        SubmitError::DaemonAmbiguous {
            kind,
            reservation_id: id,
        }
    }
}
