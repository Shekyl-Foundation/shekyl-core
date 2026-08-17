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
use super::types::{PendingTxState, RescanRequest, Stage1LedgerSpendableAccess};

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
    pub(super) fn finalize_submit_accept(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        tx_hash: TxHash,
    ) -> TxHash {
        // §5.3 decision 2: retain the network-exposed bytes for the
        // watchdog's rung-1 resubmit-same-bytes probe before the in-flight
        // record (their only holder) is dropped. Ephemeral — a restart
        // drops the map and the probe rung degrades to the operator alarm.
        //
        // WI-RPC-3 retention: nothing to write here — the record was
        // persisted at dispatch (pin 1, dispatch form), keyed by the
        // canonical txid of the bytes; dropping the entry wipes the
        // runtime copy of the secret. (A daemon returning a hash that
        // differs from the canonical txid would leave the record
        // pending under the canonical key — safe direction, the proof
        // stays servable for the tx actually broadcast.)
        if let Some(flight) = state.in_flight.remove(&id) {
            state.held_bytes.insert(tx_hash, flight.entry.tx_bytes);
        }
        release_output_locks_for(state, id);
        // F28/F37: a definite accept ends any consecutive-rejection streak
        // (it does not clear a tripped breaker — see `SubmitLoopBreaker`).
        state.loop_breaker.record_accept();

        // F14 (`DAEMON_SUBMIT_VERDICT.md` §2.6) via the journal (C2):
        // the accepting verdict means the tx is network-exposed, not
        // settled. Stamp the baseline on the owning journal row; the
        // F14 field is the derived cache and is re-derived from the
        // carried input set (spent race-guard included). Same path as
        // `AlreadyInChain` — only the baseline height differs.
        self.ledger.with_wallet_ledger_mut(|wallet| {
            let accepted_at_height = wallet.ledger.height();
            wallet.stamp_send_lock_baseline(&tx_hash.to_bytes(), accepted_at_height);
        });

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitSucceeded {
                reservation_id: id,
                tx_hash,
            },
        );

        tx_hash
    }

    /// Resolve a submit whose verdict was `AlreadyInChain { height }`
    /// (F40, §2.5): confirmation observed by verdict — the reservation is
    /// done, but **refresh remains the settlement authority**.
    ///
    /// The F14 awaiting-confirmation lock is placed in **both** height
    /// cases (fund safety first: a no-lock disposition leaves a
    /// selectable-input window an adversary who slows the wallet's own
    /// daemon's block delivery can steer it into). The lock is baselined
    /// at the daemon-claimed confirming `height`, not at the wallet's
    /// current height; `height` decides only the **release path**:
    ///
    /// - *`height` > wallet synced height:* the ordinary §2.6 path-1
    ///   release — refresh reaches the confirming block and `mark_spent`
    ///   settles spent-marking, clearing the lock.
    /// - *`height` ≤ wallet synced height:* refresh already passed that
    ///   height without observing the spend — path-1 is unreachable by
    ///   construction (the FOLLOWUPS stranded-lock wedge). Emit
    ///   [`PendingTxDiagnostic::TargetedRescanRequested`] so the driving
    ///   actor enqueues a targeted re-scan of the window around `height`
    ///   (reorg-heal machinery). A failed re-scan **never releases**
    ///   (F40-R1); it falls through to the F31 resubmit-as-status-query
    ///   via the watchdog, and consecutive fruitless re-scans are
    ///   breaker-bounded (F40-R2) → operator alarm.
    ///
    /// The verdict authorizes lock-lifecycle transitions only; `spent`
    /// stays refresh-written (`docs/FOLLOWUPS.md` "`AlreadyInChain` submit
    /// verdict", closed with the disposition split; reshaped to F40 with
    /// the `height` carve-out).
    /// Kind-blind like [`Self::finalize_submit_accept`]: places the F14
    /// lock and enqueues the release-path side effects, then returns
    /// the (unchanged) `tx_hash`. The caller constructs the public
    /// [`SubmitOutcome::AlreadyInChain`] from `tx_hash` + `height` so
    /// both success finalizers share the same return shape.
    pub(super) fn finalize_submit_already_in_chain(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        tx_hash: TxHash,
        height: u64,
    ) -> TxHash {
        // §5.3 decision 2: retain the network-exposed bytes for the
        // watchdog probe (see the accept path). The AlreadyInChain arm
        // holds too, so a fruitless-re-scan escalation can fall through to
        // the F31 resubmit-as-status-query with the original bytes.
        //
        // WI-RPC-3 retention: as on the accept path, the record was
        // persisted at dispatch — an AlreadyInChain verdict changes the
        // lock baseline, not the retention record.
        if let Some(flight) = state.in_flight.remove(&id) {
            state.held_bytes.insert(tx_hash, flight.entry.tx_bytes);
        }
        release_output_locks_for(state, id);
        // F28/F37: a definite identity-bearing verdict ends any
        // consecutive-rejection streak, same as a fresh accept.
        state.loop_breaker.record_accept();

        let synced_height = self.ledger.with_wallet_ledger_mut(|wallet| {
            let synced_height = wallet.ledger.height();
            // F40 §2.5(a): baseline at the claimed confirming height, not
            // the wallet's current height — the watchdog horizon counts
            // from the block that (per the verdict) settles the spend.
            //
            // Clamped to a height this wallet has actually reached. The
            // claim is untrusted (§7.2 rider row `AlreadyInChain.height`),
            // and that row's lie-high damage cap is "released by the §2.6
            // confirmed-absent watchdog horizon (bounded liveness cost)" —
            // which only holds if the horizon is *reachable*. The kernel
            // gate is `synced_height - baseline_height >= horizon`
            // (`submit_watchdog::escape_ladder_step`), so an unreachable
            // claim (a lying remote node, a reorg-confused daemon, or
            // `u64::MAX`) would park it at zero forever: the rung-1 probe
            // never runs, no alarm is ever raised, and the F14 lock is
            // *persisted*, so the inputs stay unspendable across restarts
            // with no escape at all. Clamping costs nothing where the claim
            // is honest — a wallet only holds a lock because it just built
            // and submitted, which requires being at the tip, so an honest
            // (a)-case claim is a handful of blocks above `synced_height`
            // against a horizon of hundreds — and it degrades the lie-high
            // case to exactly the baseline the fresh-accept path already
            // uses. The raw claim still routes the release path below and
            // still rides the verdict to the consumer; only the persisted
            // baseline is bounded.
            //
            // Journal owns the baseline (C2), and since PR-SJ-1b the F14
            // lock set *is* a view of it — the same accepting-verdict
            // site as fresh accept, so there is one write and the two
            // paths have nothing to diverge on.
            let baseline_height = height.min(synced_height);
            wallet.stamp_send_lock_baseline(&tx_hash.to_bytes(), baseline_height);
            synced_height
        });

        // F40 §2.5(b): a claim refresh has already scanned past routes to
        // the targeted re-scan. Requesting is all that happens here — the
        // R1 never-release property is structural (nothing below this
        // point can release the lock just placed), and the R2 breaker
        // lives with the re-scan executor.
        if height <= synced_height {
            // Decision 3: enqueue the control-flow request on the dedicated
            // queue the driver drains; the diagnostic below is the
            // observability trace only (sinks are observability-only).
            state.rescan_queue.push(RescanRequest {
                tx_hash,
                claimed_height: height,
            });
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::TargetedRescanRequested {
                    reservation_id: id,
                    tx_hash,
                    claimed_height: height,
                },
            );
        }

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitSucceeded {
                reservation_id: id,
                tx_hash,
            },
        );

        tx_hash
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
    pub(super) fn finalize_submit_success(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        success: SubmitSuccess,
    ) -> SubmitOutcome {
        match success {
            SubmitSuccess::Broadcast { hash, kind } => {
                let hash = self.finalize_submit_accept(state, id, hash);
                kind.into_outcome(hash)
            }
            SubmitSuccess::AlreadyInChain { hash, height } => {
                let hash = self.finalize_submit_already_in_chain(state, id, hash, height);
                SubmitOutcome::AlreadyInChain { hash, height }
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
    pub(super) fn finalize_submit_error(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        err: &SubmitterError,
    ) -> SubmitError {
        match err {
            SubmitterError::RejectedTerminal { kind } => {
                self.finalize_submit_terminal(state, id, *kind)
            }
            SubmitterError::RejectedRetryable { cause } => {
                self.finalize_submit_retryable(state, id, *cause)
            }
            SubmitterError::Ambiguous { kind } => self.finalize_submit_ambiguous(state, id, *kind),
        }
    }

    pub(super) fn finalize_submit_terminal(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        kind: TerminalErrorKind,
    ) -> SubmitError {
        if let Some(flight) = state.in_flight.remove(&id) {
            // WI-RPC-3 retention: a terminal verdict is a definite
            // refusal — the daemon did not relay (single-egress), so
            // exposure never began. Retire the dispatch-persisted
            // record; a refused build leaves no residue (pin 1's
            // discard side).
            let txid = canonical_tx_id(&flight.entry.tx_bytes);
            self.ledger.with_wallet_ledger_mut(|wallet| {
                wallet.retire_retained_tx_key(&txid.to_bytes());
                // PR-SJ-1: the journal row survives as failed-send
                // history (SJ-DQ-3, rule 82) — only the secret retires.
                wallet.send_journal.mark_terminal_rejected(&txid.to_bytes());
            });
        }
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

        SubmitError::DaemonRejectedTerminal { kind }
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
    ) -> SubmitError {
        if let Some(flight) = state.in_flight.remove(&id) {
            // WI-RPC-3 retention: §2.5 retryable is likewise definite
            // ("provably unrelayed") — retire the dispatch-persisted
            // record. The next `submit(id, gen)` re-persists at its own
            // dispatch, possibly under a new canonical txid after a
            // re-anchor rebuild, so retiring here also prevents a stale
            // record for bytes that will never be re-offered.
            let txid = canonical_tx_id(&flight.entry.tx_bytes);
            self.ledger.with_wallet_ledger_mut(|wallet| {
                wallet.retire_retained_tx_key(&txid.to_bytes());
                // PR-SJ-1: a retryable refusal undoes the dispatch — the
                // reservation returns to consumer_held and the next
                // submit re-dispatches (possibly under a new txid after
                // a re-anchor). The journal row mirrors the retention
                // record: removed here, re-born at the next dispatch.
                wallet.send_journal.undo_dispatch(&txid.to_bytes());
            });
            state.consumer_held.insert(id, flight.entry);
        }

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitRetryablyRejected {
                reservation_id: id,
                cause,
            },
        );

        SubmitError::DaemonRejectedRetryable {
            cause,
            reservation_id: id,
        }
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
