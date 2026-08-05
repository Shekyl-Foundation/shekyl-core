// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`LocalPendingTx`] — production pending-tx implementor.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use shekyl_curve_tree::{
    select_reference_height, should_reanchor, two_sided_reference_height, AssembleInput,
    BlockHeight, Gindex, ReferenceBlock, TwoSidedRefusal, REF_ANCHOR_AGE,
};
use shekyl_engine_state::LedgerBlock;
use shekyl_units::AtomicUnits;

use super::super::curve_tree_actor::CurveTreeHandle;
use super::super::diagnostics::{
    emit_pending_tx_diagnostic, BuildErrorKind, BuildRequestSummary, DiagnosticSink, DiscardReason,
    PendingTxDiagnostic,
};
use super::super::error::{
    OutputSelectorError, PendingTxError, SendError, SignerError, SubmitError,
};
use super::super::fee_estimator::{FeeEstimationContext, FeeEstimator};
use super::super::fee_snapshot::FeeSnapshotSource;
use super::super::network::Network;
use super::super::output_selector::{OutputCandidate, OutputSelector, SelectedOutputs};
use super::super::pending::{
    InFlightSubmit, PendingTx, ReservationId, ReservationTTLConfig, SubmitOutcome, TxHash,
    TxRecipientSummary, TxRequest,
};
use super::super::refresh::{derive_snapshot_id, LedgerSnapshot};
use super::super::signer::{SignedTransfer, Signer, TransferSigningContext};
use super::super::signing_assembly::assemble_tx_to_sign;
use super::super::traits::LedgerEngine;
use super::super::transaction_submitter::canonical_tx_id;
use super::super::transaction_submitter::{SubmitSuccess, SubmitterError, TransactionSubmitter};
use super::super::tx_counts::{InputCount, OutputCount};
use super::super::tx_fee_model::{build_fee_directive, fee_rate_for_priority};

use super::support::{
    build_error_kind, fail_build_after_attempted, map_fee_estimator_error,
    map_handle_err_to_reanchor, map_output_selector_error, map_signer_error,
    release_output_locks_for, with_pending_tx_state_mut, TreeSpendGate,
};
use super::types::{
    ConsumerHeldEntry, ContentFingerprint, OutputId, PendingTxState, ReanchorError,
    ReanchorOutcome, RescanRequest, Stage1LedgerSpendableAccess, SubmitLoopBreaker,
    REANCHOR_MAX_RETRIES,
};

// ============================================================================
// LocalPendingTx aggregate
// ============================================================================

/// Stage 1 production [`PendingTxEngine`](super::super::traits::PendingTxEngine) implementor.
///
/// Holds the four constructor-bound dependencies (signer, output
/// selector, fee estimator, ledger handle), the diagnostic sink, the
/// per-collection TTL config, the wallet network, and the engine's
/// `Mutex<PendingTxState>` per the (γ) lean shape.
///
/// # Construction
///
/// [`Self::new`] is the only constructor; it consumes the
/// `Arc<S: Signer>` (the secrets-holding signer per §5.4 R11 (b);
/// `LocalPendingTx` delegates all spend-secret access through the
/// `Signer` trait surface and never holds spend material directly),
/// owns the `O: OutputSelector` and `F: FeeEstimator` aggregates by
/// value, and takes the `L: LedgerEngine` handle by value (matches
/// the workspace pattern of holding `LedgerEngine` implementors by
/// concrete value rather than by `Arc<dyn>` — `LedgerEngine` is not
/// object-safe because of its `impl Future + Send` method).
///
/// # `#[non_exhaustive]` not used
///
/// `LocalPendingTx` fields are all private (`pub(crate)` at most for
/// test introspection). External callers cannot construct or
/// pattern-match against the struct shape regardless of the outer
/// `pub` visibility — they reach the type only through
/// [`Self::new`]. Future revisions add fields through `Self::new`
/// API revisions; the public-API surface is the constructor
/// signature plus the (`pub(crate)`)
/// [`PendingTxEngine`](super::super::traits::PendingTxEngine) impl, not the
/// struct shape itself.
///
/// # Not `Debug`
///
/// `LocalPendingTx` does not derive [`Debug`] because the
/// `signer: Arc<S>` field's implementor (the default
/// [`LocalSigner`](super::super::signer::LocalSigner)) holds sensitive
/// material (`AllKeysBlob`) and is explicitly non-`Debug` per F3
/// sensitive-material discipline. The pattern matches
/// [`LocalRefresh`](super::super::local_refresh::LocalRefresh) and
/// [`Engine`](super::super::Engine).
///
/// # Trait-implementation visibility
///
/// `LocalPendingTx` is `pub` so external callers can name the type
/// in the orchestrator's `Engine<S, D, L, R, P = LocalPendingTx<…>>`
/// default (C6). The
/// [`PendingTxEngine`](super::super::traits::PendingTxEngine) trait it
/// implements is itself `pub(crate)` per `V3_ENGINE_TRAIT_BOUNDARIES.md`
/// §1.4, so external callers can name `LocalPendingTx` but cannot
/// reach its trait surface directly — only through the inherent
/// methods on `Engine` that the C6 dispatch lands.
//
// `private_bounds` allow: `LocalPendingTx`'s `L: LedgerEngine` bound
// references a `pub(crate)` trait. The same `#[allow]` lives on
// `Engine<S, D, L, R, …>` per `engine/mod.rs` for the same reason —
// external callers name the type slot but cannot reach the trait
// surface directly. Stage 4's trait promotion deletes this allow.
//
#[allow(private_bounds)]
pub struct LocalPendingTx<S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    /// Spend-secret holder. `Arc<S>` because the constructor takes
    /// a pre-`Arc`'d signer (the default
    /// [`LocalSigner`](super::super::signer::LocalSigner) is held under
    /// `Arc<AllKeysBlob>` per §5.4 R11 (b); the surrounding Arc lets
    /// the engine clone-share the signer with future spawn sites
    /// without re-cloning the secret bytes).
    pub(crate) signer: Arc<S>,
    /// Output-selection strategy; held by value because typical
    /// implementors (e.g., the default
    /// [`WalletGreedyOutputSelector`](super::super::output_selector::WalletGreedyOutputSelector))
    /// are zero-sized and need no sharing semantics.
    pub(crate) output_selector: O,
    /// Fee-estimation strategy; held by value for the same reason
    /// as `output_selector`.
    pub(crate) fee_estimator: F,
    /// Atomic fee-snapshot source (§3.2 / PF2); separate from `F`.
    pub(crate) fee_snapshot_source: FS,
    /// Daemon (or test) transaction broadcaster.
    pub(crate) submitter: Arc<TS>,
    /// Shared `LedgerEngine` handle (same `Arc` as [`Engine`](super::super::Engine)'s
    /// `ledger` field at C6 assembly).
    pub(crate) ledger: Arc<L>,
    /// Clone of [`Engine`](super::super::Engine)'s FCMP++ curve-tree actor handle, used
    /// to read the tree's `ingested_tip_height` at build time and gate the
    /// spendable set on `min(synced_height, tree_cursor)` (CT-5 §3.2.1 D1/D3,
    /// commit 4b). `None` only in direct-construction unit tests that exercise
    /// selection/fee logic without a tree; the production assembly site
    /// (`engine/lifecycle.rs`) always supplies `Some`. When `None` the spend
    /// gate is inert (every matured output is selectable, the pre-4b behavior).
    pub(crate) curve_tree: Option<CurveTreeHandle>,
    /// Diagnostic sink (segment-2f §5.0.2.1 sink-binding closure).
    pub(crate) sink: Arc<dyn DiagnosticSink>,
    /// Per-collection reservation TTL config (Phase 0l). Consumed by
    /// the C7 R8 TTL sweep; constructor-held at C5β.
    #[allow(dead_code)]
    pub(crate) ttl: ReservationTTLConfig,
    /// Network the wallet was opened against; consumed when decoding
    /// recipient addresses at signing time.
    pub(crate) network: Network,
    /// Engine state guarded by [`Mutex`] for interior mutability;
    /// see [`PendingTxState`] rustdoc.
    pub(crate) state: Mutex<PendingTxState>,
    /// Build-serialization permit (W-B step 1, `docs/FOLLOWUPS.md`
    /// "build concurrency permit stays 1"): exactly one `build` runs at
    /// a time, **engine-owned** so every embedder — wallet-rpc under a
    /// read lock, the in-process GUI — inherits the serialization now
    /// that `Engine::build_pending_tx{,_async}` take `&self`. This
    /// preserves the pre-relaxation network observable: one
    /// `AssembleTx` membership round-trip against the segment layer at
    /// a time. Raising the count is a rule-21 reopen gated on
    /// anonymized segment fetch (correlated-burst observable) — never a
    /// throughput tweak.
    pub(crate) build_permit: tokio::sync::Semaphore,
    /// Test-only: overrides the Phase 1 daemon stub on the next
    /// `submit` after `SubmitAttempted` (PR 5 C7 R9 per-error-class
    /// coverage). FIFO not required — one slot consumed per submit.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) submit_daemon_outcome: Mutex<Option<Result<SubmitSuccess, SubmitterError>>>,
}

pub(super) struct BuiltPendingMeta {
    pub(super) fee: AtomicUnits,
    pub(super) selected: SelectedOutputs,
    pub(super) synced: u64,
    pub(super) tip_hash: [u8; 32],
    /// Output locks are held from assembly until `consumer_held` commit.
    pub(super) reservation_id: ReservationId,
}

/// Releases [`BuiltPendingMeta::reservation_id`] output locks unless disarmed.
pub(super) struct BuildReservationCleanup<'a, S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    engine: &'a LocalPendingTx<S, O, F, FS, TS, L>,
    reservation_id: ReservationId,
    committed: bool,
}

impl<'a, S, O, F, FS, TS, L> BuildReservationCleanup<'a, S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    pub(super) fn new(
        engine: &'a LocalPendingTx<S, O, F, FS, TS, L>,
        reservation_id: ReservationId,
    ) -> Self {
        Self {
            engine,
            reservation_id,
            committed: false,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.committed = true;
    }
}

impl<S, O, F, FS, TS, L> Drop for BuildReservationCleanup<'_, S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    fn drop(&mut self) {
        if !self.committed {
            self.engine.release_build_reservation(self.reservation_id);
        }
    }
}

/// The output of the synchronous selection phase (CT-5c): the per-input
/// `AssembleInput`s and the fee directive, captured under the state lock so the
/// `AssembleTx` round-trip + fold can run lock-free. The selected output indices
/// ride `meta.selected.indices`; the fold re-reads the transfers by those
/// indices (`TransferDetails` is not `Clone`) and guards the re-read with a
/// `gindex` check against these `AssembleInput`s.
#[allow(private_bounds)]
pub(super) struct BuildSelected {
    /// One assemble request per selected input, in transaction input order —
    /// `gindex` resolution key + `(O, C)` consistency pair (X3). Public material.
    pub(super) assemble_inputs: Vec<AssembleInput>,
    /// The fee directive sized against the real tree depth.
    pub(super) fee_directive: super::super::traits::key::FeeDirective,
    pub(super) meta: BuiltPendingMeta,
}

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
    pub(super) fn refresh_current_snapshot(&self, state: &mut PendingTxState) {
        state.current_snapshot = derive_snapshot_id(&self.ledger.snapshot());
    }

    /// CT-5d (`docs/design/CT5D_REANCHOR.md` §5): is `reference` no longer
    /// canonical? A stateless point query — the canonical block at the reference
    /// height is no longer the one the proof was anchored against (a reorg
    /// replaced it). One sync `with_ledger_block` read (F-J); handles arbitrarily
    /// many intervening reorgs for free, since it compares against the *current*
    /// canonical hash, not a retained fork history.
    pub(super) fn reference_orphaned(&self, reference: &ReferenceBlock) -> bool {
        self.ledger
            .with_ledger_block(|ledger| ledger.block_hash_at(reference.height.0).copied())
            != Some(reference.block_hash)
    }

    #[allow(clippy::unused_self)] // `self` is used only under `test` / `test-helpers` cfgs.
    pub(super) fn take_queued_submit_outcome(
        &self,
    ) -> Option<Result<SubmitSuccess, SubmitterError>> {
        #[cfg(any(test, feature = "test-helpers"))]
        {
            self.submit_daemon_outcome
                .lock()
                .expect("submit_daemon_outcome lock poisoned")
                .take()
        }
        #[cfg(not(any(test, feature = "test-helpers")))]
        {
            None
        }
    }

    /// Drain the F40 targeted re-scan queue (decision 3), returning the
    /// pending requests for the driver to execute this tick and leaving
    /// the queue empty. One lock acquisition.
    pub(crate) fn drain_rescan_queue(&self) -> Vec<RescanRequest> {
        std::mem::take(
            &mut self
                .state
                .lock()
                .expect("pending-tx state lock poisoned")
                .rescan_queue,
        )
    }

    /// Look up the retained network-exposed bytes for `tx_hash` (§5.3
    /// decision 2), cloned for the watchdog's resubmit-same-bytes probe.
    /// `None` means the bytes are gone — a restart crossed the await, or
    /// the tx already left the held projection and was pruned — and the
    /// probe rung degrades to the operator alarm.
    pub(crate) fn held_bytes_for(&self, tx_hash: &TxHash) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("pending-tx state lock poisoned")
            .held_bytes
            .get(tx_hash)
            .cloned()
    }

    /// Prune retained probe bytes down to the live held-projection set
    /// `live` (decision 2: "prune when the hash leaves the held
    /// projection"). The driver calls this after projecting
    /// `held_submits` so confirmed / released txs do not retain their
    /// bytes indefinitely.
    pub(crate) fn prune_held_bytes(&self, live: &HashSet<TxHash>) {
        self.state
            .lock()
            .expect("pending-tx state lock poisoned")
            .held_bytes
            .retain(|tx_hash, _| live.contains(tx_hash));
    }

    pub(super) fn build_select_sync(
        &self,
        request: &TxRequest,
        fee_snapshot: super::super::traits::FeeEstimates,
        tree_gate: TreeSpendGate,
        reference: Option<ReferenceBlock>,
        tree_depth: u8,
    ) -> Result<BuildSelected, SendError> {
        if request.recipients.is_empty() {
            let err = SendError::InvalidRecipient {
                reason: "TxRequest must carry at least one recipient",
            };
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::BuildFailed {
                    kind: build_error_kind(&err),
                },
            );
            return Err(err);
        }

        let recipient_count = u32::try_from(request.recipients.len()).map_err(|_| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::InvalidRecipient {
                    reason: "recipient count overflowed u32",
                },
            )
        })?;
        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::BuildAttempted {
                request_summary: BuildRequestSummary {
                    recipient_count,
                    priority: request.priority,
                },
            },
        );

        let mut state = self.state.lock().map_err(|_| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "pending-tx state lock poisoned",
                },
            )
        })?;
        self.refresh_current_snapshot(&mut state);

        // C2 (2A §3.7.5): when a curve tree is enforced, the reference block
        // anchors `REF_ANCHOR_AGE` behind the tip; an output is in the tree as
        // of that reference block only if `eligible_height <= reference_height`.
        // Without a tree there is no FCMP reference, so C2 does not apply.
        let c2_active = matches!(tree_gate, TreeSpendGate::Enforced { .. });
        let (
            synced,
            reference_height,
            tip_hash,
            candidates,
            spendable_now_total,
            pending_rebuild_total,
            not_yet_spendable_total,
            not_yet_spendable,
        ) = self.ledger.with_ledger_block(|ledger| {
            let synced = ledger.height();
            // Gate against the height the *bound* reference anchors to (computed
            // in `build` before the cursor-read `.await`), so the C2 spendability
            // decision and the tx's anchored reference are the same height even
            // if the ledger advanced during that await — otherwise the gate
            // could admit an output not in the tree at the anchored reference,
            // and the proof would not include it. Recompute only when no
            // reference was resolved (no tree / too young / tree behind the
            // reference — none of which build a tx, so there is no anchor to
            // stay consistent with).
            let reference_height = if c2_active {
                reference
                    .as_ref()
                    .map(|r| r.height.0)
                    .or_else(|| select_reference_height(synced))
            } else {
                None
            };
            let tip_hash = ledger.block_hash_at(synced).copied();
            let locked: HashSet<OutputId> = state.output_locks.keys().copied().collect();
            // Partition the matured, non-reserved set across three buckets so an
            // insufficiency surfaces as the precise, self-resolving error rather
            // than a misleading `InsufficientFunds`:
            //   - too fresh for the reference block (C2)   → not_yet_spendable
            //   - in the tree at the reference block       → candidate (now)
            //   - blocked only by the in-progress backfill → pending_rebuild
            let mut candidates: Vec<OutputCandidate> = Vec::new();
            let mut spendable_now_total: u64 = 0;
            let mut pending_rebuild_total: u64 = 0;
            let mut not_yet_spendable_total: u64 = 0;
            // `(eligible_height, amount)` per too-fresh output, so the
            // wait-blocks signal can account for the *subset needed to cover the
            // shortfall* rather than just the soonest output (which alone may
            // not suffice — that would underestimate the wait).
            let mut not_yet_spendable: Vec<(u64, u64)> = Vec::new();
            for (idx, td) in ledger.spendable_outputs(synced, None) {
                if locked.contains(&idx) {
                    continue;
                }
                let amount = td.amount();
                match reference_height {
                    // C2 active: spendability is decided against the *reference*
                    // height, not the per-output eligible height.
                    Some(rh) => {
                        if td.eligible_height > rh {
                            // Too fresh for the reference block — not in the tree
                            // there even if its leaf is already ingested.
                            let raw = amount.to_raw();
                            not_yet_spendable_total = not_yet_spendable_total.saturating_add(raw);
                            not_yet_spendable.push((td.eligible_height, raw));
                        } else if tree_gate.covers(rh) {
                            // The tree has reached the reference height, so its
                            // root is reconstructable and every `eligible <= rh`
                            // leaf is present at the reference block — spendable.
                            spendable_now_total =
                                spendable_now_total.saturating_add(amount.to_raw());
                            candidates.push(OutputCandidate { index: idx, amount });
                        } else {
                            // The tree has not yet reached the reference height
                            // (adopting / rebuilding): the reference root cannot
                            // be reconstructed, so *no* output is provable yet —
                            // even one whose own leaf is already ingested
                            // (per-output coverage is necessary but not
                            // sufficient). Self-healing as the backfill advances
                            // to the reference height.
                            pending_rebuild_total =
                                pending_rebuild_total.saturating_add(amount.to_raw());
                        }
                    }
                    // No C2 reference (no curve tree): the tree gate alone
                    // decides (`Unenforced` ⇒ covers all), preserving the
                    // no-tree path.
                    None => {
                        if tree_gate.covers(td.eligible_height) {
                            spendable_now_total =
                                spendable_now_total.saturating_add(amount.to_raw());
                            candidates.push(OutputCandidate { index: idx, amount });
                        } else {
                            pending_rebuild_total =
                                pending_rebuild_total.saturating_add(amount.to_raw());
                        }
                    }
                }
            }
            (
                synced,
                reference_height,
                tip_hash,
                candidates,
                spendable_now_total,
                pending_rebuild_total,
                not_yet_spendable_total,
                not_yet_spendable,
            )
        });

        let Some(tip_hash) = tip_hash else {
            let err = SendError::CannotSign {
                reason: "wallet has not ingested any block yet",
            };
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::BuildFailed {
                    kind: build_error_kind(&err),
                },
            );
            return Err(err);
        };

        // Pre-maturity (C2): a curve tree is enforced but the chain is too short
        // to anchor a reference block (`synced < REF_ANCHOR_AGE`) — nothing is
        // spendable yet. Clean, self-resolving as the tip advances; checked
        // after the tip-hash guard so a truly empty wallet still reports the
        // "no block yet" condition.
        if c2_active && reference_height.is_none() {
            let err = SendError::WalletTooYoungToSpend {
                synced_height: synced,
                ref_anchor_age: REF_ANCHOR_AGE,
            };
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::BuildFailed {
                    kind: build_error_kind(&err),
                },
            );
            return Err(err);
        }

        // CT-5 §3.2.1 D3 + C2 (2A §3.7.5): classify an insufficiency by what is
        // blocking the shortfall, preferring the soonest-healing explanation.
        // Tree backfill advances continuously, so `SpendUnavailableRebuilding`
        // is preferred when the tree-pending outputs alone close the gap; the C2
        // reference depth advances only with the tip, so `OutputNotYetSpendable`
        // is next when the too-fresh outputs are also required; otherwise the
        // wallet is genuinely short and `InsufficientFunds` is honest — its
        // `available` reports the full matured balance (including not-yet- and
        // pending-rebuild buckets) so the gate never makes the wallet look
        // poorer than it is.
        let resolve_insufficiency = |needed_raw: u64| -> SendError {
            let with_rebuild = spendable_now_total.saturating_add(pending_rebuild_total);
            let total_matured = with_rebuild.saturating_add(not_yet_spendable_total);
            if pending_rebuild_total > 0
                && spendable_now_total < needed_raw
                && with_rebuild >= needed_raw
            {
                SendError::SpendUnavailableRebuilding {
                    needed: needed_raw,
                    spendable_now: spendable_now_total,
                    pending_rebuild: pending_rebuild_total,
                }
            } else if not_yet_spendable_total > 0
                && with_rebuild < needed_raw
                && total_matured >= needed_raw
            {
                // The too-fresh outputs are required to cover the spend. Report
                // the height by which *enough* of them mature relative to the
                // reference — accumulate (cheapest-to-mature first) until the
                // shortfall is covered, not just the soonest output (which alone
                // may not suffice, underestimating the wait). The
                // `total_matured >= needed_raw` guard guarantees the loop
                // reaches the shortfall.
                let reference_block_height = reference_height
                    .expect("not_yet_spendable_total > 0 ⇒ C2 active ⇒ reference height set");
                let shortfall = needed_raw.saturating_sub(with_rebuild);
                let mut by_eligible = not_yet_spendable.clone();
                by_eligible.sort_unstable_by_key(|&(eligible, _)| eligible);
                let mut covered: u64 = 0;
                let mut eligible_height = reference_block_height;
                for (eligible, amount) in by_eligible {
                    eligible_height = eligible;
                    covered = covered.saturating_add(amount);
                    if covered >= shortfall {
                        break;
                    }
                }
                SendError::OutputNotYetSpendable {
                    eligible_height,
                    reference_block_height,
                    wait_blocks: eligible_height.saturating_sub(reference_block_height),
                }
            } else {
                SendError::InsufficientFunds {
                    needed: needed_raw,
                    available: total_matured,
                }
            }
        };
        // Selector-error projection: an insufficiency (empty/short candidate
        // set) routes through `resolve_insufficiency`; a returned-subset
        // violation stays an `InvalidRecipient` contract failure.
        let map_select_err = |err: OutputSelectorError, needed_raw: u64| -> SendError {
            match err {
                OutputSelectorError::ReturnedIndicesNotSubset { .. } => {
                    SendError::InvalidRecipient {
                        reason: "output selector returned indices outside candidate set",
                    }
                }
                OutputSelectorError::InsufficientFunds { .. }
                | OutputSelectorError::NoEligibleOutputs => resolve_insufficiency(needed_raw),
            }
        };

        let mut total_amount = AtomicUnits::ZERO;
        for recipient in &request.recipients {
            total_amount = total_amount
                .checked_add(recipient.amount_atomic_units)
                .ok_or_else(|| {
                    fail_build_after_attempted(
                        self.sink.as_ref(),
                        SendError::InvalidRecipient {
                            reason: "recipient amount sum overflowed u64",
                        },
                    )
                })?;
        }

        let ledger_snapshot = self.ledger.with_ledger_block(LedgerSnapshot::from_ledger);
        let payment_count = request.recipients.len();
        let rate = fee_rate_for_priority(request.priority, &fee_snapshot).map_err(|err| {
            fail_build_after_attempted(self.sink.as_ref(), map_fee_estimator_error(&err))
        })?;

        let estimate = |input_count: usize, output_count: usize| {
            self.fee_estimator
                .estimate_fee(
                    request.priority,
                    &FeeEstimationContext {
                        ledger: &ledger_snapshot,
                        recipient_count: payment_count,
                        input_count: InputCount::clamped(input_count),
                        output_count: OutputCount::clamped(output_count),
                        fee_snapshot,
                        tree_depth,
                    },
                )
                .map_err(|err| map_fee_estimator_error(&err.into()))
        };

        let fee_pass_a = estimate(1, payment_count.saturating_add(1))
            .map_err(|err| fail_build_after_attempted(self.sink.as_ref(), err))?;

        let needed = total_amount.checked_add(fee_pass_a).ok_or_else(|| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::InvalidRecipient {
                    reason: "amount + fee overflowed u64",
                },
            )
        })?;

        let mut selected: SelectedOutputs = self
            .output_selector
            .select_outputs(&candidates, needed)
            .map_err(|err| {
                let mapped = map_select_err(err.into(), needed.to_raw());
                emit_pending_tx_diagnostic(
                    self.sink.as_ref(),
                    PendingTxDiagnostic::BuildFailed {
                        kind: build_error_kind(&mapped),
                    },
                );
                mapped
            })?;

        let fee_pass_b = estimate(selected.indices.len(), payment_count.saturating_add(1))
            .map_err(|err| fail_build_after_attempted(self.sink.as_ref(), err))?;
        if fee_pass_b > fee_pass_a {
            let needed_b = total_amount.checked_add(fee_pass_b).ok_or_else(|| {
                fail_build_after_attempted(
                    self.sink.as_ref(),
                    SendError::InvalidRecipient {
                        reason: "amount + refined fee overflowed u64",
                    },
                )
            })?;
            selected = self
                .output_selector
                .select_outputs(&candidates, needed_b)
                .map_err(|err| {
                    let mapped = map_select_err(err.into(), needed_b.to_raw());
                    emit_pending_tx_diagnostic(
                        self.sink.as_ref(),
                        PendingTxDiagnostic::BuildFailed {
                            kind: build_error_kind(&mapped),
                        },
                    );
                    mapped
                })?;
        }
        let fee = estimate(selected.indices.len(), payment_count.saturating_add(1))
            .map_err(|err| fail_build_after_attempted(self.sink.as_ref(), err))?;

        let required = total_amount.checked_add(fee).ok_or_else(|| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::InvalidRecipient {
                    reason: "amount + final fee overflowed u64",
                },
            )
        })?;
        if selected.total_covered < required {
            let err = resolve_insufficiency(required.to_raw());
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::BuildFailed {
                    kind: build_error_kind(&err),
                },
            );
            return Err(err);
        }

        let fee_directive = build_fee_directive(
            &rate,
            InputCount::clamped(selected.indices.len()),
            OutputCount::clamped(payment_count),
            tree_depth,
        );

        let candidate_indices: HashSet<OutputId> = candidates.iter().map(|c| c.index).collect();
        for index in &selected.indices {
            if !candidate_indices.contains(index) {
                let err =
                    map_output_selector_error(&OutputSelectorError::ReturnedIndicesNotSubset {
                        offending_index: *index,
                    });
                emit_pending_tx_diagnostic(
                    self.sink.as_ref(),
                    PendingTxDiagnostic::BuildFailed {
                        kind: BuildErrorKind::SelectorContractViolation,
                    },
                );
                return Err(err);
            }
        }

        // CT-5c: the reference-height block hash is no longer threaded as a raw
        // `[u8; 32]` here — it rides the `ReferenceBlock` into the real
        // `assemble_tx` (T1), and the resulting `AssembledPath.tree` carries it
        // into the signing context. `tree_depth` is the real depth read at the
        // reference height (T2), already used to size the fee above.
        //
        // Build one `AssembleInput` per selected input: `gindex`
        // (= `global_output_index`) is the resolution key, and
        // `(output_key, commitment)` the post-resolution consistency pair (X3).
        // Public material only. `TransferDetails` is not `Clone` (it is
        // secret-bearing), so the secret-pathway fields are not captured here;
        // the fold re-reads the transfers by index after the assemble await and
        // guards against an index shift by checking each transfer's `gindex`
        // against the matching `AssembleInput`.
        let assemble_inputs = self.ledger.with_ledger_block(|ledger| {
            let transfers = ledger.transfers();
            let mut assemble_inputs = Vec::with_capacity(selected.indices.len());
            for &index in &selected.indices {
                let td = transfers.get(index).ok_or(SendError::CannotSign {
                    reason: "selected transfer index out of range",
                })?;
                assemble_inputs.push(AssembleInput {
                    gindex: Gindex(td.global_output_index),
                    output_key: td.key.compress().to_bytes(),
                    commitment: td.commitment.calculate().compress().to_bytes(),
                });
            }
            Ok::<_, SendError>(assemble_inputs)
        })?;

        let reservation_id = ReservationId::new(state.next_id);
        state.next_id = state
            .next_id
            .checked_add(1)
            .expect("ReservationId u64 counter overflowed within a single engine handle");
        for index in &selected.indices {
            state.output_locks.insert(*index, reservation_id);
        }

        drop(state);

        Ok(BuildSelected {
            assemble_inputs,
            fee_directive,
            meta: BuiltPendingMeta {
                fee,
                selected,
                synced,
                tip_hash,
                reservation_id,
            },
        })
    }

    pub(super) fn release_build_reservation(&self, reservation_id: ReservationId) {
        with_pending_tx_state_mut(&self.state, |state| {
            release_output_locks_for(state, reservation_id);
        });
    }

    /// Re-validate the selected inputs at build's commit boundary.
    ///
    /// Selection is separated from commit by the lock-free prover window
    /// (`AssembleTx` + signing). `refresh` merges scan results under a
    /// *shared* engine borrow (`refresh.rs` — `apply_scan_result` behind
    /// `read().await`), so no embedder lock serializes that merge against
    /// this window; it can land inside it. Two things it does invalidate a
    /// build in flight:
    ///
    /// - **the transfer vector shifted** (a reorg rolled back and replayed
    ///   blocks), so `indices` no longer address the outputs the paths were
    ///   assembled for — committing would bind the reservation to the wrong
    ///   outputs. Detected as a `gindex` mismatch, the same identity check
    ///   the pre-sign fold uses ([`assemble_tx_to_sign`]);
    /// - **an input was observed spent**, i.e. a co-spend from another copy
    ///   of the seed landed on chain. The signed transaction is already
    ///   dead — the daemon will reject it as a double spend.
    ///
    /// Either way, refuse. The user gets a clean build failure and the
    /// reservation cleanup releases the output locks, instead of a
    /// `PendingTx` we already know cannot be submitted. This does not make
    /// the merge atomic with the build — nothing can, because the spend
    /// happened outside this wallet — it bounds the build to what was still
    /// true at commit, which is the whole window this method closes.
    fn revalidate_selected_inputs(
        &self,
        indices: &[usize],
        assemble_inputs: &[AssembleInput],
    ) -> Result<(), SendError> {
        // Parallel arrays in transaction-input order, built in lockstep by
        // `build_select_sync`; a length mismatch is internal plumbing, not a
        // runtime condition.
        debug_assert_eq!(
            indices.len(),
            assemble_inputs.len(),
            "assemble-input count must equal selected input count",
        );
        let verdict = if indices.len() != assemble_inputs.len() {
            Err(SendError::CannotSign {
                reason: "assemble-input count does not match selected input count",
            })
        } else {
            self.ledger.with_ledger_block(|ledger| {
                let transfers = ledger.transfers();
                for (&index, ai) in indices.iter().zip(assemble_inputs) {
                    let Some(td) = transfers.get(index) else {
                        return Err(SendError::CannotSign {
                            reason: "selected transfer index out of range at commit",
                        });
                    };
                    if td.global_output_index != ai.gindex.0 {
                        return Err(SendError::CannotSign {
                            reason: "selected transfer shifted under the transaction before commit",
                        });
                    }
                    if td.spent {
                        return Err(SendError::CannotSign {
                            reason: "a selected input was spent elsewhere during assembly",
                        });
                    }
                }
                Ok(())
            })
        };
        verdict.map_err(|reason| fail_build_after_attempted(self.sink.as_ref(), reason))
    }

    pub(super) fn commit_built_sync(
        &self,
        request: &TxRequest,
        meta: &BuiltPendingMeta,
        assemble_inputs: &[AssembleInput],
        reference: ReferenceBlock,
        signed: SignedTransfer,
    ) -> Result<PendingTx, SendError> {
        // WI-RPC-3 retention: take the whole `SignedTransfer` so the
        // per-tx secret rides into `consumer_held` alongside the bytes
        // (persisted at submit-ACCEPTED, wiped with the entry on
        // discard). Destructure once; the secret moves, never copies.
        let SignedTransfer {
            tx_bytes,
            tx_key_secret,
        } = signed;
        let mut state = self.state.lock().map_err(|_| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "pending-tx state lock poisoned",
                },
            )
        })?;
        // Build's lock₂ — the same discipline the re-anchor's lock₂
        // applies to its reference (`CT5D_REANCHOR.md` §5), on the axis
        // build actually depends on: its inputs. Selection ran *before*
        // the lock-free window (the `AssembleTx` round-trip and the
        // signer), and refresh's ledger merge takes a **shared** engine
        // borrow — no embedder lock excludes it from that window, so
        // both of its effects have to be re-checked here rather than
        // assumed away. The fold's `gindex` guard covers the pre-sign
        // half only; this is the post-sign re-check, under the state
        // lock, immediately before the reservation becomes
        // `consumer_held`.
        self.revalidate_selected_inputs(&meta.selected.indices, assemble_inputs)?;
        self.refresh_current_snapshot(&mut state);

        let id = meta.reservation_id;
        let snapshot_id = state.current_snapshot;
        let created_at = Instant::now();

        let summary: Vec<TxRecipientSummary> = request
            .recipients
            .iter()
            .map(|recipient| TxRecipientSummary {
                address: recipient.address.clone(),
                amount_atomic_units: recipient.amount_atomic_units,
            })
            .collect();

        // CT-5d: the realized content fingerprint `content_gen` advances against
        // (§4 F-G). Built with checked arithmetic — the balance was validated in
        // `build_select_sync`, so a failure here is corrupt state and must fail
        // the build rather than feed a wrong value into a consent decision.
        let fingerprint =
            ContentFingerprint::from_build(meta.fee, &summary, meta.selected.total_covered)
                .map_err(|err| fail_build_after_attempted(self.sink.as_ref(), err))?;

        state.consumer_held.insert(
            id,
            ConsumerHeldEntry {
                created_at,
                snapshot_id,
                built_at_height: meta.synced,
                built_at_tip_hash: meta.tip_hash,
                tx_bytes: tx_bytes.clone(),
                request: request.clone(),
                reference,
                // A fresh build is generation 0; re-anchor bumps it (§4).
                content_gen: 0,
                fingerprint,
                tx_key_secret,
            },
        );

        let pending = PendingTx {
            id,
            built_at_height: meta.synced,
            built_at_tip_hash: meta.tip_hash,
            fee_atomic_units: meta.fee,
            snapshot_id,
            tx_bytes,
            recipients: summary,
            // Fresh build: generation 0, anchored at the resolved reference.
            content_gen: 0,
            reference_height: reference.height.0,
        };

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::BuildSucceeded {
                reservation_id: id,
                snapshot_id,
                outputs_count: u32::try_from(meta.selected.indices.len()).unwrap_or(u32::MAX),
            },
        );

        Ok(pending)
    }

    /// CT-5d re-anchor — **reprove** path ([`docs/design/CT5D_REANCHOR.md`] §3/§3a):
    /// refresh a `consumer_held` proof against a fresh reference without changing
    /// its inputs.
    ///
    /// Three-phase so the FCMP++ prover never holds the state lock (mirrors
    /// `build`, and the shape the Stage-4 `PendingTxActor` migration needs):
    ///
    /// 1. **async pre-phase** (no state lock) — select the fresh reference under
    ///    the two-sided ingested-tip gate (§3b) and compute the fixed-input fee
    ///    at the fresh depth.
    /// 2. **prover** (lock-free) — `assemble_tx` + fold + sign.
    /// 3. **lock₂** (sync) — re-validate the reference is still canonical (the
    ///    TOCTOU the lock-drop opens, §5, all sync `with_ledger_block` reads —
    ///    F-J) and swap `tx_bytes` / `reference` / `fingerprint` / `content_gen`
    ///    in place. `content_gen` advances iff the realized content changed (§4).
    ///
    /// Reselection (a deep reorg that orphaned a selected output, or a fresh-depth
    /// fee the fixed inputs cannot cover — F-I) is the CT-5d-deferred path: it
    /// surfaces as [`ReanchorError::ReselectionRequired`] so the consumer
    /// discards and rebuilds — never a bad proof, never a silent mutation.
    ///
    /// Runs under [`Self::build_permit`]: the prover phase issues the same
    /// `AssembleTx` membership round-trip `build` does, so it belongs to the
    /// same serialized network observable. Acquired once for the whole retry
    /// loop — each attempt is another round-trip. Nothing on this path calls
    /// `build`, so the single permit cannot be re-entered.
    pub(super) async fn reanchor_consumer_held(
        &self,
        id: ReservationId,
    ) -> Result<ReanchorOutcome, ReanchorError> {
        let handle =
            self.curve_tree
                .as_ref()
                .ok_or(ReanchorError::Failed(SendError::CannotSign {
                    reason: "curve tree required to re-anchor a membership proof",
                }))?;

        let _build_permit = self
            .build_permit
            .acquire()
            .await
            .expect("build permit is never closed");

        // The lock-free prover run can re-stale the freshly-anchored reference
        // (the lock₂ TOCTOU); retry the whole loop a bounded number of times
        // before surfacing a clean "resyncing" (§3a).
        let mut last_resync: Option<ReanchorError> = None;
        for _attempt in 0..REANCHOR_MAX_RETRIES {
            // --- lock₀ (sync): snapshot the entry's rebuild context ---
            // Only the rebuild *inputs* are snapshotted here. The consent baseline
            // (the entry's current fingerprint / content_gen) is deliberately NOT
            // captured at lock₀: a concurrent re-anchor can advance it while the
            // prover runs, so it is re-read authoritatively at lock₂ (§4 F-G) to
            // keep content_gen monotonic.
            let (request, selected_indices) = {
                let state = self.state.lock().map_err(|_| {
                    ReanchorError::Failed(SendError::CannotSign {
                        reason: "pending-tx state lock poisoned",
                    })
                })?;
                let held = state.consumer_held.get(&id).ok_or(ReanchorError::Failed(
                    SendError::CannotSign {
                        reason: "reservation is no longer consumer_held",
                    },
                ))?;
                // Reprove keeps the same inputs: recover them from `output_locks`
                // (the same shape `finalize_submit_accept` uses).
                let mut selected: Vec<OutputId> = state
                    .output_locks
                    .iter()
                    .filter_map(|(o, owner)| (*owner == id).then_some(*o))
                    .collect();
                selected.sort_unstable();
                (held.request.clone(), selected)
            };

            let summary: Vec<TxRecipientSummary> = request
                .recipients
                .iter()
                .map(|r| TxRecipientSummary {
                    address: r.address.clone(),
                    amount_atomic_units: r.amount_atomic_units,
                })
                .collect();

            // --- phase 0 (async, no state lock): fresh reference + fixed-input fee ---
            let fee_snapshot = self
                .fee_snapshot_source
                .fetch()
                .await
                .map_err(|err| ReanchorError::Failed(map_fee_estimator_error(&err)))?;
            let covered_through = handle
                .ingested_tip_height()
                .await
                .map_err(|err| map_handle_err_to_reanchor(&err))?
                .map(|bh| bh.0);
            let ingested = covered_through.ok_or(ReanchorError::ReferenceResyncing {
                detail: "curve tree has not ingested any block yet",
            })?;
            let chain_tip = self.ledger.with_ledger_block(LedgerBlock::height);
            // Two-sided ingested-tip gate (§3b, F-C) — the shared
            // [`two_sided_reference_height`] definition (also the emission
            // claim orchestrator's): the lower arm anchors at or below the
            // ingested tip; the upper arm refuses a reference already past
            // the rebuild threshold — same predicate the lock₂
            // re-validation uses (`should_reanchor`, inclusive at
            // REBUILD_AT), so a reference that passes here can never
            // immediately fail lock₂ on the age criterion and burn a
            // prover attempt. Both are never-submit-a-bad-proof gates.
            let reference_height =
                two_sided_reference_height(chain_tip, ingested).map_err(|refusal| {
                    ReanchorError::ReferenceResyncing {
                        detail: match refusal {
                            TwoSidedRefusal::ChainTooShort => {
                                "chain too short to anchor a reference"
                            }
                            TwoSidedRefusal::TreeTooFarBehind => {
                                "tree too far behind to anchor a submittable reference; resync"
                            }
                        },
                    }
                })?;
            let (curve_tree_root, depth) = handle
                .reference_root_and_depth(BlockHeight(reference_height))
                .await
                .map_err(|err| map_handle_err_to_reanchor(&err))?;
            let reference = match self
                .ledger
                .with_ledger_block(|ledger| ledger.block_hash_at(reference_height).copied())
            {
                Some(block_hash) => ReferenceBlock {
                    height: BlockHeight(reference_height),
                    curve_tree_root,
                    block_hash,
                },
                None => {
                    return Err(ReanchorError::ReferenceResyncing {
                        detail: "reference-height block hash missing from ledger",
                    })
                }
            };

            // Fixed-input fee at the fresh depth (F-I). The inputs do not change
            // on the reprove path, so `input_count` is the already-selected set;
            // a fee the current inputs cannot cover escalates to reselection.
            let ledger_snapshot = self.ledger.with_ledger_block(LedgerSnapshot::from_ledger);
            let payment_count = request.recipients.len();
            let rate = fee_rate_for_priority(request.priority, &fee_snapshot)
                .map_err(|err| ReanchorError::Failed(map_fee_estimator_error(&err)))?;
            let fee = self
                .fee_estimator
                .estimate_fee(
                    request.priority,
                    &FeeEstimationContext {
                        ledger: &ledger_snapshot,
                        recipient_count: payment_count,
                        input_count: InputCount::clamped(selected_indices.len()),
                        output_count: OutputCount::clamped(payment_count.saturating_add(1)),
                        fee_snapshot,
                        tree_depth: depth,
                    },
                )
                .map_err(|err| ReanchorError::Failed(map_fee_estimator_error(&err.into())))?;

            let mut total_amount = AtomicUnits::ZERO;
            for recipient in &request.recipients {
                total_amount = total_amount
                    .checked_add(recipient.amount_atomic_units)
                    .ok_or(ReanchorError::Failed(SendError::InvalidRecipient {
                        reason: "recipient amount sum overflowed u64",
                    }))?;
            }
            let required = total_amount.checked_add(fee).ok_or(ReanchorError::Failed(
                SendError::InvalidRecipient {
                    reason: "amount + fee overflowed u64",
                },
            ))?;

            // Re-read the selected inputs for `total_covered` and the assemble
            // inputs (public material only; the fold re-reads the secret pathway
            // by index after the assemble, guarding an index shift via `gindex`).
            let (assemble_inputs, total_covered) = self
                .ledger
                .with_ledger_block(|ledger| {
                    let transfers = ledger.transfers();
                    let mut assemble_inputs = Vec::with_capacity(selected_indices.len());
                    let mut covered = AtomicUnits::ZERO;
                    for &index in &selected_indices {
                        let td = transfers.get(index).ok_or(SendError::CannotSign {
                            reason: "selected transfer index out of range during re-anchor",
                        })?;
                        covered =
                            covered
                                .checked_add(td.amount())
                                .ok_or(SendError::CannotSign {
                                    reason: "selected-input sum overflowed during re-anchor",
                                })?;
                        assemble_inputs.push(AssembleInput {
                            gindex: Gindex(td.global_output_index),
                            output_key: td.key.compress().to_bytes(),
                            commitment: td.commitment.calculate().compress().to_bytes(),
                        });
                    }
                    Ok::<_, SendError>((assemble_inputs, covered))
                })
                .map_err(ReanchorError::Failed)?;

            if total_covered < required {
                return Err(ReanchorError::ReselectionRequired {
                    detail:
                        "fresh-depth fee exceeds the selected inputs' coverage; discard and rebuild",
                });
            }
            let fee_directive = build_fee_directive(
                &rate,
                InputCount::clamped(selected_indices.len()),
                OutputCount::clamped(payment_count),
                depth,
            );

            // --- phase 2 (prover, lock-free): assemble + fold + sign ---
            let paths = handle
                .assemble_tx(reference, assemble_inputs.clone())
                .await
                .map_err(|err| map_handle_err_to_reanchor(&err))?;
            // Check *every* path's depth, not just the first: all paths share the
            // one reference's tree so they should agree, but verifying all closes
            // the gap if that invariant ever breaks (the per-input branch-layer
            // count is authoritatively re-checked downstream in tx-builder's
            // `validate_inputs`; this is the fee-sizing pre-check).
            if paths.iter().any(|p| p.tree.tree_depth != depth) {
                // The tree moved under the reference between the depth read and
                // the assemble — re-stale; retry the whole loop.
                last_resync = Some(ReanchorError::ReferenceResyncing {
                    detail: "assembled tree depth diverged from the fresh reference",
                });
                continue;
            }
            let tx_to_sign = self
                .ledger
                .with_ledger_block(|ledger| {
                    assemble_tx_to_sign(
                        self.network,
                        &request,
                        &selected_indices,
                        ledger.transfers(),
                        &assemble_inputs,
                        &paths,
                        fee_directive,
                    )
                })
                .map_err(ReanchorError::Failed)?;
            let signed = self
                .signer
                .sign_transfer(TransferSigningContext::from_tx(tx_to_sign))
                .await
                .map_err(|err| {
                    let signer_err: SignerError = err.into();
                    ReanchorError::Failed(map_signer_error(&signer_err))
                })?;
            // WI-RPC-3 retention: a reprove re-mints the per-tx secret
            // (fresh scalar → fresh output derivations → fresh bytes),
            // so the swap below replaces the entry's held secret too;
            // the superseded secret zeroizes on drop. A `continue`
            // retry drops this pair the same way — no residue.
            let SignedTransfer {
                tx_bytes,
                tx_key_secret,
            } = signed;
            // Checked + single-sourced with the fresh-build path (§4 F-G); the
            // fee-coverage check above guarantees this succeeds here.
            let new_fingerprint = ContentFingerprint::from_build(fee, &summary, total_covered)
                .map_err(ReanchorError::Failed)?;

            // --- lock₂ (sync): authoritative re-validation + commit the swap ---
            let mut state = self.state.lock().map_err(|_| {
                ReanchorError::Failed(SendError::CannotSign {
                    reason: "pending-tx state lock poisoned",
                })
            })?;
            // A concurrent submit/discard could have removed the entry while the
            // prover ran (we held no lock). Fail clean, leaving nothing changed.
            if !state.consumer_held.contains_key(&id) {
                return Err(ReanchorError::Failed(SendError::CannotSign {
                    reason: "reservation left consumer_held during re-anchor",
                }));
            }
            // Authoritative staleness re-derivation at commit (the lock₂ TOCTOU,
            // §3a/§5): the fresh reference must still be canonical and not itself
            // already due for re-anchor. All sync ledger reads (F-J).
            let current_tip = self.ledger.with_ledger_block(LedgerBlock::height);
            let still_canonical = self
                .ledger
                .with_ledger_block(|ledger| ledger.block_hash_at(reference_height).copied())
                == Some(reference.block_hash);
            if !still_canonical || should_reanchor(current_tip, reference_height) {
                last_resync = Some(ReanchorError::ReferenceResyncing {
                    detail: "reference re-staled during the prover run",
                });
                continue;
            }
            let Some(current_tip_hash) = self
                .ledger
                .with_ledger_block(|ledger| ledger.block_hash_at(current_tip).copied())
            else {
                return Err(ReanchorError::Failed(SendError::CannotSign {
                    reason: "current tip block hash missing from ledger",
                }));
            };
            self.refresh_current_snapshot(&mut state);
            let snapshot_id = state.current_snapshot;

            let entry = state
                .consumer_held
                .get_mut(&id)
                .expect("consumer_held membership re-checked above");

            // `content_gen` advances iff the realized content changed — measured
            // against the entry's CURRENT materialized fingerprint and generation,
            // read here under lock₂, never `seen_gen` and never the lock₀ snapshot
            // (§4 F-G). Reading the committed state at commit keeps the
            // advancement monotonic when a concurrent re-anchor advanced the entry
            // while this attempt's prover ran.
            let content_changed = new_fingerprint != entry.fingerprint;
            // `checked_add`, not saturating: `content_gen` is the consent counter,
            // so a saturated value would silently stop advancing and defeat the
            // must-re-confirm invariant. Overflow is unreachable in practice (a
            // u64 of content-changing re-anchors), but fail clean if it ever
            // occurs — the entry is left untouched (still the prior proof).
            let content_gen = if content_changed {
                entry
                    .content_gen
                    .checked_add(1)
                    .ok_or(ReanchorError::Failed(SendError::CannotSign {
                        reason: "content_gen overflow on re-anchor (consent counter exhausted)",
                    }))?
            } else {
                entry.content_gen
            };

            entry.tx_bytes = tx_bytes;
            entry.tx_key_secret = tx_key_secret;
            entry.reference = reference;
            entry.fingerprint = new_fingerprint;
            entry.content_gen = content_gen;
            entry.built_at_height = current_tip;
            entry.built_at_tip_hash = current_tip_hash;
            entry.snapshot_id = snapshot_id;

            return Ok(if content_changed {
                ReanchorOutcome::ContentChanged { content_gen }
            } else {
                ReanchorOutcome::Reproved { content_gen }
            });
        }

        // Retries exhausted: the tip/tree is moving faster than the prover can
        // anchor against it. A clean "retry later" beats spinning (§3a).
        Err(last_resync.unwrap_or(ReanchorError::ReferenceResyncing {
            detail: "re-anchor retries exhausted; tip moving too fast, retry later",
        }))
    }

    pub(super) async fn submit_async(
        &self,
        id: ReservationId,
        seen_gen: u64,
    ) -> Result<SubmitOutcome, SubmitError> {
        // --- pre-flight: membership under the state lock, staleness outside it
        // (CT-5d §5). The reference is the staleness authority — it *replaces* the
        // SnapshotId / built_at_tip_hash checks, so a benign tip advance no longer
        // invalidates a still-canonical proof; only an aged-out or reorg-orphaned
        // reference triggers a re-anchor. Only the membership classification and
        // the `ReferenceBlock` copy need the pending-tx lock; the staleness reads
        // hit the ledger (a different lock) and are re-validated authoritatively at
        // the re-anchor's lock₂ regardless, so the state lock is dropped before
        // touching the ledger (F5: no nested lock, less contention).
        let reference = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| SubmitError::ReservationNotFound { reservation_id: id })?;
            self.refresh_current_snapshot(&mut state);

            let in_consumer = state.consumer_held.contains_key(&id);
            let in_flight = state.in_flight.contains_key(&id);
            match (in_consumer, in_flight) {
                (false, false) => {
                    return Err(SubmitError::ReservationNotFound { reservation_id: id });
                }
                // A re-submit while in_flight is await/query the daemon, never a
                // rebuild (F-E): the daemon owns the resolution authority.
                (false, true) => {
                    return Err(SubmitError::SubmitAlreadyPending { reservation_id: id });
                }
                (true, true) => {
                    panic!("invariant: rid is in at most one of consumer_held / in_flight");
                }
                (true, false) => {}
            }

            state
                .consumer_held
                .get(&id)
                .expect("consumer_held membership established above")
                .reference
        };

        // Staleness decision — ledger reads only, no pending-tx lock held (F-J).
        let current_tip = self.ledger.with_ledger_block(LedgerBlock::height);
        let stale =
            should_reanchor(current_tip, reference.height.0) || self.reference_orphaned(&reference);

        // --- re-anchor if stale (three-phase, lock-free prover) ---
        if stale {
            match self.reanchor_consumer_held(id).await {
                // Reproved or ContentChanged: the entry now carries a fresh proof
                // and a possibly-advanced content_gen. The broadcast gate below
                // enforces consent uniformly via seen_gen, so both fall through.
                Ok(_) => {}
                Err(ReanchorError::ReselectionRequired { .. }) => {
                    return Err(SubmitError::ReselectionRequired { reservation_id: id });
                }
                Err(ReanchorError::ReferenceResyncing { .. } | ReanchorError::Failed(_)) => {
                    return Err(SubmitError::ReanchorUnavailable { reservation_id: id });
                }
            }
        }

        // --- broadcast gate (sync): content_gen consent + atomic flip, then send ---
        let tx_bytes = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| SubmitError::ReservationNotFound { reservation_id: id })?;
            self.refresh_current_snapshot(&mut state);

            // The entry can leave `consumer_held` between the pre-flight read and
            // here: the lock is released across the (possible) re-anchor, and the
            // engine is `&self` + `Mutex` — a *concurrent* `submit(id)` may have
            // already flipped it to `in_flight` (the re-anchor itself never does).
            // Preserve the P2 contract uniformly: a flipped entry is
            // `SubmitAlreadyPending`, a vanished one is discarded / never-existed.
            // Peek `content_gen` only (a `Copy`, no entry clone); the entry is
            // moved out below iff the consent gate passes.
            let content_gen = match state.consumer_held.get(&id) {
                Some(held) => held.content_gen,
                None => {
                    return Err(if state.in_flight.contains_key(&id) {
                        SubmitError::SubmitAlreadyPending { reservation_id: id }
                    } else {
                        SubmitError::ReservationNotFound { reservation_id: id }
                    });
                }
            };

            // CT-5d (§4): broadcast only what the consumer authorized. `seen_gen`
            // must match the materialized `content_gen`; a mismatch means a
            // re-anchor (this submit's, or a prior one the consumer has not
            // re-confirmed) advanced the realized content — withhold and return
            // the advanced generation. Makes broadcasting unauthorized content
            // unrepresentable. The entry stays `consumer_held` (not moved).
            if seen_gen != content_gen {
                return Err(SubmitError::ContentChanged {
                    reservation_id: id,
                    content_gen,
                });
            }

            // Consent satisfied. Move the entry out of `consumer_held` and flip it
            // to `in_flight` atomically under the lock, then send lock-free —
            // "committed as of" the flip (F-H). The lock is held continuously
            // since the peek above (no await), so the entry is still present.
            // `in_flight` preserves the *whole* entry (re-anchor substrate
            // included) so a §2.5 retryable rejection can restore it to
            // `consumer_held` losslessly; one `tx_bytes` clone moves on to the
            // send.
            let held = state
                .consumer_held
                .remove(&id)
                .expect("consumer_held membership established above, lock held throughout");
            let tx_bytes = held.tx_bytes.clone();

            // WI-RPC-3 retention (OUTBOUND PREREQUISITE pin 1, dispatch
            // form): persist the per-tx secret BEFORE the bytes can
            // leave for the daemon. The accept verdict is an
            // *observation* about network exposure, not its start — a
            // crash or dropped connection between this send and the
            // verdict leaves a tx the network may still mine, and a
            // secret that lived only in the runtime `in_flight` map
            // died with the process, permanently disabling the OUTBOUND
            // proof for a payment that settles normally. Definite
            // refusals (terminal / retryable — provably unrelayed under
            // single-egress, §2.5) retire the record in their
            // finalizers, so a never-accepted build still leaves no
            // residue; accept / already-in-chain / ambiguous / crash
            // keep it.
            //
            // Second copy, accounted: from here the persisted record is
            // the durable holder; the runtime copy stays on the entry
            // only so a §2.5 retryable restoration can re-dispatch, and
            // is wiped when the entry drops (`TxSecretKey` is
            // zeroize-on-drop).
            let dispatch_txid = canonical_tx_id(&held.tx_bytes);
            let retained = shekyl_engine_state::TxSecretKey::new(zeroize::Zeroizing::new(
                *held.tx_key_secret.as_bytes(),
            ));
            self.ledger.with_wallet_ledger_mut(|wallet| {
                wallet.record_retained_tx_key(dispatch_txid.to_bytes(), retained);
            });

            let submitted_at = Instant::now();
            state.in_flight.insert(
                id,
                InFlightSubmit {
                    entry: held,
                    submitted_at,
                },
            );

            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::SubmitAttempted { reservation_id: id },
            );

            if let Some(outcome) = self.take_queued_submit_outcome() {
                // Test-injected daemon reply: same finalization as the
                // production dispatch below, through the same two methods,
                // so the injected path cannot certify a projection the real
                // one does not perform.
                return match outcome {
                    Ok(success) => Ok(self.finalize_submit_success(&mut state, id, success)),
                    Err(err) => Err(self.finalize_submit_error(&mut state, id, &err)),
                };
            }

            tx_bytes
        };

        let submitter = Arc::clone(&self.submitter);
        let success = match submitter.submit(tx_bytes).await {
            Ok(success) => success,
            Err(submit_err) => {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| SubmitError::ReservationNotFound { reservation_id: id })?;
                return Err(self.finalize_submit_error(&mut state, id, &submit_err));
            }
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| SubmitError::ReservationNotFound { reservation_id: id })?;

        Ok(self.finalize_submit_success(&mut state, id, success))
    }

    pub(super) fn discard_sync(
        &self,
        id: ReservationId,
        reason: DiscardReason,
    ) -> Result<(), PendingTxError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PendingTxError::ReservationNotFound { reservation_id: id })?;

        let in_consumer = state.consumer_held.contains_key(&id);
        let in_flight = state.in_flight.contains_key(&id);
        match (in_consumer, in_flight) {
            (false, false) => {
                return Err(PendingTxError::ReservationNotFound { reservation_id: id });
            }
            (false, true) => {
                return Err(PendingTxError::DiscardBlockedPendingDaemonAck { reservation_id: id });
            }
            (true, true) => {
                panic!("invariant: rid is in at most one of consumer_held / in_flight");
            }
            (true, false) => {}
        }

        state.consumer_held.remove(&id);
        release_output_locks_for(&mut state, id);

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::Discarded {
                reservation_id: id,
                reason,
            },
        );

        Ok(())
    }

    /// Operator acknowledgment of a tripped F28/F37 loop-breaker
    /// (`DAEMON_SUBMIT_VERDICT.md` §2.5): clears the tripped state and
    /// the consecutive-rejection streak, re-enabling `build`. The
    /// operator investigates the systematic disagreement the alarm
    /// named *before* acknowledging — the breaker cannot distinguish a
    /// fixed root cause from an unfixed one.
    ///
    /// `dead_code` allow: the consumer-facing wiring (CLI/RPC operator
    /// surface) lands with the §5.3 watchdog; the reset path exists now
    /// so the breaker's lifecycle is complete and testable.
    #[allow(dead_code)]
    pub(crate) fn acknowledge_submit_loop_breaker(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.loop_breaker.acknowledge();
        }
    }

    #[allow(dead_code)] // trait surface only; production wiring lands with mempool eviction (V3.x).
    pub(super) fn signal_mempool_evicted_sync(
        &self,
        rid: ReservationId,
    ) -> Result<(), PendingTxError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PendingTxError::ReservationNotFound {
                reservation_id: rid,
            })?;

        if !state.in_flight.contains_key(&rid) {
            return Err(PendingTxError::ReservationNotFound {
                reservation_id: rid,
            });
        }

        state.in_flight.remove(&rid);
        release_output_locks_for(&mut state, rid);

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::Discarded {
                reservation_id: rid,
                reason: DiscardReason::MempoolEvicted,
            },
        );

        Ok(())
    }
    /// Construct a new [`LocalPendingTx`].
    ///
    /// **Pre-condition (Stage 1).** The constructor reads
    /// `ledger.snapshot()` once to seed the engine's
    /// `current_snapshot` field; the seed is refreshed on every
    /// mutating call's first step (so an opener that
    /// constructs the engine before applying scan results
    /// observes an outdated seed only until the first call, not
    /// indefinitely).
    ///
    /// # Construction site
    ///
    /// The orchestrator constructs `LocalPendingTx` in
    /// `Engine::create` / `Engine::open_*` (`engine/lifecycle.rs`),
    /// which is the production assembly site.
    #[allow(clippy::too_many_arguments)] // mirrors `Engine::open_*` assembly arity.
    pub(crate) fn new(
        signer: Arc<S>,
        output_selector: O,
        fee_estimator: F,
        fee_snapshot_source: FS,
        submitter: Arc<TS>,
        ledger: Arc<L>,
        curve_tree: Option<CurveTreeHandle>,
        sink: Arc<dyn DiagnosticSink>,
        ttl: ReservationTTLConfig,
        network: Network,
    ) -> Self {
        let current_snapshot = super::super::refresh::derive_snapshot_id(&ledger.snapshot());
        let state = Mutex::new(PendingTxState {
            current_snapshot,
            output_locks: HashMap::new(),
            consumer_held: HashMap::new(),
            in_flight: HashMap::new(),
            next_id: 0,
            loop_breaker: SubmitLoopBreaker::default(),
            held_bytes: HashMap::new(),
            rescan_queue: Vec::new(),
        });
        Self {
            signer,
            output_selector,
            fee_estimator,
            fee_snapshot_source,
            submitter,
            ledger,
            curve_tree,
            sink,
            ttl,
            network,
            state,
            build_permit: tokio::sync::Semaphore::new(1),
            #[cfg(any(test, feature = "test-helpers"))]
            submit_daemon_outcome: Mutex::new(None),
        }
    }

    /// Queue the daemon round-trip outcome for the next `submit`
    /// (test / `test-helpers` only). Consumed after
    /// `SubmitAttempted` is emitted and the rid moves to `in_flight`.
    #[cfg(any(test, feature = "test-helpers"))]
    #[allow(dead_code)] // Canonical C7 R9 test-driver API; hybrid tests land in C7.
    pub(crate) fn queue_submit_daemon_outcome(
        &self,
        outcome: Result<SubmitSuccess, SubmitterError>,
    ) {
        *self
            .submit_daemon_outcome
            .lock()
            .expect("submit_daemon_outcome lock poisoned") = Some(outcome);
    }
}
