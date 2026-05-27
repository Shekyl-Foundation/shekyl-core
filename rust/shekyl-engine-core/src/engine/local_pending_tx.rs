// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `LocalPendingTx` — the Stage 1 production
//! [`PendingTxEngine`] implementor.
//!
//! Per [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`] §5.0.1 and
//! `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.4, `LocalPendingTx` aggregates
//! four constructor-bound dependencies (a `Signer`, an
//! `OutputSelector`, a `FeeEstimator`, and a `LedgerEngine` handle),
//! threads the diagnostic sink and the [`ReservationTTLConfig`]
//! through the same constructor, and holds the engine's
//! `Mutex<PendingTxState>` for interior mutability over the (γ)
//! three-collection lean shape (`output_locks` / `consumer_held` /
//! `in_flight`).
//!
//! # C5α skeleton
//!
//! This commit lands the struct shape and a stubbed `PendingTxEngine`
//! impl whose method bodies return `unimplemented!("filled in C5β")`.
//! The skeleton compiles green so C5β's diff is a body-fill rather
//! than a structural change — the load-bearing extraction commit (C5β)
//! ports the free-function bodies from
//! [`super::pending`]'s
//! `build_pending_tx_in_state` / `submit_pending_tx_in_state` /
//! `discard_pending_tx_in_state` triple into the trait-method bodies
//! with the segment-2h (γ) collection-moves shape replacing the
//! enum-state-mutation shape per §5.6.8 C5β.
//!
//! # Handler-atomicity discipline (segment-2h P7 pin)
//!
//! All mutating handlers (`build` / `submit` / `discard` /
//! `signal_mempool_evicted`) acquire `self.state.lock()` once at
//! entry and hold the guard across the entire sequence of lock
//! claim/release on `output_locks`, collection insert/remove on
//! `consumer_held` / `in_flight`, and sink emission. No `.await`
//! between mutation steps. The `Mutex` (not `RwLock`) choice is
//! deliberate per §2.4: `PendingTxEngine`'s operations are
//! predominantly write-style — even `outstanding` is a read against
//! state that mutates on every other call.
//!
//! [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md
//! [`ReservationTTLConfig`]: super::pending::ReservationTTLConfig

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use shekyl_engine_state::LedgerBlock;

use super::diagnostics::{
    emit_pending_tx_diagnostic, BuildErrorKind, BuildRequestSummary, DiagnosticSink,
    DiscardReason, PendingTxDiagnostic,
};
use super::error::{
    FeeEstimatorError, OutputSelectorError, PendingTxError, SendError, SignerError, SubmitError,
};
use super::fee_estimator::{FeeEstimationContext, FeeEstimator};
use super::local_ledger::LocalLedger;
use super::network::Network;
use super::output_selector::{OutputCandidate, OutputSelector, SelectedOutputs};
use super::pending::{
    InFlightSubmit, PendingTx, ReservationId, ReservationTTLConfig, SnapshotId, TxHash,
    TxRecipientSummary, TxRequest,
};
use super::refresh::{derive_snapshot_id, LedgerSnapshot};
use super::signer::{Signer, TransferSigningContext};
use super::traits::{LedgerEngine, PendingTxEngine};

/// Per-output identifier used as the `output_locks` map key.
///
/// **C5α placeholder.** Stage 1 currently identifies outputs by their
/// `usize` transfer-index within `LedgerBlock::transfers()`. C5β's
/// body extraction confirms this alias matches the existing
/// `Reservation::selected_transfer_indices` semantics; if subsequent
/// work needs a richer identifier (e.g., a `(height, tx_index,
/// output_index)` triple), the alias is upgraded to a newtype with
/// a single grep-able rename.
pub(crate) type OutputId = usize;

/// Per-reservation metadata while the rid lives in `consumer_held`.
///
/// The (γ) lean shape stores collection membership in
/// `consumer_held` / `in_flight` and keeps `output_locks` as the
/// single source of truth for per-output claims. `snapshot_id` is
/// still required for lazy-R5 submit-time staleness checks even
/// though V3.0's `consumer_held` map values are lighter than the
/// V3.x eager-discard `ConsumerHeldEntry { snapshot_id, created_at }`
/// substrate named in §5.6.7 P9.
#[derive(Debug, Clone)]
pub(crate) struct ConsumerHeldEntry {
    /// Build-time [`Instant`] for the R8 TTL safety-net.
    pub created_at: Instant,
    /// [`SnapshotId`] pinned at build for submit-time comparison.
    pub snapshot_id: SnapshotId,
    /// Engine `synced_height` at build (defense-in-depth checks).
    pub built_at_height: u64,
    /// `block_hash_at(built_at_height)` at build.
    pub built_at_tip_hash: [u8; 32],
}

/// Stage 1 ledger access for spendable-output enumeration.
///
/// `LedgerEngine` does not yet expose matured-output enumeration;
/// Stage 1's sole production implementor is [`LocalLedger`]. C5β
/// reaches `LedgerBlock::spendable_outputs` through this trait rather
/// than widening the public `LedgerEngine` surface.
trait Stage1LedgerSpendableAccess: LedgerEngine {
    fn with_ledger_block<R>(&self, f: impl FnOnce(&LedgerBlock) -> R) -> R;

    fn with_ledger_block_mut<R>(&self, f: impl FnOnce(&mut LedgerBlock) -> R) -> R;
}

impl Stage1LedgerSpendableAccess for LocalLedger {
    fn with_ledger_block<R>(&self, f: impl FnOnce(&LedgerBlock) -> R) -> R {
        let guard = self.read();
        f(&guard.ledger.ledger)
    }

    fn with_ledger_block_mut<R>(&self, f: impl FnOnce(&mut LedgerBlock) -> R) -> R {
        let mut guard = self.write();
        f(&mut guard.ledger.ledger)
    }
}

// ============================================================================
// PendingTxState (γ three-collection lean shape)
// ============================================================================

/// Engine-internal mutable state guarded by [`LocalPendingTx::state`].
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
///
/// # `dead_code` allow
///
/// C5α stubs all `PendingTxEngine` method bodies with
/// `unimplemented!()`; the fields are read by C5β's extraction.
/// Pattern matches the [`InFlightSubmit`] /
/// [`ReservationTTLConfig`] `dead_code` allows pinned at C2γ
/// landing time.
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
}

// ============================================================================
// LocalPendingTx aggregate
// ============================================================================

/// Stage 1 production [`PendingTxEngine`] implementor.
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
/// [`PendingTxEngine`] impl, not the
/// struct shape itself.
///
/// # Not `Debug`
///
/// `LocalPendingTx` does not derive [`Debug`] because the
/// `signer: Arc<S>` field's implementor (the default
/// [`LocalSigner`](super::signer::LocalSigner)) holds sensitive
/// material (`AllKeysBlob`) and is explicitly non-`Debug` per F3
/// sensitive-material discipline. The pattern matches
/// [`LocalRefresh`](super::local_refresh::LocalRefresh) and
/// [`Engine`](super::Engine).
///
/// # Trait-implementation visibility
///
/// `LocalPendingTx` is `pub` so external callers can name the type
/// in the orchestrator's `Engine<S, D, L, R, P = LocalPendingTx<…>>`
/// default (C6). The
/// [`PendingTxEngine`] trait it
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
pub struct LocalPendingTx<S, O, F, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    /// Spend-secret holder. `Arc<S>` because the constructor takes
    /// a pre-`Arc`'d signer (the default
    /// [`LocalSigner`](super::signer::LocalSigner) is held under
    /// `Arc<AllKeysBlob>` per §5.4 R11 (b); the surrounding Arc lets
    /// the engine clone-share the signer with future spawn sites
    /// without re-cloning the secret bytes).
    pub(crate) signer: Arc<S>,
    /// Output-selection strategy; held by value because typical
    /// implementors (e.g., the default
    /// [`WalletGreedyOutputSelector`](super::output_selector::WalletGreedyOutputSelector))
    /// are zero-sized and need no sharing semantics.
    pub(crate) output_selector: O,
    /// Fee-estimation strategy; held by value for the same reason
    /// as `output_selector`.
    pub(crate) fee_estimator: F,
    /// `LedgerEngine` handle used for `current_snapshot` reads at
    /// submit-time and balance / matured-output projection.
    pub(crate) ledger: L,
    /// Diagnostic sink (segment-2f §5.0.2.1 sink-binding closure).
    pub(crate) sink: Arc<dyn DiagnosticSink>,
    /// Per-collection reservation TTL config (Phase 0l). Consumed by
    /// the C7 R8 TTL sweep; constructor-held at C5β.
    #[allow(dead_code)]
    pub(crate) ttl: ReservationTTLConfig,
    /// Network the wallet was opened against. Consumed when address-
    /// binding validation lands in the build pipeline (C6+).
    #[allow(dead_code)]
    pub(crate) network: Network,
    /// Engine state guarded by [`Mutex`] for interior mutability;
    /// see [`PendingTxState`] rustdoc.
    pub(crate) state: Mutex<PendingTxState>,
}

#[allow(private_bounds)]
fn release_output_locks_for(state: &mut PendingTxState, rid: ReservationId) {
    state.output_locks.retain(|_, owner| *owner != rid);
}

fn build_error_kind(err: &SendError) -> BuildErrorKind {
    match err {
        SendError::InvalidRecipient { .. } | SendError::Tx(_) => {
            BuildErrorKind::InvalidRecipient
        }
        SendError::InsufficientFunds { .. } => BuildErrorKind::InsufficientFunds,
        SendError::CannotSign { .. } => BuildErrorKind::LedgerNotReady,
        SendError::Io(_) => BuildErrorKind::SignerUnavailable,
    }
}

fn map_output_selector_error(err: &OutputSelectorError) -> SendError {
    match *err {
        OutputSelectorError::InsufficientFunds { needed, available } => {
            SendError::InsufficientFunds { needed, available }
        }
        OutputSelectorError::NoEligibleOutputs => SendError::InsufficientFunds {
            needed: 0,
            available: 0,
        },
        OutputSelectorError::ReturnedIndicesNotSubset { .. } => SendError::InvalidRecipient {
            reason: "output selector returned indices outside candidate set",
        },
    }
}

fn map_fee_estimator_error(_err: &FeeEstimatorError) -> SendError {
    SendError::CannotSign {
        reason: "fee estimation unavailable",
    }
}

fn map_signer_error(_err: &SignerError) -> SendError {
    SendError::CannotSign {
        reason: "signer unavailable",
    }
}

fn phase1_tx_hash(id: ReservationId) -> TxHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.raw().to_le_bytes());
    TxHash(bytes)
}

#[allow(private_bounds)]
impl<S, O, F, L> LocalPendingTx<S, O, F, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    fn refresh_current_snapshot(&self, state: &mut PendingTxState) {
        state.current_snapshot = derive_snapshot_id(&self.ledger.snapshot());
    }

    fn build_sync(&self, request: &TxRequest) -> Result<PendingTx, SendError> {
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

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::BuildAttempted {
                request_summary: BuildRequestSummary {
                    recipient_count: u32::try_from(request.recipients.len())
                        .map_err(|_| SendError::InvalidRecipient {
                            reason: "recipient count overflowed u32",
                        })?,
                    priority: request.priority,
                },
            },
        );

        let mut state = self
            .state
            .lock()
            .map_err(|_| SendError::CannotSign {
                reason: "pending-tx state lock poisoned",
            })?;
        self.refresh_current_snapshot(&mut state);

        let (synced, tip_hash, candidates) = self.ledger.with_ledger_block(|ledger| {
            let synced = ledger.height();
            let tip_hash = ledger.block_hash_at(synced).copied();
            let locked: HashSet<OutputId> = state.output_locks.keys().copied().collect();
            let candidates: Vec<OutputCandidate> = ledger
                .spendable_outputs(synced, request.from_subaddress, None)
                .into_iter()
                .filter(|(idx, _)| !locked.contains(idx))
                .map(|(idx, td)| OutputCandidate {
                    index: idx,
                    amount: td.amount(),
                })
                .collect();
            (synced, tip_hash, candidates)
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

        let mut total_amount: u64 = 0;
        for recipient in &request.recipients {
            total_amount = total_amount
                .checked_add(recipient.amount_atomic_units)
                .ok_or(SendError::InvalidRecipient {
                    reason: "recipient amount sum overflowed u64",
                })?;
        }

        let ledger_snapshot = self
            .ledger
            .with_ledger_block(LedgerSnapshot::from_ledger);
        let fee = self
            .fee_estimator
            .estimate_fee(
                request.priority,
                &FeeEstimationContext {
                    ledger: &ledger_snapshot,
                    recipient_count: request.recipients.len(),
                    input_count: 0,
                },
            )
            .map_err(|err| map_fee_estimator_error(&err.into()))?;

        let needed = total_amount
            .checked_add(fee)
            .ok_or(SendError::InvalidRecipient {
                reason: "amount + fee overflowed u64",
            })?;

        let selected: SelectedOutputs = self
            .output_selector
            .select_outputs(&candidates, needed)
            .map_err(|err| map_output_selector_error(&err.into()))?;

        let candidate_indices: HashSet<OutputId> = candidates.iter().map(|c| c.index).collect();
        for index in &selected.indices {
            if !candidate_indices.contains(index) {
                let err = map_output_selector_error(&OutputSelectorError::ReturnedIndicesNotSubset {
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

        let signing_context = TransferSigningContext::phase1_stub();
        let signed = self
            .signer
            .sign_transfer(&signing_context)
            .map_err(|err| map_signer_error(&err.into()))?;
        let tx_bytes = signed.tx_bytes().to_vec();

        let id = ReservationId::new(state.next_id);
        state.next_id = state
            .next_id
            .checked_add(1)
            .expect("ReservationId u64 counter overflowed within a single engine handle");

        let snapshot_id = state.current_snapshot;
        let created_at = Instant::now();
        for index in &selected.indices {
            state.output_locks.insert(*index, id);
        }
        state.consumer_held.insert(
            id,
            ConsumerHeldEntry {
                created_at,
                snapshot_id,
                built_at_height: synced,
                built_at_tip_hash: tip_hash,
            },
        );

        let summary: Vec<TxRecipientSummary> = request
            .recipients
            .iter()
            .map(|recipient| TxRecipientSummary {
                address: recipient.address.clone(),
                amount_atomic_units: recipient.amount_atomic_units,
            })
            .collect();

        let pending = PendingTx {
            id,
            built_at_height: synced,
            built_at_tip_hash: tip_hash,
            fee_atomic_units: fee,
            snapshot_id,
            tx_bytes,
            recipients: summary,
        };

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::BuildSucceeded {
                reservation_id: id,
                snapshot_id,
                outputs_count: u32::try_from(selected.indices.len()).unwrap_or(u32::MAX),
            },
        );

        Ok(pending)
    }

    fn submit_sync(&self, id: ReservationId) -> Result<TxHash, SubmitError> {
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
            (false, true) => {
                return Err(SubmitError::SubmitAlreadyPending { reservation_id: id });
            }
            (true, true) => {
                panic!("invariant: rid is in at most one of consumer_held / in_flight");
            }
            (true, false) => {}
        }

        let held = state
            .consumer_held
            .get(&id)
            .expect("consumer_held membership established above")
            .clone();

        if held.snapshot_id != state.current_snapshot {
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::SubmitSnapshotInvalidated {
                    reservation_id: id,
                    reservation_snapshot: held.snapshot_id,
                    current_snapshot: state.current_snapshot,
                },
            );
            return Err(SubmitError::SnapshotInvalidated {
                reservation_snapshot: held.snapshot_id,
                current_snapshot: state.current_snapshot,
            });
        }

        let stored_tip = self
            .ledger
            .with_ledger_block(|ledger| ledger.block_hash_at(held.built_at_height).copied());
        if stored_tip != Some(held.built_at_tip_hash) {
            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::SubmitSnapshotInvalidated {
                    reservation_id: id,
                    reservation_snapshot: held.snapshot_id,
                    current_snapshot: state.current_snapshot,
                },
            );
            return Err(SubmitError::SnapshotInvalidated {
                reservation_snapshot: held.snapshot_id,
                current_snapshot: state.current_snapshot,
            });
        }

        let created_at = held.created_at;
        state.consumer_held.remove(&id);
        let submitted_at = Instant::now();
        state.in_flight.insert(
            id,
            InFlightSubmit {
                snapshot_id: held.snapshot_id,
                created_at,
                submitted_at,
            },
        );

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitAttempted { reservation_id: id },
        );

        // Phase 1 stub: daemon always accepts; Phase 2a replaces with
        // a real broadcast call.
        let tx_hash = phase1_tx_hash(id);

        let selected_indices: Vec<OutputId> = state
            .output_locks
            .iter()
            .filter_map(|(output_id, owner)| (*owner == id).then_some(*output_id))
            .collect();

        state.in_flight.remove(&id);
        release_output_locks_for(&mut state, id);

        self.ledger.with_ledger_block_mut(|ledger| {
            for index in selected_indices {
                if let Some(td) = ledger.transfer_mut(index) {
                    td.spent = true;
                }
            }
        });

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::SubmitSucceeded {
                reservation_id: id,
                tx_hash,
            },
        );

        Ok(tx_hash)
    }

    fn discard_sync(
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
                return Err(PendingTxError::DiscardBlockedPendingDaemonAck {
                    reservation_id: id,
                });
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

    fn signal_mempool_evicted_sync(&self, rid: ReservationId) -> Result<(), PendingTxError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PendingTxError::ReservationNotFound { reservation_id: rid })?;

        if !state.in_flight.contains_key(&rid) {
            return Err(PendingTxError::ReservationNotFound { reservation_id: rid });
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
    /// mutating call's first step at C5β (so an opener that
    /// constructs the engine before applying scan results
    /// observes an outdated seed only until the first call, not
    /// indefinitely).
    ///
    /// # `dead_code` allow
    ///
    /// C5α lands the constructor; C6 wires the first orchestrator-
    /// side construction site (`Engine::create` / `Engine::open_*`
    /// in `engine/lifecycle.rs`).
    #[allow(dead_code)]
    pub fn new(
        signer: Arc<S>,
        output_selector: O,
        fee_estimator: F,
        ledger: L,
        sink: Arc<dyn DiagnosticSink>,
        ttl: ReservationTTLConfig,
        network: Network,
    ) -> Self {
        let current_snapshot =
            super::refresh::derive_snapshot_id(&ledger.snapshot());
        let state = Mutex::new(PendingTxState {
            current_snapshot,
            output_locks: HashMap::new(),
            consumer_held: HashMap::new(),
            in_flight: HashMap::new(),
            next_id: 0,
        });
        Self {
            signer,
            output_selector,
            fee_estimator,
            ledger,
            sink,
            ttl,
            network,
            state,
        }
    }
}

// ============================================================================
// PendingTxEngine impl (C5α stub bodies)
// ============================================================================

impl<S, O, F, L> PendingTxEngine for LocalPendingTx<S, O, F, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    fn build(
        &self,
        request: TxRequest,
    ) -> impl Future<Output = Result<PendingTx, SendError>> + Send {
        std::future::ready(self.build_sync(&request))
    }

    fn submit(
        &self,
        id: ReservationId,
    ) -> impl Future<Output = Result<TxHash, SubmitError>> + Send {
        std::future::ready(self.submit_sync(id))
    }

    fn discard(
        &self,
        id: ReservationId,
        reason: DiscardReason,
    ) -> Result<(), PendingTxError> {
        self.discard_sync(id, reason)
    }

    fn signal_mempool_evicted(
        &self,
        rid: ReservationId,
    ) -> Result<(), PendingTxError> {
        self.signal_mempool_evicted_sync(rid)
    }

    fn outstanding(&self) -> usize {
        let state = self
            .state
            .lock()
            .expect("pending-tx state lock poisoned");
        state.consumer_held.len() + state.in_flight.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::diagnostics::{DiscardReason, TracingDiagnosticSink};
    use crate::engine::error::PendingTxError;
    use crate::engine::fee_estimator::DaemonFeeEstimator;
    use crate::engine::output_selector::WalletGreedyOutputSelector;
    use crate::engine::pending::{FeePriority, TxRecipient, STUB_FEE_ATOMIC_UNITS};
    use crate::engine::signer::LocalSigner;
    use crate::engine::traits::PendingTxEngine;
    use crate::engine::LocalLedger;
    use shekyl_scanner::RecoveredWalletOutput;
    use shekyl_crypto_pq::account::{
        rederive_account, AllKeysBlob, DerivationNetwork, SeedFormat, MASTER_SEED_BYTES,
    };

    /// Deterministic test seed. Distinct from
    /// `SIGNER_TEST_MASTER_SEED` (`engine/signer.rs`) so the C5α
    /// constructor test does not share derivation state with the
    /// C4α `LocalSigner` fixtures. `seed[i] = (i * 17) ^ 0x5B`
    /// deterministic.
    const PENDING_TX_TEST_MASTER_SEED: [u8; MASTER_SEED_BYTES] = {
        let mut seed = [0u8; MASTER_SEED_BYTES];
        let mut i: u8 = 0;
        while (i as usize) < MASTER_SEED_BYTES {
            seed[i as usize] = i.wrapping_mul(17) ^ 0x5B;
            i += 1;
        }
        seed
    };

    fn test_keys() -> Arc<AllKeysBlob> {
        Arc::new(
            rederive_account(
                &PENDING_TX_TEST_MASTER_SEED,
                DerivationNetwork::Fakechain,
                SeedFormat::Raw32,
            )
            .expect("rederive_account against fakechain raw32 seed"),
        )
    }

    fn test_ledger() -> LocalLedger {
        LocalLedger::from_test_blocks(Vec::new())
    }

    /// C5α smoke test: constructor succeeds and the engine's state
    /// initializes to the (γ) empty-collections baseline.
    #[test]
    fn local_pending_tx_new_constructs() {
        let keys = test_keys();
        let pending = LocalPendingTx::new(
            Arc::new(LocalSigner::new(keys)),
            WalletGreedyOutputSelector,
            DaemonFeeEstimator,
            test_ledger(),
            Arc::new(TracingDiagnosticSink),
            ReservationTTLConfig::default(),
            Network::Mainnet,
        );

        let state = pending.state.lock().expect("state lock not poisoned");
        assert!(state.output_locks.is_empty());
        assert!(state.consumer_held.is_empty());
        assert!(state.in_flight.is_empty());
        assert_eq!(state.next_id, 0);
    }

    fn make_recovered_output(seed: u8, global_index: u64, amount: u64) -> RecoveredWalletOutput {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
        use shekyl_oxide::primitives::Commitment;
        use shekyl_scanner::{RecoveredWalletOutput, WalletOutput};

        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&global_index.to_le_bytes());
        bytes[8] = seed;
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let key = &scalar * ED25519_BASEPOINT_TABLE;
        let base = WalletOutput::new_for_test(
            [seed; 32],
            0,
            global_index,
            key,
            Scalar::ZERO,
            Commitment {
                mask: Scalar::ONE,
                amount,
            },
            None,
        );
        RecoveredWalletOutput::new_for_test(base, amount)
    }

    fn populate_ledger(
        ledger: &LocalLedger,
        block_height: u64,
        outputs: Vec<RecoveredWalletOutput>,
        final_height: u64,
    ) {
        use shekyl_scanner::{LedgerIndexesExt, Timelocked};

        let mut guard = ledger.write();
        let state = &mut *guard;
        let ledger_block = &mut state.ledger.ledger;
        let indexes = &mut state.indexes;
        let timelocked = Timelocked::from_vec(outputs);
        let block_hash = [u8::try_from(block_height & 0xFF).unwrap(); 32];
        let inserted_range =
            indexes.process_scanned_outputs(ledger_block, block_height, block_hash, timelocked);
        assert!(!inserted_range.is_empty() || ledger_block.transfer_count() == 0);
        for h in (block_height + 1)..=final_height {
            let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
            let _ = indexes.process_scanned_outputs(
                ledger_block,
                h,
                hash,
                Timelocked::from_vec(Vec::new()),
            );
        }
    }

    fn standard_request(amount: u64) -> TxRequest {
        TxRequest {
            recipients: vec![TxRecipient {
                address: "test_address".to_string(),
                amount_atomic_units: amount,
            }],
            priority: FeePriority::Standard,
            from_subaddress: None,
        }
    }

    fn test_pending_tx(ledger: LocalLedger) -> LocalPendingTx<LocalSigner, WalletGreedyOutputSelector, DaemonFeeEstimator, LocalLedger> {
        LocalPendingTx::new(
            Arc::new(LocalSigner::new(test_keys())),
            WalletGreedyOutputSelector,
            DaemonFeeEstimator,
            ledger,
            Arc::new(TracingDiagnosticSink),
            ReservationTTLConfig::default(),
            Network::Mainnet,
        )
    }

    #[tokio::test]
    async fn build_then_submit_marks_outputs_spent() {
        let ledger = test_ledger();
        populate_ledger(
            &ledger,
            1,
            vec![
                make_recovered_output(1, 100, 10_000),
                make_recovered_output(2, 101, 5_000),
            ],
            20,
        );
        let pending = test_pending_tx(ledger);

        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        assert_eq!(built.fee_atomic_units, STUB_FEE_ATOMIC_UNITS);
        assert_eq!(pending.outstanding(), 1);

        let tx_hash = pending.submit(built.id).await.expect("submit ok");
        assert_eq!(&tx_hash.0[..8], &built.id.raw().to_le_bytes());
        assert_eq!(pending.outstanding(), 0);

        let spent = pending
            .ledger
            .read()
            .ledger
            .ledger
            .transfers()
            .first()
            .expect("output 0")
            .spent;
        assert!(spent);
    }

    #[tokio::test]
    async fn discard_releases_output_locks() {
        let ledger = test_ledger();
        populate_ledger(
            &ledger,
            1,
            vec![
                make_recovered_output(1, 100, 10_000),
                make_recovered_output(2, 101, 6_000),
            ],
            20,
        );
        let pending = test_pending_tx(ledger);

        let first = pending
            .build(standard_request(7_000))
            .await
            .expect("first build");
        pending
            .discard(first.id, DiscardReason::ConsumerExplicit)
            .expect("discard ok");
        assert_eq!(pending.outstanding(), 0);

        let second = pending
            .build(standard_request(7_000))
            .await
            .expect("second build reuses released output");
        assert_eq!(second.id.raw(), 1);
    }

    #[tokio::test]
    async fn discard_blocked_while_in_flight() {
        let ledger = test_ledger();
        populate_ledger(
            &ledger,
            1,
            vec![make_recovered_output(1, 100, 10_000)],
            20,
        );
        let pending = test_pending_tx(ledger);

        let built = pending
            .build(standard_request(1_000))
            .await
            .expect("build ok");

        // Force in_flight without completing submit by manipulating state.
        {
            let mut state = pending.state.lock().expect("state lock");
            let held = state
                .consumer_held
                .remove(&built.id)
                .expect("consumer_held entry");
            state.in_flight.insert(
                built.id,
                InFlightSubmit {
                    snapshot_id: held.snapshot_id,
                    created_at: held.created_at,
                    submitted_at: Instant::now(),
                },
            );
        }

        let err = pending
            .discard(built.id, DiscardReason::ConsumerExplicit)
            .unwrap_err();
        assert!(matches!(
            err,
            PendingTxError::DiscardBlockedPendingDaemonAck { .. }
        ));
    }
}
