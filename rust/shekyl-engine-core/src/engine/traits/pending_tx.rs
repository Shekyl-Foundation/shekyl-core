// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PendingTxEngine` trait surface.
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2.4 and
//! [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`] §4 (Phase 0a +
//! 0e + 0f + 0m binding form), `PendingTxEngine` owns the reservation
//! lifecycle for the wallet's `PendingTx` flow: `build` reserves
//! inputs against the current ledger snapshot and produces a
//! caller-visible `PendingTx` handle; `submit` dispatches the
//! reservation's tx bytes to the daemon and resolves the in-flight
//! state per the (γ) lean state shape; `discard` releases a
//! consumer-held reservation; `signal_mempool_evicted` admits a
//! consumer-observed mempool eviction per the F2 ownership-boundary
//! adjudication (segment-2i G1); `outstanding` reports the count of
//! reservations awaiting resolution.
//!
//! # Round 3 disposition: `&self` over `&mut self`
//!
//! All mutating methods take `&self`, not `&mut self`, per
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2 `&mut → &self` sweep.
//! The Stage 1 implementor [`LocalPendingTx`] carries
//! `Mutex<PendingTxState>` for interior mutability over the
//! (γ) three-collection shape (`output_locks` / `consumer_held` /
//! `in_flight`); every mutating handler acquires the mutex once and
//! holds it across the lock claim/release + collection move + sink
//! emit per the **handler-atomicity discipline (segment-2h P7 pin)**.
//! Stage 4's `ActorRef<PendingTxActor>` replaces the runtime mutex
//! with mailbox-FIFO serialization; the trait surface is identical
//! across both stages.
//!
//! # Concrete-typed returns (segment-2h `Self::Error` retirement)
//!
//! The trait does NOT declare an associated `Error` type. The
//! `build` / `submit` / `discard` / `signal_mempool_evicted` methods
//! return concrete types directly:
//!
//! - `build → Result<PendingTx, SendError>` — build-time validation
//!   vocabulary (insufficient funds, no spendable outputs, selector
//!   contract violation per F4).
//! - `submit → Result<TxHash, SubmitError>` — submit-time outcome
//!   vocabulary discriminating `TerminalErrorKind` (drops from
//!   `in_flight` on resolution) vs. `AmbiguousErrorKind` (R9
//!   daemon-side-authority preserved; rid stays `in_flight`) vs.
//!   `SnapshotInvalidated` (segment-2h F1 lazy R5 disposition).
//! - `discard → Result<(), PendingTxError>` — F2 ownership-boundary
//!   discrimination (`DiscardBlockedPendingDaemonAck` vs.
//!   `ReservationNotFound`).
//! - `signal_mempool_evicted → Result<(), PendingTxError>` — Phase
//!   0m surface; emits `Discarded { reason: MempoolEvicted }` on
//!   success.
//!
//! The split exists because the four vocabularies cover distinct
//! domains; collapsing them into a single associated type would
//! force consumers to discriminate by variant rather than by error
//! type (Round 2 Q9.8 closure).
//!
//! # `Send + Sync + 'static` supertrait
//!
//! The supertrait bound supports the Stage 4 `kameo`-equivalent
//! actor wrap of [`LocalPendingTx`] as the actor body. Listing it
//! at the trait surface catches the common failure mode where a
//! trait that "happens to be `Send + Sync + 'static` today" gains
//! a non-`Send` field (a `Signer` impl holding a non-`Send` HSM
//! handle, a `FeeEstimator` impl holding a non-`Send` RPC client)
//! before the actor wrap forces the issue.
//!
//! # Visibility (`pub(crate)` until JSON-RPC cutover)
//!
//! Per [`super`]'s visibility doc: traits ship `pub(crate)` until
//! V3.2's JSON-RPC server cutover; consumers reach functionality
//! via [`Engine<S>`](super::super::Engine)'s inherent methods, not
//! via direct trait dispatch.
//!
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
//! [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`]: ../../../../../docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md
//! [`LocalPendingTx`]: super::super::local_pending_tx::LocalPendingTx

use std::future::Future;

use crate::engine::diagnostics::DiscardReason;
use crate::engine::error::{PendingTxError, SendError, SubmitError};
use crate::engine::pending::{PendingTx, ReservationId, TxHash, TxRequest};

/// Engine-side surface for the [`PendingTx`] lifecycle (§2.4).
///
/// Implementors carry the (γ) three-collection state
/// (`output_locks` / `consumer_held` / `in_flight`) under interior
/// mutability (Stage 1) or actor-local state (Stage 4) and serve
/// the five-method surface uniformly across both stages.
///
/// # Supertrait bounds
///
/// - `Send + Sync + 'static` — see module-level rustdoc.
/// - **Not** `Clone` — implementors hold `Arc<S: Signer>` (spend
///   material; not safely `Clone`-derived per the architectural-
///   inheritance discipline) so a forced `Clone` would re-introduce
///   the secret-duplication hazard.
///
/// # Trait-parameter taxonomy
///
/// The Stage 1 implementor [`LocalPendingTx`] is parameterized on
/// the secondary-engine trait surfaces (`Signer` / `OutputSelector`
/// / `FeeEstimator`) plus the `LedgerEngine` handle for
/// snapshot-id reads at submit-time; the parameterization is an
/// implementor concern, not a trait-surface concern (the trait
/// itself takes no generic parameters).
///
/// [`LocalPendingTx`]: super::super::local_pending_tx::LocalPendingTx
pub(crate) trait PendingTxEngine: Send + Sync + 'static {
    /// Build a pending transaction against the current ledger
    /// snapshot; reserves the selected inputs in `consumer_held`
    /// and returns the [`PendingTx`] handle to the caller.
    ///
    /// On success the rid is inserted into `consumer_held` with
    /// the build-time `Instant`; the selected outputs are locked
    /// in `output_locks` (`output → rid` keying enforces the
    /// no-double-spend P6 invariant). A
    /// `PendingTxDiagnostic::BuildSucceeded` is emitted via the
    /// constructor-bound `DiagnosticSink` (per §5.0.3
    /// emission/return coherence R8 pin).
    ///
    /// # Errors
    ///
    /// Returns [`SendError`] for build-time validation failures
    /// (insufficient funds, no spendable outputs, selector
    /// rejected the request per the F4 caller-side subset
    /// re-verification discipline, fee estimator unavailable,
    /// etc.). Per the Round 2 Q9.8 closure, [`SendError`] is the
    /// build-time vocabulary; runtime invariants surface through
    /// [`PendingTxError`] on later trait calls.
    ///
    /// # `Send` futures via `impl Future + Send`
    ///
    /// Uses the explicit
    /// `-> impl Future<Output = Result<PendingTx, SendError>> + Send`
    /// return type rather than `async fn` so the `Send` bound on
    /// the returned future is part of the trait contract (callers
    /// `tokio::spawn` the future and need `Send` propagation
    /// through monomorphization). Matches the
    /// [`RefreshEngine`](super::refresh::RefreshEngine) and
    /// [`LedgerEngine`](super::ledger::LedgerEngine) precedents.
    fn build(
        &self,
        request: TxRequest,
    ) -> impl Future<Output = Result<PendingTx, SendError>> + Send;

    /// Submit the named reservation to the daemon.
    ///
    /// **Collection-move discipline (segment-2h P4 table).** On
    /// entry, `id` MUST be in `consumer_held` (else returns
    /// `SubmitError::ReservationNotFound` or
    /// `SubmitError::SubmitAlreadyPending` per the P3 / P2
    /// discriminating switch). On `submit` dispatch, the rid
    /// moves from `consumer_held` to `in_flight`; on daemon
    /// resolution, the rid either (a) drops from `in_flight` on
    /// `TerminalErrorKind` outcomes (and the engine emits
    /// `Discarded { rid, DaemonRejectedTerminal { kind } }`), or
    /// (b) stays in `in_flight` on `AmbiguousErrorKind` outcomes
    /// (R9 daemon-side-authority per Finding 2; the engine emits
    /// `SubmitPendingResolution { rid, tx_hash, kind }`), or (c)
    /// drops from `in_flight` on accept (and the engine emits
    /// `SubmitSucceeded { rid, tx_hash }`).
    ///
    /// **Staleness check (segment-2h F1 pin).** Before
    /// dispatching to the daemon, the handler reads the current
    /// snapshot id (Stage 1 reads exact ledger truth under the
    /// `Mutex<PendingTxState>` guard) and compares against the
    /// reservation's `snapshot_id`. On mismatch the engine emits
    /// `SubmitSnapshotInvalidated { rid, reservation_snapshot,
    /// current_snapshot }`, returns
    /// `SubmitError::SnapshotInvalidated`, and **does NOT
    /// auto-release** the reservation (segment-2h lazy R5
    /// disposition); the consumer must call `discard(rid,
    /// ConsumerExplicit)` to release `output_locks`. R8 TTL
    /// safety-net handles consumer abandonment.
    ///
    /// # Errors
    ///
    /// Returns [`SubmitError`] for the full submit-time outcome
    /// taxonomy; see [`SubmitError`]'s rustdoc.
    fn submit(&self, id: ReservationId)
        -> impl Future<Output = Result<TxHash, SubmitError>> + Send;

    /// Discard the named reservation with an explicit reason.
    ///
    /// **F2 ownership-boundary discipline (segment-2h pin).**
    /// Consumer-initiated `discard` on a reservation in
    /// `in_flight` returns
    /// `PendingTxError::DiscardBlockedPendingDaemonAck`; the
    /// daemon owns the resolution authority while the rid is
    /// `in_flight` (Finding-2 ambiguous-outcome handling). On
    /// `consumer_held` rids, the handler atomically removes the
    /// rid from `consumer_held`, releases `output_locks` for the
    /// rid, and emits `PendingTxDiagnostic::Discarded { rid,
    /// reason }`.
    ///
    /// # Errors
    ///
    /// - [`PendingTxError::ReservationNotFound`] if `id` is not in
    ///   `consumer_held` (either never existed or already
    ///   resolved).
    /// - [`PendingTxError::DiscardBlockedPendingDaemonAck`] if
    ///   `id` is in `in_flight` (F2 ownership-boundary rejection).
    fn discard(&self, id: ReservationId, reason: DiscardReason) -> Result<(), PendingTxError>;

    /// Signal that a previously-submitted reservation's tx has
    /// been observed evicted from the daemon's mempool (Phase 0m
    /// per segment-2i G1 disposition).
    ///
    /// **F2 ownership-boundary adjudication (segment-2i G1 pin).**
    /// Mempool eviction is an *observation* the consumer made
    /// that the actor couldn't make itself (the actor has no
    /// direct visibility into the daemon's mempool state); the
    /// observation is *of a state already terminal at the network
    /// level* (the tx is gone from the mempool; the daemon will
    /// never `Accept` it). The signal admits one specific
    /// observation under F2; it does NOT admit consumer-side
    /// terminal *decisions* (a hypothetical
    /// `signal_user_force_cancel` shape that F2 forbids). The
    /// narrow-vs-wide method-shape question is adjudicated
    /// per-method: each new "consumer signals terminal"
    /// candidate gets its own narrow method and its own F2
    /// adjudication entry. A wider
    /// `signal_external_terminal(rid, reason)` shape would
    /// silently admit decision-class signals; the narrow shape
    /// preserves the per-method F2 adjudication grep-ability
    /// that the wider shape forecloses.
    ///
    /// On success: the rid drops from `in_flight`, `output_locks`
    /// are released for the rid, and the engine emits
    /// `PendingTxDiagnostic::Discarded { rid, reason:
    /// DiscardReason::MempoolEvicted }` (all within a single
    /// P7-atomic handler step).
    ///
    /// # Errors
    ///
    /// - [`PendingTxError::ReservationNotFound`] if `rid` is not in
    ///   `in_flight` — including rids in `consumer_held` (eviction
    ///   is meaningful only for in-flight reservations; consumer-
    ///   held reservations were never submitted to the daemon).
    #[allow(dead_code)] // V3.x mempool-eviction surface; no production caller at C6.
    fn signal_mempool_evicted(&self, rid: ReservationId) -> Result<(), PendingTxError>;

    /// Total in-process reservations awaiting resolution. Sum of
    /// `consumer_held.len() + in_flight.len()` per the (γ) lean
    /// state shape.
    ///
    /// # Cancellation
    ///
    /// Synchronous read with no side effect; not awaitable.
    ///
    /// # Idempotency
    ///
    /// **Yes**: a snapshot read of the current `consumer_held +
    /// in_flight` cardinality. Repeated calls observe whatever
    /// value the last mutating call left in place.
    fn outstanding(&self) -> usize;
}
