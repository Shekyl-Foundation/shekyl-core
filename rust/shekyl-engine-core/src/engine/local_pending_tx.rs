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
//! # `PendingTxEngine` impl
//!
//! The trait-method bodies port the build / submit / discard logic from
//! [`super::pending`]'s
//! `build_pending_tx_in_state` / `submit_pending_tx_in_state` /
//! `discard_pending_tx_in_state` triple, using the segment-2h (γ)
//! collection-moves shape (`output_locks` / `consumer_held` /
//! `in_flight`) rather than an enum-state-mutation shape (per §5.6.8).
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
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use shekyl_curve_tree::{
    select_reference_height, should_reanchor, AssembleInput, BlockHeight, Gindex, ReferenceBlock,
    REBUILD_AT, REF_ANCHOR_AGE,
};
use shekyl_engine_state::LedgerBlock;
use shekyl_units::AtomicUnits;

use super::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use super::diagnostics::{
    emit_pending_tx_diagnostic, BuildErrorKind, BuildRequestSummary, DiagnosticSink, DiscardReason,
    PendingTxDiagnostic,
};
use super::error::{
    AmbiguousErrorKind, FeeEstimatorError, IoError, OutputSelectorError, PendingTxError, SendError,
    SignerError, SubmitError, TerminalErrorKind,
};
use super::fee_estimator::{FeeEstimationContext, FeeEstimator};
use super::fee_snapshot::FeeSnapshotSource;
use super::local_ledger::LocalLedger;
use super::network::Network;
use super::output_selector::{OutputCandidate, OutputSelector, SelectedOutputs};
use super::pending::{
    InFlightSubmit, PendingTx, ReservationId, ReservationTTLConfig, SnapshotId, TxHash,
    TxRecipientSummary, TxRequest,
};
use super::refresh::{derive_snapshot_id, LedgerSnapshot};
use super::signer::{Signer, TransferSigningContext};
use super::signing_assembly::assemble_tx_to_sign;
use super::traits::{LedgerEngine, PendingTxEngine};
use super::transaction_submitter::TransactionSubmitter;
use super::tx_fee_model::{build_fee_directive, fee_rate_for_priority};

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
    fn from_parts(
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
                height: BlockHeight(0),
                curve_tree_root: [0u8; 32],
                block_hash: [0u8; 32],
            },
            content_gen: 0,
            fingerprint: ContentFingerprint::from_parts(AtomicUnits::ZERO, &[], AtomicUnits::ZERO),
        }
    }
}

/// Stage 1 ledger access for spendable-output enumeration.
///
/// `LedgerEngine` does not yet expose matured-output enumeration;
/// Stage 1's sole production implementor is [`LocalLedger`]. `LocalPendingTx`
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

impl<L> Stage1LedgerSpendableAccess for Arc<L>
where
    L: Stage1LedgerSpendableAccess,
{
    fn with_ledger_block<R>(&self, f: impl FnOnce(&LedgerBlock) -> R) -> R {
        self.as_ref().with_ledger_block(f)
    }

    fn with_ledger_block_mut<R>(&self, f: impl FnOnce(&mut LedgerBlock) -> R) -> R {
        self.as_ref().with_ledger_block_mut(f)
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
    /// Atomic fee-snapshot source (§3.2 / PF2); separate from `F`.
    pub(crate) fee_snapshot_source: FS,
    /// Daemon (or test) transaction broadcaster.
    pub(crate) submitter: Arc<TS>,
    /// Shared `LedgerEngine` handle (same `Arc` as [`Engine`](super::Engine)'s
    /// `ledger` field at C6 assembly).
    pub(crate) ledger: Arc<L>,
    /// Clone of [`Engine`](super::Engine)'s FCMP++ curve-tree actor handle, used
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
    /// Network the wallet was opened against. Consumed when address-
    /// Network the wallet was opened against (address decode at sign).
    pub(crate) network: Network,
    /// Engine state guarded by [`Mutex`] for interior mutability;
    /// see [`PendingTxState`] rustdoc.
    pub(crate) state: Mutex<PendingTxState>,
    /// Test-only: overrides the Phase 1 daemon stub on the next
    /// `submit` after `SubmitAttempted` (PR 5 C7 R9 per-error-class
    /// coverage). FIFO not required — one slot consumed per submit.
    #[cfg(any(test, feature = "test-helpers"))]
    pub(crate) submit_daemon_outcome: Mutex<Option<Result<TxHash, SubmitError>>>,
}

#[allow(private_bounds)]
fn release_output_locks_for(state: &mut PendingTxState, rid: ReservationId) {
    state.output_locks.retain(|_, owner| *owner != rid);
}

/// Best-effort state access for cleanup paths (sign/commit failure).
///
/// Mutating handlers fail loud on poison; cleanup must still release
/// `output_locks` so a poisoned mutex does not strand spendable outputs.
fn with_pending_tx_state_mut<R>(
    mutex: &Mutex<PendingTxState>,
    f: impl FnOnce(&mut PendingTxState) -> R,
) -> R {
    let mut state = mutex.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut state)
}

/// Spend-time gate on curve-tree membership coverage (CT-5 §3.2.1 D1/D3).
///
/// The spendable set is capped at `min(synced_height, tree_cursor)` so a wallet
/// whose ledger tip has outrun the curve tree — an adopting wallet, or any
/// wallet whose `.curvetree` store was rebuilt — does not select outputs for
/// which the local tree cannot yet assemble a membership path. Coverage is
/// keyed on the output's `eligible_height` (the height at which it enters the
/// tree and `is_spendable` already admits it), so this gate is exactly the
/// curve-tree projection of `min(synced_height, tree_cursor)`.
#[derive(Clone, Copy)]
enum TreeSpendGate {
    /// No curve tree wired into this builder (direct-construction unit tests).
    /// The gate is inert; every matured output is selectable (pre-4b behavior).
    Unenforced,
    /// Curve tree present, with the last-ingested height it reported. An output
    /// is tree-covered iff its `eligible_height <= covered_through`;
    /// `covered_through == None` means the tree is fresh/empty and covers
    /// nothing (the adopting-wallet pre-backfill state).
    Enforced { covered_through: Option<u64> },
}

impl TreeSpendGate {
    /// Whether an output maturing at `eligible_height` is covered by the tree.
    fn covers(self, eligible_height: u64) -> bool {
        match self {
            TreeSpendGate::Unenforced => true,
            TreeSpendGate::Enforced { covered_through } => {
                covered_through.is_some_and(|cap| eligible_height <= cap)
            }
        }
    }
}

/// Map a build-time [`CurveTreeHandleError`] (a failed `ingested_tip_height`
/// cursor read) into the terminal [`SendError::CurveTreeUnavailable`]. This is
/// the *hard-failure* path (the actor is fail-stopped); the benign "tree is
/// behind" lag is the cursor-read-**succeeds**-with-a-low-value path and
/// surfaces as [`SendError::SpendUnavailableRebuilding`] instead.
fn map_curve_tree_handle_error_for_send(err: &CurveTreeHandleError) -> SendError {
    // `detail` is documented as the stringified `CurveTreeHandleError`
    // (`error.rs`); render the actual variant — including the inner
    // `ClientError` the previous hand-strings dropped — so the diagnostic is
    // actionable. The error carries no secret material.
    SendError::CurveTreeUnavailable {
        detail: format!("{err:?}"),
    }
}

/// Classify a curve-tree handle error encountered during a CT-5d re-anchor
/// (`docs/design/CT5D_REANCHOR.md` §3): the two `CurveTreeHandleError` variants
/// map to the two re-anchor failure modes.
fn map_handle_err_to_reanchor(err: &CurveTreeHandleError) -> ReanchorError {
    match err {
        // The client returned an error *inside* the handler: the selected input
        // is not resolvable at the fresh reference — almost always a
        // reorg-orphaned output. Content-preserving reprove is impossible;
        // reselection (CT-5d-deferred) is the fix, so tell the consumer to
        // discard and rebuild rather than carry a proof that cannot be built.
        CurveTreeHandleError::Client(_) => ReanchorError::ReselectionRequired {
            detail:
                "membership assembly failed at the fresh reference (input likely reorg-orphaned); discard and rebuild",
        },
        // The actor is fail-stopped / timed out — transient, recoverable by
        // respawn; retriable once the tree resyncs.
        CurveTreeHandleError::Unavailable => ReanchorError::ReferenceResyncing {
            detail: "curve tree actor unavailable; retry once it resyncs",
        },
    }
}

fn build_error_kind(err: &SendError) -> BuildErrorKind {
    match err {
        SendError::InvalidRecipient { .. } | SendError::Tx(_) => BuildErrorKind::InvalidRecipient,
        SendError::InsufficientFunds { .. } => BuildErrorKind::InsufficientFunds,
        SendError::SpendUnavailableRebuilding { .. } => BuildErrorKind::RebuildingMembershipData,
        SendError::OutputNotYetSpendable { .. } => BuildErrorKind::OutputNotYetSpendable,
        // The chain is too short to anchor a reference block — a ledger-maturity
        // readiness condition, projected like the other "ledger not ready" case.
        SendError::WalletTooYoungToSpend { .. } => BuildErrorKind::LedgerNotReady,
        SendError::CannotSign { reason } if *reason == "wallet has not ingested any block yet" => {
            BuildErrorKind::LedgerNotReady
        }
        SendError::CannotSign { .. } => BuildErrorKind::SignerUnavailable,
        // A curve-tree actor that cannot be queried is an infrastructure
        // outage indistinguishable, to the caller, from the daemon being down.
        SendError::CurveTreeUnavailable { .. } | SendError::Io(_) => {
            BuildErrorKind::DaemonUnavailable
        }
    }
}

fn emit_build_failed(sink: &dyn DiagnosticSink, err: &SendError) {
    emit_pending_tx_diagnostic(
        sink,
        PendingTxDiagnostic::BuildFailed {
            kind: build_error_kind(err),
        },
    );
}

fn fail_build_after_attempted(sink: &dyn DiagnosticSink, err: SendError) -> SendError {
    emit_build_failed(sink, &err);
    err
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

fn map_fee_estimator_error(err: &FeeEstimatorError) -> SendError {
    SendError::Io(IoError::Daemon {
        detail: err.to_string(),
    })
}

fn map_signer_error(err: &SignerError) -> SendError {
    match err {
        SignerError::Unavailable => SendError::CannotSign {
            reason: "signer unavailable",
        },
        SignerError::RemoteFailure { reason } => SendError::CannotSign { reason },
    }
}

fn phase1_tx_hash(id: ReservationId) -> TxHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.raw().to_le_bytes());
    TxHash::from_bytes(bytes)
}

#[allow(private_bounds)]
struct BuiltPendingMeta {
    fee: AtomicUnits,
    selected: SelectedOutputs,
    synced: u64,
    tip_hash: [u8; 32],
    /// Output locks are held from assembly until `consumer_held` commit.
    reservation_id: ReservationId,
}

/// Releases [`BuiltPendingMeta::reservation_id`] output locks unless disarmed.
struct BuildReservationCleanup<'a, S, O, F, FS, TS, L>
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
    fn new(engine: &'a LocalPendingTx<S, O, F, FS, TS, L>, reservation_id: ReservationId) -> Self {
        Self {
            engine,
            reservation_id,
            committed: false,
        }
    }

    fn disarm(&mut self) {
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
struct BuildSelected {
    /// One assemble request per selected input, in transaction input order —
    /// `gindex` resolution key + `(O, C)` consistency pair (X3). Public material.
    assemble_inputs: Vec<AssembleInput>,
    /// The fee directive sized against the real tree depth.
    fee_directive: super::traits::key::FeeDirective,
    meta: BuiltPendingMeta,
}

/// Bounded retries for the re-anchor lock₂ TOCTOU (CT-5d [`docs/design/CT5D_REANCHOR.md`]
/// §3a): the tip/tree can move during the lock-free prover run, re-staling the
/// freshly-anchored reference. Retry the whole pre-phase→prover→commit loop a
/// few times; a tip moving faster than this is better surfaced as a clean
/// "resyncing, retry later" than spun on.
const REANCHOR_MAX_RETRIES: u8 = 3;

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
    fn refresh_current_snapshot(&self, state: &mut PendingTxState) {
        state.current_snapshot = derive_snapshot_id(&self.ledger.snapshot());
    }

    /// CT-5d (`docs/design/CT5D_REANCHOR.md` §5): is `reference` no longer
    /// canonical? A stateless point query — the canonical block at the reference
    /// height is no longer the one the proof was anchored against (a reorg
    /// replaced it). One sync `with_ledger_block` read (F-J); handles arbitrarily
    /// many intervening reorgs for free, since it compares against the *current*
    /// canonical hash, not a retained fork history.
    fn reference_orphaned(&self, reference: &ReferenceBlock) -> bool {
        self.ledger
            .with_ledger_block(|ledger| ledger.block_hash_at(reference.height.0).copied())
            != Some(reference.block_hash)
    }

    #[allow(clippy::unused_self)] // `self` is used only under `test` / `test-helpers` cfgs.
    fn take_queued_submit_outcome(&self) -> Option<Result<TxHash, SubmitError>> {
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

    fn finalize_submit_accept(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        tx_hash: TxHash,
    ) -> TxHash {
        let selected_indices: Vec<OutputId> = state
            .output_locks
            .iter()
            .filter_map(|(output_id, owner)| (*owner == id).then_some(*output_id))
            .collect();

        state.in_flight.remove(&id);
        release_output_locks_for(state, id);

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

        tx_hash
    }

    fn finalize_submit_terminal(
        &self,
        state: &mut PendingTxState,
        id: ReservationId,
        kind: TerminalErrorKind,
    ) -> SubmitError {
        state.in_flight.remove(&id);
        release_output_locks_for(state, id);

        emit_pending_tx_diagnostic(
            self.sink.as_ref(),
            PendingTxDiagnostic::Discarded {
                reservation_id: id,
                reason: DiscardReason::DaemonRejectedTerminal { kind },
            },
        );

        SubmitError::DaemonRejectedTerminal { kind }
    }

    fn finalize_submit_ambiguous(
        &self,
        state: &PendingTxState,
        id: ReservationId,
        kind: AmbiguousErrorKind,
    ) -> SubmitError {
        let tx_hash = state
            .in_flight
            .get(&id)
            .map(|flight| TxHash::from_bytes(shekyl_crypto_hash::cn_fast_hash(&flight.tx_bytes)))
            .unwrap_or_else(|| phase1_tx_hash(id));

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

    fn build_select_sync(
        &self,
        request: &TxRequest,
        fee_snapshot: super::traits::FeeEstimates,
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
                        input_count,
                        output_count,
                        fee_snapshot,
                        tree_depth,
                    },
                )
                .map_err(|err| map_fee_estimator_error(&err.into()))
        };

        let fee_pass_a = estimate(1, payment_count + 1)
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

        let fee_pass_b = estimate(selected.indices.len(), payment_count + 1)
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
        let fee = estimate(selected.indices.len(), payment_count + 1)
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

        let fee_directive =
            build_fee_directive(&rate, selected.indices.len(), payment_count, tree_depth);

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

    fn release_build_reservation(&self, reservation_id: ReservationId) {
        with_pending_tx_state_mut(&self.state, |state| {
            release_output_locks_for(state, reservation_id);
        });
    }

    fn commit_built_sync(
        &self,
        request: &TxRequest,
        meta: &BuiltPendingMeta,
        reference: ReferenceBlock,
        tx_bytes: Vec<u8>,
    ) -> Result<PendingTx, SendError> {
        let mut state = self.state.lock().map_err(|_| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "pending-tx state lock poisoned",
                },
            )
        })?;
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
        // (§4 F-G). `change = total_covered − Σrecipients − fee`; the balance was
        // already validated in `build_select_sync`, so the saturating arithmetic
        // here only guards a corrupted-state underflow (never expected).
        let paid: u64 = summary
            .iter()
            .map(|r| r.amount_atomic_units.to_raw())
            .fold(0u64, u64::saturating_add);
        let change = AtomicUnits::from_raw(
            meta.selected
                .total_covered
                .to_raw()
                .saturating_sub(paid)
                .saturating_sub(meta.fee.to_raw()),
        );
        let fingerprint = ContentFingerprint::from_parts(meta.fee, &summary, change);

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
    async fn reanchor_consumer_held(
        &self,
        id: ReservationId,
    ) -> Result<ReanchorOutcome, ReanchorError> {
        let handle =
            self.curve_tree
                .as_ref()
                .ok_or(ReanchorError::Failed(SendError::CannotSign {
                    reason: "curve tree required to re-anchor a membership proof",
                }))?;

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
            // Two-sided ingested-tip gate (§3b, F-C): the lower arm anchors at or
            // below the ingested tip; the upper arm refuses a reference already
            // past the rebuild threshold (the tree is too far behind to anchor a
            // submittable reference). Both are never-submit-a-bad-proof gates.
            let anchor_tip = chain_tip.min(ingested);
            let reference_height = anchor_tip.checked_sub(REF_ANCHOR_AGE).ok_or(
                ReanchorError::ReferenceResyncing {
                    detail: "chain too short to anchor a reference",
                },
            )?;
            if chain_tip.saturating_sub(reference_height) > REBUILD_AT {
                return Err(ReanchorError::ReferenceResyncing {
                    detail: "tree too far behind to anchor a submittable reference; resync",
                });
            }
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
                        input_count: selected_indices.len(),
                        output_count: payment_count + 1,
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
            let change = AtomicUnits::from_raw(
                total_covered
                    .to_raw()
                    .saturating_sub(total_amount.to_raw())
                    .saturating_sub(fee.to_raw()),
            );
            let fee_directive =
                build_fee_directive(&rate, selected_indices.len(), payment_count, depth);

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
            let tx_bytes = signed.tx_bytes().to_vec();
            let new_fingerprint = ContentFingerprint::from_parts(fee, &summary, change);

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
            let content_gen = if content_changed {
                entry.content_gen.saturating_add(1)
            } else {
                entry.content_gen
            };

            entry.tx_bytes = tx_bytes;
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

    async fn submit_async(&self, id: ReservationId, seen_gen: u64) -> Result<TxHash, SubmitError> {
        // --- pre-flight (sync): membership + reference-staleness decision (CT-5d
        // §5). The reference is the staleness authority — it *replaces* the
        // SnapshotId / built_at_tip_hash checks, so a benign tip advance no longer
        // invalidates a still-canonical proof; only an aged-out or reorg-orphaned
        // reference triggers a re-anchor. All sync ledger reads (F-J).
        let stale = {
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

            let reference = state
                .consumer_held
                .get(&id)
                .expect("consumer_held membership established above")
                .reference;
            let current_tip = self.ledger.with_ledger_block(LedgerBlock::height);
            should_reanchor(current_tip, reference.height.0) || self.reference_orphaned(&reference)
        };

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

            // Consent satisfied. Move the entry out of `consumer_held` (no deep
            // clone of `tx_bytes`) and flip it to `in_flight` atomically under the
            // lock, then send lock-free — "committed as of" the flip (F-H). The
            // lock is held continuously since the peek above (no await), so the
            // entry is still present. Only the one `tx_bytes` copy `in_flight`
            // retains (for ambiguous-resolution hash/retry) is cloned; the
            // original moves on to the send.
            let held = state
                .consumer_held
                .remove(&id)
                .expect("consumer_held membership established above, lock held throughout");
            let tx_bytes = held.tx_bytes;
            let submitted_at = Instant::now();
            state.in_flight.insert(
                id,
                InFlightSubmit {
                    tx_bytes: tx_bytes.clone(),
                    snapshot_id: held.snapshot_id,
                    created_at: held.created_at,
                    submitted_at,
                },
            );

            emit_pending_tx_diagnostic(
                self.sink.as_ref(),
                PendingTxDiagnostic::SubmitAttempted { reservation_id: id },
            );

            if let Some(outcome) = self.take_queued_submit_outcome() {
                return match outcome {
                    Ok(tx_hash) => Ok(self.finalize_submit_accept(&mut state, id, tx_hash)),
                    Err(SubmitError::DaemonRejectedTerminal { kind }) => {
                        Err(self.finalize_submit_terminal(&mut state, id, kind))
                    }
                    Err(SubmitError::DaemonAmbiguous {
                        kind,
                        reservation_id,
                    }) => {
                        debug_assert_eq!(
                            reservation_id, id,
                            "queued DaemonAmbiguous must name the reservation under submit"
                        );
                        Err(self.finalize_submit_ambiguous(&state, id, kind))
                    }
                    Err(e) => {
                        state.in_flight.remove(&id);
                        release_output_locks_for(&mut state, id);
                        Err(e)
                    }
                };
            }

            tx_bytes
        };

        let submitter = Arc::clone(&self.submitter);
        let tx_hash = match submitter.submit(tx_bytes).await {
            Ok(hash) => hash,
            Err(submit_err) => {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| SubmitError::ReservationNotFound { reservation_id: id })?;
                return Err(match submit_err {
                    SubmitError::DaemonRejectedTerminal { kind } => {
                        self.finalize_submit_terminal(&mut state, id, kind)
                    }
                    SubmitError::DaemonAmbiguous { kind, .. } => {
                        self.finalize_submit_ambiguous(&state, id, kind)
                    }
                    other => other,
                });
            }
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| SubmitError::ReservationNotFound { reservation_id: id })?;

        Ok(self.finalize_submit_accept(&mut state, id, tx_hash))
    }

    fn discard_sync(&self, id: ReservationId, reason: DiscardReason) -> Result<(), PendingTxError> {
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

    #[allow(dead_code)] // trait surface only; production wiring lands with mempool eviction (V3.x).
    fn signal_mempool_evicted_sync(&self, rid: ReservationId) -> Result<(), PendingTxError> {
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
        let current_snapshot = super::refresh::derive_snapshot_id(&ledger.snapshot());
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
            fee_snapshot_source,
            submitter,
            ledger,
            curve_tree,
            sink,
            ttl,
            network,
            state,
            #[cfg(any(test, feature = "test-helpers"))]
            submit_daemon_outcome: Mutex::new(None),
        }
    }

    /// Queue the daemon round-trip outcome for the next `submit`
    /// (test / `test-helpers` only). Consumed after
    /// `SubmitAttempted` is emitted and the rid moves to `in_flight`.
    #[cfg(any(test, feature = "test-helpers"))]
    #[allow(dead_code)] // Canonical C7 R9 test-driver API; hybrid tests land in C7.
    pub(crate) fn queue_submit_daemon_outcome(&self, outcome: Result<TxHash, SubmitError>) {
        *self
            .submit_daemon_outcome
            .lock()
            .expect("submit_daemon_outcome lock poisoned") = Some(outcome);
    }
}

// ============================================================================
// PendingTxEngine impl
// ============================================================================

impl<S, O, F, FS, TS, L> PendingTxEngine for LocalPendingTx<S, O, F, FS, TS, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    FS: FeeSnapshotSource,
    TS: TransactionSubmitter,
    L: LedgerEngine + Stage1LedgerSpendableAccess,
{
    async fn build(&self, request: TxRequest) -> Result<PendingTx, SendError> {
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

        let fee_snapshot = self.fee_snapshot_source.fetch().await.map_err(|err| {
            fail_build_after_attempted(self.sink.as_ref(), map_fee_estimator_error(&err))
        })?;
        // CT-5 §3.2.1 D1/D3 (commit 4b): read the curve-tree resume cursor
        // *before* the synchronous selection so the spendable set is gated on
        // `min(synced_height, tree_cursor)`. This is the only `.await` the gate
        // needs — `build_assemble_sync` then runs entirely under the state lock
        // with the cursor snapshot in hand. A failed read is the hard-failure
        // path (`CurveTreeUnavailable`), distinct from the benign "tree behind"
        // lag the gate itself surfaces (`SpendUnavailableRebuilding`).
        let tree_gate = match &self.curve_tree {
            None => TreeSpendGate::Unenforced,
            Some(handle) => {
                let covered_through = handle.ingested_tip_height().await.map_err(|err| {
                    fail_build_after_attempted(
                        self.sink.as_ref(),
                        map_curve_tree_handle_error_for_send(&err),
                    )
                })?;
                TreeSpendGate::Enforced {
                    covered_through: covered_through.map(|bh| bh.0),
                }
            }
        };
        // CT-5b §3.2 / CT-5c: bind the reference block the proof anchors to and
        // read the tree depth there. The reference root is never persisted
        // (derive>hold, R1-Q6) — read `(root, depth)` from the actor at
        // `reference_height = tip − REF_ANCHOR_AGE` in one snapshot
        // (`reference_root_and_depth`, Q1). Only when a tree is enforced, the
        // chain is old enough, and the tree has reached the reference height (so
        // the root is reconstructable); otherwise leave it unresolved and the
        // synchronous selection classifies the condition (`WalletTooYoungToSpend`
        // / `SpendUnavailableRebuilding`) or, with no tree, the assembly step
        // below refuses (a spend requires the curve tree — no synthetic
        // fallback). The depth sizes the FCMP++ proof weight for fee estimation;
        // its `1` default is inert because those unresolved cases never assemble.
        let (reference, tree_depth) = match &self.curve_tree {
            Some(handle) => {
                let synced = self.ledger.with_ledger_block(LedgerBlock::height);
                match select_reference_height(synced) {
                    Some(rh)
                        if matches!(
                            tree_gate,
                            TreeSpendGate::Enforced { covered_through: Some(c) } if c >= rh
                        ) =>
                    {
                        let (curve_tree_root, depth) = handle
                            .reference_root_and_depth(BlockHeight(rh))
                            .await
                            .map_err(|err| {
                                fail_build_after_attempted(
                                    self.sink.as_ref(),
                                    map_curve_tree_handle_error_for_send(&err),
                                )
                            })?;
                        let block_hash = self
                            .ledger
                            .with_ledger_block(|ledger| ledger.block_hash_at(rh).copied())
                            .ok_or_else(|| {
                                fail_build_after_attempted(
                                    self.sink.as_ref(),
                                    SendError::CannotSign {
                                        reason: "reference-height block hash missing from ledger",
                                    },
                                )
                            })?;
                        (
                            Some(ReferenceBlock {
                                height: BlockHeight(rh),
                                curve_tree_root,
                                block_hash,
                            }),
                            depth,
                        )
                    }
                    _ => (None, 1u8),
                }
            }
            None => (None, 1u8),
        };
        let BuildSelected {
            assemble_inputs,
            fee_directive,
            meta,
        } = self.build_select_sync(&request, fee_snapshot, tree_gate, reference, tree_depth)?;
        let mut reservation_cleanup = BuildReservationCleanup::new(self, meta.reservation_id);

        // CT-5c: assemble the real FCMP++ membership paths for the whole tx in
        // one actor round-trip (`AssembleTx`, T3), then fold them into the
        // signing context. A spend requires the curve tree and a resolved
        // reference; both hold whenever the C2 gate admitted a candidate, so
        // their absence here is a not-yet-spendable / no-tree condition the gate
        // already classified — a defensive refusal, not a user-facing path. The
        // reservation cleanup (armed above) releases the output locks if any of
        // these steps fail.
        let handle = self.curve_tree.as_ref().ok_or_else(|| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "curve tree required to assemble a membership proof",
                },
            )
        })?;
        let reference = reference.ok_or_else(|| {
            fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "no reference block resolved for membership assembly",
                },
            )
        })?;
        let paths = handle
            .assemble_tx(reference, assemble_inputs.clone())
            .await
            .map_err(|err| {
                fail_build_after_attempted(
                    self.sink.as_ref(),
                    map_curve_tree_handle_error_for_send(&err),
                )
            })?;
        // Q1: the assembled depth must equal the depth the fee was sized against.
        // Both are read at the one reference height, so a divergence means the
        // tree moved under the reference — refuse rather than sign a proof whose
        // weight the fee did not cover. Holds as a tautology under a valid
        // reference; never fires benignly. Check *every* path (all share the one
        // reference's tree, so they should agree — verifying all closes the gap
        // if that invariant ever breaks).
        if paths.iter().any(|p| p.tree.tree_depth != tree_depth) {
            return Err(fail_build_after_attempted(
                self.sink.as_ref(),
                SendError::CannotSign {
                    reason: "assembled tree depth diverged from the fee estimate",
                },
            ));
        }
        // Fold the real paths into the signing context, re-reading the selected
        // transfers by index for their secret-pathway fields (`TransferDetails`
        // is not `Clone`). `assemble_tx_to_sign` guards each re-read with a
        // `gindex` check against `assemble_inputs`, so an index shift under a
        // reorg during the assemble round-trip is refused, not mis-signed.
        let tx_to_sign = self.ledger.with_ledger_block(|ledger| {
            assemble_tx_to_sign(
                self.network,
                &request,
                &meta.selected.indices,
                ledger.transfers(),
                &assemble_inputs,
                &paths,
                fee_directive,
            )
        })?;
        let signed = self
            .signer
            .sign_transfer(TransferSigningContext::from_tx(tx_to_sign))
            .await
            .map_err(|err| {
                let signer_err: SignerError = err.into();
                fail_build_after_attempted(self.sink.as_ref(), map_signer_error(&signer_err))
            })?;
        let tx_bytes = signed.tx_bytes().to_vec();
        let pending = self.commit_built_sync(&request, &meta, reference, tx_bytes)?;
        reservation_cleanup.disarm();
        Ok(pending)
    }

    fn submit(
        &self,
        id: ReservationId,
        seen_gen: u64,
    ) -> impl Future<Output = Result<TxHash, SubmitError>> + Send {
        let this = self;
        async move { this.submit_async(id, seen_gen).await }
    }

    fn discard(&self, id: ReservationId, reason: DiscardReason) -> Result<(), PendingTxError> {
        self.discard_sync(id, reason)
    }

    fn signal_mempool_evicted(&self, rid: ReservationId) -> Result<(), PendingTxError> {
        self.signal_mempool_evicted_sync(rid)
    }

    fn outstanding(&self) -> usize {
        let state = self.state.lock().expect("pending-tx state lock poisoned");
        state.consumer_held.len() + state.in_flight.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::diagnostics::{
        AssertionSink, DiagnosticSink, DiscardReason, PanickingSink, PanickingSinkTrigger,
        PendingTxDiagnostic, TracingDiagnosticSink,
    };
    use crate::engine::error::{
        AmbiguousErrorKind, PendingTxError, SubmitError, TerminalErrorKind,
    };
    use crate::engine::fee_estimator::DaemonFeeEstimator;
    use crate::engine::fee_snapshot::FixedFeeSnapshotSource;
    use crate::engine::key_actor::KeyEngineHandle;
    use crate::engine::local_keys::LocalKeys;
    use crate::engine::output_selector::WalletGreedyOutputSelector;
    use crate::engine::pending::{FeePriority, TxRecipient};
    use crate::engine::signer::LocalSigner;
    use crate::engine::traits::FeeEstimates;
    use crate::engine::traits::PendingTxEngine;
    use crate::engine::transaction_submitter::TransactionSubmitter;
    use crate::engine::LocalLedger;
    use shekyl_address::ShekylAddress;
    use shekyl_crypto_pq::account::AllKeysBlob;
    use shekyl_crypto_pq::account::{generate_account_from_raw_seed, DerivationNetwork};
    use shekyl_curve_tree::{BlockHeight, CurveTreeClient};
    use shekyl_rpc::FeeRate;
    use shekyl_scanner::RecoveredWalletOutput;
    use tempfile::TempDir;

    /// Deterministic raw32 test seed. Distinct from `SIGNER_TEST_MASTER_SEED`
    /// (`engine/signer.rs`) so pending-tx tests do not share derivation state
    /// with the C4α `LocalSigner` fixtures.
    const PENDING_TX_TEST_RAW_SEED: [u8; 32] = {
        let mut seed = [0u8; 32];
        let mut i: u8 = 0;
        while (i as usize) < 32 {
            seed[i as usize] = i.wrapping_mul(17) ^ 0x5B;
            i += 1;
        }
        seed
    };

    const TEST_OUTPUT_TX_KEY: [u8; 32] = [11u8; 32];

    fn test_account_blob() -> AllKeysBlob {
        let (_master, blob) =
            generate_account_from_raw_seed(&PENDING_TX_TEST_RAW_SEED, DerivationNetwork::Testnet)
                .expect("testnet raw32 rederivation succeeds");
        blob
    }

    /// Primary-claim spend public key (`D + m₀·G`) so bundle recovery matches on-chain outputs.
    fn test_recipient_spend_pk() -> [u8; 32] {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::Scalar;
        use shekyl_crypto_pq::output_claim::{output_spend_offset_scalar, PRIMARY_CLAIM_INDEX_LE};
        use zeroize::Zeroizing;

        let blob = test_account_blob();
        let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(
            *blob.view_sk.as_canonical_bytes(),
        ));
        let spend_public = CompressedEdwardsY(*blob.spend_pk.as_canonical_bytes())
            .decompress()
            .expect("spend_pk decompresses");
        let m = output_spend_offset_scalar(&view_scalar, &PRIMARY_CLAIM_INDEX_LE);
        (spend_public + (&m * ED25519_BASEPOINT_TABLE))
            .compress()
            .to_bytes()
    }

    fn test_payment_address() -> String {
        let blob = test_account_blob();
        ShekylAddress::new(
            Network::Mainnet,
            test_recipient_spend_pk(),
            *blob.view_pk.as_canonical_bytes(),
            blob.ml_kem_ek.to_vec(),
        )
        .encode()
        .expect("encode payment address for test wallet")
    }

    /// Spawn a `KeyActor` over the pending-tx test blob.
    fn test_signer_handle() -> KeyEngineHandle {
        KeyEngineHandle::spawn(test_account_blob())
    }

    fn test_ledger() -> LocalLedger {
        LocalLedger::from_test_blocks(Vec::new())
    }

    fn test_fee_estimates() -> FeeEstimates {
        // mask=1 keeps `FeeRate`'s fee↔weight roundtrip consistent with the
        // structural predictor's fee varint term under `converge_fee`.
        let tiny = FeeRate::new(1, 1).expect("tiny test fee rate is non-zero");
        FeeEstimates {
            economy: tiny,
            standard: tiny,
            priority: tiny,
            quantization_mask: 1,
        }
    }

    fn test_fee_snapshot_source() -> FixedFeeSnapshotSource {
        FixedFeeSnapshotSource::new(test_fee_estimates())
    }

    struct TestTransactionSubmitter;

    impl TransactionSubmitter for TestTransactionSubmitter {
        async fn submit(&self, tx_bytes: Vec<u8>) -> Result<TxHash, SubmitError> {
            let hash = shekyl_crypto_hash::cn_fast_hash(&tx_bytes);
            Ok(TxHash::from_bytes(hash))
        }
    }

    fn test_submitter() -> Arc<TestTransactionSubmitter> {
        Arc::new(TestTransactionSubmitter)
    }

    /// Smoke test: constructor succeeds and the engine's state
    /// initializes to the (γ) empty-collections baseline.
    #[tokio::test]
    async fn local_pending_tx_new_constructs() {
        let key = test_signer_handle();
        let pending = LocalPendingTx::new(
            Arc::new(LocalSigner::new(key)),
            WalletGreedyOutputSelector,
            DaemonFeeEstimator,
            test_fee_snapshot_source(),
            test_submitter(),
            Arc::new(test_ledger()),
            None,
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
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::Scalar;
        use shekyl_crypto_pq::output::construct_output;
        use shekyl_oxide::primitives::Commitment;
        use shekyl_scanner::{RecoveredWalletOutput, WalletOutput};

        let blob = test_account_blob();
        let mut tx_hash = [0u8; 32];
        tx_hash[..8].copy_from_slice(&global_index.to_le_bytes());
        tx_hash[8] = seed;
        let output_index = u64::from(seed);
        let constructed = construct_output(
            &TEST_OUTPUT_TX_KEY,
            &blob.x25519_pk,
            &blob.ml_kem_ek,
            &test_recipient_spend_pk(),
            amount,
            output_index,
        )
        .expect("construct_output for test wallet output");
        let key = CompressedEdwardsY(constructed.output_key)
            .decompress()
            .expect("output key decompresses");
        let commitment = Commitment {
            mask: Scalar::from_canonical_bytes(constructed.z).expect("mask canonical"),
            amount,
        };
        let base = WalletOutput::new_for_test(
            tx_hash,
            output_index,
            global_index,
            key,
            Scalar::ZERO,
            commitment,
            None,
        );
        RecoveredWalletOutput::new_for_test(base, amount)
    }

    /// Advance the ledger by empty blocks `from..=to` (no owned outputs), keeping
    /// the `[h & 0xFF; 32]` block-hash scheme `populate_ledger` uses so an earlier
    /// reference height stays canonical. Used by the CT-5d re-anchor KATs to age a
    /// reference past the rebuild horizon without changing the funded set.
    fn advance_ledger_empty_blocks(ledger: &LocalLedger, from: u64, to: u64) {
        use shekyl_scanner::{LedgerIndexesExt, Timelocked};

        let mut guard = ledger.write();
        let state = &mut *guard;
        let ledger_block = &mut state.ledger.ledger;
        let indexes = &mut state.indexes;
        for h in from..=to {
            let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
            let _ = indexes.process_scanned_outputs(
                ledger_block,
                h,
                hash,
                Timelocked::from_vec(Vec::new()),
            );
        }
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

        // Scan-only test paths skip the merge post-pass; align on-chain fields
        // with `construct_output` so the 2a-3 sign bridge can run.
        use shekyl_crypto_pq::handle::derive_output_handle;
        use shekyl_crypto_pq::kem::HybridCiphertext;
        use shekyl_crypto_pq::output::{compute_output_key_image, construct_output};
        use shekyl_generators::biased_hash_to_point;

        let blob = test_account_blob();
        let local = LocalKeys::from_test_seed(PENDING_TX_TEST_RAW_SEED);
        let transfer_count = ledger_block.transfer_count();
        for i in 0..transfer_count {
            let Some(td) = ledger_block.transfer_mut(i) else {
                continue;
            };
            let amount = td.amount().to_raw();
            let output_index = td.internal_output_index;
            let constructed = construct_output(
                &TEST_OUTPUT_TX_KEY,
                &blob.x25519_pk,
                &blob.ml_kem_ek,
                &test_recipient_spend_pk(),
                amount,
                output_index,
            )
            .expect("construct_output for test ledger output");

            let ciphertext = HybridCiphertext {
                x25519: constructed.kem_ciphertext_x25519,
                ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
            };
            td.source_ciphertext = Some(ciphertext.clone());
            td.output_handle = Some(derive_output_handle(
                blob.view_sk.as_canonical_bytes(),
                td.tx_hash.as_bytes(),
                output_index,
            ));

            let bundle = local
                .derive_primary_source_secrets_bundle(&ciphertext, output_index)
                .expect("derive secrets for test output");
            let combined: [u8; 64] = bundle.combined_ss[..64]
                .try_into()
                .expect("combined_ss length");
            let hp = biased_hash_to_point(constructed.output_key)
                .compress()
                .to_bytes();
            let ki = compute_output_key_image(
                &combined,
                output_index,
                blob.spend_sk.as_canonical_bytes(),
                &hp,
            )
            .expect("key image for test output")
            .key_image;
            indexes.set_key_image(ledger_block, i, ki);
        }
    }

    fn standard_request(amount: u64) -> TxRequest {
        TxRequest {
            recipients: vec![TxRecipient {
                address: test_payment_address(),
                amount_atomic_units: AtomicUnits::from_raw(amount),
            }],
            priority: FeePriority::Standard,
        }
    }

    type TestPendingTx = LocalPendingTx<
        LocalSigner,
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        FixedFeeSnapshotSource,
        TestTransactionSubmitter,
        LocalLedger,
    >;

    fn test_pending_tx(ledger: Arc<LocalLedger>) -> TestPendingTx {
        LocalPendingTx::new(
            Arc::new(LocalSigner::new(test_signer_handle())),
            WalletGreedyOutputSelector,
            DaemonFeeEstimator,
            test_fee_snapshot_source(),
            test_submitter(),
            ledger,
            None,
            Arc::new(TracingDiagnosticSink),
            ReservationTTLConfig::default(),
            Network::Mainnet,
        )
    }

    fn test_pending_tx_with_sink(
        ledger: Arc<LocalLedger>,
        sink: Arc<dyn DiagnosticSink>,
    ) -> TestPendingTx {
        LocalPendingTx::new(
            Arc::new(LocalSigner::new(test_signer_handle())),
            WalletGreedyOutputSelector,
            DaemonFeeEstimator,
            test_fee_snapshot_source(),
            test_submitter(),
            ledger,
            None,
            sink,
            ReservationTTLConfig::default(),
            Network::Mainnet,
        )
    }

    fn funded_ledger() -> Arc<LocalLedger> {
        let ledger = Arc::new(test_ledger());
        populate_ledger(
            ledger.as_ref(),
            1,
            vec![
                make_recovered_output(1, 100, 50_000),
                make_recovered_output(2, 101, 30_000),
            ],
            20,
        );
        ledger
    }

    // --- CT-5a commit 4b-1: curve-tree spend-gate KATs (D1/D3) --------------

    /// A fresh, empty curve-tree handle over a tempdir store. Its
    /// `ingested_tip_height` is `None`, so the spend gate (`Enforced { None }`)
    /// treats every matured output as `pending_rebuild` — the adopting /
    /// first-run wallet whose tree has not begun backfilling.
    fn fresh_tree_handle() -> (TempDir, CurveTreeHandle) {
        let dir = TempDir::new().expect("tempdir");
        let client = CurveTreeClient::open(dir.path().join("curve_tree.redb"))
            .expect("open fresh curve-tree client");
        let handle = CurveTreeHandle::spawn(client);
        (dir, handle)
    }

    /// A curve-tree handle whose resume cursor has been advanced to `cap` by
    /// ingesting empty leaves for every block `0..=cap`. Empty-leaf ingest
    /// advances `ingested_tip_height` without contributing leaves (the
    /// merge-driven ingest KATs rely on the same property), which is all the
    /// spend gate reads — it compares `eligible_height <= covered_through`.
    async fn tree_handle_ingested_through(cap: u64) -> (TempDir, CurveTreeHandle) {
        let (dir, handle) = fresh_tree_handle();
        for h in 0..=cap {
            handle
                .ingest(BlockHeight(h), std::sync::Arc::new(Vec::new()))
                .await
                .expect("empty-leaf ingest advances the cursor");
        }
        (dir, handle)
    }

    /// CT-5c consistent fixture: a `(ledger, tree)` pair whose tree leaves
    /// **are** the ledger's owned outputs, so the real `assemble_path` resolves
    /// each by gindex and the signer builds a real membership proof.
    ///
    /// Each `specs` entry is `(seed, amount)`; the output's `global_output_index`
    /// is its position, so it equals the tree's drain-order gindex (the owned
    /// outputs are the chain's first and only leaves). They are populated into
    /// the ledger at `owned_block` (which also wires the secret-pathway fields)
    /// and ingested into the tree as one non-miner transaction at the same
    /// height — `TaggedKey` non-miner maturity is `+DEFAULT_LOCK_WINDOW`
    /// (= `SPENDABLE_AGE`), matching the ledger's `eligible_height`. The block's
    /// `0x07` leaf-hash blob carries each output's real `h_pqc`, so the tree
    /// leaf's identity (`O`, `C`, `h_pqc`) equals the ledger output's. Empty
    /// blocks advance the cursor to `synced`. Pick `owned_block` so the leaves
    /// are drained at the reference height: `owned_block + SPENDABLE_AGE <=
    /// synced - REF_ANCHOR_AGE`.
    async fn funded_ledger_and_tree(
        specs: &[(u8, u64)],
        owned_block: u64,
        synced: u64,
    ) -> (Arc<LocalLedger>, TempDir, CurveTreeHandle) {
        use curve25519_dalek::scalar::Scalar;
        use shekyl_crypto_pq::output::construct_output;
        use shekyl_curve_tree::{RawOutput, TargetKind};
        use shekyl_oxide::primitives::Commitment;

        // Ledger side: the same `make_recovered_output` outputs `populate_ledger`
        // wires the secret-pathway fields (`source_ciphertext`, `output_handle`,
        // `key_image`) for. `global_output_index` = position = tree gindex.
        let ledger = Arc::new(test_ledger());
        let recovered: Vec<_> = specs
            .iter()
            .enumerate()
            .map(|(i, &(seed, amt))| make_recovered_output(seed, i as u64, amt))
            .collect();
        populate_ledger(ledger.as_ref(), owned_block, recovered, synced);

        // Tree side: reconstruct each output's on-chain identity (`O`, `C`,
        // `h_pqc`) and ingest them as the chain's first outputs so gindex ==
        // global_output_index.
        let blob = test_account_blob();
        let mut raw_outputs = Vec::with_capacity(specs.len());
        let mut leaf_blob = Vec::with_capacity(specs.len() * 32);
        for &(seed, amt) in specs {
            let output_index = u64::from(seed);
            let c = construct_output(
                &TEST_OUTPUT_TX_KEY,
                &blob.x25519_pk,
                &blob.ml_kem_ek,
                &test_recipient_spend_pk(),
                amt,
                output_index,
            )
            .expect("construct_output for consistent tree leaf");
            let commitment = Commitment {
                mask: Scalar::from_canonical_bytes(c.z).expect("mask canonical"),
                amount: amt,
            }
            .calculate()
            .compress()
            .to_bytes();
            raw_outputs.push(RawOutput {
                output_key: c.output_key,
                commitment: Some(commitment),
                target: TargetKind::TaggedKey,
            });
            leaf_blob.extend_from_slice(&c.h_pqc);
        }

        let (dir, handle) = fresh_tree_handle();
        for h in 0..=synced {
            let txs = if h == owned_block {
                Arc::new(vec![crate::scan::OwnedTxLeaves {
                    is_miner: false,
                    leaf_hash_blob: Some(leaf_blob.clone()),
                    outputs: raw_outputs.clone(),
                }])
            } else {
                Arc::new(Vec::new())
            };
            handle
                .ingest(BlockHeight(h), txs)
                .await
                .expect("consistent-fixture ingest");
        }
        (ledger, dir, handle)
    }

    fn test_pending_tx_with_tree(ledger: Arc<LocalLedger>, tree: CurveTreeHandle) -> TestPendingTx {
        LocalPendingTx::new(
            Arc::new(LocalSigner::new(test_signer_handle())),
            WalletGreedyOutputSelector,
            DaemonFeeEstimator,
            test_fee_snapshot_source(),
            test_submitter(),
            ledger,
            Some(tree),
            Arc::new(TracingDiagnosticSink),
            ReservationTTLConfig::default(),
            Network::Mainnet,
        )
    }

    fn test_pending_tx_with_tree_and_sink(
        ledger: Arc<LocalLedger>,
        tree: CurveTreeHandle,
        sink: Arc<dyn DiagnosticSink>,
    ) -> TestPendingTx {
        LocalPendingTx::new(
            Arc::new(LocalSigner::new(test_signer_handle())),
            WalletGreedyOutputSelector,
            DaemonFeeEstimator,
            test_fee_snapshot_source(),
            test_submitter(),
            ledger,
            Some(tree),
            sink,
            ReservationTTLConfig::default(),
            Network::Mainnet,
        )
    }

    /// CT-5c: the standard funded fixture (`funded_ledger`'s two outputs,
    /// 50_000 + 30_000) backed by a **consistent** curve tree — the tree leaves
    /// are those outputs, so the real `assemble_path` resolves them and the
    /// signer builds a real proof. Returns the pending engine, the ledger, and
    /// the tree-store `TempDir` (which the caller must keep alive). Replaces the
    /// pre-CT-5c `test_pending_tx(funded_ledger())`, which had no tree.
    async fn funded_pending_tx() -> (TestPendingTx, Arc<LocalLedger>, TempDir) {
        let (ledger, dir, tree) = funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
        (pending, ledger, dir)
    }

    /// [`funded_pending_tx`] with a caller-supplied diagnostic sink.
    async fn funded_pending_tx_with_sink(
        sink: Arc<dyn DiagnosticSink>,
    ) -> (TestPendingTx, Arc<LocalLedger>, TempDir) {
        let (ledger, dir, tree) = funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
        let pending = test_pending_tx_with_tree_and_sink(Arc::clone(&ledger), tree, sink);
        (pending, ledger, dir)
    }

    /// [`funded_pending_tx`] with a **single** 50_000 output — for reservation
    /// tests that assert a second build is blocked because the one output is
    /// locked (a two-output fixture would let the second build use the spare).
    async fn funded_pending_tx_one() -> (TestPendingTx, Arc<LocalLedger>, TempDir) {
        let (ledger, dir, tree) = funded_ledger_and_tree(&[(1, 50_000)], 1, 20).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
        (pending, ledger, dir)
    }

    /// `TreeSpendGate::covers` boundary: the inert (no-tree) gate covers
    /// everything; a fresh tree covers nothing; a cursor at `H` covers
    /// eligibility `<= H` and excludes `H + 1`.
    #[test]
    fn tree_spend_gate_covers_boundary() {
        assert!(TreeSpendGate::Unenforced.covers(0));
        assert!(TreeSpendGate::Unenforced.covers(u64::MAX));
        assert!(!TreeSpendGate::Enforced {
            covered_through: None,
        }
        .covers(0));
        let gate = TreeSpendGate::Enforced {
            covered_through: Some(11),
        };
        assert!(gate.covers(0));
        assert!(gate.covers(11));
        assert!(!gate.covers(12));
    }

    /// D1/D3 core KAT — the adopting / first-run wallet. Matured balance is in
    /// the ledger but the curve tree is fresh (empty), so no output can yet
    /// have a membership proof. The gate must surface the self-healing
    /// [`SendError::SpendUnavailableRebuilding`] (not a misleading
    /// `InsufficientFunds`), reporting nothing spendable and the full matured
    /// balance as `pending_rebuild`.
    #[tokio::test]
    async fn adopting_wallet_spend_unavailable_during_rebuild() {
        let ledger = funded_ledger(); // 50_000 + 30_000 matured at synced=20
        let (_dir, tree) = fresh_tree_handle();
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

        let err = pending
            .build(standard_request(7_000))
            .await
            .expect_err("a fresh tree gates every matured output");
        match err {
            SendError::SpendUnavailableRebuilding {
                needed,
                spendable_now,
                pending_rebuild,
            } => {
                assert!(needed >= 7_000, "needed covers the request plus fee");
                assert_eq!(spendable_now, 0, "no output is tree-covered yet");
                assert_eq!(
                    pending_rebuild, 80_000,
                    "the whole matured balance awaits the rebuild"
                );
            }
            other => panic!("expected SpendUnavailableRebuilding, got {other:?}"),
        }
    }

    /// Once the tree has ingested up to the **reference** height the gate is
    /// inert and the spend builds. synced 20 → reference 14; the cursor (20)
    /// covers the reference, so its root is reconstructable and the eligible-11
    /// outputs are present at the reference block — spendable.
    #[tokio::test]
    async fn rebuilt_tree_spends_normally() {
        // A consistent tree caught up past the reference height (synced 20 −
        // REF_ANCHOR_AGE 6 = 14): the outputs' leaves are present and the
        // reference root is reconstructable, so the spend gate is inert and the
        // build assembles a real proof.
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;

        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("a caught-up tree imposes no gate");
        assert!(
            !built.tx_bytes.is_empty(),
            "the gate-inert build produces a tx"
        );
    }

    /// CT-5b gate KAT: per-output tree coverage is **necessary but not
    /// sufficient**. An output's own leaf can be ingested (cursor ≥ eligible)
    /// while the tree is still behind the *reference* height — and the FCMP
    /// proof anchors to the reference block, whose root is unreconstructable
    /// until the tree reaches it. So such an output is not spendable: the build
    /// surfaces the self-healing `SpendUnavailableRebuilding` rather than
    /// proceeding against the wrong (placeholder) reference. synced 20 →
    /// reference 14; output A (eligible 11) is individually covered by cursor 11
    /// but the tree has not reached reference 14.
    #[tokio::test]
    async fn tree_behind_reference_blocks_individually_covered_output() {
        let ledger = Arc::new(test_ledger());
        // A: block 1 → eligible 11, 50_000; synced 20 → reference 14.
        populate_ledger(
            ledger.as_ref(),
            1,
            vec![make_recovered_output(1, 100, 50_000)],
            20,
        );
        // Cursor 11 covers A's own leaf (11 ≤ 11) but is below reference 14.
        let (_dir, tree) = tree_handle_ingested_through(11).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

        let err = pending
            .build(standard_request(7_000))
            .await
            .expect_err("the tree has not reached the reference height");
        match err {
            SendError::SpendUnavailableRebuilding {
                spendable_now,
                pending_rebuild,
                ..
            } => {
                assert_eq!(
                    spendable_now, 0,
                    "no output is spendable until the tree reaches the reference"
                );
                assert_eq!(
                    pending_rebuild, 50_000,
                    "A awaits the tree reaching reference 14, despite its own leaf being ingested"
                );
            }
            other => panic!("expected SpendUnavailableRebuilding, got {other:?}"),
        }
    }

    /// C2 KAT (2A §3.7.5, CT-5b DoD). `synced = 15` ⇒ `reference_height =
    /// 15 − REF_ANCHOR_AGE(6) = 9`. An output at block 1 matures at
    /// `eligible = 1 + SPENDABLE_AGE(10) = 11`: matured at the tip (11 ≤ 15)
    /// **and** in the tree (cursor 15 ≥ 11), but too fresh for the reference
    /// block (11 > 9). The C2 gate must surface a clean
    /// [`SendError::OutputNotYetSpendable`] with a wait-N-blocks signal — not a
    /// spendable candidate, a `SpendUnavailableRebuilding`, or an
    /// `InsufficientFunds`.
    #[tokio::test]
    async fn output_not_yet_spendable_at_reference_block() {
        let ledger = Arc::new(test_ledger());
        populate_ledger(
            ledger.as_ref(),
            1,
            vec![make_recovered_output(1, 100, 50_000)],
            15,
        );
        // Cursor at 15 covers the eligible-11 output, isolating C2 (reference
        // depth) from the tree-lag `SpendUnavailableRebuilding` path.
        let (_dir, tree) = tree_handle_ingested_through(15).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

        let err = pending
            .build(standard_request(7_000))
            .await
            .expect_err("the only output is too fresh for the reference block");
        match err {
            SendError::OutputNotYetSpendable {
                eligible_height,
                reference_block_height,
                wait_blocks,
            } => {
                assert_eq!(eligible_height, 11, "block 1 + SPENDABLE_AGE");
                assert_eq!(reference_block_height, 9, "synced 15 − REF_ANCHOR_AGE");
                assert_eq!(
                    wait_blocks, 2,
                    "spendable once the reference reaches 11 (tip 17)"
                );
            }
            other => panic!("expected OutputNotYetSpendable, got {other:?}"),
        }
    }

    /// C2 wait-blocks KAT: when *multiple* too-fresh outputs are needed to cover
    /// the spend, `wait_blocks` must reflect the height by which **enough** of
    /// them mature — not the soonest single output (which alone is insufficient
    /// and would underestimate the wait). synced 15 → reference 9; output A
    /// (eligible 11, 10_000) is too small alone for the 30_000 spend (+fee), so
    /// B (eligible 13, 50_000) is also required → the wait is `13 − 9 = 4`, not
    /// `11 − 9 = 2`.
    #[tokio::test]
    async fn output_not_yet_spendable_wait_covers_required_subset() {
        let ledger = Arc::new(test_ledger());
        // A: block 1 → eligible 11, 10_000. B: block 3 → eligible 13, 50_000.
        // Fill synced to 15 so both are matured but too fresh (reference 9).
        populate_ledger(
            ledger.as_ref(),
            1,
            vec![make_recovered_output(1, 100, 10_000)],
            2,
        );
        populate_ledger(
            ledger.as_ref(),
            3,
            vec![make_recovered_output(3, 101, 50_000)],
            15,
        );
        let (_dir, tree) = tree_handle_ingested_through(15).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

        let err = pending
            .build(standard_request(30_000))
            .await
            .expect_err("both too-fresh outputs are needed to cover 30_000 + fee");
        match err {
            SendError::OutputNotYetSpendable {
                eligible_height,
                reference_block_height,
                wait_blocks,
            } => {
                assert_eq!(reference_block_height, 9);
                assert_eq!(
                    eligible_height, 13,
                    "the binding output is B (eligible 13), not the soonest A (11)"
                );
                assert_eq!(wait_blocks, 4, "wait until enough matures, not the soonest");
            }
            other => panic!("expected OutputNotYetSpendable, got {other:?}"),
        }
    }

    /// C2 pre-maturity KAT: a curve tree is enforced but `synced = 5 <
    /// REF_ANCHOR_AGE(6)`, so `select_reference_height` returns `None` — there is
    /// no reference block to anchor a proof. The build must surface the clean
    /// [`SendError::WalletTooYoungToSpend`], not a misleading insufficiency.
    #[tokio::test]
    async fn wallet_too_young_to_spend_before_reference_anchor() {
        let ledger = Arc::new(test_ledger());
        populate_ledger(
            ledger.as_ref(),
            1,
            vec![make_recovered_output(1, 100, 50_000)],
            5,
        );
        let (_dir, tree) = tree_handle_ingested_through(5).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

        let err = pending
            .build(standard_request(7_000))
            .await
            .expect_err("the chain is too short to anchor a reference block");
        match err {
            SendError::WalletTooYoungToSpend {
                synced_height,
                ref_anchor_age,
            } => {
                assert_eq!(synced_height, 5);
                assert_eq!(ref_anchor_age, REF_ANCHOR_AGE);
            }
            other => panic!("expected WalletTooYoungToSpend, got {other:?}"),
        }
    }

    /// CT-5c DoD: a real-root membership proof builds and submits end-to-end.
    /// The consistent fixture's tree leaves **are** the ledger's owned outputs,
    /// so the engine resolves the real `assemble_path` at the reference height
    /// (`tip − REF_ANCHOR_AGE` = 14 for synced 20; the eligible-11 output is
    /// drained there), folds it into the signing context, and the signer builds
    /// a real FCMP++ proof against the reconstructed root — the last synthetic
    /// placeholder on the spend path is gone. (The `reference_block` *hash*
    /// binding, distinct from the curve-tree root, is pinned by the curve-tree
    /// `assemble_kat`; conflating them is the prover bug `shekyl-tx-builder`
    /// exists to prevent.)
    #[tokio::test]
    async fn real_root_membership_proof_builds_and_submits() {
        let (ledger, _tree_dir, tree) = funded_ledger_and_tree(&[(1, 50_000)], 1, 20).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("a real-root membership proof builds against the consistent tree");
        assert!(
            !built.tx_bytes.is_empty(),
            "the build produces a real signed tx"
        );

        let tx_hash = pending
            .submit(built.id, built.content_gen)
            .await
            .expect("submit ok");
        assert_eq!(
            tx_hash,
            TxHash::from_bytes(shekyl_crypto_hash::cn_fast_hash(&built.tx_bytes)),
            "the submitted hash is the signed tx bytes' hash",
        );
    }

    /// CT-5d (§4 F-G/F-G′): the content fingerprint is semantic and
    /// canonically-ordered — it is invariant under the privacy output shuffle
    /// (which a reprove re-runs) and excludes the re-randomized change address
    /// (the change *amount* is captured, the address is not even a parameter),
    /// but it does move on any change to *who gets how much* or the fee.
    #[test]
    fn content_fingerprint_is_order_invariant_and_amount_sensitive() {
        let r = |addr: &str, amt: u64| TxRecipientSummary {
            address: addr.to_string(),
            amount_atomic_units: AtomicUnits::from_raw(amt),
        };
        let fee = AtomicUnits::from_raw(1_000);
        let change = AtomicUnits::from_raw(500);

        let base = ContentFingerprint::from_parts(fee, &[r("addr_a", 10), r("addr_b", 20)], change);
        // F-G′: the same recipients/amounts in a different output order compare
        // equal — a reprove's reshuffle must not bump content_gen.
        let reshuffled =
            ContentFingerprint::from_parts(fee, &[r("addr_b", 20), r("addr_a", 10)], change);
        assert_eq!(
            base, reshuffled,
            "output order must not change the fingerprint"
        );
        // Idempotent: rebuilding the identical content compares equal.
        let again =
            ContentFingerprint::from_parts(fee, &[r("addr_a", 10), r("addr_b", 20)], change);
        assert_eq!(base, again, "identical content is idempotent");

        // The consent axis: fee, change amount, and recipient amount each move it.
        assert_ne!(
            base,
            ContentFingerprint::from_parts(
                AtomicUnits::from_raw(2_000),
                &[r("addr_a", 10), r("addr_b", 20)],
                change
            ),
            "a different fee is a content change"
        );
        assert_ne!(
            base,
            ContentFingerprint::from_parts(
                fee,
                &[r("addr_a", 10), r("addr_b", 20)],
                AtomicUnits::from_raw(600)
            ),
            "a different change amount is a content change"
        );
        assert_ne!(
            base,
            ContentFingerprint::from_parts(fee, &[r("addr_a", 11), r("addr_b", 20)], change),
            "a different recipient amount is a content change"
        );
    }

    /// CT-5d (§3a, headline): a proof carried past the rebuild horizon
    /// re-anchors at submit (the reprove path) and broadcasts. Same inputs, same
    /// tree depth → the realized content is unchanged → `content_gen` stays put
    /// → transparent broadcast.
    #[tokio::test]
    async fn submit_reanchors_at_horizon_then_broadcasts() {
        let (ledger, _tree_dir, tree) = funded_ledger_and_tree(&[(1, 50_000)], 1, 20).await;
        // Clone the handle so the test can advance the (shared-actor) tree cursor
        // after handing one to the engine.
        let tree_for_advance = tree.clone();
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        assert_eq!(built.reference_height, 14);
        assert_eq!(built.content_gen, 0, "fresh build is generation 0");

        // Advance BOTH the ledger and the tree well past the rebuild horizon:
        // chain tip 80, tree ingested through 80. Reference age 80 − 14 = 66 ≥
        // REBUILD_AT (50) → submit must re-anchor (reprove) at 80 − 6 = 74; the
        // owned leaf (drained at 1 + SPENDABLE_AGE = 11) is in the tree there.
        advance_ledger_empty_blocks(ledger.as_ref(), 21, 80);
        for h in 21..=80 {
            tree_for_advance
                .ingest(BlockHeight(h), std::sync::Arc::new(Vec::new()))
                .await
                .expect("advance tree cursor");
        }

        pending
            .submit(built.id, built.content_gen)
            .await
            .expect("horizon re-anchor reproves and broadcasts transparently");
        assert_eq!(
            pending.outstanding(),
            0,
            "submit consumed the reservation after re-anchor"
        );
    }

    /// CT-5d (§3b, F-C upper arm): when the tree lags the chain tip so far that a
    /// freshly-anchored reference would already be past the rebuild threshold,
    /// the re-anchor refuses cleanly (`ReanchorUnavailable`) rather than anchor a
    /// stale reference — and the reservation is preserved.
    #[tokio::test]
    async fn submit_reanchor_unavailable_when_tree_too_far_behind() {
        let (ledger, _tree_dir, tree) = funded_ledger_and_tree(&[(1, 50_000)], 1, 20).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");

        // Advance the ledger far ahead (chain 80) but NOT the tree (cursor stays
        // at 20): the fresh reference would anchor at min(80, 20) − 6 = 14, age
        // 80 − 14 = 66 > REBUILD_AT (50). The upper arm fails clean.
        advance_ledger_empty_blocks(ledger.as_ref(), 21, 80);

        let err = pending
            .submit(built.id, built.content_gen)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SubmitError::ReanchorUnavailable { reservation_id } if reservation_id == built.id),
            "tree-too-far-behind must fail clean as ReanchorUnavailable, got {err:?}"
        );
        assert_eq!(
            pending.outstanding(),
            1,
            "reservation preserved on clean fail"
        );
    }

    /// CT-5c: a spend requires the curve tree to assemble a membership proof.
    /// With no tree configured (a degenerate test/partial-construction state),
    /// a build that clears selection is **refused** rather than producing an
    /// unprovable transaction — the synthetic fallback is gone.
    #[tokio::test]
    async fn build_without_curve_tree_is_refused() {
        let pending = test_pending_tx(funded_ledger());
        let err = pending
            .build(standard_request(7_000))
            .await
            .expect_err("a build with no curve tree must be refused");
        assert!(
            matches!(err, SendError::CannotSign { reason } if reason.contains("curve tree")),
            "no-tree build must be refused with a curve-tree reason: {err:?}"
        );
    }

    #[tokio::test]
    async fn build_then_submit_marks_outputs_spent() {
        // CT-5c: a consistent ledger+tree so the real `assemble_path` resolves
        // the spent output and the signer builds a real membership proof.
        let (ledger, _tree_dir, tree) =
            funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);

        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        assert!(
            built.fee_atomic_units > AtomicUnits::ZERO,
            "fee estimator returns a positive fee from the test snapshot"
        );
        assert!(
            !built.tx_bytes.is_empty(),
            "2a-3 build produces non-empty signed tx bytes"
        );
        {
            use shekyl_oxide::transaction::Transaction;
            let mut cursor: &[u8] = &built.tx_bytes;
            let tx = Transaction::read(&mut cursor).expect("built tx parses");
            let Transaction::V3 { prefix, .. } = &tx;
            let n_in = prefix.inputs.len();
            let n_out = prefix.outputs.len();
            // Real tree depth for the 2-leaf consistent fixture is 2
            // (`layer_count_for_leaves(2)`); the fee was sized against it.
            let predicted = crate::engine::tx_fee_model::predict_weight(
                n_in,
                n_out,
                2,
                built.fee_atomic_units.to_raw(),
            );
            assert_eq!(
                predicted,
                tx.weight(),
                "predict_weight matches Transaction::weight() on build path"
            );
        }
        assert_eq!(pending.outstanding(), 1);

        let tx_hash = pending
            .submit(built.id, built.content_gen)
            .await
            .expect("submit ok");
        assert_eq!(
            tx_hash,
            TxHash::from_bytes(shekyl_crypto_hash::cn_fast_hash(&built.tx_bytes))
        );
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
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;

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
        let (pending, _ledger, _tree_dir) = funded_pending_tx_one().await;

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
                    tx_bytes: held.tx_bytes,
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

    // ── C7 R9 per-error-class (segment-2h emission shape) ─────────

    #[tokio::test]
    async fn submit_double_spend_emits_terminal_discarded() {
        let sink = Arc::new(AssertionSink::new());
        let (pending, _ledger, _tree_dir) =
            funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        pending.queue_submit_daemon_outcome(Err(SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::DoubleSpend,
        }));

        let err = pending
            .submit(built.id, built.content_gen)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SubmitError::DaemonRejectedTerminal {
                kind: TerminalErrorKind::DoubleSpend
            }
        ));
        assert_eq!(pending.outstanding(), 0);

        let events = sink.recorded_pending();
        assert!(
            matches!(
                events.as_slice(),
                [
                    PendingTxDiagnostic::BuildAttempted { .. },
                    PendingTxDiagnostic::BuildSucceeded { .. },
                    PendingTxDiagnostic::SubmitAttempted { .. },
                    PendingTxDiagnostic::Discarded {
                        reason: DiscardReason::DaemonRejectedTerminal {
                            kind: TerminalErrorKind::DoubleSpend
                        },
                        ..
                    },
                ]
            ),
            "unexpected pending diagnostic stream: {events:?}"
        );
    }

    #[tokio::test]
    async fn submit_fee_too_low_releases_outputs() {
        let sink = Arc::new(AssertionSink::new());
        let (pending, _ledger, _tree_dir) =
            funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        pending.queue_submit_daemon_outcome(Err(SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::FeeTooLow,
        }));
        let err = pending
            .submit(built.id, built.content_gen)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SubmitError::DaemonRejectedTerminal {
                kind: TerminalErrorKind::FeeTooLow
            }
        ));
        assert_eq!(pending.outstanding(), 0);

        let second = pending
            .build(standard_request(7_000))
            .await
            .expect("outputs released after terminal reject");
        assert_eq!(second.id.raw(), 1);
        let events = sink.recorded_pending();
        assert!(
            events.iter().any(|e| matches!(
                e,
                PendingTxDiagnostic::Discarded {
                    reason: DiscardReason::DaemonRejectedTerminal {
                        kind: TerminalErrorKind::FeeTooLow
                    },
                    ..
                }
            )),
            "expected terminal Discarded emission: {events:?}"
        );
    }

    #[tokio::test]
    async fn submit_malformed_releases_outputs() {
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        pending.queue_submit_daemon_outcome(Err(SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::Malformed,
        }));
        assert!(matches!(
            pending.submit(built.id, built.content_gen).await,
            Err(SubmitError::DaemonRejectedTerminal {
                kind: TerminalErrorKind::Malformed
            })
        ));
        assert_eq!(pending.outstanding(), 0);
        pending
            .build(standard_request(7_000))
            .await
            .expect("outputs released");
    }

    #[tokio::test]
    async fn submit_timeout_keeps_reservation_in_flight() {
        let sink = Arc::new(AssertionSink::new());
        let (pending, _ledger, _tree_dir) =
            funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        pending.queue_submit_daemon_outcome(Err(SubmitError::DaemonAmbiguous {
            kind: AmbiguousErrorKind::DaemonTimeout,
            reservation_id: built.id,
        }));

        let err = pending
            .submit(built.id, built.content_gen)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SubmitError::DaemonAmbiguous {
                kind: AmbiguousErrorKind::DaemonTimeout,
                ..
            }
        ));
        assert_eq!(pending.outstanding(), 1);

        let events = sink.recorded_pending();
        assert!(
            matches!(
                events.last(),
                Some(PendingTxDiagnostic::SubmitPendingResolution {
                    kind: AmbiguousErrorKind::DaemonTimeout,
                    ..
                })
            ),
            "expected SubmitPendingResolution, got {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, PendingTxDiagnostic::Discarded { .. })),
            "ambiguous submit must not emit Discarded: {events:?}"
        );

        let discard_err = pending
            .discard(built.id, DiscardReason::ConsumerExplicit)
            .unwrap_err();
        assert!(matches!(
            discard_err,
            PendingTxError::DiscardBlockedPendingDaemonAck { .. }
        ));
    }

    #[tokio::test]
    async fn submit_daemon_unavailable_same_as_timeout() {
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        pending.queue_submit_daemon_outcome(Err(SubmitError::DaemonAmbiguous {
            kind: AmbiguousErrorKind::DaemonUnavailable,
            reservation_id: built.id,
        }));
        assert!(matches!(
            pending.submit(built.id, built.content_gen).await,
            Err(SubmitError::DaemonAmbiguous {
                kind: AmbiguousErrorKind::DaemonUnavailable,
                ..
            })
        ));
        assert_eq!(pending.outstanding(), 1);
    }

    // ── Phase 0m: signal_mempool_evicted (STAGE_1_PR_5 §5.6.12 C5β) ─

    async fn build_in_flight_via_daemon_timeout(pending: &TestPendingTx) -> PendingTx {
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        pending.queue_submit_daemon_outcome(Err(SubmitError::DaemonAmbiguous {
            kind: AmbiguousErrorKind::DaemonTimeout,
            reservation_id: built.id,
        }));
        assert!(matches!(
            pending.submit(built.id, built.content_gen).await,
            Err(SubmitError::DaemonAmbiguous {
                kind: AmbiguousErrorKind::DaemonTimeout,
                ..
            })
        ));
        assert_eq!(pending.outstanding(), 1);
        built
    }

    #[tokio::test]
    async fn signal_mempool_evicted_on_in_flight_succeeds() {
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
        let built = build_in_flight_via_daemon_timeout(&pending).await;
        pending
            .signal_mempool_evicted(built.id)
            .expect("in_flight eviction succeeds");
        assert_eq!(pending.outstanding(), 0);
    }

    #[tokio::test]
    async fn signal_mempool_evicted_on_consumer_held_returns_not_found() {
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        let err = pending
            .signal_mempool_evicted(built.id)
            .expect_err("consumer_held is not eviction-relevant");
        assert!(matches!(err, PendingTxError::ReservationNotFound { .. }));
    }

    #[tokio::test]
    async fn signal_mempool_evicted_on_never_existed_returns_not_found() {
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
        let err = pending
            .signal_mempool_evicted(ReservationId::new(99))
            .expect_err("unknown rid");
        assert!(matches!(err, PendingTxError::ReservationNotFound { .. }));
    }

    #[tokio::test]
    async fn signal_mempool_evicted_emits_mempool_evicted_diagnostic() {
        let sink = Arc::new(AssertionSink::new());
        let (pending, _ledger, _tree_dir) =
            funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
        let built = build_in_flight_via_daemon_timeout(&pending).await;
        pending
            .signal_mempool_evicted(built.id)
            .expect("eviction ok");
        let events = sink.recorded_pending();
        assert!(
            matches!(
                events.last(),
                Some(PendingTxDiagnostic::Discarded {
                    reason: DiscardReason::MempoolEvicted,
                    ..
                })
            ),
            "expected MempoolEvicted diagnostic, got {events:?}"
        );
    }

    #[tokio::test]
    async fn signal_mempool_evicted_releases_output_locks() {
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
        let built = build_in_flight_via_daemon_timeout(&pending).await;
        pending
            .signal_mempool_evicted(built.id)
            .expect("eviction releases locks");
        assert_eq!(pending.outstanding(), 0);
        let second = pending
            .build(standard_request(7_000))
            .await
            .expect("outputs released after eviction");
        assert_eq!(second.id.raw(), 1);
    }

    /// F2 ownership boundary: ambiguous `in_flight` admits eviction signal;
    /// post-eviction `discard` is idempotent-not-found, not blocked.
    #[tokio::test]
    async fn signal_mempool_evicted_ownership_boundary() {
        let (pending, _ledger, _tree_dir) = funded_pending_tx().await;
        let built = build_in_flight_via_daemon_timeout(&pending).await;

        pending
            .discard(built.id, DiscardReason::ConsumerExplicit)
            .expect_err("consumer cannot force-discard ambiguous in_flight");
        pending
            .signal_mempool_evicted(built.id)
            .expect("eviction observation succeeds");
        assert_eq!(pending.outstanding(), 0);

        let err = pending
            .discard(built.id, DiscardReason::ConsumerExplicit)
            .expect_err("rid gone after eviction");
        assert!(matches!(err, PendingTxError::ReservationNotFound { .. }));
    }

    // ── C7 emission/return coherence ──────────────────────────────

    #[tokio::test]
    async fn pending_tx_build_emission_return_coherence() {
        let sink = Arc::new(AssertionSink::new());
        let (pending, _ledger, _tree_dir) =
            funded_pending_tx_with_sink(Arc::clone(&sink) as Arc<dyn DiagnosticSink>).await;
        let err = pending
            .build(standard_request(999_999_999))
            .await
            .unwrap_err();
        assert!(matches!(err, SendError::InsufficientFunds { .. }));
        let events = sink.recorded_pending();
        assert!(
            matches!(
                events.as_slice(),
                [
                    PendingTxDiagnostic::BuildAttempted { .. },
                    PendingTxDiagnostic::BuildFailed { .. },
                ]
            ),
            "build error must emit BuildFailed before return: {events:?}"
        );
    }

    /// CT-5d (§5): a benign tip advance no longer invalidates a still-canonical,
    /// in-window proof — it broadcasts as-is, with no re-anchor. This replaces the
    /// pre-CT-5d `SnapshotInvalidated`-on-every-block behavior: the reference, not
    /// the `SnapshotId`, is now the staleness authority.
    #[tokio::test]
    async fn submit_carries_proof_across_benign_tip_advance() {
        let sink = Arc::new(AssertionSink::new());
        let (ledger, _tree_dir, tree) =
            funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
        let pending = test_pending_tx_with_tree_and_sink(
            Arc::clone(&ledger),
            tree,
            Arc::clone(&sink) as Arc<dyn DiagnosticSink>,
        );
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        // Reference anchored at tip(20) − REF_ANCHOR_AGE(6) = 14.
        assert_eq!(built.reference_height, 14);

        // Advance the tip a few blocks with no reorg: reference age 25 − 14 = 11,
        // well within the daemon window and still canonical → not stale.
        populate_ledger(
            ledger.as_ref(),
            21,
            vec![make_recovered_output(3, 200, 1_000)],
            25,
        );

        pending
            .submit(built.id, built.content_gen)
            .await
            .expect("benign tip advance broadcasts the existing proof as-is");
        assert_eq!(pending.outstanding(), 0, "submit consumed the reservation");

        let events = sink.recorded_pending();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, PendingTxDiagnostic::SubmitSucceeded { .. })),
            "benign advance must submit successfully: {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, PendingTxDiagnostic::SubmitSnapshotInvalidated { .. })),
            "CT-5d retires SnapshotInvalidated on a benign tip advance: {events:?}"
        );
    }

    #[tokio::test]
    async fn pending_tx_panicking_sink_unwind_safe_on_build() {
        let sink = Arc::new(PanickingSink::new(PanickingSinkTrigger::Any));
        let pending = test_pending_tx_with_sink(funded_ledger(), sink);
        let join = tokio::spawn(async move { pending.build(standard_request(7_000)).await }).await;
        assert!(
            join.is_err(),
            "PanickingSink::Any must panic the spawned build task"
        );

        let (recovery, _r_ledger, _r_tree_dir) = funded_pending_tx().await;
        assert_eq!(recovery.outstanding(), 0);
        recovery
            .build(standard_request(7_000))
            .await
            .expect("engine usable after sink panic");
        assert_eq!(recovery.outstanding(), 1);
    }

    /// CT-5d (§4): the `content_gen` consent gate. Submitting with a `seen_gen`
    /// that does not match the reservation's materialized `content_gen` is
    /// withheld as [`SubmitError::ContentChanged`] — never broadcast — and the
    /// reservation stays `consumer_held`. Re-confirming with the correct
    /// generation broadcasts. (Here the mismatch is synthetic: a fresh build is
    /// generation 0, so a consumer passing a stale generation 1 is refused.)
    #[tokio::test]
    async fn submit_with_mismatched_seen_gen_is_withheld_as_content_changed() {
        let (ledger, _tree_dir, tree) =
            funded_ledger_and_tree(&[(1, 50_000), (2, 30_000)], 1, 20).await;
        let pending = test_pending_tx_with_tree(Arc::clone(&ledger), tree);
        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        assert_eq!(built.content_gen, 0, "a fresh build is generation 0");

        // Submit immediately (no tip advance → not stale, no re-anchor) with a
        // generation the consumer never saw: withhold, do not broadcast.
        let err = pending
            .submit(built.id, built.content_gen + 1)
            .await
            .unwrap_err();
        let SubmitError::ContentChanged {
            reservation_id,
            content_gen,
        } = err
        else {
            panic!("expected ContentChanged, got {err:?}");
        };
        assert_eq!(reservation_id, built.id);
        assert_eq!(
            content_gen, 0,
            "the materialized generation to re-confirm with"
        );
        assert_eq!(
            pending.outstanding(),
            1,
            "withheld: the reservation stays consumer_held"
        );

        // Re-confirming with the correct generation broadcasts.
        pending
            .submit(built.id, 0)
            .await
            .expect("correct seen_gen broadcasts");
        assert_eq!(pending.outstanding(), 0);
    }

    /// Scan ingest only — leaves `key_image == None` (production scan sentinel path).
    fn populate_ledger_scan_only(
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

    fn daemon_fee_estimates_distinct() -> FeeEstimates {
        FeeEstimates {
            economy: FeeRate::new(1, 1).expect("economy rate"),
            standard: FeeRate::new(10, 1).expect("standard rate"),
            priority: FeeRate::new(100, 1).expect("priority rate"),
            quantization_mask: 1,
        }
    }

    type DaemonBackedPendingTx = LocalPendingTx<
        LocalSigner,
        WalletGreedyOutputSelector,
        DaemonFeeEstimator,
        crate::engine::fee_snapshot::DaemonFeeSnapshotSource<
            crate::engine::test_support::TestDaemon,
        >,
        crate::engine::transaction_submitter::DaemonTransactionSubmitter<
            crate::engine::test_support::TestDaemon,
        >,
        LocalLedger,
    >;

    fn daemon_backed_pending_tx(
        daemon: Arc<crate::engine::test_support::TestDaemon>,
        ledger: Arc<LocalLedger>,
        tree: CurveTreeHandle,
    ) -> DaemonBackedPendingTx {
        daemon.set_fee_estimates(daemon_fee_estimates_distinct());
        LocalPendingTx::new(
            Arc::new(LocalSigner::new(test_signer_handle())),
            WalletGreedyOutputSelector,
            DaemonFeeEstimator,
            crate::engine::fee_snapshot::DaemonFeeSnapshotSource::from_arc(Arc::clone(&daemon)),
            Arc::new(crate::engine::transaction_submitter::DaemonTransactionSubmitter::new(daemon)),
            ledger,
            Some(tree),
            Arc::new(TracingDiagnosticSink),
            ReservationTTLConfig::default(),
            Network::Mainnet,
        )
    }

    /// PHASE_2A_SEND_PATH.md §8.3 — outputs stay locked after build until submit/discard.
    #[tokio::test]
    async fn reserved_outputs_blocked_from_second_build() {
        let (pending, _ledger, _tree_dir) = funded_pending_tx_one().await;
        let _first = pending
            .build(standard_request(7_000))
            .await
            .expect("first build");
        let err = pending.build(standard_request(1_000)).await.unwrap_err();
        assert!(
            matches!(err, SendError::InsufficientFunds { .. }),
            "second build must not double-select reserved output: {err:?}"
        );
    }

    #[test]
    fn assemble_tx_to_sign_rejects_missing_key_image() {
        use crate::engine::signing_assembly::assemble_tx_to_sign;
        use crate::engine::tx_fee_model::build_fee_directive;
        use shekyl_curve_tree::{
            AssembleInput, AssembledPath, Gindex, TreeContext as CtTreeContext,
        };
        use shekyl_rpc::FeeRate;

        let ledger = Arc::new(test_ledger());
        populate_ledger_scan_only(
            ledger.as_ref(),
            1,
            vec![make_recovered_output(1, 100, 50_000)],
            20,
        );
        let request = standard_request(7_000);
        let rate = FeeRate::new(10, 1).expect("rate");
        let fee_directive = build_fee_directive(&rate, 1, request.recipients.len(), 1);
        // The `gindex` must equal the output's `global_output_index` (100) so the
        // index-stability guard passes and the missing-`key_image` check inside
        // `input_context_from_transfer` is reached. The path is unused before
        // that check fires, so a placeholder suffices.
        let assemble_inputs = vec![AssembleInput {
            gindex: Gindex(100),
            output_key: [0u8; 32],
            commitment: [0u8; 32],
        }];
        let paths = vec![AssembledPath {
            leaf_chunk: Vec::new(),
            c1_layers: Vec::new(),
            c2_layers: Vec::new(),
            tree: CtTreeContext {
                reference_block: [0u8; 32],
                tree_root: [0u8; 32],
                tree_depth: 1,
            },
        }];
        let err = ledger.with_ledger_block(|block| {
            assemble_tx_to_sign(
                Network::Mainnet,
                &request,
                &[0],
                block.transfers(),
                &assemble_inputs,
                &paths,
                fee_directive,
            )
        });
        let Err(SendError::CannotSign { reason }) = err else {
            panic!("expected CannotSign for missing key_image, got {err:?}");
        };
        assert!(
            reason.contains("key_image"),
            "reason should name key_image: {reason}"
        );
    }

    /// PHASE_2A_SEND_PATH.md §8.3 — daemon fee flows through to built tx.
    #[tokio::test]
    async fn build_then_submit_via_test_daemon_uses_daemon_fee() {
        use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};
        use crate::engine::tx_fee_model::{
            converge_fee, fee_from_weight, fee_rate_for_priority, predict_weight,
        };
        use shekyl_oxide::transaction::Transaction;

        let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        let (ledger, _tree_dir, tree) =
            funded_ledger_and_tree(&[(1, 500_000), (2, 300_000)], 1, 20).await;
        let pending = daemon_backed_pending_tx(Arc::clone(&daemon), Arc::clone(&ledger), tree);

        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        assert!(!built.tx_bytes.is_empty());

        let mut cursor: &[u8] = &built.tx_bytes;
        let tx = Transaction::read(&mut cursor).expect("built tx parses");
        let Transaction::V3 { prefix, .. } = &tx;
        let n_in = prefix.inputs.len();
        let n_out = prefix.outputs.len();

        let snapshot = daemon_fee_estimates_distinct();
        let rate = fee_rate_for_priority(FeePriority::Standard, &snapshot).expect("standard rate");
        // Real tree depth for the 2-leaf consistent fixture is 2.
        let seed = fee_from_weight(&rate, predict_weight(n_in, n_out, 2, 0));
        let expected_fee = converge_fee(&rate, n_in, n_out, 2, seed);
        assert_eq!(
            built.fee_atomic_units.to_raw(),
            expected_fee,
            "built fee must match daemon Standard tier through production path"
        );
        assert_eq!(
            predict_weight(n_in, n_out, 2, built.fee_atomic_units.to_raw()),
            tx.weight()
        );

        let tx_hash = pending
            .submit(built.id, built.content_gen)
            .await
            .expect("submit ok");
        assert_eq!(
            tx_hash,
            TxHash::from_bytes(shekyl_crypto_hash::cn_fast_hash(&built.tx_bytes))
        );
        assert_eq!(daemon.submitted_count(), 1);

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
    async fn daemon_dedupes_identical_tx_bytes() {
        use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};
        use crate::engine::transaction_submitter::DaemonTransactionSubmitter;

        let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        let (ledger, _tree_dir, tree) =
            funded_ledger_and_tree(&[(1, 500_000), (2, 300_000)], 1, 20).await;
        let pending = daemon_backed_pending_tx(Arc::clone(&daemon), ledger, tree);

        let built = pending
            .build(standard_request(7_000))
            .await
            .expect("build ok");
        pending
            .submit(built.id, built.content_gen)
            .await
            .expect("first submit");
        assert_eq!(daemon.submitted_count(), 1);

        let submitter = DaemonTransactionSubmitter::new(Arc::clone(&daemon));
        let hash_again = submitter
            .submit(built.tx_bytes.clone())
            .await
            .expect("daemon dedup accepts identical bytes");
        assert_eq!(
            hash_again,
            TxHash::from_bytes(shekyl_crypto_hash::cn_fast_hash(&built.tx_bytes))
        );
        assert_eq!(daemon.submitted_count(), 1);

        let err = pending
            .submit(built.id, built.content_gen)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SubmitError::ReservationNotFound { .. }),
            "reservation consumed after first submit: {err:?}"
        );
    }
}
