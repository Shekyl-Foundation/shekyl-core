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

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::diagnostics::{DiagnosticSink, DiscardReason};
use super::error::{PendingTxError, SendError, SubmitError};
use super::fee_estimator::FeeEstimator;
use super::network::Network;
use super::output_selector::OutputSelector;
use super::pending::{
    InFlightSubmit, PendingTx, ReservationId, ReservationTTLConfig, SnapshotId, TxHash, TxRequest,
};
use super::signer::Signer;
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
///   consumer has not yet submitted. The map value is the build-
///   time [`Instant`] for the V3.0 R8 TTL safety-net.
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
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct PendingTxState {
    /// Engine's current view of the ledger [`SnapshotId`].
    pub current_snapshot: SnapshotId,
    /// Per-output lock map. See struct rustdoc.
    pub output_locks: HashMap<OutputId, ReservationId>,
    /// Reservations built but not yet submitted. Value is the
    /// build-time [`Instant`] for TTL aging.
    pub consumer_held: HashMap<ReservationId, Instant>,
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
// `dead_code` allow on fields: C5α stubs all `PendingTxEngine`
// method bodies with `unimplemented!()`; the fields are consumed by
// C5β's body extraction.
#[allow(private_bounds, dead_code)]
pub struct LocalPendingTx<S, O, F, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    L: LedgerEngine,
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
    /// Per-collection reservation TTL config (Phase 0l).
    pub(crate) ttl: ReservationTTLConfig,
    /// Network the wallet was opened against; used for
    /// address-binding validation during `build`.
    pub(crate) network: Network,
    /// Engine state guarded by [`Mutex`] for interior mutability;
    /// see [`PendingTxState`] rustdoc.
    pub(crate) state: Mutex<PendingTxState>,
}

#[allow(private_bounds)]
impl<S, O, F, L> LocalPendingTx<S, O, F, L>
where
    S: Signer,
    O: OutputSelector,
    F: FeeEstimator,
    L: LedgerEngine,
{
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
    L: LedgerEngine,
{
    // The trait method explicitly uses `-> impl Future + Send` (not
    // `async fn`) so the `Send` bound is part of the trait contract
    // per `engine/traits/pending_tx.rs` rustdoc. `async fn` syntax
    // would drop the explicit `+ Send` bound. Matches the
    // `LocalRefresh::produce_scan_result` precedent.
    #[allow(clippy::manual_async_fn)]
    fn build(
        &self,
        _request: TxRequest,
    ) -> impl Future<Output = Result<PendingTx, SendError>> + Send {
        async move { unimplemented!("LocalPendingTx::build body lands in C5β") }
    }

    #[allow(clippy::manual_async_fn)]
    fn submit(
        &self,
        _id: ReservationId,
    ) -> impl Future<Output = Result<TxHash, SubmitError>> + Send {
        async move { unimplemented!("LocalPendingTx::submit body lands in C5β") }
    }

    fn discard(&self, _id: ReservationId, _reason: DiscardReason) -> Result<(), PendingTxError> {
        unimplemented!("LocalPendingTx::discard body lands in C5β")
    }

    fn signal_mempool_evicted(&self, _rid: ReservationId) -> Result<(), PendingTxError> {
        unimplemented!("LocalPendingTx::signal_mempool_evicted body lands in C5β")
    }

    fn outstanding(&self) -> usize {
        unimplemented!("LocalPendingTx::outstanding body lands in C5β")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::diagnostics::TracingDiagnosticSink;
    use crate::engine::fee_estimator::DaemonFeeEstimator;
    use crate::engine::output_selector::WalletGreedyOutputSelector;
    use crate::engine::signer::LocalSigner;
    use crate::engine::LocalLedger;
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
}
