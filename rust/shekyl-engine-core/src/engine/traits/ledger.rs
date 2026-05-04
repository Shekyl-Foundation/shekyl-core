// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `LedgerEngine` trait surface.
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2.2, `LedgerEngine` is
//! the wallet-side trait that owns the confirmed-chain ledger:
//! `LedgerBlock` (the chain projection scanned out of daemon blocks),
//! the matured-output index, and the balance projection. It is the
//! reservation-agnostic half of the wallet's spendable-state surface;
//! the spendable-balance projection that subtracts in-flight
//! `PendingTx` reservations lives on `PendingTxEngine` (§2.6) per
//! the Round 3 ownership decision. Per-transaction history is read
//! directly from the underlying `LedgerBlock` rather than through
//! the trait — see the Phase 0c section below.
//!
//! # Round 3 disposition: `&self` over `&mut self`
//!
//! The trait's mutating method [`LedgerEngine::apply_scan_result`]
//! takes `&self`, not `&mut self`, because Stage 1's default
//! implementing type `LocalLedger` carries
//! `RwLock<LedgerState>` for interior mutability. The trait would
//! otherwise force every reader/writer in `Engine` to hold an
//! exclusive borrow across an `await`, which conflicts with the
//! `Arc<…>` clone-and-share pattern that `tokio::spawn` uses to
//! schedule the producer task in `run_refresh_task`. The lock is
//! acquired internally by the implementor; the trait surface
//! exposes the `&self` shape uniformly to callers.
//!
//! # Stage-4 swap-in (§7)
//!
//! At Stage 4 the `LedgerEngine` bound is satisfied by an
//! `ActorRef<LedgerActor>` rather than by the in-process
//! [`LocalLedger`] wrapping `RwLock<LedgerState>`. Trait method
//! signatures do not change; only the implementor type does.
//! Callers that bind against `L: LedgerEngine` get the swap-in
//! for free.
//!
//! # Reservation tracker placement
//!
//! Per the §2.2 / §2.6 amendment landed in PR #22, the
//! `PendingReservations` tracker is owned by [`PendingTxEngine`],
//! not [`LedgerEngine`]. [`LedgerEngine::balance`] returns the
//! reservation-agnostic [`BalanceSummary`] computed from
//! `LedgerBlock` alone; the spendable-balance projection that
//! subtracts in-flight reservations lives on `PendingTxEngine`
//! (§2.6 surface, lands in PR 6). The split keeps `LedgerEngine`
//! identifiable as the §1.5 actor that owns confirmed-chain state
//! and lets `PendingTxEngine` own all reservation lifecycle in one
//! place.
//!
//! # `BalanceSummary` over `Balance` (Phase 0b)
//!
//! [`LedgerEngine::balance`] returns [`BalanceSummary`] (the
//! `shekyl_scanner` aggregate the codebase uses today: `confirmed`,
//! `pending`, `total`), not a `Balance` newtype. Per the §2.2
//! Phase 0b amendment landed in PR #23, the `BalanceSummary`-vs-
//! `Balance` rename is a §7 out-of-scope follow-up; PR 2 takes the
//! existing aggregate as-is to keep the trait extraction small and
//! reviewable.
//!
//! # No `transfers()` trait method (Phase 0c)
//!
//! Per the §2.2 Phase 0c amendment landed in PR #25, the trait
//! surface does **not** include a `transfers()` method.
//! `TransferDetails` is deliberately non-`Clone` per the privacy/
//! security discipline pinned at
//! `rust/shekyl-engine-state/src/transfer.rs` (cloning would
//! duplicate `Zeroizing<[u8; N]>` secrets into a heap allocation
//! the compiler cannot track). A `fn transfers(&self) ->
//! Vec<TransferDetails>` ownership-transfer signature is therefore
//! unsatisfiable without breaking that discipline; per
//! `.cursor/rules/00-mission.mdc` priority 1 ("security and
//! quantum resilience are preconditions"), the trait method is
//! removed rather than the discipline relaxed. Wallet-internal
//! callers consume the `LedgerBlock::transfers(&self) ->
//! &[TransferDetails]` slice accessor directly (the borrow is
//! `Clone`-discipline-respecting by construction); a future
//! Stage 4 actor consumer that needs trait-level enumeration can
//! re-introduce the surface via a non-secret view type designed
//! against its concrete threat model.
//!
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
//! [`LocalLedger`]: super::super::ledger::LocalLedger
//! [`PendingTxEngine`]: super::super::pending::PendingTxEngine
//! [`BalanceSummary`]: shekyl_scanner::BalanceSummary

use shekyl_scanner::BalanceSummary;

use crate::engine::error::{LedgerError, RefreshError};
use crate::engine::refresh::LedgerSnapshot;
use crate::scan::ScanResult;

/// Engine-side view of the confirmed-chain ledger surface (§2.2).
///
/// Implementors carry the wallet's [`LedgerBlock`] (and the matured-
/// output index it projects) under interior mutability. Callers
/// ([`Engine<S>`](super::super::Engine) orchestration,
/// `RefreshEngine::merge_into_ledger`, balance accessors) bind
/// against the trait, not the concrete type, so the Stage 4 swap-in
/// does not require call-site changes.
///
/// # Supertrait bounds
///
/// - `Send + Sync + 'static` — `LedgerEngine` instances are shared
///   across the orchestration future and the producer task in
///   `run_refresh_task`'s `tokio::spawn`'d future, typically as
///   `Arc<L>`. `LocalLedger` (Stage 1) and `ActorRef<LedgerActor>`
///   (Stage 4) both satisfy these bounds; `Arc<RwLock<…>>` is
///   `Send + Sync` whenever its contents are.
/// - **Not** `Clone` — unlike [`DaemonEngine`], `LedgerEngine`
///   instances wrap `RwLock<…>` (or, at Stage 4, an `ActorRef`)
///   and are shared by `Arc`, not by clone. Implementors that
///   need a clone for refresh-task scheduling clone the `Arc`
///   wrapper, not the trait object.
///
/// # `type Error: Into<LedgerError>`
///
/// The trait declares an [`Self::Error`] associated type for
/// forward compatibility. None of the Stage 1 methods surface
/// `Self::Error` today: the three read methods are infallible and
/// `apply_scan_result` returns [`RefreshError`] because the
/// failure mode crosses the `LedgerEngine` / `RefreshEngine`
/// boundary (§1.5). The bound is the named landing pad for
/// future additive variants per §8.2.
///
/// [`DaemonEngine`]: super::daemon::DaemonEngine
/// [`LedgerBlock`]: shekyl_engine_state::LedgerBlock
pub(crate) trait LedgerEngine: Send + Sync + 'static {
    /// Implementor-specific error. Convertible into
    /// [`LedgerError`] so [`Engine<S>`](super::super::Engine)
    /// orchestration code can propagate uniform errors regardless
    /// of implementor.
    type Error: Into<LedgerError>;

    /// Highest block height the wallet has fully ingested.
    /// Equivalent to [`LedgerBlock::height()`].
    ///
    /// # Cancellation
    ///
    /// Class **a** per §4: a synchronous read with no side effect.
    /// Not awaitable; cancellation is not a concept on this method.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: a snapshot read of the wallet's recorded
    /// `synced_height`. Repeated calls observe whatever value the
    /// last [`Self::apply_scan_result`] write left in place.
    ///
    /// # Panics
    ///
    /// Never panics. Implementors that route through actor message
    /// handlers (Stage 4) surface handler panics as
    /// [`Self::Error`] (mappable to [`LedgerError`]) per §5.1's
    /// `RuntimeFailure` discipline, not as a panic of this method.
    ///
    /// [`LedgerBlock::height()`]: shekyl_engine_state::LedgerBlock::height
    #[allow(dead_code)] // Stage 1 PR 2: production call sites migrate in commit 5.
    fn synced_height(&self) -> u64;

    /// Snapshot the reorg-detection window the producer needs for
    /// parent-hash compares and the fork-point walk.
    ///
    /// # Cancellation
    ///
    /// Class **a** per §4: a synchronous read with no side effect.
    /// Not awaitable.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: builds an owned [`LedgerSnapshot`] from the
    /// current `LedgerBlock`. Repeated calls produce equivalent
    /// snapshots until the next [`Self::apply_scan_result`] write.
    ///
    /// # Panics
    ///
    /// Never panics. Per [`Self::synced_height`]'s panic note.
    #[allow(dead_code)] // Stage 1 PR 2: production call sites migrate in commit 5.
    fn snapshot(&self) -> LedgerSnapshot;

    /// Reservation-agnostic balance computed from `LedgerBlock`
    /// alone.
    ///
    /// Per the §2.2 / §2.6 split, this method returns the
    /// committed-chain projection without subtracting in-flight
    /// `PendingTx` reservations. The reservation-aware
    /// "spendable balance" projection lives on
    /// [`PendingTxEngine`](super::super::pending::PendingTxEngine)
    /// (§2.6, lands in PR 6).
    ///
    /// # Cancellation
    ///
    /// Class **a** per §4: a synchronous read; the projection
    /// runs in-line under the read guard.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: a deterministic projection of the current
    /// `LedgerBlock`. Repeated calls return equivalent
    /// [`BalanceSummary`] values until the next
    /// [`Self::apply_scan_result`] write.
    ///
    /// # Panics
    ///
    /// Never panics. Per [`Self::synced_height`]'s panic note.
    #[allow(dead_code)] // Stage 1 PR 2: production call sites migrate in commit 5.
    fn balance(&self) -> BalanceSummary;

    /// Apply a producer-emitted [`ScanResult`] to the ledger,
    /// advancing `synced_height` and folding new transfers /
    /// outputs into the projection.
    ///
    /// Returns [`RefreshError::ConcurrentMutation`] if the scan
    /// result's `processed_height_range.start` no longer matches
    /// `synced_height + 1` — i.e., another `apply_scan_result`
    /// merged between the producer's snapshot and this call. The
    /// refresh driver retries with a fresh snapshot per §5.2.
    ///
    /// # Cancellation
    ///
    /// Class **b** per §4: a side-effecting write under the
    /// `RwLock` write guard. The implementor's lock-ordering rules
    /// (cross-cutting lock 4 in `docs/V3_WALLET_DECISION_LOG.md`)
    /// state that the merge runs to completion or fails atomically;
    /// dropping the future before completion does not leave the
    /// ledger in a partial state because the implementor only
    /// commits after the per-height apply loop succeeds in full.
    ///
    /// # Idempotency
    ///
    /// **Conditionally** per §4. Re-applying the *same*
    /// `ScanResult` after a successful merge is a
    /// `ConcurrentMutation` (because `synced_height` has advanced),
    /// which is the correct retry signal: the caller observes that
    /// the work has already landed and re-snapshots. Re-applying a
    /// `ScanResult` whose `start_height` does match
    /// `synced_height + 1` after a transient task panic is safe
    /// because the implementor commits atomically.
    ///
    /// # Panics
    ///
    /// Never panics on contract violations: a
    /// [`MalformedScanResult`](RefreshError::MalformedScanResult)
    /// from the producer is surfaced through `Result`, not panic.
    /// Lock-poisoning is the only panic source — a previous holder
    /// of the write guard panicked mid-merge — and is treated as
    /// an unrecoverable wallet-state defect per §5.1.
    fn apply_scan_result(
        &self,
        scan_result: ScanResult,
    ) -> impl std::future::Future<Output = Result<(), RefreshError>> + Send;
}
