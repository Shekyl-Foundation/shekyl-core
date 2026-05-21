// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `RefreshEngine` trait surface — the producer-side contract for
//! the wallet refresh / snapshot-merge loop.
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2.3 and
//! [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §4, the Stage 1
//! refresh extraction splits the existing monolithic
//! `engine/refresh.rs::run_refresh_task` into:
//!
//! - **Orchestrator side** (stays on
//!   [`Engine`](super::super::Engine)): owns the retry loop, the
//!   snapshot/merge lock acquisition, the
//!   [`RefreshHandle`](super::super::RefreshHandle) lifecycle, and
//!   the two outer cancellation checkpoints (1 + 4).
//! - **Producer side** (lifts to this trait): owns the
//!   per-block scan loop, the per-transaction match path, the
//!   diagnostic-stream emit calls, and the three inner
//!   cancellation checkpoints (2 + 3 + 5).
//!
//! C1 (this commit) introduces only the trait surface. The
//! orchestrator continues to drive the existing
//! `run_refresh_task` body. C4 introduces the `LocalRefresh`
//! aggregate implementor; C5 parameterizes
//! [`Engine`](super::super::Engine) on
//! `R: RefreshEngine = LocalRefresh` and dispatches through the
//! trait at the call boundary.
//!
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
//! [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::engine::diagnostics::DiagnosticSink;
use crate::engine::error::RefreshError;
use crate::engine::refresh::{LedgerSnapshot, RefreshOptions, RefreshProgress};
use crate::engine::traits::daemon::DaemonEngine;
use crate::scan::ScanResult;

/// Producer-side surface for the wallet refresh / snapshot-merge
/// loop (§2.3, Phase 0a binding form per §4).
///
/// Implementors carry the per-instance view-and-spend material
/// (today: [`LocalRefresh`] holds an owned
/// [`ViewMaterial`](super::super::ViewMaterial); Stage 4: an
/// `ActorRef<RefreshActor>` wraps actor-owned state). Callers
/// ([`Engine<S>`](super::super::Engine) orchestration only) bind
/// against the trait, not the concrete type, so the Stage 4
/// swap-in does not require call-site changes.
///
/// # Supertrait bounds
///
/// - `Send + Sync + 'static` — the trait object is shared with
///   the producer task spawned by `run_refresh_task`'s
///   `tokio::spawn` and may outlive the orchestrator's stack
///   frame. `LocalRefresh` satisfies the bound by construction
///   (no interior mutability beyond `ViewMaterial`'s owned
///   secret bundle); `ActorRef<RefreshActor>` will at Stage 4.
///
/// # Associated error type
///
/// [`Self::Error`] is the implementor-specific error.
/// Convertible into [`RefreshError`] so
/// [`Engine<S>`](super::super::Engine) orchestration code can
/// propagate uniform errors regardless of implementor.
///
/// **Unit-variant-only at the trait surface** (Phase 0c binding
/// per §4 + §5.4.7 R6 two-channel reframe). Trait implementors
/// MUST NOT add fielded variants to their `Error` type that carry
/// caller-attacker payloads (e.g., raw daemon `String`s, secret
/// pointers, etc.). Per-event detail flows through the
/// [`DiagnosticSink`] channel, not through the terminal error.
/// The orchestrator-side [`RefreshError`] retains fielded variants
/// (e.g., `ConcurrentMutation { wallet, result }`,
/// `InternalInvariantViolation { context }`) for orchestrator-only
/// internal use; those variants are not surfaced by trait
/// implementors at the trait boundary.
///
/// # Cancellation discipline (five checkpoints; F2 per §5.4.9)
///
/// The refresh path observes cooperative cancellation at five
/// named checkpoints per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]
/// §2.3 + §7 invariant 4. Ownership splits between the
/// orchestrator (checkpoints 1 + 4) and the producer
/// (checkpoints 2 + 3 + 5).
///
/// **List ordering vs. checkpoint numbering.** The bullets below
/// are listed in **temporal-firing order** (the order in which
/// checkpoints fire during a single refresh attempt:
/// 1 → 2 → 3 → 5 → 4), not in numeric order. The checkpoint
/// numbering itself preserves the design-round audit trail per
/// [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §7 item 4
/// ("checkpoint 5 added per PR 4 Round 4 F2"): numbers 1–4 were
/// the original
/// four-checkpoint discipline; the per-transaction inner safe-
/// point was added later as checkpoint 5 rather than renumbering
/// the existing four sites. Renumbering to numeric-sequential
/// order is rejected per `21-reversion-clause-discipline.mdc`'s
/// substrate-anchored disposition: 12+ existing cross-reference
/// sites across the codebase (CHANGELOG, design docs,
/// orchestrator code, producer code) would all need
/// synchronized migration, and the audit-trail provenance of
/// "checkpoint 5 = the F2-added one" carries reviewer-facing
/// information that pure-sequential numbering would lose.
///
/// 1. **Orchestrator — pre-attempt** (before producer entry). If
///    the cancel token has fired, the orchestrator returns
///    [`RefreshError::Cancelled`] without entering the producer
///    body.
/// 2. **Producer — pre-fetch** (top of `produce_scan_result`,
///    before the first daemon read). Producer returns the
///    cancellation discriminant.
/// 3. **Producer — pre-scan** (after snapshot fetch, before the
///    per-block scan loop begins). Producer returns the
///    cancellation discriminant; the unfetched per-block work is
///    abandoned with no wallet-side state change.
/// 5. **Producer — per-transaction inner check** (top of each
///    per-transaction iteration inside the per-block scan loop).
///    Fires at a §5.4.9 F11 + F11-S **safe point**: AFTER the
///    prior iteration's `Zeroizing<…>`-wrapped per-output
///    materials have dropped at scope exit, BEFORE the next
///    transaction's view-tag / hybrid-decap / key-image derivation
///    begins. Mid-derivation firing is FORBIDDEN; the secret-drop
///    window between iterations is the safe-point pin. If F11-S's
///    per-output escalation measurement (recorded in C4's commit
///    message per §6) lifts the granularity to per-output, the
///    same safe-point semantics apply between consecutive
///    per-output decap iterations within the per-tx loop.
/// 4. **Orchestrator — pre-merge** (after producer returns
///    `Ok(ScanResult)`, before the write-lock acquisition that
///    merges the scan result into wallet state). If the cancel
///    token has fired, the orchestrator drops the returned
///    [`ScanResult`] and returns [`RefreshError::Cancelled`]
///    without taking the write lock.
///
/// # Atomicity-under-cancellation (R7 per §5.4.7)
///
/// On producer-side cancellation at checkpoints 2, 3, or 5,
/// `produce_scan_result` returns the cancellation discriminant
/// instead of a partial [`ScanResult`]. The trait contract is
/// **all-or-nothing** at the [`ScanResult`] boundary: callers
/// observe either a complete `ScanResult` (orchestrator may then
/// proceed to checkpoint 4) or the cancellation error
/// (orchestrator returns without merge). The producer never
/// surfaces a truncated `ScanResult` containing only the
/// pre-cancellation blocks; partial output would let the
/// orchestrator's merge path see state that no scan completed,
/// breaking the audited-mutation-chain invariant per §1.
///
/// # Diagnostic-stream contract
///
/// `diagnostics: &dyn DiagnosticSink` is the second of the two
/// load-bearing channels (§5.4.7 R6 two-channel reframe). The
/// producer emits per-event observability to this sink during
/// the scan; the terminal return continues to carry the
/// `Result<ScanResult, Self::Error>` discriminant. See
/// [`DiagnosticSink`] for the seven contract pins. The
/// emission/return coherence pin (§5.4.6) is PERMANENT CI
/// coverage via C7's
/// `produce_scan_result_emission_return_coherence` property
/// test; prose/test drift resolves AGAINST the test.
///
/// # Daemon-handle borrowing
///
/// `daemon: &D` is borrowed for the producer's lifetime per call.
/// The producer does not retain the borrow past
/// [`Self::produce_scan_result`]'s return; the orchestrator owns
/// the long-lived [`DaemonClient`](super::super::DaemonClient)
/// (or Stage 4's `ActorRef<DaemonActor>`) and shares it by
/// reference.
/// Generic `D` (rather than `&dyn DaemonEngine`) preserves
/// monomorphized dispatch through the `Rpc` supertrait surface
/// per §2.5.
///
/// # `LedgerSnapshot` value-typed contract
///
/// `snapshot: LedgerSnapshot` is taken by value (owned move). Per
/// §5.4.5 the snapshot is the producer's read-only view of wallet
/// state at the attempt's start instant; the value-typed contract
/// pin ensures the producer cannot observe orchestrator-side
/// state mutation mid-scan (the read lock that materialized the
/// snapshot has been dropped before the producer is entered).
/// Returning the snapshot's contents (e.g., as part of a
/// `ScanResult` field) is forbidden by construction: the producer
/// receives only the immutable view, not a mutable reference into
/// wallet state.
///
/// # `Send` futures via `impl Future + Send`
///
/// The associated method uses the explicit
/// `-> impl Future<Output = Result<ScanResult, Self::Error>> + Send`
/// return type rather than `async fn` so the `Send` bound on the
/// returned future is part of the trait contract (callers
/// `tokio::spawn` the future and need `Send` propagation through
/// monomorphization). This matches the [`DaemonEngine`] and
/// [`LedgerEngine`](super::ledger::LedgerEngine) precedents.
///
/// [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
/// [`LocalRefresh`]: super::super::LocalRefresh
pub(crate) trait RefreshEngine: Send + Sync + 'static {
    /// Implementor-specific error. Convertible into
    /// [`RefreshError`] so [`Engine<S>`](super::super::Engine)
    /// orchestration code propagates uniform errors regardless of
    /// implementor.
    ///
    /// **Unit-variant-only at the trait surface** per the
    /// trait-level rustdoc above.
    type Error: Into<RefreshError>;

    /// Produce a [`ScanResult`] for one refresh attempt against
    /// the given [`LedgerSnapshot`] and daemon handle.
    ///
    /// See the trait-level rustdoc for the full contract:
    ///
    /// - Five-checkpoint cancellation discipline (this method
    ///   owns checkpoints 2, 3, and 5; the orchestrator owns
    ///   checkpoints 1 and 4).
    /// - Atomicity-under-cancellation (R7): no partial
    ///   `ScanResult` ever returned.
    /// - F11 + F11-S checkpoint-5 safe-point pin: cancellation
    ///   between per-transaction iterations, after the prior
    ///   iteration's `Zeroizing<…>` drops, before the next
    ///   iteration's first secret derivation.
    /// - Diagnostic-stream channel (`diagnostics`): per-event
    ///   observability augmenting the terminal return.
    /// - `LedgerSnapshot` value-typed contract.
    /// - `daemon: &D` borrowed for the call's lifetime only.
    ///
    /// # Idempotency
    ///
    /// Each call is a fresh attempt; retries land in the
    /// orchestrator's retry loop, not by re-calling this method
    /// with the same arguments. The producer does not preserve
    /// per-attempt state across calls (§5.4.6
    /// "restart-amnesia is deliberate").
    ///
    /// # Panics
    ///
    /// Never panics in the production [`LocalRefresh`]
    /// implementor. Implementors that route through actor message
    /// handlers (Stage 4) surface handler panics as
    /// [`Self::Error`] (mappable to [`RefreshError`]'s
    /// internal-invariant-violation discriminant per §5.1's
    /// runtime-failure discipline; C3 introduces the
    /// `InternalInvariantViolation` variant the trait-error
    /// conversion lands on), not as a panic of this method. Sinks that panic on `emit` are exercised by C7's
    /// `produce_scan_result_panicking_sink_unwind_safe` property
    /// test: the producer's `Scanner` zeroization must complete
    /// on unwind, the cancellation token must remain consistent,
    /// and the producer must unwind without corrupting interior
    /// state.
    ///
    /// [`LocalRefresh`]: super::super::LocalRefresh
    #[allow(dead_code)] // C5 lands the first orchestrator-side dispatch through this method.
    #[allow(clippy::too_many_arguments)] // 6 explicit args is the Phase 0a binding form.
    fn produce_scan_result<D: DaemonEngine>(
        &self,
        snapshot: LedgerSnapshot,
        daemon: &D,
        opts: RefreshOptions,
        cancel: CancellationToken,
        progress: watch::Sender<RefreshProgress>,
        diagnostics: &dyn DiagnosticSink,
    ) -> impl std::future::Future<Output = Result<ScanResult, Self::Error>> + Send;
}
