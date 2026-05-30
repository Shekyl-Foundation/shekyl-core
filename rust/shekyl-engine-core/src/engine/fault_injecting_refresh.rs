// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `FaultInjecting<R: RefreshEngine>` — composable failure-injection
//! wrapper for the [`RefreshEngine`] trait surface (Stage 1 PR 4
//! C6α test substrate).
//!
//! # Why this exists (no-Mock substrate per PR 3 §2.1.2)
//!
//! The Round 4 PR 4 plan was a parallel-implementation `MockRefresh`
//! mirroring `TestDaemon` / `MockLedger`; the Round 5 substrate-
//! decision amendment (commit `8484e669a`) replaced that plan with
//! the binding no-Mock substrate shape PR 3
//! [`§2.1.2`](../../../../../docs/design/STAGE_1_PR_3_KEY_ENGINE.md)
//! settled. Building `MockRefresh` would have re-instantiated the
//! parallel-implementation anti-pattern PR 3 rejected as a category,
//! compounding the Mock-X debt
//! [`docs/FOLLOWUPS.md`](../../../../../docs/FOLLOWUPS.md) already
//! scheduled to be paid down. Five named failure modes apply: test-
//! only types as production attack surface; conflation of test-input
//! injection with substitute implementations; inherited-from-Monero
//! pattern that has produced real bugs in the inherited codebase;
//! foreclosure of composition with future trait implementors; and
//! tests verifying fake semantics rather than real semantics.
//!
//! The composable wrapper avoids all five. Tests construct
//! `FaultInjecting::new(LocalRefresh::new(...))`, queue failures
//! through [`queue_failure`], and exercise the orchestrator against
//! the same production implementor — only the trait-boundary
//! behaviour is perturbed.
//!
//! # Wrapper API (Option (i) per Round 5 sub-pin extension)
//!
//! The wrapper carries `type Error = RefreshError` rather than
//! `type Error = R::Error`: the queue holds `RefreshError` values
//! directly, uniform across all `R`. This matches the
//! [`RefreshEngine`] trait's own `Error` shape (the production
//! [`LocalRefresh`](super::local_refresh::LocalRefresh) uses
//! `type Error = RefreshError`), so the queue type and the trait
//! surface line up without a `Self::Error` indirection, giving the
//! smoke-test surface a single uniform queue type to shape against.
//!
//! Direct injection of any [`RefreshError`] variant is allowed —
//! including `MalformedScanResult`, `ConcurrentMutation`, and
//! `AlreadyRunning` (which the production [`RefreshEngine`] impl
//! never returns, all three being orchestrator-constructed per
//! [`engine/merge.rs`](../merge.rs)). Direct injection of an
//! orchestrator-constructed variant exercises the orchestrator's
//! handling of "what if the trait surface produced this variant
//! directly" — a deliberate test affordance, not a production-
//! reachable code path. See the
//! [Round 5 sub-pin extension F-Mock-3-sharpening](../../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md)
//! disposition for the trait-reachable vs. orchestrator-constructed
//! enumeration.
//!
//! # Queue contract (F-Mock-2)
//!
//! - **FIFO ordering.** Injections are popped head-first; if a test
//!   injects `[A, B]` in that order, the next two calls return `A`
//!   then `B`. The ordering pin forecloses property tests that
//!   assert per-call return-discriminant ordering from failing
//!   unhelpfully against a LIFO or unordered implementation.
//! - **Drain inspector.** [`queued_failures`] reports the current
//!   queue length per the existing
//!   [`MockLedger::queued_failures`](super::test_support) precedent.
//!   Tests verify queue-drain by asserting
//!   `wrapper.queued_failures() == 0` at teardown, closing the
//!   false-positive class where a test injects a failure, runs the
//!   engine, asserts the engine handled correctly, and never
//!   notices the injection path was not exercised.
//! - **`debug_assert!` on Drop.** If a test leaves the wrapper
//!   without draining, the wrapper's [`Drop`] impl fires
//!   `debug_assert!` — panic-on-leftover in test/debug builds;
//!   silent in release (release builds must not have the wrapper
//!   compiled in regardless, per the
//!   `#[cfg(any(test, feature = "test-helpers"))]` gating on the
//!   module declaration in [`super`]).
//! - **Reentrance.** If a test injects a failure and the producer's
//!   body internally re-enters via some path that calls back into
//!   [`RefreshEngine`], the second call also pops from the queue
//!   per the "pop head if non-empty" semantics. V3.0 [`LocalRefresh`]
//!   has no such reentrance pattern; the pin is for forward-
//!   compatibility with Stage 4 actor-mesh implementors that may
//!   carry different reentrance behaviour.
//!
//! # Composition paradigm (§6.1 paradigm pin)
//!
//! The wrapper is a synchronous trait dispatcher with a wrapper-
//! internal queue, **not** an actor mailbox. No `Sender` / `Receiver`
//! channel, no message-passing, no supervision. The Mutex is
//! short-lived (pop + release before the `.await` boundary, never
//! held across one); composition-paradigm by construction. The
//! "drive causes through one wrapper, observe effects on the
//! orchestrator surface" testing shape translates cleanly to Stage 4
//! actor-paradigm tests because the wrapper boundary moves from
//! trait-dispatch to message-handler-dispatch with no test-shape
//! change.
//!
//! [`LocalRefresh`]: super::local_refresh::LocalRefresh
//! [`RefreshEngine`]: super::traits::RefreshEngine
//! [`RefreshError`]: super::error::RefreshError

use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::diagnostics::DiagnosticSink;
use super::error::RefreshError;
use super::refresh::{LedgerSnapshot, RefreshOptions, RefreshProgress};
use super::traits::daemon::DaemonEngine;
use super::traits::refresh::RefreshEngine;
use crate::scan::ScanResult;

/// Composable failure-injection wrapper over any
/// [`RefreshEngine`] implementor. See the module-level rustdoc for
/// the no-Mock rationale, the Option (i) wrapper API, the F-Mock-2
/// queue contract, and the composition-paradigm framing.
pub(crate) struct FaultInjecting<R: RefreshEngine> {
    /// Production implementor wrapped by this fault injector. Held
    /// by-value (not by-Arc) because the wrapper is constructed in
    /// test setup and dropped at test teardown; the Arc that
    /// `Engine::refresh` holds wraps the *wrapper*, not the inner.
    inner: R,
    /// FIFO queue of pre-built [`RefreshError`] values. Each call to
    /// [`produce_scan_result`](RefreshEngine::produce_scan_result)
    /// pops the head; an empty queue delegates to `inner`.
    ///
    /// `Mutex` rather than `RwLock` because every access mutates
    /// (push at queue, pop at consume, len at drain inspector); the
    /// short-lived lock matches the [`MockLedger::queue_concurrent_mutation`](super::test_support)
    /// precedent.
    queue: Mutex<VecDeque<RefreshError>>,
}

impl<R: RefreshEngine> FaultInjecting<R> {
    /// Wrap `inner` with an empty failure queue. Tests typically
    /// pair this with [`super::Engine::replace_refresh`] to install
    /// the wrapper on an already-constructed engine.
    ///
    /// `dead_code` allow matches the sibling [`queue_failure`] /
    /// [`queued_failures`] gates: under the `test-helpers` feature
    /// (without `cfg(test)`), the crate-internal smoke tests are
    /// not compiled and no consumer of `new` is in scope until C6β /
    /// C6γ hybrid tests land the first downstream user.
    #[allow(dead_code)]
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Queue one [`RefreshError`] for the next
    /// [`produce_scan_result`](RefreshEngine::produce_scan_result)
    /// call. Multiple invocations queue multiple failures (FIFO
    /// drain per the F-Mock-2 contract). Once the queue empties,
    /// subsequent calls delegate to the wrapped `inner` producer.
    #[allow(dead_code)] // Phase 1 author: lands as the canonical test-driver API in C6β/C6γ hybrid tests.
    pub(crate) fn queue_failure(&self, err: RefreshError) {
        self.queue
            .lock()
            .expect("FaultInjecting queue poisoned")
            .push_back(err);
    }

    /// Number of failure injections still queued. Tests assert
    /// against this to confirm the orchestrator drained the queue
    /// (i.e., the injection path was exercised, not silently
    /// bypassed). See the F-Mock-2 drain-inspector contract pin in
    /// the module-level rustdoc.
    #[allow(dead_code)] // Phase 1 author: lands as the canonical test-driver inspector in C6β/C6γ hybrid tests.
    pub(crate) fn queued_failures(&self) -> usize {
        self.queue
            .lock()
            .expect("FaultInjecting queue poisoned")
            .len()
    }
}

impl<R> super::scan_floor::ScanStartFloorProvider for FaultInjecting<R>
where
    R: super::scan_floor::ScanStartFloorProvider + RefreshEngine,
{
    fn scan_start_floor(&self) -> u64 {
        self.inner.scan_start_floor()
    }
}

impl<R: RefreshEngine> Drop for FaultInjecting<R> {
    /// Panic if a test left the wrapper without draining its
    /// injected failures. Per the F-Mock-2 contract in the
    /// module-level rustdoc, `debug_assert!` is used so the panic
    /// fires in `cfg(test)` / debug builds but stays silent in
    /// release; release builds should not compile the wrapper in
    /// regardless (per the `#[cfg(any(test, feature =
    /// "test-helpers"))]` module gate).
    ///
    /// `Mutex::get_mut` is used to bypass the lock — `Drop` is
    /// synchronous and the wrapper is `&mut`-borrowed by its
    /// destructor, so the lock cannot be contested. The
    /// `PoisonError` branch returns `0` (treat a poisoned queue as
    /// empty for assertion purposes) because the lock can only be
    /// poisoned by a previous panic, in which case the wrapper's
    /// `Drop` is firing during unwind and a `debug_assert!` panic
    /// during unwind would abort the process. Production builds
    /// have the wrapper compiled out entirely so this branch is
    /// test/debug-only safety scaffolding.
    fn drop(&mut self) {
        let remaining = self.queue.get_mut().map(|q| q.len()).unwrap_or(0);
        debug_assert!(
            remaining == 0,
            "FaultInjecting<R> dropped with {remaining} queued failure(s) un-consumed; \
             tests must drain by issuing enough produce_scan_result(..) calls on the \
             wrapper to consume every queued failure (queued_failures() inspects the \
             remaining count for debugging)"
        );
    }
}

impl<R: RefreshEngine> RefreshEngine for FaultInjecting<R> {
    /// `type Error = RefreshError` per the Option (i) wrapper API
    /// (module-level rustdoc). The wrapper exposes the
    /// orchestrator-side `RefreshError` surface uniformly across all
    /// `R`, matching the production
    /// [`LocalRefresh`](super::local_refresh::LocalRefresh)'s own
    /// `type Error = RefreshError`.
    type Error = RefreshError;

    // The trait method explicitly uses `-> impl Future + Send` (not
    // `async fn`) so the `Send` bound is part of the trait contract
    // per `engine/traits/refresh.rs` rustdoc. `async fn` syntax
    // would drop the explicit `+ Send` bound. See
    // `local_refresh.rs::produce_scan_result` for the precedent.
    #[allow(clippy::manual_async_fn)]
    fn produce_scan_result<D: DaemonEngine>(
        &self,
        snapshot: LedgerSnapshot,
        daemon: &D,
        opts: RefreshOptions,
        cancel: CancellationToken,
        progress: watch::Sender<RefreshProgress>,
        diagnostics: &dyn DiagnosticSink,
    ) -> impl std::future::Future<Output = Result<ScanResult, Self::Error>> + Send {
        // Pop synchronously OUTSIDE the async block so the Mutex is
        // released before the future is constructed. Composes with
        // the tokio scheduler discipline that no synchronous lock is
        // held across an `.await` boundary.
        let injected = self
            .queue
            .lock()
            .expect("FaultInjecting queue poisoned")
            .pop_front();
        async move {
            if let Some(err) = injected {
                return Err(err);
            }
            // Delegate to the inner producer. The `Into::into` is
            // the trait-bound conversion `R::Error: Into<RefreshError>`
            // (declared on `RefreshEngine::Error`). For
            // `R = LocalRefresh` this routes through the
            // `From<LocalRefreshError> for RefreshError` impl at
            // `local_refresh.rs:369–386`; for `R = RefreshError`
            // (e.g., a transient test stub), the conversion is the
            // identity per `impl<T> From<T> for T`.
            self.inner
                .produce_scan_result(snapshot, daemon, opts, cancel, progress, diagnostics)
                .await
                .map_err(Into::into)
        }
    }
}

#[cfg(test)]
mod tests {
    //! Class 1 smoke tests per the Round 5 sub-pin extension
    //! F-Mock-8 disposition (wrapper-based trait-surface tests).
    //! Four sub-properties: empty-queue passthrough, single-
    //! injection-then-delegation, multi-injection FIFO ordering,
    //! and queue-drain-on-teardown plus the `#[should_panic]`
    //! companion that exercises the Drop-time `debug_assert!`.
    //!
    //! Class 2 (From-conversion tests against `LocalRefresh`)
    //! lives at `local_refresh.rs`'s
    //! `local_refresh_error_maps_to_refresh_error` test — the
    //! precedent the F-Mock-8 disposition cites. The two classes
    //! are sibling, not redundant: the wrapper bypasses the `From`
    //! conversion by injecting `RefreshError` directly per the
    //! Option (i) API, so wrapper tests do not exercise the From
    //! impl; Class 2 is what verifies the From impl behavior.

    use std::sync::Arc;

    use shekyl_engine_state::LedgerBlock;
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::engine::diagnostics::NoopDiagnosticSink;
    use crate::engine::error::{IoError, RefreshError};
    use crate::engine::refresh::{LedgerSnapshot, RefreshOptions, RefreshPhase, RefreshProgress};
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};
    use crate::engine::traits::refresh::RefreshEngine;

    /// Trivial `RefreshEngine` stub: returns an empty `ScanResult`
    /// anchored at the snapshot's `synced_height + 1`. Used as the
    /// `inner` producer for Class 1 smoke tests so that delegation
    /// success is observable without running the full
    /// `LocalRefresh` scan path (which requires fully-typed
    /// view-material the smoke tests have no use for).
    ///
    /// **Not a Mock-X.** This is a one-method stub for one specific
    /// test surface (the wrapper's delegation path), not a parallel
    /// implementation of the full `RefreshEngine` contract. Per the
    /// PR 3 §2.1.5 four-pattern pre-flight checklist:
    /// (a) one method, not the full trait surface;
    /// (b) no failure injection inside this stub — the wrapper
    /// drives all failure semantics;
    /// (c) lives in `#[cfg(test)]` only;
    /// (d) no `clone()` semantics, no actor-mesh shape.
    /// The stub is the minimum surface needed to observe wrapper
    /// delegation; it has no consumer outside this test module.
    struct DelegationStub;

    impl crate::engine::scan_floor::ScanStartFloorProvider for DelegationStub {
        fn scan_start_floor(&self) -> u64 {
            0
        }
    }

    impl RefreshEngine for DelegationStub {
        type Error = RefreshError;

        #[allow(clippy::manual_async_fn)]
        fn produce_scan_result<D: DaemonEngine>(
            &self,
            snapshot: LedgerSnapshot,
            _daemon: &D,
            _opts: RefreshOptions,
            _cancel: CancellationToken,
            _progress: watch::Sender<RefreshProgress>,
            _diagnostics: &dyn DiagnosticSink,
        ) -> impl std::future::Future<Output = Result<ScanResult, Self::Error>> + Send {
            async move {
                let start = snapshot.synced_height.saturating_add(1);
                Ok(ScanResult::empty_at(start, None))
            }
        }
    }

    /// Construct a `(LedgerSnapshot, CancellationToken,
    /// watch::Sender<RefreshProgress>)` triple suitable for driving
    /// the wrapper's `produce_scan_result` in a smoke test. The
    /// snapshot is parameterless (default-empty); cancellation is
    /// unfired; progress receiver is dropped (the wrapper does not
    /// emit progress, only the inner producer does).
    fn smoke_inputs() -> (
        LedgerSnapshot,
        CancellationToken,
        watch::Sender<RefreshProgress>,
    ) {
        // Empty `LedgerBlock` builds an empty snapshot via the
        // canonical `from_ledger` path (no test-only
        // `LedgerSnapshot` constructor exists, and per
        // `25-rust-architecture.mdc` we route through the production
        // constructor rather than bypass it).
        let snapshot = LedgerSnapshot::from_ledger(&LedgerBlock::empty());
        let cancel = CancellationToken::new();
        let (progress, _rx) = watch::channel(RefreshProgress {
            height: 0,
            blocks_processed: 0,
            blocks_total: 0,
            phase: RefreshPhase::Scanning,
        });
        (snapshot, cancel, progress)
    }

    /// **Property 1 — empty-queue passthrough.** Wrapper with empty
    /// queue delegates to inner producer; no injection consumed.
    #[tokio::test]
    async fn empty_queue_delegates_to_inner() {
        let wrapper = FaultInjecting::new(DelegationStub);
        assert_eq!(wrapper.queued_failures(), 0);

        let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        let (snapshot, cancel, progress) = smoke_inputs();
        let sink = NoopDiagnosticSink;

        let result = wrapper
            .produce_scan_result(
                snapshot,
                daemon.as_ref(),
                RefreshOptions::default(),
                cancel,
                progress,
                &sink,
            )
            .await;

        // ScanResult doesn't implement Debug, so we can't render the
        // Ok payload in the assertion message; report only the Err
        // discriminant for diagnostics.
        assert!(
            result.is_ok(),
            "empty-queue wrapper should delegate to inner and succeed; got Err({:?})",
            result.err()
        );
        assert_eq!(wrapper.queued_failures(), 0);
    }

    /// **Property 2 — single-injection-then-delegation.** Queue one
    /// `RefreshError`; first call returns the injection; second
    /// call delegates to the inner producer.
    #[tokio::test]
    async fn single_injection_consumed_then_delegates() {
        let wrapper = FaultInjecting::new(DelegationStub);
        wrapper.queue_failure(RefreshError::Cancelled);
        assert_eq!(wrapper.queued_failures(), 1);

        let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        let sink = NoopDiagnosticSink;

        // First call: pops the injection.
        let (snapshot, cancel, progress) = smoke_inputs();
        let first = wrapper
            .produce_scan_result(
                snapshot,
                daemon.as_ref(),
                RefreshOptions::default(),
                cancel,
                progress,
                &sink,
            )
            .await;
        assert!(
            matches!(first, Err(RefreshError::Cancelled)),
            "first call should return the queued Cancelled; got Err({:?}) / is_ok={}",
            first.as_ref().err(),
            first.is_ok()
        );
        assert_eq!(wrapper.queued_failures(), 0);

        // Second call: queue empty, delegates to inner.
        let (snapshot, cancel, progress) = smoke_inputs();
        let second = wrapper
            .produce_scan_result(
                snapshot,
                daemon.as_ref(),
                RefreshOptions::default(),
                cancel,
                progress,
                &sink,
            )
            .await;
        assert!(
            second.is_ok(),
            "second call should delegate to inner and succeed; got Err({:?})",
            second.err()
        );
    }

    /// **Property 3 — multi-injection FIFO ordering.** Queue
    /// `[A, B]`; first call returns `A`; second call returns `B`;
    /// third call delegates to the inner producer.
    #[tokio::test]
    async fn multi_injection_drains_fifo() {
        let wrapper = FaultInjecting::new(DelegationStub);
        wrapper.queue_failure(RefreshError::Cancelled);
        wrapper.queue_failure(RefreshError::Io(IoError::Daemon {
            detail: "FIFO test: second injection".to_string(),
        }));
        assert_eq!(wrapper.queued_failures(), 2);

        let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        let sink = NoopDiagnosticSink;

        // First call: head is Cancelled.
        let (snapshot, cancel, progress) = smoke_inputs();
        let first = wrapper
            .produce_scan_result(
                snapshot,
                daemon.as_ref(),
                RefreshOptions::default(),
                cancel,
                progress,
                &sink,
            )
            .await;
        assert!(
            matches!(first, Err(RefreshError::Cancelled)),
            "FIFO head should be Cancelled; got Err({:?})",
            first.as_ref().err()
        );
        assert_eq!(wrapper.queued_failures(), 1);

        // Second call: next is the Io(Daemon) injection.
        let (snapshot, cancel, progress) = smoke_inputs();
        let second = wrapper
            .produce_scan_result(
                snapshot,
                daemon.as_ref(),
                RefreshOptions::default(),
                cancel,
                progress,
                &sink,
            )
            .await;
        assert!(
            matches!(second, Err(RefreshError::Io(IoError::Daemon { .. }))),
            "FIFO next should be Io(Daemon); got Err({:?})",
            second.as_ref().err()
        );
        assert_eq!(wrapper.queued_failures(), 0);

        // Third call: queue empty, delegates to inner.
        let (snapshot, cancel, progress) = smoke_inputs();
        let third = wrapper
            .produce_scan_result(
                snapshot,
                daemon.as_ref(),
                RefreshOptions::default(),
                cancel,
                progress,
                &sink,
            )
            .await;
        assert!(
            third.is_ok(),
            "third call should delegate to inner and succeed; got Err({:?})",
            third.err()
        );
    }

    /// **Property 4 (drain inspector).** Queue two failures, drain
    /// both, observe `queued_failures` reflects each step.
    /// (Separated from the Drop-time `debug_assert!` panic test
    /// below to keep the success path independent of the panic
    /// path.)
    #[tokio::test]
    async fn queued_failures_reflects_drain() {
        let wrapper = FaultInjecting::new(DelegationStub);
        wrapper.queue_failure(RefreshError::Cancelled);
        wrapper.queue_failure(RefreshError::Cancelled);
        assert_eq!(wrapper.queued_failures(), 2);

        let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        let sink = NoopDiagnosticSink;

        let (snapshot, cancel, progress) = smoke_inputs();
        let first = wrapper
            .produce_scan_result(
                snapshot,
                daemon.as_ref(),
                RefreshOptions::default(),
                cancel,
                progress,
                &sink,
            )
            .await;
        // Consume the injected `Result` to satisfy `#[must_use]`;
        // the drain count is what this test asserts on.
        assert!(
            first.is_err(),
            "drain-inspector: first call should return the queued failure"
        );
        assert_eq!(wrapper.queued_failures(), 1);

        let (snapshot, cancel, progress) = smoke_inputs();
        let second = wrapper
            .produce_scan_result(
                snapshot,
                daemon.as_ref(),
                RefreshOptions::default(),
                cancel,
                progress,
                &sink,
            )
            .await;
        assert!(
            second.is_err(),
            "drain-inspector: second call should return the queued failure"
        );
        assert_eq!(wrapper.queued_failures(), 0);
    }

    /// **Property 4 companion — Drop-time `debug_assert!` fires
    /// on un-drained queue.** Construct a wrapper, queue a failure,
    /// let it drop without consuming. `#[should_panic]` verifies
    /// the debug_assert fires per the F-Mock-2 contract pin.
    ///
    /// `cfg(debug_assertions)` gates the test: release builds
    /// (without `debug_assertions`) compile out the assert and
    /// the test would falsely pass without panicking. Per the
    /// `90-commits.mdc` scope discipline this gate matches the
    /// `debug_assert!`'s own gate, preserving symmetry.
    #[test]
    #[should_panic(expected = "FaultInjecting<R> dropped with 1 queued failure(s) un-consumed")]
    #[cfg(debug_assertions)]
    fn drop_with_un_drained_queue_panics() {
        let wrapper = FaultInjecting::new(DelegationStub);
        wrapper.queue_failure(RefreshError::Cancelled);
        // wrapper drops here with queued_failures() == 1 → panic.
    }
}
