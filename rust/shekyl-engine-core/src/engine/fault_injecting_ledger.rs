// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `FaultInjecting<L: LedgerEngine>` — composable failure-injection
//! wrapper for the [`LedgerEngine`] trait surface (Stage 1 PR 4
//! C6β test substrate).
//!
//! # Why this exists (no-Mock substrate per PR 3 §2.1.2)
//!
//! The pre-PR-4 substrate was the parallel-implementation
//! [`MockLedger`](super::test_support) carried forward from PR 2;
//! the Round 5 substrate-decision amendment (commit `8484e669a`)
//! deleted that approach as a category per the no-Mock substrate
//! discipline PR 3
//! [`§2.1.2`](../../../../../docs/design/STAGE_1_PR_3_KEY_ENGINE.md)
//! settled. The retroactive `MockLedger` cleanup
//! ([`docs/FOLLOWUPS.md`](../../../../../docs/FOLLOWUPS.md) entry
//! "Stage 1 retroactive Mock-X cleanup: `MockLedger` →
//! `LocalLedger::from_test_blocks(...)` + `FaultInjecting<LocalLedger>`")
//! lands at C6β; this module is the wrapper-side half of that
//! cleanup, paired with
//! [`super::local_ledger::LocalLedger::from_test_blocks`] (the
//! production-only constructor half).
//!
//! Five named failure modes that `MockLedger`-style parallel
//! implementations introduce — test-only types as production
//! attack surface; conflation of test-input injection with
//! substitute implementations; inherited-from-Monero pattern that
//! has produced real bugs in the inherited codebase; foreclosure
//! of composition with future implementors; tests verifying fake
//! semantics rather than real semantics — are avoided by
//! construction here. Tests construct
//! `FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()))`,
//! queue failures through [`queue_failure`] or
//! [`queue_concurrent_mutation`], and exercise the orchestrator
//! against the same production [`LocalLedger`] implementor — only
//! the trait-boundary behaviour is perturbed.
//!
//! # Wrapper API (Option (i), cross-wrapper symmetry with
//! `FaultInjecting<R: RefreshEngine>`)
//!
//! The wrapper queues [`RefreshError`] values directly. The
//! [`LedgerEngine::apply_scan_result`] signature returns
//! `Result<(), RefreshError>` (not `Result<(), Self::Error>`) per
//! the two-enum architecture pin in
//! [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](../../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md)
//! §6.1.1 — the trait surface speaks the orchestrator-side enum
//! directly because the merge runs against orchestrator-side
//! invariants. The queue type therefore matches the return type
//! verbatim, and no `Into<...>` conversion runs on the injection
//! path.
//!
//! The `FaultInjecting<R: RefreshEngine>` companion at
//! [`super::fault_injecting_refresh`] uses the same queue type
//! by the same rationale (the Option (i) wrapper API maps
//! `type Error = RefreshError` on the `R` wrapper so the two
//! wrappers expose a uniform queue surface to smoke tests).
//! Cross-wrapper queue-shape uniformity is the load-bearing
//! property the design's Round 5 F-Mock-3-sharpening disposition
//! anchors.
//!
//! # Queue contract (F-Mock-2)
//!
//! Same contract as [`super::fault_injecting_refresh::FaultInjecting`]:
//!
//! - **FIFO ordering.** Injections are popped head-first; if a
//!   test injects `[A, B]` in that order, the next two
//!   `apply_scan_result` calls return `Err(A)` then `Err(B)`.
//! - **Drain inspector.** [`queued_failures`] reports the current
//!   queue length per the existing
//!   [`MockLedger::queued_failures`](super::test_support)
//!   precedent (the C6β migration adopts the same method name,
//!   identical semantics, per the F-Mock-5 migration table). Tests
//!   verify queue-drain by asserting
//!   `wrapper.queued_failures() == 0` at teardown.
//! - **`debug_assert!` on Drop.** If a test leaves the wrapper
//!   without draining, the wrapper's [`Drop`] impl fires
//!   `debug_assert!` — panic-on-leftover in test/debug builds;
//!   silent in release. Production builds do not compile the
//!   wrapper in regardless (`#[cfg(any(test, feature =
//!   "test-helpers"))]` module gate per F-Mock-1).
//! - **Reentrance.** If a test injects a failure and the
//!   `apply_scan_result` body re-enters via some path that calls
//!   back into [`LedgerEngine`], the second call also pops from
//!   the queue per the "pop head if non-empty" semantics. The
//!   V3.0 [`LocalLedger`] merge body has no such reentrance
//!   pattern; the pin is for forward-compatibility with Stage 4
//!   actor-mesh implementors that may carry different reentrance
//!   behaviour.
//!
//! # Composition paradigm (§6.1 paradigm pin)
//!
//! Synchronous trait dispatcher with a wrapper-internal queue,
//! **not** an actor mailbox. No `Sender` / `Receiver` channel, no
//! message-passing, no supervision. The `Mutex` is short-lived
//! (pop + release before the `.await` boundary on
//! `apply_scan_result`; pop + release before the synchronous
//! return on read methods); composition-paradigm by construction.
//! Stage 4's actor-paradigm tests inherit the same "drive causes
//! through one wrapper, observe effects on the orchestrator
//! surface" testing shape; the wrapper boundary moves from
//! trait-dispatch to message-handler-dispatch with no test-shape
//! change.
//!
//! # Convenience: `queue_concurrent_mutation`
//!
//! The F-Mock-5 migration table preserves
//! `MockLedger::queue_concurrent_mutation()` as
//! `FaultInjecting<LocalLedger>::queue_concurrent_mutation()`
//! with identical semantics. The convenience method is the §5.2
//! retry-contract injection point the existing hybrid retry test
//! consumes; preserving the method-name surface keeps the C6β
//! migration's diff focused on the one-line construction
//! replacement (`MockLedger::with_seed(...)` →
//! `FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()))`)
//! rather than rewiring every call site's injection idiom. The
//! method synthesizes a `RefreshError::ConcurrentMutation` with
//! placeholder `wallet`/`result` heights — matching the
//! pre-C6β `MockLedger` behaviour where the hybrid test asserts
//! on the variant tag, not the per-field heights.
//!
//! [`LocalLedger`]: super::local_ledger::LocalLedger
//! [`LedgerEngine`]: super::traits::LedgerEngine
//! [`RefreshError`]: super::error::RefreshError

use std::collections::VecDeque;
use std::sync::Mutex;

use shekyl_scanner::BalanceSummary;

use super::error::{LedgerError, RefreshError};
use super::refresh::LedgerSnapshot;
use super::traits::ledger::LedgerEngine;
use crate::scan::ScanResult;

/// Composable failure-injection wrapper over any
/// [`LedgerEngine`] implementor. See the module-level rustdoc for
/// the no-Mock rationale, the Option (i) wrapper API, the
/// F-Mock-2 queue contract, the composition-paradigm framing, and
/// the `queue_concurrent_mutation` convenience rationale.
pub(crate) struct FaultInjecting<L: LedgerEngine> {
    /// Production implementor wrapped by this fault injector. Held
    /// by-value (not by-`Arc`) because the wrapper is constructed in
    /// test setup and dropped at test teardown; the engine's
    /// `ledger: L` slot holds the wrapper directly.
    inner: L,
    /// FIFO queue of pre-built [`RefreshError`] values. Each call to
    /// [`apply_scan_result`](LedgerEngine::apply_scan_result) pops
    /// the head; an empty queue delegates to `inner`.
    ///
    /// `Mutex` rather than `RwLock` because every access mutates
    /// (push at queue, pop at consume, len at drain inspector); the
    /// short-lived lock matches the
    /// [`MockLedger::queue_concurrent_mutation`](super::test_support)
    /// precedent and the sibling
    /// [`super::fault_injecting_refresh::FaultInjecting`] choice.
    queue: Mutex<VecDeque<RefreshError>>,
}

impl<L: LedgerEngine> FaultInjecting<L> {
    /// Wrap `inner` with an empty failure queue. Tests typically
    /// pair this with
    /// [`super::Engine::replace_ledger`](super::Engine::replace_ledger)
    /// to install the wrapper on an already-constructed engine
    /// (`Engine<S, D, LocalLedger, R>` →
    /// `Engine<S, D, FaultInjecting<LocalLedger>, R>`).
    ///
    /// `dead_code` allow: under `--features test-helpers` without
    /// `cfg(test)` no caller is in scope; the C6β hybrid retry test
    /// `hybrid_apply_scan_result_retries_on_concurrent_mutation`
    /// in [`super::refresh`] is the canonical caller and lives
    /// behind `cfg(test)`. Symmetric with the
    /// [`super::fault_injecting_refresh::FaultInjecting::new`]
    /// disposition.
    #[allow(dead_code)]
    pub(crate) fn new(inner: L) -> Self {
        Self {
            inner,
            queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Queue one [`RefreshError`] for the next
    /// [`apply_scan_result`](LedgerEngine::apply_scan_result) call.
    /// Multiple invocations queue multiple failures (FIFO drain
    /// per the F-Mock-2 contract). Once the queue empties,
    /// subsequent calls delegate to the wrapped `inner` ledger.
    ///
    /// `dead_code` allow: the convenience method
    /// [`queue_concurrent_mutation`] covers every current call
    /// site in the C6β migration; this general-injection method
    /// lands as the canonical test-driver API for hybrid tests
    /// that need richer failure variants (e.g., the C7 hybrid
    /// retry test per the design doc's §6 preservation list).
    #[allow(dead_code)]
    pub(crate) fn queue_failure(&self, err: RefreshError) {
        self.queue
            .lock()
            .expect("FaultInjecting<L> queue poisoned")
            .push_back(err);
    }

    /// Queue one [`RefreshError::ConcurrentMutation`] for the next
    /// [`apply_scan_result`](LedgerEngine::apply_scan_result) call.
    ///
    /// Preserves the
    /// [`MockLedger::queue_concurrent_mutation`](super::test_support)
    /// method name and semantics per the F-Mock-5 migration table:
    /// the §5.2 retry-contract injection point the existing hybrid
    /// retry test consumes, with placeholder `wallet`/`result`
    /// heights matching the pre-C6β `MockLedger` behaviour. The
    /// hybrid test asserts on the variant tag (the engine's retry
    /// classifier branches on variant, not on the height fields);
    /// placeholder heights are sufficient to exercise the retry
    /// path. If a future test needs realistic per-attempt heights,
    /// callers use [`queue_failure`] with a fully-populated
    /// `ConcurrentMutation` instead.
    ///
    /// `dead_code` allow: same disposition as [`new`] — under
    /// `--features test-helpers` without `cfg(test)` no caller is
    /// in scope; the `cfg(test)`-gated hybrid retry test is the
    /// canonical caller.
    #[allow(dead_code)]
    pub(crate) fn queue_concurrent_mutation(&self) {
        self.queue_failure(RefreshError::ConcurrentMutation {
            wallet: 0,
            result: 0,
        });
    }

    /// Number of failure injections still queued. Tests assert
    /// against this to confirm the orchestrator drained the queue
    /// (i.e., the injection path was exercised, not silently
    /// bypassed). See the F-Mock-2 drain-inspector contract pin in
    /// the module-level rustdoc.
    ///
    /// `dead_code` allow: same disposition as [`new`] — under
    /// `--features test-helpers` without `cfg(test)` no caller is
    /// in scope; the `cfg(test)`-gated hybrid retry test is the
    /// canonical caller.
    #[allow(dead_code)]
    pub(crate) fn queued_failures(&self) -> usize {
        self.queue
            .lock()
            .expect("FaultInjecting<L> queue poisoned")
            .len()
    }
}

impl<L: LedgerEngine> Drop for FaultInjecting<L> {
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
            "FaultInjecting<L> dropped with {remaining} queued failures un-consumed; \
             tests must drain via queued_failures() and consume_or_inject"
        );
    }
}

impl<L: LedgerEngine> LedgerEngine for FaultInjecting<L> {
    /// `type Error = LedgerError` (uniform across all `L`), per the
    /// trait's `type Error: Into<LedgerError>` bound. The wrapper
    /// itself never returns this `Error` — the
    /// [`apply_scan_result`](LedgerEngine::apply_scan_result)
    /// signature speaks the orchestrator-side `RefreshError`
    /// directly per the two-enum architecture pin
    /// ([`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`](../../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md)
    /// §6.1.1) — but the associated type is still required for the
    /// bound. The choice of `LedgerError` (rather than
    /// `L::Error`) keeps the wrapper's `Self::Error` uniform
    /// across all `L`, mirroring the
    /// [`super::fault_injecting_refresh::FaultInjecting`] Option
    /// (i) choice of `type Error = RefreshError`.
    type Error = LedgerError;

    fn synced_height(&self) -> u64 {
        // Read methods are not failure-injectable; the §5.2 retry
        // contract is anchored on `apply_scan_result` alone.
        // Delegate verbatim to the inner implementor.
        self.inner.synced_height()
    }

    fn snapshot(&self) -> LedgerSnapshot {
        self.inner.snapshot()
    }

    fn balance(&self) -> BalanceSummary {
        self.inner.balance()
    }

    fn apply_scan_result(
        &self,
        scan_result: ScanResult,
    ) -> impl std::future::Future<Output = Result<(), RefreshError>> + Send {
        // Pop synchronously OUTSIDE the async block so the Mutex is
        // released before the future is constructed. Composes with
        // the tokio scheduler discipline that no synchronous lock
        // is held across an `.await` boundary; matches the sibling
        // [`super::fault_injecting_refresh::FaultInjecting`]'s
        // pop-then-async shape.
        let injected = self
            .queue
            .lock()
            .expect("FaultInjecting<L> queue poisoned")
            .pop_front();
        async move {
            if let Some(err) = injected {
                return Err(err);
            }
            // Delegate to the inner ledger. The trait surface
            // already returns `Result<(), RefreshError>` directly
            // (two-enum architecture pin); no `Into::into` is
            // required on the success path.
            self.inner.apply_scan_result(scan_result).await
        }
    }
}

#[cfg(test)]
mod tests {
    //! Class 1 smoke tests per the Round 5 sub-pin extension
    //! F-Mock-8 disposition (wrapper-based trait-surface tests),
    //! mirroring [`super::fault_injecting_refresh`]'s smoke
    //! suite. Tests cover the F-Mock-2 queue contract over the
    //! [`LedgerEngine`] surface: empty-queue passthrough, single-
    //! injection-then-delegation, multi-injection FIFO ordering,
    //! the convenience `queue_concurrent_mutation` shape, and the
    //! queue-drain-on-teardown `debug_assert!` companion.
    //!
    //! These tests inherit and replace the pre-C6β `MockLedger`
    //! contract tests at
    //! [`super::test_support`]'s former `tests` module sub-suite
    //! ("MockLedger contract") — the surface exercised is
    //! functionally identical because the C6β substrate is
    //! `MockLedger`'s structural shape extracted into the
    //! production [`super::local_ledger::LocalLedger`] +
    //! composable wrapper pair (per F-Mock-4 verification: the
    //! pre-C6β `MockLedger` already delegated to the canonical
    //! `apply_scan_result_to_state` merge body).

    use super::*;
    use crate::engine::local_ledger::LocalLedger;

    /// **Property 1 — empty-queue passthrough.** Wrapper with empty
    /// queue delegates to inner ledger; no injection consumed.
    /// Mirrors the pre-C6β
    /// `mock_ledger_empty_state_reports_zero_height` /
    /// `mock_ledger_apply_empty_result_advances_through_no_failure`
    /// pair.
    #[tokio::test]
    async fn empty_queue_delegates_to_inner_apply() {
        let wrapper = FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()));
        assert_eq!(wrapper.queued_failures(), 0);
        assert_eq!(wrapper.synced_height(), 0);

        // Empty range against the empty wallet applies as a no-op
        // merge per the canonical `apply_scan_result_to_state`
        // body (LocalLedger delegate); height does not advance.
        let result = ScanResult::empty_at(1, None);
        wrapper
            .apply_scan_result(result)
            .await
            .expect("empty-queue wrapper should delegate to inner LocalLedger and succeed");
        assert_eq!(wrapper.queued_failures(), 0);
        assert_eq!(
            wrapper.synced_height(),
            0,
            "empty range merges as no-op; height unchanged"
        );
    }

    /// **Property 2 — single-injection-then-delegation.** Queue
    /// one [`RefreshError`]; first call returns the injection;
    /// second call delegates to the inner ledger.
    /// Mirrors the pre-C6β
    /// `mock_ledger_queue_concurrent_mutation_returns_failure_then_drains`
    /// test, generalized to accept any `RefreshError` variant via
    /// [`queue_failure`].
    #[tokio::test]
    async fn single_injection_consumed_then_delegates() {
        let wrapper = FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()));
        wrapper.queue_failure(RefreshError::ConcurrentMutation {
            wallet: 7,
            result: 9,
        });
        assert_eq!(wrapper.queued_failures(), 1);

        let first = wrapper
            .apply_scan_result(ScanResult::empty_at(1, None))
            .await
            .expect_err("first call should surface the queued ConcurrentMutation");
        assert!(
            matches!(
                first,
                RefreshError::ConcurrentMutation {
                    wallet: 7,
                    result: 9
                }
            ),
            "queued ConcurrentMutation should surface with its exact heights; got {first:?}"
        );
        assert_eq!(wrapper.queued_failures(), 0);

        // Second call: queue empty, delegates to inner LocalLedger
        // and runs the canonical merge body successfully.
        wrapper
            .apply_scan_result(ScanResult::empty_at(1, None))
            .await
            .expect("post-drain apply should delegate to inner and succeed");
        assert_eq!(
            wrapper.synced_height(),
            0,
            "empty range merges as no-op; height unchanged"
        );
    }

    /// **Property 3 — multi-injection FIFO ordering.** Queue
    /// `[A, B]`; first call returns `A`; second call returns `B`;
    /// third call delegates to the inner ledger.
    /// Mirrors the pre-C6β `mock_ledger_failure_queue_is_fifo`
    /// test.
    #[tokio::test]
    async fn multi_injection_drains_fifo() {
        let wrapper = FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()));
        wrapper.queue_failure(RefreshError::ConcurrentMutation {
            wallet: 1,
            result: 1,
        });
        wrapper.queue_failure(RefreshError::ConcurrentMutation {
            wallet: 2,
            result: 2,
        });
        assert_eq!(wrapper.queued_failures(), 2);

        let first = wrapper
            .apply_scan_result(ScanResult::empty_at(1, None))
            .await
            .expect_err("FIFO head should surface first");
        assert!(
            matches!(
                first,
                RefreshError::ConcurrentMutation {
                    wallet: 1,
                    result: 1
                }
            ),
            "FIFO head; got {first:?}"
        );
        assert_eq!(wrapper.queued_failures(), 1);

        let second = wrapper
            .apply_scan_result(ScanResult::empty_at(1, None))
            .await
            .expect_err("second queued failure should surface next");
        assert!(
            matches!(
                second,
                RefreshError::ConcurrentMutation {
                    wallet: 2,
                    result: 2
                }
            ),
            "FIFO second; got {second:?}"
        );
        assert_eq!(wrapper.queued_failures(), 0);

        // Third call: queue empty, delegates to inner.
        wrapper
            .apply_scan_result(ScanResult::empty_at(1, None))
            .await
            .expect("post-drain apply should delegate to inner and succeed");
    }

    /// **Property 4 — convenience `queue_concurrent_mutation`.**
    /// The F-Mock-5-preserved convenience method synthesizes a
    /// `ConcurrentMutation` injection with placeholder heights;
    /// the wrapper surfaces it as the next failure.
    #[tokio::test]
    async fn convenience_queue_concurrent_mutation() {
        let wrapper = FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()));
        wrapper.queue_concurrent_mutation();
        assert_eq!(wrapper.queued_failures(), 1);

        let injected = wrapper
            .apply_scan_result(ScanResult::empty_at(1, None))
            .await
            .expect_err("convenience-queued failure should surface as ConcurrentMutation");
        assert!(
            matches!(injected, RefreshError::ConcurrentMutation { .. }),
            "convenience method synthesizes ConcurrentMutation; got {injected:?}"
        );
        assert_eq!(wrapper.queued_failures(), 0);
    }

    /// **Property 5 — queue-drain-on-teardown.** Dropping the
    /// wrapper with un-consumed injections fires the `Drop`
    /// `debug_assert!`. Companion to the sibling
    /// [`super::fault_injecting_refresh`]
    /// `wrapper_drop_with_undrained_queue_panics` test.
    ///
    /// `#[should_panic]` rather than catching the panic — the
    /// failure path is intrinsic to `Drop`, and the test infra
    /// observes the unwind.
    #[test]
    #[should_panic(expected = "FaultInjecting<L> dropped with 1 queued failures un-consumed")]
    fn wrapper_drop_with_undrained_queue_panics() {
        let wrapper = FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()));
        wrapper.queue_failure(RefreshError::ConcurrentMutation {
            wallet: 0,
            result: 0,
        });
        // wrapper drops here with one failure un-consumed
    }

    /// **Property 6 — read-path delegation.** The non-mutating
    /// trait methods (`synced_height`, `snapshot`, `balance`) are
    /// not failure-injectable; they delegate verbatim to the
    /// inner ledger regardless of queue state.
    #[tokio::test]
    async fn read_methods_delegate_through_queue() {
        let wrapper = FaultInjecting::new(LocalLedger::from_test_blocks(Vec::new()));
        wrapper.queue_concurrent_mutation();

        // Queue holds a pending failure for apply_scan_result, but
        // read methods are unaffected: they pass through to the
        // inner LocalLedger's canonical projections.
        assert_eq!(wrapper.synced_height(), 0);
        let snap = wrapper.snapshot();
        assert_eq!(snap.synced_height, 0);
        let bal = wrapper.balance();
        // Empty ledger has zero confirmed balance.
        assert_eq!(bal.total, 0);
        assert_eq!(bal.unlocked, 0);
        assert_eq!(
            wrapper.queued_failures(),
            1,
            "read methods do not pop queue"
        );

        // Drain the queue before drop so the test exits cleanly
        // (debug_assert!-on-Drop discipline).
        let drain_result = wrapper
            .apply_scan_result(ScanResult::empty_at(1, None))
            .await;
        assert!(
            drain_result.is_err(),
            "queued failure should surface as Err: {drain_result:?}"
        );
        assert_eq!(wrapper.queued_failures(), 0);
    }
}
