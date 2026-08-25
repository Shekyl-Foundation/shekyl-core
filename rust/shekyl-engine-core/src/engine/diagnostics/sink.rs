// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The [`DiagnosticSink`] seam and its shipped implementors.

use std::time::Duration;

use tracing::{event, Level};

use super::{PendingTxDiagnostic, RefreshDiagnostic};

/// Producer-side sink for [`RefreshDiagnostic`] events.
///
/// Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §5.4.6 the
/// sink trait carries seven contract pins:
///
/// 1. **Non-blocking emit.** [`emit`](Self::emit) MUST NOT block
///    the producer. Producer liveness is the orchestrator's
///    primary cancellation-checkpoint guarantee; an emit call that
///    blocks the producer thread defeats the §5.4.9 F2
///    five-checkpoint discipline. Sinks that need to buffer
///    (e.g., write events to a channel) must use bounded
///    non-blocking sends and drop on overflow.
///
/// 2. **Emission/return coherence.** Per §5.4.6 emission/return
///    coherence: if the producer returns an error variant
///    corresponding to a diagnostic class (e.g., the terminal
///    return is a `Cancelled` error after a sequence of timeouts),
///    the sink stream observed up to the return must be consistent
///    with the return discriminant. The C7
///    `produce_scan_result_emission_return_coherence` property
///    test pins this as PERMANENT CI coverage; prose/test drift
///    resolves AGAINST the test.
///
/// 3. **Per-emitter FIFO ordering.** Per §5.4.6 F4, a single
///    producer task's emits to a single sink instance preserve
///    FIFO ordering. Multiple producer tasks emitting to the same
///    sink do NOT — cross-emitter ordering is undefined.
///    [`TracingDiagnosticSink`] documents this by class through
///    the underlying `tracing` subscriber's ordering contract.
///
/// 4. **In-process trust boundary.** Per §5.4.6 + §5.4.8 #4 the
///    sink interface carries no serialization surface; events
///    never cross a process boundary. JSON-RPC-server-side
///    consumption (V3.2 follow-up) routes through an explicit
///    in-process aggregator/republisher actor (F5 V3.x
///    follow-up), not through this trait.
///
/// 5. **Restart-amnesia is deliberate.** Producer-side per-attempt
///    state (rate-limit counters per §5.4.8 #5 / F6 + F13 sub-pin)
///    is cleared at attempt start, not preserved across retries.
///    The retry loop runs orchestrator-side; the producer is
///    re-entered fresh on each attempt and the sink sees the new
///    attempt's stream from the producer's initial state.
///
/// 6. **Implementor liveness.** `Send + Sync + 'static` so the
///    sink can be shared `&dyn DiagnosticSink` between the
///    orchestrator that constructs it and the producer task that
///    emits. The trait object lifetime is the
///    [`produce_scan_result`](crate::engine::traits::RefreshEngine::produce_scan_result)
///    call.
///
/// 7. **Drop is the cancel-checkpoint.** Sinks that hold
///    background resources (e.g., a tracing subscriber filter
///    handle) drop them in their own [`Drop`] impl; the trait
///    interface does not expose a separate shutdown call.
///
/// # `pub` visibility
///
/// Per the §6 review-checklist disposition the sink trait is
/// `pub` at the crate root (in contrast to the `pub(crate)`
/// [`RefreshEngine`](crate::engine::traits::RefreshEngine) trait
/// extraction surface). External consumers may construct sinks
/// to pass into the orchestrator's refresh path; the trait is
/// part of the configuration surface, not the engine-extraction
/// surface.
///
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
pub trait DiagnosticSink: Send + Sync + 'static {
    /// Emit one [`RefreshDiagnostic`] event onto the sink.
    ///
    /// # Contract
    ///
    /// - **Non-blocking** per pin 1 above. Implementors MUST NOT
    ///   block the calling thread.
    /// - **Per-emitter FIFO** per pin 3 above. Calls from a
    ///   single producer task to a single sink instance preserve
    ///   call-order.
    /// - **Infallible at the trait surface.** Implementors that
    ///   need to drop on backpressure do so silently; the
    ///   producer cannot recover from sink failure and the trait
    ///   surface does not expose that information.
    fn emit(&self, event: RefreshDiagnostic);

    /// Emit one [`PendingTxDiagnostic`] event onto the sink.
    ///
    /// Companion to [`emit`](Self::emit) for the PR 5
    /// `PendingTxEngine` producer per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0f.
    ///
    /// # Default impl
    ///
    /// Default discards the event. Per-trait-method-with-default
    /// preserves backward compatibility for V3.0's existing
    /// `RefreshDiagnostic`-only consumers: PR 4's
    /// [`NoopDiagnosticSink`] / [`TracingDiagnosticSink`] /
    /// `AssertionSink` / `PanickingSink` continue to compile
    /// against this trait without modification — and the default
    /// `{}` body matches `NoopDiagnosticSink`'s intent already.
    /// C5β (the trait-impl-bodies sub-commit) introduces production
    /// `emit_pending_tx` emission sites; the C5α / C7
    /// sink-side overrides for assertion-coverage and
    /// observability follow the same template `RefreshDiagnostic`
    /// established.
    ///
    /// # Contract
    ///
    /// All seven `DiagnosticSink` contract pins carry verbatim to
    /// this method:
    ///
    /// 1. **Non-blocking emit** — implementors MUST NOT block.
    /// 2. **Emission/return coherence** — sink stream up to the
    ///    trait return must agree with the discriminant of the
    ///    return value per §5.0.3.
    /// 3. **Per-emitter FIFO** — single-producer / single-sink
    ///    pairings preserve call-order; cross-emitter ordering is
    ///    undefined.
    /// 4. **In-process trust boundary** — no serialization
    ///    surface; events do not cross a process boundary. The
    ///    `tx_hash: Option<TxHash>` field on `SubmitSucceeded` /
    ///    `SubmitPendingResolution` is admissible at this
    ///    boundary because every `Some` hash is daemon-reported /
    ///    on-chain by construction, and `None` marks the one case
    ///    with nothing real to report — an ambiguous submit whose
    ///    bytes the engine no longer holds (synthetic ids are
    ///    retired; segment-2i G1 per PR 4 §5.4.8 #4 field-level
    ///    recursive-trust-boundary discipline).
    /// 5. **Restart-amnesia is deliberate** — producer-side per-
    ///    attempt state is cleared at attempt start.
    /// 6. **Implementor liveness** — `Send + Sync + 'static`.
    /// 7. **Drop is the cancel-checkpoint** — Drop handles
    ///    background resource teardown.
    #[allow(unused_variables)]
    fn emit_pending_tx(&self, event: PendingTxDiagnostic) {
        // Default: drop. C5 overrides per-sink for assertion-
        // and observability-class coverage.
    }
}

/// Drop-everything [`DiagnosticSink`] implementation.
///
/// `NoopDiagnosticSink` is the V3.0 default sink: it
/// unconditionally discards every event. Useful for callers that
/// don't want producer-side observability (e.g., a one-shot
/// scripted refresh in a test fixture, or a benchmark path where
/// tracing-subscriber overhead would skew the measurement).
///
/// # Zero-cost
///
/// The unit struct holds no state; the [`emit`](Self::emit)
/// method is a no-op the compiler eliminates after monomorphization
/// when the sink is used as a concrete type. Wrapped behind
/// `&dyn DiagnosticSink` (the trait-method calling convention),
/// the call is one virtual dispatch + one empty function-body
/// execution per event — bounded by the producer's per-block
/// emission budget per §5.4.8 #5.
///
/// # Test usage
///
/// `NoopDiagnosticSink::new()` is `const`; the struct is `Copy`
/// so it can be constructed inline (`&NoopDiagnosticSink`) at
/// call sites without naming the value.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDiagnosticSink;

impl NoopDiagnosticSink {
    /// Construct a new no-op sink. `const` so the struct can be
    /// embedded in `static` consumer state without `lazy_static`.
    pub const fn new() -> Self {
        Self
    }
}

impl DiagnosticSink for NoopDiagnosticSink {
    fn emit(&self, _event: RefreshDiagnostic) {
        // Intentional drop — see crate-level rustdoc.
    }
}

/// [`tracing`]-backed [`DiagnosticSink`] with F9-conformant
/// per-class projections.
///
/// Routes each [`RefreshDiagnostic`] variant to a
/// [`tracing::event!`] call with the projection contract pinned
/// in [`RefreshDiagnostic`]'s F9 binding (variant tags + bucketed
/// numerics; no raw [`Duration`] / `fork_height` / `height`).
///
/// # Levels
///
/// - [`DaemonMalformed`](RefreshDiagnostic::DaemonMalformed),
///   [`DaemonProtocolError`](RefreshDiagnostic::DaemonProtocolError)
///   — [`Level::WARN`] (data-integrity / protocol-violation
///   signals).
/// - [`DaemonTimeout`](RefreshDiagnostic::DaemonTimeout),
///   [`ReorgObserved`](RefreshDiagnostic::ReorgObserved) —
///   [`Level::INFO`] (transient transport / normal chain-event
///   signals).
/// - [`ScanProgress`](RefreshDiagnostic::ScanProgress),
///   [`SuppressedRateLimit`](RefreshDiagnostic::SuppressedRateLimit)
///   — [`Level::DEBUG`] (high-frequency / informational signals).
///
/// # Target
///
/// All events emit under the
/// `shekyl_engine_core::refresh::diagnostic` target so
/// subscribers can filter the diagnostic stream independent of
/// other engine-core tracing output.
///
/// # F4 per-emitter FIFO
///
/// Per §5.4.6 F4, ordering of events emitted by a single
/// producer task to a single sink instance is preserved. This
/// sink delegates to [`tracing::event!`]; the underlying
/// subscriber observes the same ordering the producer emitted.
/// Cross-task ordering remains undefined (the §5.4.6 F4 cross-
/// emitter contract).
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingDiagnosticSink;

impl TracingDiagnosticSink {
    /// Construct a new tracing sink. `const` so the struct can
    /// be embedded in `static` consumer state.
    pub const fn new() -> Self {
        Self
    }
}

impl DiagnosticSink for TracingDiagnosticSink {
    fn emit(&self, refresh_event: RefreshDiagnostic) {
        match refresh_event {
            RefreshDiagnostic::DaemonMalformed { kind } => {
                event!(
                    target: "shekyl_engine_core::refresh::diagnostic",
                    Level::WARN,
                    diagnostic = "daemon_malformed",
                    kind = ?kind,
                );
            }
            RefreshDiagnostic::DaemonTimeout { op, elapsed } => {
                event!(
                    target: "shekyl_engine_core::refresh::diagnostic",
                    Level::INFO,
                    diagnostic = "daemon_timeout",
                    op = ?op,
                    elapsed_bucket = elapsed_bucket(elapsed),
                );
            }
            RefreshDiagnostic::DaemonProtocolError { kind } => {
                event!(
                    target: "shekyl_engine_core::refresh::diagnostic",
                    Level::WARN,
                    diagnostic = "daemon_protocol_error",
                    kind = ?kind,
                );
            }
            RefreshDiagnostic::ReorgObserved {
                fork_height: _,
                depth,
            } => {
                event!(
                    target: "shekyl_engine_core::refresh::diagnostic",
                    Level::INFO,
                    diagnostic = "reorg_observed",
                    depth_bucket = depth_bucket(depth),
                );
            }
            RefreshDiagnostic::ScanProgress {
                height: _,
                candidates,
            } => {
                event!(
                    target: "shekyl_engine_core::refresh::diagnostic",
                    Level::DEBUG,
                    diagnostic = "scan_progress",
                    candidates_bucket = candidates_bucket(candidates),
                );
            }
            RefreshDiagnostic::SuppressedRateLimit { class } => {
                event!(
                    target: "shekyl_engine_core::refresh::diagnostic",
                    Level::DEBUG,
                    diagnostic = "suppressed_rate_limit",
                    class = ?class,
                );
            }
        }
    }
}

/// Bucket a [`Duration`] into one of the F9-confirmed labels:
/// `"<100ms"`, `"100ms-1s"`, `">1s"`.
///
/// Per F9 the raw duration is NOT projected (timing-correlation
/// closure on adversarial daemon timing). Three buckets balance
/// observability ("did the call complete near the timeout
/// budget?") against the closure.
pub(crate) const fn elapsed_bucket(d: Duration) -> &'static str {
    // Use as_secs/subsec_millis to keep this const-fn-friendly
    // across the supported Rust toolchain range. `as_millis()` is
    // const since 1.46 but returns u128, which we don't need.
    let secs = d.as_secs();
    let sub_millis = d.subsec_millis();
    if secs == 0 && sub_millis < 100 {
        "<100ms"
    } else if secs == 0 {
        "100ms-1s"
    } else {
        ">1s"
    }
}

/// Bucket a reorganization depth into one of the F9-confirmed
/// labels: `"1"`, `"2-10"`, `">10"`.
///
/// Per F9 the bucketing balances observability ("how
/// deep was the reorg?") against the chain-timing correlation
/// closure on raw depth values.
pub(crate) const fn depth_bucket(d: u32) -> &'static str {
    match d {
        0 | 1 => "1",
        2..=10 => "2-10",
        _ => ">10",
    }
}

/// Bucket a candidates count into one of the F9-confirmed labels:
/// `"none"`, `"few"`, `"many"`.
///
/// Per F9 the bucketing balances observability ("did
/// the scan find anything?") against the wallet-activity
/// correlation closure on raw candidate counts.
pub(crate) const fn candidates_bucket(c: usize) -> &'static str {
    match c {
        0 => "none",
        1..=9 => "few",
        _ => "many",
    }
}

// ============================================================================
// AssertionSink / PanickingSink — C7 property-test sinks
// ============================================================================

/// Recording [`DiagnosticSink`] for the §5.4.6 emission/return
/// coherence property test.
///
/// Records every [`RefreshDiagnostic`] event emitted on it in the
/// order they arrived, behind a [`std::sync::Mutex`] over a
/// [`Vec`]. Tests inspect the recorded stream after the producer
/// returns to assert the coherence contract:
///
/// - For every non-[`crate::engine::error::RefreshError::Cancelled`]
///   producer-returned error, the stream contains at least one
///   corresponding [`RefreshDiagnostic`] event class
///   ("`MalformedScanResult` ↔ `DaemonMalformed`",
///   "`Io` ↔ `DaemonProtocolError` or `DaemonTimeout`").
/// - No error-attributed event ([`RefreshDiagnostic::DaemonMalformed`],
///   [`RefreshDiagnostic::DaemonProtocolError`],
///   [`RefreshDiagnostic::DaemonTimeout`]) is followed by an
///   `Ok(_)` producer return — the "phantom error" failure mode the
///   §5.4.6 prose names.
///
/// # Permanent CI coverage pin (§5.4.6 / F3)
///
/// The `AssertionSink` + the
/// [`local_refresh::tests::produce_scan_result_emission_return_coherence`](crate::engine::local_refresh)
/// property test that consumes it are **permanent CI regression
/// coverage** per §5.4.6. Every PR touching any [`crate::engine::traits::RefreshEngine`]
/// implementation MUST keep the property test green; a failure is a
/// contract violation, not a test-investigation event. The
/// implementation either satisfies the coherence contract or the
/// design doc is updated with explicit re-pin language and the test
/// follows. Prose/test drift resolves AGAINST the test.
///
/// # Gating
///
/// `#[cfg(any(test, feature = "test-helpers"))] pub` per the C6α
/// F-Mock-1 symmetry pin: crate-internal tests instantiate the sink
/// inline; downstream `test-helpers`-feature consumers (none
/// pre-genesis) reach it through the public type name. Production
/// builds do not compile the type.
///
/// # Concurrent emission
///
/// The §5.4.6 non-blocking pin tolerates concurrent `emit` calls
/// from multiple producer tasks; `AssertionSink`'s recording lock
/// satisfies this only when contention is bounded. The V3.0
/// `LocalRefresh` producer is single-task; for multi-emitter
/// scenarios (Stage 4 actor-mesh tests), a lock-free recording sink
/// would replace this implementation. The test substrate is
/// adequate for V3.0 producer coverage.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Default)]
pub struct AssertionSink {
    /// Recording buffer; `Mutex` guards the append on `emit` and the
    /// drain on inspection. `RwLock` would not help — every access
    /// is a write to either the vector or a read of the captured
    /// snapshot, and the C7 tests do not race readers against the
    /// producer task.
    events: std::sync::Mutex<Vec<RefreshDiagnostic>>,
    /// PR 5 C7 companion buffer for [`PendingTxDiagnostic`] events.
    pending_events: std::sync::Mutex<Vec<PendingTxDiagnostic>>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl AssertionSink {
    /// Construct a fresh recording sink with an empty buffer.
    #[must_use]
    #[allow(dead_code)] // Phase 1 author: lands as the canonical C7 coherence-test constructor.
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
            pending_events: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Snapshot the recorded events, cloning the inner buffer so
    /// the sink can continue receiving emissions while the
    /// inspection runs. The clone is bounded by the producer's
    /// per-attempt emission ceiling (§5.4.8 #5 +
    /// [`crate::engine::local_refresh::PER_BLOCK_CEILING`]) times the
    /// scan range, so per-test memory is bounded.
    #[allow(dead_code)] // Phase 1 author: lands as the canonical C7 coherence-test inspector.
    pub fn recorded(&self) -> Vec<RefreshDiagnostic> {
        self.events
            .lock()
            .expect("AssertionSink events poisoned")
            .clone()
    }

    /// Number of events the sink has observed since construction.
    /// Equivalent to `recorded().len()` but avoids the clone.
    #[allow(dead_code)] // Phase 1 author: convenience inspector for count-only assertions.
    pub fn count(&self) -> usize {
        self.events
            .lock()
            .expect("AssertionSink events poisoned")
            .len()
    }

    /// Snapshot the recorded [`PendingTxDiagnostic`] stream (PR 5 C7).
    #[allow(dead_code)] // Phase 1 author: canonical C7 pending coherence-test inspector.
    pub fn recorded_pending(&self) -> Vec<PendingTxDiagnostic> {
        self.pending_events
            .lock()
            .expect("AssertionSink pending_events poisoned")
            .clone()
    }

    /// Number of pending-tx events observed since construction.
    #[allow(dead_code)] // Phase 1 author: convenience inspector for count-only assertions.
    pub fn count_pending(&self) -> usize {
        self.pending_events
            .lock()
            .expect("AssertionSink pending_events poisoned")
            .len()
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl DiagnosticSink for AssertionSink {
    fn emit(&self, event: RefreshDiagnostic) {
        self.events
            .lock()
            .expect("AssertionSink events poisoned")
            .push(event);
    }

    fn emit_pending_tx(&self, event: PendingTxDiagnostic) {
        self.pending_events
            .lock()
            .expect("AssertionSink pending_events poisoned")
            .push(event);
    }
}

/// Panic-on-emit [`DiagnosticSink`] for the §5.4.6
/// producer-panic-safety property test.
///
/// Configured to panic when the producer emits a specific class of
/// event (or every event, per the [`Trigger::Any`] variant). Drives
/// the producer-side robustness property: a panicking sink unwinds
/// through the producer's call frame; the producer's
/// [`shekyl_scanner::Scanner`] is zeroized on drop via the
/// [`zeroize::ZeroizeOnDrop`] chain on
/// [`crate::engine::view_material::ViewMaterial`]; no half-emitted scan
/// state or cancellation-token inconsistency remains observable
/// after the unwind.
///
/// # Producer-side robustness property (§5.4.6, binding)
///
/// Per §5.4.6: "any panic propagating out of `emit` results in a
/// predictable refresh-attempt failure with `Scanner` cleanly
/// zeroized via `Drop`, no leaked half-state, and the cancellation
/// token consistently in either fired-or-not state". The C7
/// [`local_refresh::tests::produce_scan_result_panicking_sink_unwind_safe`](crate::engine::local_refresh)
/// test consumes this sink to assert that property at the
/// orchestrator boundary:
///
/// - The producer's future resolves to a `JoinError::Panic` when
///   driven through `tokio::spawn`.
/// - The cancellation token remains unfired (the panic
///   short-circuits the producer before any
///   `cancel.cancel()` would fire; the token's external observer
///   sees a consistent unfired-state).
/// - A subsequent fresh refresh attempt against the same engine
///   succeeds (no corrupted engine state from the prior unwind).
///
/// # Scanner zeroization (structural property)
///
/// The [`shekyl_scanner::Scanner`] held inside the producer's stack
/// frame is dropped during unwind; its [`zeroize::ZeroizeOnDrop`]
/// chain (via [`crate::engine::view_material::ViewMaterial`]'s embedded
/// zeroize types) wipes the spend / view / KEM secret bytes. Direct
/// observation of the wipe requires either an instrumented
/// `Scanner` type or a memory-witness counter — both are V3.x
/// extensions per the §5.4.6 "Round 4 test deliverable" prose. C7
/// pins the structural property at the orchestrator boundary
/// (panic propagates cleanly; no half-state) and relies on the
/// `ZeroizeOnDrop` derive on `ViewMaterial` for the wipe property
/// the underlying scanner inherits.
///
/// # Permanent CI coverage pin (§5.4.6 / F3)
///
/// Parallel to [`AssertionSink`]: every PR touching any
/// [`crate::engine::traits::RefreshEngine`] implementation MUST keep the
/// panic-safety property test green. A test failure is a
/// producer-side robustness contract violation.
///
/// # Gating
///
/// `#[cfg(any(test, feature = "test-helpers"))] pub` per the C6α
/// F-Mock-1 symmetry pin.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Clone, Copy)]
pub struct PanickingSink {
    /// Which class of event triggers the panic. [`Trigger::Any`]
    /// panics on the first emission of any class.
    trigger: PanickingSinkTrigger,
}

/// Trigger discriminant for [`PanickingSink`]. Each variant names a
/// [`RefreshDiagnostic`] class; an emission whose class matches the
/// configured trigger fires the panic. [`Self::Any`] panics on the
/// first emission regardless of class — useful for testing the
/// general unwind-safety property without binding the test to a
/// specific producer code path.
///
/// # Why not just `Option<RefreshDiagnostic-discriminant>`?
///
/// [`RefreshDiagnostic`] carries non-`Copy` payload fields
/// (`Duration` is `Copy`, but the enum's full identity includes
/// payload values the trigger doesn't compare against). The
/// dedicated trigger enum keeps the configuration surface tag-only
/// and `Copy`, matching the [`PanickingSink`] derive shape.
#[cfg(any(test, feature = "test-helpers"))]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Variants are referenced by C7 panic-safety property tests (cfg(test)) and by downstream test-helpers consumers.
pub enum PanickingSinkTrigger {
    /// Panic on the first emission of any class. Drives the
    /// general producer-panic-safety property regardless of which
    /// code path inside the producer first emits.
    Any,
    /// Panic on first [`RefreshDiagnostic::DaemonMalformed`]
    /// emission. Pairs with a malformed-block-injecting test
    /// daemon to exercise the unwind-during-malformed-detection
    /// path.
    OnDaemonMalformed,
    /// Panic on first [`RefreshDiagnostic::DaemonProtocolError`]
    /// emission. Pairs with an `RpcError`-injecting test daemon to
    /// exercise the unwind-during-rpc-failure path.
    OnDaemonProtocolError,
    /// Panic on first [`RefreshDiagnostic::ScanProgress`] emission.
    /// Pairs with any successful scan to exercise the
    /// unwind-during-per-block-progress path (the most frequent
    /// emit site).
    OnScanProgress,
}

#[cfg(any(test, feature = "test-helpers"))]
impl PanickingSink {
    /// Construct a sink that panics on the first emission matching
    /// `trigger`.
    #[must_use]
    #[allow(dead_code)] // Phase 1 author: lands as the canonical C7 panic-safety-test constructor.
    pub const fn new(trigger: PanickingSinkTrigger) -> Self {
        Self { trigger }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
impl DiagnosticSink for PanickingSink {
    fn emit(&self, event: RefreshDiagnostic) {
        let fires = matches!(
            (self.trigger, &event),
            (PanickingSinkTrigger::Any, _)
                | (
                    PanickingSinkTrigger::OnDaemonMalformed,
                    RefreshDiagnostic::DaemonMalformed { .. },
                )
                | (
                    PanickingSinkTrigger::OnDaemonProtocolError,
                    RefreshDiagnostic::DaemonProtocolError { .. },
                )
                | (
                    PanickingSinkTrigger::OnScanProgress,
                    RefreshDiagnostic::ScanProgress { .. },
                )
        );
        if fires {
            panic!(
                "PanickingSink configured trigger {:?} fired on emission {:?}",
                self.trigger, event
            );
        }
    }

    fn emit_pending_tx(&self, event: PendingTxDiagnostic) {
        if self.trigger == PanickingSinkTrigger::Any {
            panic!(
                "PanickingSink configured trigger {:?} fired on pending-tx emission {:?}",
                self.trigger, event
            );
        }
    }
}
