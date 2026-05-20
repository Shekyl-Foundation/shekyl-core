// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Producer-side diagnostic stream for
//! [`RefreshEngine`](super::traits::RefreshEngine).
//!
//! Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §5.4.6 +
//! §5.4.7 R6 (the two-channel reframe), the trait surface has two
//! load-bearing channels:
//!
//! 1. The terminal return: `Result<ScanResult, Self::Error>`. The
//!    `Error` side is **unit-variant-only** at the trait surface
//!    (Phase 0c per §4); orchestrator-side
//!    [`RefreshError`](super::RefreshError) carries the fielded
//!    discriminants.
//!
//! 2. The producer's per-event diagnostic stream, emitted to a
//!    [`DiagnosticSink`] passed by reference to
//!    [`produce_scan_result`](super::traits::RefreshEngine::produce_scan_result).
//!
//! # C1 scaffolding scope
//!
//! C1 lands only the names: [`DiagnosticSink`] (the trait) and
//! [`RefreshDiagnostic`] (the enum, currently variant-less under
//! `#[non_exhaustive]`). C2 populates the variants, the bounded
//! supporting enums (`MalformedKind`, `DaemonOp`,
//! `ProtocolErrorKind`, `SuppressedClass`), and the Stage 1 sink
//! implementations (`NoopDiagnosticSink`, `TracingDiagnosticSink`)
//! against the C4 producer body's actual emission sites. Splitting
//! across C1 / C2 preserves the Phase 1 bisection-discipline gate:
//! C1 introduces no behaviour change, only the trait surface
//! [`RefreshEngine`](super::traits::RefreshEngine) needs to
//! reference at compile time.
//!
//! # Trust boundary
//!
//! The diagnostic stream's trust boundary is **in-process only**
//! per §5.4.6 + §5.4.8 #4. The sink trait carries no serialization
//! surface; events do not cross a process boundary, and the
//! variants are restricted to bounded enums (no caller-attacker
//! payloads). The §5.4.8 #5 per-class emission budget (F6 + F13
//! sub-pin) lives in the C4 producer body, not on the sink
//! interface.
//!
//! [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md

/// Producer-side diagnostic event.
///
/// Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §5.4.6, the
/// producer ([`RefreshEngine`](super::traits::RefreshEngine)
/// implementor) emits events of this enum onto a
/// [`DiagnosticSink`] during the scan. The terminal return type
/// of [`produce_scan_result`](super::traits::RefreshEngine::produce_scan_result)
/// remains `Result<ScanResult, Self::Error>`; this enum carries the
/// per-event observability stream that augments — but does not
/// replace — the terminal result.
///
/// # `#[non_exhaustive]`
///
/// The enum is `#[non_exhaustive]` so the Round-4-audit-confirmed
/// variant set (`DaemonMalformed`, `DaemonTimeout`,
/// `DaemonProtocolError`, `ReorgObserved`, `ScanProgress`,
/// `SuppressedRateLimit`) lands additively in C2 without breaking
/// downstream `match` exhaustiveness assumptions. Stage 4 and V3.x
/// extensions land variants additively under the same discipline.
///
/// # C1 scaffolding
///
/// C1 lands the name with no variants; C2 populates the six
/// Round-4-audit-confirmed variants and the bounded supporting
/// enums against the C4 producer body's emission sites.
///
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum RefreshDiagnostic {}

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
///    sink do NOT — cross-emitter ordering is undefined. C2's
///    `TracingDiagnosticSink` documents this by class.
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
///    [`produce_scan_result`](super::traits::RefreshEngine::produce_scan_result)
///    call.
///
/// 7. **Drop is the cancel-checkpoint.** Sinks that hold
///    background resources (e.g., a tracing subscriber filter
///    handle) drop them in their own [`Drop`] impl; the trait
///    interface does not expose a separate shutdown call.
///
/// # `pub(crate)` visibility
///
/// Per `traits/mod.rs`'s Round-4a Item 13 disposition, trait
/// surfaces ship `pub(crate)` until the JSON-RPC server cutover at
/// V3.2 (per `wallet_rpc_server` follow-up in `docs/FOLLOWUPS.md`).
/// External consumers reach refresh diagnostics via the
/// orchestrator's inherent methods, not via direct trait dispatch.
/// Promoting to `pub` later is additive.
///
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
pub(crate) trait DiagnosticSink: Send + Sync + 'static {
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
    ///
    /// # C1 scaffolding
    ///
    /// C1 lands the method signature only; no implementor exists
    /// until C2. Producer-side calls land in C4 alongside the
    /// `LocalRefresh::produce_scan_result` body.
    #[allow(dead_code)] // C2 lands the first sink impl; C4 lands the first emit-site.
    fn emit(&self, event: RefreshDiagnostic);
}
