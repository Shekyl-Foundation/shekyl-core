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
//! # Variant set (Round 4 audit pin per §5.4.6)
//!
//! [`RefreshDiagnostic`] has six audit-confirmed variants:
//!
//! - [`RefreshDiagnostic::DaemonMalformed`] — daemon returned a
//!   block whose on-wire structure fails scanner validation.
//! - [`RefreshDiagnostic::DaemonTimeout`] — daemon RPC exceeded
//!   the producer's timeout budget at one of the named ops.
//! - [`RefreshDiagnostic::DaemonProtocolError`] — daemon returned
//!   a typed RPC error that classifies into one of the bounded
//!   [`ProtocolErrorKind`] tags.
//! - [`RefreshDiagnostic::ReorgObserved`] — producer observed a
//!   chain reorganization vs. the orchestrator's snapshot.
//! - [`RefreshDiagnostic::ScanProgress`] — per-block scan progress
//!   notification (producer-side rate-limited; see below).
//! - [`RefreshDiagnostic::SuppressedRateLimit`] — emission of a
//!   one-shot notice when the producer first drops an event for a
//!   class due to the per-block emission budget (F6 + F13 sub-pin).
//!
//! All supporting enums ([`MalformedKind`], [`DaemonOp`],
//! [`ProtocolErrorKind`], [`SuppressedClass`]) are
//! `#[non_exhaustive]` so the Round-4-audit-confirmed sets extend
//! additively. Stage 4 / V3.x extensions land variants under the
//! same discipline.
//!
//! # Trust boundary
//!
//! The diagnostic stream's trust boundary is **in-process only**
//! per §5.4.6 + §5.4.8 #4. The sink trait carries no serialization
//! surface; events do not cross a process boundary, and the
//! variants are restricted to bounded enums + bounded numeric
//! values (no caller-attacker `String` payloads — the §5.4.7 R6
//! memory-amplifier closure is binding).
//!
//! # Producer-side per-class emission budget (§5.4.8 #5)
//!
//! The §5.4.8 #5 per-class emission budget (F6 + F13 sub-pin) is
//! enforced **producer-side** in C4's
//! `LocalRefresh::emit_state`, not on the sink interface. Sinks
//! see only the events that survive the producer-side per-block
//! ceiling. The first time the producer drops an event for a
//! class within an attempt, it emits one
//! [`RefreshDiagnostic::SuppressedRateLimit`] with the affected
//! [`SuppressedClass`] and latches `notice_emitted` for the
//! remainder of the attempt; subsequent in-class drops happen
//! silently (the latch closes the emission-cadence covert
//! channel).
//!
//! [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md

use std::time::Duration;

use tracing::{event, Level};

/// Classification of a producer-side malformed-block detection.
///
/// Maps to scanner-rejection causes today
/// ([`ScanError`](shekyl_scanner::ScanError)); per the
/// `#[non_exhaustive]` discipline, additional kinds may be added
/// additively as the producer's detection sites grow at Stage 4 /
/// V3.x without breaking downstream `match` exhaustiveness
/// assumptions.
///
/// The variant set was enumerated in C2 against the existing
/// `engine/refresh.rs::produce_scan_result` body (the same body
/// C4 lifts into `LocalRefresh`). Each variant corresponds to a
/// scanner-error-class detected at the producer's per-block scan
/// site.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MalformedKind {
    /// The fetched block carries an unsupported protocol version.
    /// Corresponds to
    /// [`ScanError::UnsupportedProtocol`](shekyl_scanner::ScanError::UnsupportedProtocol).
    UnsupportedProtocolVersion,

    /// The fetched block's internal structure (outputs / proofs /
    /// commitments / ...) failed scanner-side structural
    /// validation. Corresponds to
    /// [`ScanError::InvalidScannableBlock`](shekyl_scanner::ScanError::InvalidScannableBlock).
    InvalidBlockStructure,

    /// The fetched block contains a transaction whose output count
    /// exceeds [`shekyl_scanner::MAX_OUTPUTS`] (the FCMP++
    /// Bulletproofs+ CRS bound; canonically anchored at
    /// `shekyl_generators::MAX_BULLETPROOF_COMMITMENTS`).
    ///
    /// # Producer-side detection (PR 4 C4 emission site)
    ///
    /// The producer runs a per-tx pre-pass over each fetched
    /// block's transactions BEFORE invoking the scanner; any
    /// transaction whose `prefix.outputs.len() > MAX_OUTPUTS`
    /// triggers one [`RefreshDiagnostic::DaemonMalformed`] event
    /// carrying this variant. The pre-pass is the engine-side
    /// diagnostic emission discipline; the scanner additionally
    /// enforces the bound as a defense-in-depth gate inside
    /// `InternalScanner::scan_transaction_with_cancel` (skip-and-log
    /// shape; consensus validation would also reject the
    /// transaction).
    ///
    /// # Why a dedicated variant (vs. `InvalidBlockStructure`)
    ///
    /// `InvalidBlockStructure` is the catch-all for scanner-side
    /// structural rejection driven by `ScanError::InvalidScannableBlock`.
    /// The excessive-outputs case is detected by the producer's
    /// pre-pass — *before* the scanner is invoked — so it never
    /// surfaces as a `ScanError` and would otherwise be invisible
    /// at the diagnostic layer. The dedicated variant lets
    /// consumers (e.g., [`TracingDiagnosticSink`]) distinguish
    /// "the daemon delivered a structurally-invalid block at the
    /// per-block level" from "the daemon delivered a transaction
    /// with an excessive output count" — the two signal different
    /// adversarial hypotheses (block-level malformation vs.
    /// per-tx attempted scan-budget inflation per PR 4 §3.1 /
    /// F11-S substrate).
    ///
    /// # Spec reference
    ///
    /// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §3.1
    /// (sub-block lock-latency property under adversarial daemon
    /// block crafting); §5.4.9 F11-S (per-output safe-point
    /// escalation criterion); §7.X C4 (the
    /// `LocalRefresh::produce_scan_result` per-tx pre-pass emission
    /// site).
    ///
    /// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
    ExcessiveOutputs,
}

/// Bounded enumeration of the producer's daemon-RPC operations
/// that are timeout-classified per
/// [`RefreshDiagnostic::DaemonTimeout`].
///
/// Two ops are timing-classified at C2: `GetHeight` (the
/// snapshot-tip read) and `GetScannableBlockByNumber` (the
/// per-block fetch inside the producer's scan loop). Other RPC
/// calls fire and forget without timing classification at the
/// diagnostic boundary; the producer's internal timeout budget
/// remains the load-bearing classifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonOp {
    /// `Rpc::get_height` — used to capture the daemon tip at the
    /// start of each attempt.
    GetHeight,

    /// `Rpc::get_scannable_block_by_number` — used to fetch each
    /// block in the producer's scan range.
    GetScannableBlockByNumber,
}

/// Bounded classification of typed RPC errors surfaced via
/// [`RefreshDiagnostic::DaemonProtocolError`].
///
/// Per the §5.4.7 R6 memory-amplifier closure (binding), the
/// producer MUST classify [`RpcError`](shekyl_rpc::RpcError)
/// variant tags into this bounded enum without propagating the
/// underlying `String` payload. The classification preserves the
/// audit-readable failure category; the dropped payload denies
/// adversarial daemons a memory-amplification channel into the
/// wallet's observability stream.
///
/// The five variants enumerate the [`RpcError`](shekyl_rpc::RpcError)
/// variants that surface at the producer's daemon-call boundary.
/// Additional variants land additively under the
/// `#[non_exhaustive]` discipline if `shekyl_rpc::RpcError` grows.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolErrorKind {
    /// Transport-level connection failure (e.g., dropped TCP,
    /// TLS handshake failure, DNS resolution failure).
    ConnectionError,

    /// Daemon-internal error surfaced through the RPC envelope
    /// (e.g., daemon-side panic, daemon-side resource exhaustion).
    InternalError,

    /// Daemon returned a response that fails RPC-envelope
    /// validation (malformed JSON, missing required field,
    /// type mismatch at the RPC layer rather than the block
    /// layer).
    InvalidNode,

    /// Daemon rejected a transaction submission. (Future use:
    /// surfaces at the send-tx path once `PendingTxEngine`
    /// extraction lands; included in C2 for forward-template
    /// completeness per §5.4.6 audit-confirmed set.)
    InvalidTransaction,

    /// Daemon-reported pruned-block condition: the requested
    /// block has been pruned from the daemon's database and
    /// cannot be served.
    PrunedTransaction,
}

/// Bounded enumeration of the [`RefreshDiagnostic`] classes that
/// the producer's per-block emission budget (§5.4.8 #5) may
/// suppress.
///
/// Per the F6 + F13 sub-pin, the producer maintains per-class
/// `(u32 counter, bool notice_emitted)` state per attempt; on
/// first-suppression-per-class-per-attempt it emits one
/// [`RefreshDiagnostic::SuppressedRateLimit`] carrying the
/// affected class and latches `notice_emitted = true` for the
/// remainder of the attempt. The
/// [`RefreshDiagnostic::SuppressedRateLimit`] variant itself is
/// **not** rate-limited (it never appears in this enum):
/// rate-limiting the suppression notice would defeat its purpose.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuppressedClass {
    /// [`RefreshDiagnostic::DaemonMalformed`] events suppressed
    /// after the per-block ceiling was hit for this class.
    DaemonMalformed,

    /// [`RefreshDiagnostic::DaemonTimeout`] events suppressed.
    DaemonTimeout,

    /// [`RefreshDiagnostic::DaemonProtocolError`] events
    /// suppressed.
    DaemonProtocolError,

    /// [`RefreshDiagnostic::ReorgObserved`] events suppressed.
    ReorgObserved,

    /// [`RefreshDiagnostic::ScanProgress`] events suppressed.
    ScanProgress,
}

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
/// variant set extends additively as the producer surfaces new
/// detection sites at Stage 4 / V3.x. Downstream `match`
/// exhaustiveness assumptions hold for the present six variants;
/// new variants land with default-arm coverage at consumer sites.
///
/// # Variant projection-type contract (F9, binding)
///
/// Per §5.4.9 F9, the canonical observability projection for
/// each variant routes through [`TracingDiagnosticSink`]:
///
/// - [`DaemonMalformed`](Self::DaemonMalformed) — log
///   [`MalformedKind`] variant tag only.
/// - [`DaemonTimeout`](Self::DaemonTimeout) — log [`DaemonOp`]
///   tag + bucketed elapsed (`<100ms` / `100ms-1s` / `>1s`); raw
///   [`Duration`] is NOT projected (timing-correlation closure).
/// - [`DaemonProtocolError`](Self::DaemonProtocolError) — log
///   [`ProtocolErrorKind`] variant tag only.
/// - [`ReorgObserved`](Self::ReorgObserved) — log bucketed
///   `depth` (`1` / `2-10` / `>10`); `fork_height` is NOT
///   projected (chain-timing correlation closure).
/// - [`ScanProgress`](Self::ScanProgress) — log bucketed
///   `candidates` (`none` / `few` / `many`); `height` is NOT
///   projected (wallet-activity correlation closure). Producer-side
///   rate-limited per §5.4.8 #5.
/// - [`SuppressedRateLimit`](Self::SuppressedRateLimit) — log
///   [`SuppressedClass`] variant tag only.
///
/// The variant carries the unprojected fields for in-process
/// consumers that want richer detail (e.g., a future
/// aggregator/republisher consumer per F5 V3.x); the
/// [`TracingDiagnosticSink`] is the canonical projector for the
/// V3.0 surface.
///
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum RefreshDiagnostic {
    /// Daemon returned a structurally-malformed block at the
    /// scanner-validation boundary. Classified by
    /// [`MalformedKind`] for bounded reporting.
    DaemonMalformed {
        /// Which malformation class the producer detected.
        kind: MalformedKind,
    },

    /// Daemon RPC exceeded the producer's timeout budget at the
    /// named [`DaemonOp`]. `elapsed` is the producer's measured
    /// wall-clock duration; projected via bucketed labels in
    /// [`TracingDiagnosticSink`] per F9.
    DaemonTimeout {
        /// The RPC operation that timed out.
        op: DaemonOp,

        /// The producer-measured elapsed time before the timeout
        /// fired. Not projected raw — see the F9 contract on
        /// [`RefreshDiagnostic`].
        elapsed: Duration,
    },

    /// Daemon returned a typed RPC error classified into a
    /// bounded [`ProtocolErrorKind`]. Per the §5.4.7 R6
    /// memory-amplifier closure, the underlying
    /// [`RpcError`](shekyl_rpc::RpcError) `String` payload is NOT
    /// propagated.
    DaemonProtocolError {
        /// Bounded classification of the underlying RPC error
        /// variant tag.
        kind: ProtocolErrorKind,
    },

    /// Producer observed a chain reorganization vs. the
    /// orchestrator's snapshot. `fork_height` and `depth` are the
    /// producer's measurements; projected via bucketed `depth`
    /// only in [`TracingDiagnosticSink`] per F9 (chain-timing
    /// correlation closure on `fork_height`).
    ReorgObserved {
        /// Block height where the fork was detected (relative to
        /// the snapshot tip). Not projected — see the F9 contract.
        fork_height: u64,

        /// Reorganization depth in blocks. Projected as a
        /// bucketed label.
        depth: u32,
    },

    /// Per-block scan-progress notification. Producer-side
    /// rate-limited per §5.4.8 #5 (F6 + F13 sub-pin); see the
    /// crate-level rustdoc for the per-class emission budget
    /// discipline.
    ScanProgress {
        /// Current scan height. Not projected — see the F9
        /// contract (wallet-activity correlation closure).
        height: u64,

        /// Number of matched outputs observed at this height.
        /// Projected as a bucketed label.
        candidates: usize,
    },

    /// First-suppression notice for a class within an attempt.
    /// Per the F6 + F13 sub-pin, emitted exactly once per class
    /// per attempt when the producer's per-block emission ceiling
    /// is hit and the `notice_emitted` latch is still `false`.
    /// Subsequent in-class suppressions happen silently to close
    /// the emission-cadence covert channel.
    SuppressedRateLimit {
        /// The class whose events are being suppressed.
        class: SuppressedClass,
    },
}

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
///    [`produce_scan_result`](super::traits::RefreshEngine::produce_scan_result)
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
/// [`RefreshEngine`](super::traits::RefreshEngine) trait
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
const fn elapsed_bucket(d: Duration) -> &'static str {
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
const fn depth_bucket(d: u32) -> &'static str {
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
const fn candidates_bucket(c: usize) -> &'static str {
    match c {
        0 => "none",
        1..=9 => "few",
        _ => "many",
    }
}

#[cfg(test)]
mod tests {
    //! Sink-construction and projection-stability smoke tests.
    //!
    //! Behavioral coverage (`AssertionSink` / `PanickingSink`
    //! property tests; emission/return coherence pin) lands in
    //! C7 against the C4 producer body. C2's tests only verify
    //! that the bucket projections are stable at the variant
    //! boundaries that F9 names — the contract pins (§5.4.8 #5
    //! per-class emission budget; §5.4.6 emission/return
    //! coherence) are exercised end-to-end in C7.

    use super::*;

    #[test]
    fn elapsed_bucket_thresholds_match_f9_contract() {
        assert_eq!(elapsed_bucket(Duration::from_millis(0)), "<100ms");
        assert_eq!(elapsed_bucket(Duration::from_millis(99)), "<100ms");
        assert_eq!(elapsed_bucket(Duration::from_millis(100)), "100ms-1s");
        assert_eq!(elapsed_bucket(Duration::from_millis(999)), "100ms-1s");
        assert_eq!(elapsed_bucket(Duration::from_secs(1)), ">1s");
        assert_eq!(elapsed_bucket(Duration::from_secs(60)), ">1s");
    }

    #[test]
    fn depth_bucket_thresholds_match_f9_contract() {
        assert_eq!(depth_bucket(0), "1");
        assert_eq!(depth_bucket(1), "1");
        assert_eq!(depth_bucket(2), "2-10");
        assert_eq!(depth_bucket(10), "2-10");
        assert_eq!(depth_bucket(11), ">10");
        assert_eq!(depth_bucket(u32::MAX), ">10");
    }

    #[test]
    fn candidates_bucket_thresholds_match_f9_contract() {
        assert_eq!(candidates_bucket(0), "none");
        assert_eq!(candidates_bucket(1), "few");
        assert_eq!(candidates_bucket(9), "few");
        assert_eq!(candidates_bucket(10), "many");
        assert_eq!(candidates_bucket(usize::MAX), "many");
    }

    #[test]
    fn noop_sink_swallows_every_audited_variant() {
        let sink = NoopDiagnosticSink::new();
        sink.emit(RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure,
        });
        sink.emit(RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::ExcessiveOutputs,
        });
        sink.emit(RefreshDiagnostic::DaemonTimeout {
            op: DaemonOp::GetHeight,
            elapsed: Duration::from_millis(250),
        });
        sink.emit(RefreshDiagnostic::DaemonProtocolError {
            kind: ProtocolErrorKind::ConnectionError,
        });
        sink.emit(RefreshDiagnostic::ReorgObserved {
            fork_height: 12345,
            depth: 3,
        });
        sink.emit(RefreshDiagnostic::ScanProgress {
            height: 99999,
            candidates: 0,
        });
        sink.emit(RefreshDiagnostic::SuppressedRateLimit {
            class: SuppressedClass::ScanProgress,
        });
    }

    #[test]
    fn tracing_sink_does_not_panic_on_any_audited_variant() {
        // The tracing-subscriber installation is global and
        // managed by upstream test harnesses; this test just
        // confirms each match arm completes without panicking
        // when invoked with a representative payload from each
        // variant. F9 projection-stability is verified by the
        // bucket-threshold tests above.
        let sink = TracingDiagnosticSink::new();
        sink.emit(RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::UnsupportedProtocolVersion,
        });
        sink.emit(RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::ExcessiveOutputs,
        });
        sink.emit(RefreshDiagnostic::DaemonTimeout {
            op: DaemonOp::GetScannableBlockByNumber,
            elapsed: Duration::from_millis(1500),
        });
        sink.emit(RefreshDiagnostic::DaemonProtocolError {
            kind: ProtocolErrorKind::InternalError,
        });
        sink.emit(RefreshDiagnostic::ReorgObserved {
            fork_height: 1,
            depth: 11,
        });
        sink.emit(RefreshDiagnostic::ScanProgress {
            height: 0,
            candidates: 50,
        });
        sink.emit(RefreshDiagnostic::SuppressedRateLimit {
            class: SuppressedClass::DaemonProtocolError,
        });
    }
}
