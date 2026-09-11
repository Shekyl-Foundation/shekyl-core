// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `RefreshEngine` diagnostic events + shared producer-side vocabulary (PR 4).

use std::time::Duration;

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
    /// `shekyl_curve_generators::MAX_BULLETPROOF_COMMITMENTS`).
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
    /// consumers (e.g., [`TracingDiagnosticSink`](super::TracingDiagnosticSink)) distinguish
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
/// snapshot-tip read) and `FetchScannableBlock` (the
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

    /// `DaemonEngine::fetch_scannable_block` — used to fetch each
    /// block in the producer's scan range.
    FetchScannableBlock,
}

/// Bounded classification of typed RPC errors surfaced via
/// [`RefreshDiagnostic::DaemonProtocolError`].
///
/// Per the §5.4.7 R6 memory-amplifier closure (binding), the
/// producer MUST classify [`RpcError`](shekyl_rpc_client::RpcError)
/// variant tags into this bounded enum without propagating the
/// underlying `String` payload. The classification preserves the
/// audit-readable failure category; the dropped payload denies
/// adversarial daemons a memory-amplification channel into the
/// wallet's observability stream.
///
/// The five variants enumerate the [`RpcError`](shekyl_rpc_client::RpcError)
/// variants that surface at the producer's daemon-call boundary.
/// Additional variants land additively under the
/// `#[non_exhaustive]` discipline if `shekyl_rpc_client::RpcError` grows.
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
/// producer ([`RefreshEngine`](crate::engine::traits::RefreshEngine)
/// implementor) emits events of this enum onto a
/// [`DiagnosticSink`](super::DiagnosticSink) during the scan. The terminal return type
/// of [`produce_scan_result`](crate::engine::traits::RefreshEngine::produce_scan_result)
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
/// each variant routes through [`TracingDiagnosticSink`](super::TracingDiagnosticSink):
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
/// [`TracingDiagnosticSink`](super::TracingDiagnosticSink) is the canonical projector for the
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
    /// [`TracingDiagnosticSink`](super::TracingDiagnosticSink) per F9.
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
    /// [`RpcError`](shekyl_rpc_client::RpcError) `String` payload is NOT
    /// propagated.
    DaemonProtocolError {
        /// Bounded classification of the underlying RPC error
        /// variant tag.
        kind: ProtocolErrorKind,
    },

    /// Producer observed a chain reorganization vs. the
    /// orchestrator's snapshot. `fork_height` and `depth` are the
    /// producer's measurements; projected via bucketed `depth`
    /// only in [`TracingDiagnosticSink`](super::TracingDiagnosticSink) per F9 (chain-timing
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
