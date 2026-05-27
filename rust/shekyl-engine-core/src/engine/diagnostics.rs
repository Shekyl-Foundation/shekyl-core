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

use super::error::{AmbiguousErrorKind, TerminalErrorKind};
use super::pending::{FeePriority, ReservationId, SnapshotId, TxHash};

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

// ----------------------------------------------------------------------------
// PR 5 — `PendingTxEngine` diagnostic-stream surface
// ----------------------------------------------------------------------------
//
// The types below are PR 5's analog of `RefreshDiagnostic` + supporting
// projections. Per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0f, the
// PR 5 producer (`LocalPendingTx`) emits onto the same `DiagnosticSink`
// trait introduced in PR 4 — extended above with the
// [`emit_pending_tx`](DiagnosticSink::emit_pending_tx) default-method
// shape so PR 4's existing implementors continue to compile unmodified.
//
// C3 (this commit) lands the type substrate + emission-helper
// infrastructure. Production emission sites live in C5 per the
// emission/return coherence contract (§5.0.3): a method's emissions and
// its terminal return discriminant land together so the contract is
// expressible at a single review surface.

/// Build-side error projection for
/// [`PendingTxDiagnostic::BuildFailed`].
///
/// Distinguishes the broad build-failure classes a consumer needs to
/// react to (or surface to the user) without leaking
/// [`SendError`](super::error::SendError)'s `reason: &'static str`
/// payloads across the diagnostic-stream's recursive-trust-boundary
/// (PR 4 §5.4.8 #4). The projection taxonomy is intentionally coarser
/// than `SendError`'s; the orchestrator-side error carries the
/// fielded discriminants for callers that need them.
///
/// Per segment-2h's `BuildFailureClass`-renamed-to-`BuildErrorKind`
/// convention (matches [`TerminalErrorKind`] / [`AmbiguousErrorKind`]
/// from C2α), the enum lives in this module rather than in
/// `engine::error` because it is the diagnostic-side projection,
/// not the trait-return-side error. `#[non_exhaustive]` per the PR 4
/// /segment-2b extensibility discipline.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuildErrorKind {
    /// A [`TxRecipient`](super::pending::TxRecipient) failed
    /// recipient-side validation (zero amount, malformed address,
    /// etc.).
    InvalidRecipient,

    /// Wallet output coverage is insufficient for the requested
    /// transfer + fee; orchestrator-side
    /// [`SendError::InsufficientFunds`](super::error::SendError::InsufficientFunds)
    /// carries the fielded `needed` / `available` payload.
    InsufficientFunds,

    /// The configured `Signer` surface is unavailable (e.g., HW
    /// signer disconnected; cooperative-signing peer offline).
    /// V3.0 surface uses `LocalSigner` exclusively, so this
    /// variant is reserved for V3.x; lands as part of the
    /// projection enumeration to forestall an additive break.
    /// `Signer` trait lands in C4α.
    SignerUnavailable,

    /// `LedgerEngine` reports the snapshot is not yet ready for
    /// build (e.g., wallet has not yet completed its first scan).
    /// V3.0 has no caller-visible "engine not ready" variant on
    /// [`SendError`](super::error::SendError); this projection
    /// reserves the slot for C5α's classification of the cases
    /// where `build` early-rejects against an uninitialized
    /// `LedgerSnapshot`.
    LedgerNotReady,

    /// The configured `OutputSelector` returned a set whose
    /// indices were not a subset of the candidate set the engine
    /// supplied — the F4 caller-side subset re-verification
    /// rejected the result. Mirrors
    /// [`OutputSelectorError::ReturnedIndicesNotSubset`](super::error::OutputSelectorError::ReturnedIndicesNotSubset)
    /// in the projection taxonomy. Segment-2h C2β addition per
    /// §5.6.5 F4. `OutputSelector` trait lands in C4β.
    SelectorContractViolation,
}

/// Coarse-grained projection of a
/// [`TxRequest`](super::pending::TxRequest) for diagnostic emission.
///
/// Phase 0f recursive-trust-boundary projection per PR 4 §5.4.8 #4:
/// the diagnostic stream's trust boundary is in-process only, but
/// the projection still avoids exposing fingerprintable / linkable
/// material. Recipient addresses, amounts, and the from-subaddress
/// filter are not projected (correlation-attack surface for any
/// future intra-process consumer). The projection exposes:
///
/// - `recipient_count` — the number of distinct
///   [`TxRecipient`](super::pending::TxRecipient) entries in the
///   request.
/// - `priority` — the requested
///   [`FeePriority`](super::pending::FeePriority) tier (already
///   public-API by virtue of being on the caller-facing request).
///
/// Bounded numeric + bounded enum projections; no caller-attacker
/// `String` payloads (§5.4.7 R6 memory-amplifier closure carries
/// to PR 5 verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildRequestSummary {
    /// Number of recipients in the requested transfer.
    pub recipient_count: u32,

    /// Fee-priority tier from the request.
    pub priority: FeePriority,
}

/// Reason supplied to `PendingTxEngine::discard` (the trait lands
/// in C5α) and reported on [`PendingTxDiagnostic::Discarded`].
///
/// Per §5.6.4 segment-2h disposition and §5.6.12 segment-2i
/// disposition:
///
/// - `ConsumerExplicit` — the consumer called `discard` (deliberate
///   release of a `consumer_held` reservation).
/// - `DaemonRejectedTerminal { kind }` — the daemon round-trip
///   completed with a [`TerminalErrorKind`] result; the
///   reservation's outputs are released back to the pool. R9
///   disposition.
/// - `TTLAutoDiscard` — the reservation aged past its
///   [`ReservationTTLConfig`](super::pending::ReservationTTLConfig)
///   budget. R8 segment-2e variant; V3.x emitter is the
///   `ReservationTTLActor` (no V3.0 emitter — variant pre-pinned
///   so the V3.x consumer-actor PR lands additively).
/// - `MempoolEvicted` — the daemon's mempool observation surface
///   confirmed the in-flight tx has been evicted; segment-2i G1
///   addition. V3.0 has no in-process emitter (the V3.x
///   `MempoolMonitorActor` consumer-actor PR introduces the
///   emitter); pre-V3.x test fixtures exercise the call site
///   directly.
///
/// Segment-2h pinning **REMOVED**
/// `DiscardReason::SnapshotRotationAutoDiscard`. Snapshot
/// rotation does not drive automatic collection-moves at V3.0
/// per the lazy R5 preservation (§5.6.5 F5+F6 / §5.6.6 P9);
/// consumers learn at submit-time via
/// [`SubmitError::SnapshotInvalidated`](super::error::SubmitError::SnapshotInvalidated).
/// V3.x eager-discard opt-in (FOLLOWUPS §5.6.7 P9 trigger)
/// reintroduces the variant alongside the selective-discard
/// substrate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscardReason {
    /// Consumer called `discard` explicitly.
    ConsumerExplicit,

    /// Daemon round-trip completed with a terminal error; the
    /// reservation's outputs are released back to the pool.
    DaemonRejectedTerminal {
        /// Which terminal sub-class the daemon reported.
        kind: TerminalErrorKind,
    },

    /// The reservation aged past its
    /// [`ReservationTTLConfig`](super::pending::ReservationTTLConfig)
    /// budget (R8 segment-2e; V3.x `ReservationTTLActor`
    /// emitter; no V3.0 in-process emitter).
    TTLAutoDiscard,

    /// The daemon's mempool observation surface confirmed the
    /// in-flight tx has been evicted (segment-2i G1; V3.x
    /// `MempoolMonitorActor` emitter; no V3.0 in-process
    /// emitter).
    MempoolEvicted,
}

/// Producer-side diagnostic event for the `PendingTxEngine` trait
/// (the trait lands in C5α).
///
/// Parallel to PR 4's [`RefreshDiagnostic`]; the variant set is
/// pinned in §5.0.2 of `STAGE_1_PR_5_PENDING_TX_ENGINE.md` per
/// the segment-2h reshape (lazy R5 preservation + P4 collection-
/// moves table) and the segment-2i G1 amendments (mempool
/// eviction + `tx_hash` projection on success/pending variants).
///
/// # Per-variant emission sites (segment-2h §5.6.4 P4 table)
///
/// | Variant | Emission site |
/// |---|---|
/// | `BuildAttempted` | C5 `LocalPendingTx::build` entry, after request validation. |
/// | `BuildSucceeded` | C5 `LocalPendingTx::build` exit, after `Reservation` + `output_locks` inserted (P7-atomic). |
/// | `BuildFailed` | C5 `LocalPendingTx::build` error paths; mapped from [`SendError`](super::error::SendError) via [`BuildErrorKind`]. |
/// | `SubmitAttempted` | C5 `LocalPendingTx::submit` entry, after F2 ownership-boundary dispatch. |
/// | `SubmitSucceeded` | C5 `LocalPendingTx::submit` happy-path exit; paired with daemon-`Accepted` outcome. |
/// | `SubmitPendingResolution` | C5 `LocalPendingTx::submit` ambiguous-daemon-outcome exit; reservation stays in `in_flight` per F2 ownership-boundary. |
/// | `SubmitSnapshotInvalidated` | C5 `LocalPendingTx::submit` lazy-R5 staleness-check exit before daemon dispatch. |
/// | `Discarded` | C5 `LocalPendingTx::discard` exit; C5 daemon-terminal-error path; C5β `signal_mempool_evicted` (segment-2i G1). |
/// | `ReservationOutstanding` | V3.x `ReservationTTLActor` emitter only; no V3.0 in-process emitter (variant pre-pinned for the V3.x consumer-actor PR). |
///
/// **No `SubmitFailed` variant.** Segment-2h removed the variant —
/// terminal errors emit via `Discarded { reason:
/// DaemonRejectedTerminal { kind } }`; ambiguous errors emit via
/// `SubmitPendingResolution`. The lifecycle-class distinction is
/// load-bearing on the emission side, parallel to the
/// type-correctness motivation for splitting
/// [`SubmitErrorKind`](https://example.invalid) into
/// [`TerminalErrorKind`] + [`AmbiguousErrorKind`] on the
/// error-return side.
///
/// # Trust boundary
///
/// In-process only per PR 4 §5.4.6 + §5.4.8 #4; the
/// [`DiagnosticSink`] trait carries no serialization surface.
/// The `tx_hash: TxHash` projections on `SubmitSucceeded` and
/// `SubmitPendingResolution` are admissible at the recursive-
/// trust-boundary discipline (PR 4 §5.4.8 #4) because the hash
/// is on-chain by construction — not secret material.
///
/// # `#[non_exhaustive]`
///
/// Variant set additions ride along with consumer-actor PRs in
/// V3.x; the `#[non_exhaustive]` discipline forecloses additive
/// breakage at the `match` level (PR 4 / segment-2b pattern).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum PendingTxDiagnostic {
    /// `build` was invoked; emitted at handler entry after request
    /// validation. Carries a [`BuildRequestSummary`] projection
    /// rather than the raw `TxRequest`.
    BuildAttempted {
        /// Bounded projection of the request shape (no recipient
        /// addresses / amounts / from-subaddress filter).
        request_summary: BuildRequestSummary,
    },

    /// `build` succeeded; a fresh `Reservation` was registered.
    BuildSucceeded {
        /// The newly-allocated reservation's id.
        reservation_id: ReservationId,

        /// The ledger [`SnapshotId`] the reservation was built
        /// against (lazy R5 surface — staleness is detected at
        /// next `submit` / `discard` against the engine's
        /// current_snapshot).
        snapshot_id: SnapshotId,

        /// Number of outputs claimed by the new reservation
        /// (projection over `Reservation`'s output set).
        outputs_count: u32,
    },

    /// `build` failed; mapped from [`SendError`](super::error::SendError)
    /// via [`BuildErrorKind`].
    BuildFailed {
        /// Which build-failure class the engine surfaced.
        kind: BuildErrorKind,
    },

    /// `submit` was invoked on a reservation; emitted at handler
    /// entry after F2 ownership-boundary dispatch.
    SubmitAttempted {
        /// The reservation the consumer asked to submit.
        reservation_id: ReservationId,
    },

    /// Daemon accepted the submitted tx; reservation released
    /// from `in_flight` and `output_locks` swept.
    SubmitSucceeded {
        /// The reservation that succeeded.
        reservation_id: ReservationId,

        /// The accepted tx's hash. Segment-2i G1 projection —
        /// required by the V3.x `MempoolMonitorActor` consumer
        /// to correlate mempool observation results back to
        /// rids. On-chain by construction (admissible at the
        /// recursive-trust-boundary).
        tx_hash: TxHash,
    },

    /// Daemon round-trip completed with an
    /// [`AmbiguousErrorKind`] outcome; reservation stays in
    /// `in_flight` per F2 ownership-boundary. Consumer learns
    /// terminal resolution via `SubmitSucceeded` /
    /// `Discarded { DaemonRejectedTerminal }` /
    /// `Discarded { MempoolEvicted }` arriving later, or via R8
    /// TTL safety-net.
    SubmitPendingResolution {
        /// The reservation whose submit ended in an ambiguous
        /// state.
        reservation_id: ReservationId,

        /// The submitted tx's hash — segment-2i G1 projection;
        /// V3.x `MempoolMonitorActor` observes mempool-
        /// presence-disappears as one resolution path even when
        /// the daemon's eventual response is the other.
        tx_hash: TxHash,

        /// Which ambiguous sub-class the daemon round-trip
        /// surfaced.
        kind: AmbiguousErrorKind,
    },

    /// Lazy-R5 staleness check at `submit` entry: the
    /// reservation's `snapshot_id` did not match the engine's
    /// `current_snapshot`. Reservation does NOT auto-release;
    /// consumer must call `discard(rid, ConsumerExplicit)` to
    /// free `output_locks` (segment-2h F2 disposition).
    SubmitSnapshotInvalidated {
        /// The stale reservation.
        reservation_id: ReservationId,

        /// The reservation's recorded snapshot id (the one it
        /// was built against).
        reservation_snapshot: SnapshotId,

        /// The engine's current snapshot id (the rotated one
        /// the staleness check fired against).
        current_snapshot: SnapshotId,
    },

    /// A reservation was discarded (the `output_locks` for the
    /// rid were swept and the rid removed from its collection).
    /// The [`DiscardReason`] discriminant carries the cause.
    Discarded {
        /// The discarded reservation's id.
        reservation_id: ReservationId,

        /// Why the discard occurred.
        reason: DiscardReason,
    },

    /// A reservation has been outstanding past its
    /// [`ReservationTTLConfig`](super::pending::ReservationTTLConfig)
    /// budget. V3.x `ReservationTTLActor` emitter only; pre-
    /// pinned for the V3.x consumer-actor PR (no V3.0 in-
    /// process emitter).
    ReservationOutstanding {
        /// Which reservation has aged out.
        reservation_id: ReservationId,

        /// How long the reservation has been outstanding.
        age: Duration,
    },
}

/// Emit one [`PendingTxDiagnostic`] event onto the given sink.
///
/// Helper parallel to the inline `sink.emit(event)` pattern PR 4's
/// `LocalRefresh` body uses for [`RefreshDiagnostic`]; consolidating
/// the dispatch behind a free function makes the C5 emission-site
/// rewrites a search-and-call rather than a search-and-method-
/// rewrite (and forecloses sink-method-name drift between the
/// type and the dispatch).
///
/// C3 (this commit) lands the helper; C5 wires its call sites in
/// `LocalPendingTx`'s extracted method bodies per the emission/
/// return coherence contract pin (§5.0.3) — emission helpers land
/// in their own commit; emission sites land with the methods that
/// emit, so the coherence-property review surface is the method
/// body, not the helper definition.
///
/// `#[allow(dead_code)]`: the helper has no production caller until
/// C5α's `LocalPendingTx::build` skeleton lands the first emission
/// site. Same template as
/// [`derive_snapshot_id`](super::refresh::derive_snapshot_id) in C1
/// → C2γ (where the function was annotated with `dead_code` until
/// `build_pending_tx_in_state` consumed it; here the dead-code
/// annotation lifts at C5α). The annotation is itself a discipline
/// pin: a future maintainer who wants to remove the helper must
/// confirm no C5+ consumer exists first.
#[allow(dead_code)]
pub(crate) fn emit_pending_tx_diagnostic(sink: &dyn DiagnosticSink, event: PendingTxDiagnostic) {
    sink.emit_pending_tx(event);
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
    ///    `tx_hash: TxHash` field on `SubmitSucceeded` /
    ///    `SubmitPendingResolution` is admissible at this
    ///    boundary because the hash is on-chain by construction
    ///    (segment-2i G1 per PR 4 §5.4.8 #4 field-level
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
/// - For every non-[`super::error::RefreshError::Cancelled`]
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
/// [`local_refresh::tests::produce_scan_result_emission_return_coherence`](super::local_refresh)
/// property test that consumes it are **permanent CI regression
/// coverage** per §5.4.6. Every PR touching any [`super::traits::RefreshEngine`]
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
#[allow(dead_code)] // Constructed by C7 property tests (cfg(test)) and by downstream test-helpers consumers.
pub struct AssertionSink {
    /// Recording buffer; `Mutex` guards the append on `emit` and the
    /// drain on inspection. `RwLock` would not help — every access
    /// is a write to either the vector or a read of the captured
    /// snapshot, and the C7 tests do not race readers against the
    /// producer task.
    events: std::sync::Mutex<Vec<RefreshDiagnostic>>,
}

#[cfg(any(test, feature = "test-helpers"))]
impl AssertionSink {
    /// Construct a fresh recording sink with an empty buffer.
    #[must_use]
    #[allow(dead_code)] // Phase 1 author: lands as the canonical C7 coherence-test constructor.
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Snapshot the recorded events, cloning the inner buffer so
    /// the sink can continue receiving emissions while the
    /// inspection runs. The clone is bounded by the producer's
    /// per-attempt emission ceiling (§5.4.8 #5 +
    /// [`super::local_refresh::PER_BLOCK_CEILING`]) times the
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
}

#[cfg(any(test, feature = "test-helpers"))]
impl DiagnosticSink for AssertionSink {
    fn emit(&self, event: RefreshDiagnostic) {
        self.events
            .lock()
            .expect("AssertionSink events poisoned")
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
/// [`super::view_material::ViewMaterial`]; no half-emitted scan
/// state or cancellation-token inconsistency remains observable
/// after the unwind.
///
/// # Producer-side robustness property (§5.4.6, binding)
///
/// Per §5.4.6: "any panic propagating out of `emit` results in a
/// predictable refresh-attempt failure with `Scanner` cleanly
/// zeroized via `Drop`, no leaked half-state, and the cancellation
/// token consistently in either fired-or-not state". The C7
/// [`local_refresh::tests::produce_scan_result_panicking_sink_unwind_safe`](super::local_refresh)
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
/// chain (via [`super::view_material::ViewMaterial`]'s embedded
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
/// [`super::traits::RefreshEngine`] implementation MUST keep the
/// panic-safety property test green. A test failure is a
/// producer-side robustness contract violation.
///
/// # Gating
///
/// `#[cfg(any(test, feature = "test-helpers"))] pub` per the C6α
/// F-Mock-1 symmetry pin.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Constructed by C7 panic-safety property tests (cfg(test)) and by downstream test-helpers consumers.
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

    // ------------------------------------------------------------------------
    // C7 smoke tests — AssertionSink / PanickingSink
    // ------------------------------------------------------------------------
    //
    // These are construction-and-trigger smoke tests; the full
    // §5.4.6 emission/return coherence and producer-panic-safety
    // properties land as proptest-driven coverage in
    // `local_refresh.rs` and as the hybrid retry test in
    // `refresh.rs`. The smoke tests below verify the sinks' own
    // contract: AssertionSink records in FIFO order, PanickingSink
    // panics only on matched triggers.

    #[test]
    fn assertion_sink_records_events_in_emission_order() {
        let sink = AssertionSink::new();
        assert_eq!(sink.count(), 0);
        sink.emit(RefreshDiagnostic::DaemonProtocolError {
            kind: ProtocolErrorKind::ConnectionError,
        });
        sink.emit(RefreshDiagnostic::DaemonMalformed {
            kind: MalformedKind::InvalidBlockStructure,
        });
        sink.emit(RefreshDiagnostic::ScanProgress {
            height: 42,
            candidates: 3,
        });
        assert_eq!(sink.count(), 3);
        let recorded = sink.recorded();
        assert!(matches!(
            recorded[0],
            RefreshDiagnostic::DaemonProtocolError {
                kind: ProtocolErrorKind::ConnectionError
            }
        ));
        assert!(matches!(
            recorded[1],
            RefreshDiagnostic::DaemonMalformed {
                kind: MalformedKind::InvalidBlockStructure
            }
        ));
        assert!(matches!(
            recorded[2],
            RefreshDiagnostic::ScanProgress {
                height: 42,
                candidates: 3
            }
        ));
    }

    #[test]
    fn assertion_sink_recorded_clones_buffer_without_draining() {
        let sink = AssertionSink::new();
        sink.emit(RefreshDiagnostic::ScanProgress {
            height: 1,
            candidates: 0,
        });
        let snap1 = sink.recorded();
        let snap2 = sink.recorded();
        assert_eq!(snap1.len(), 1);
        assert_eq!(snap2.len(), 1);
        assert_eq!(sink.count(), 1);
    }

    #[test]
    fn panicking_sink_any_fires_on_first_emission() {
        let sink = PanickingSink::new(PanickingSinkTrigger::Any);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.emit(RefreshDiagnostic::ScanProgress {
                height: 1,
                candidates: 0,
            });
        }));
        assert!(result.is_err(), "Any trigger must panic on emit");
    }

    #[test]
    fn panicking_sink_on_daemon_malformed_only_fires_on_matched_class() {
        let sink = PanickingSink::new(PanickingSinkTrigger::OnDaemonMalformed);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.emit(RefreshDiagnostic::ScanProgress {
                height: 1,
                candidates: 0,
            });
            sink.emit(RefreshDiagnostic::DaemonProtocolError {
                kind: ProtocolErrorKind::ConnectionError,
            });
        }));
        assert!(
            result.is_ok(),
            "OnDaemonMalformed must NOT fire on ScanProgress or DaemonProtocolError"
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.emit(RefreshDiagnostic::DaemonMalformed {
                kind: MalformedKind::InvalidBlockStructure,
            });
        }));
        assert!(
            result.is_err(),
            "OnDaemonMalformed must fire on DaemonMalformed emit"
        );
    }

    #[test]
    fn panicking_sink_on_protocol_error_only_fires_on_matched_class() {
        let sink = PanickingSink::new(PanickingSinkTrigger::OnDaemonProtocolError);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.emit(RefreshDiagnostic::DaemonMalformed {
                kind: MalformedKind::InvalidBlockStructure,
            });
        }));
        assert!(
            result.is_ok(),
            "OnDaemonProtocolError must NOT fire on DaemonMalformed"
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.emit(RefreshDiagnostic::DaemonProtocolError {
                kind: ProtocolErrorKind::InternalError,
            });
        }));
        assert!(
            result.is_err(),
            "OnDaemonProtocolError must fire on DaemonProtocolError emit"
        );
    }

    #[test]
    fn panicking_sink_on_scan_progress_only_fires_on_matched_class() {
        let sink = PanickingSink::new(PanickingSinkTrigger::OnScanProgress);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.emit(RefreshDiagnostic::DaemonMalformed {
                kind: MalformedKind::InvalidBlockStructure,
            });
        }));
        assert!(
            result.is_ok(),
            "OnScanProgress must NOT fire on DaemonMalformed"
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.emit(RefreshDiagnostic::ScanProgress {
                height: 7,
                candidates: 0,
            });
        }));
        assert!(result.is_err(), "OnScanProgress must fire on ScanProgress");
    }
}
