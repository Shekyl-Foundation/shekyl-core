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

// Split by workflow per ENGINE_COMPOSITION_DECOMPOSITION.md §2 (the
// transfer/ carve precedent): same code, new ownership. Every item is
// re-exported here so historical `engine::diagnostics::X` import paths
// keep working unchanged.
mod pending_tx_events;
mod refresh_events;
mod sink;

pub(crate) use pending_tx_events::emit_pending_tx_diagnostic;
pub use pending_tx_events::{
    BuildErrorKind, BuildRequestSummary, DiscardReason, PendingTxDiagnostic, WatchdogAlarmReason,
    WatchdogProbeOutcome,
};
pub use refresh_events::{
    DaemonOp, MalformedKind, ProtocolErrorKind, RefreshDiagnostic, SuppressedClass,
};
// The items themselves are `cfg(any(test, feature = "test-helpers"))`,
// but this module is `pub(crate)`, so the only consumers that can reach
// them through this path are the crate's own `cfg(test)` suites — a
// feature-only build would flag the re-export as unused.
#[cfg(test)]
pub use sink::{AssertionSink, PanickingSink, PanickingSinkTrigger};
pub use sink::{DiagnosticSink, NoopDiagnosticSink, TracingDiagnosticSink};

// The unit suite globs `super::*`; the bucket projections it pins are
// private helpers of the sink workflow, surfaced to the suite alone.
#[cfg(test)]
pub(crate) use sink::{candidates_bucket, depth_bucket, elapsed_bucket};

#[cfg(test)]
#[path = "../diagnostics_tests.rs"]
mod tests;
