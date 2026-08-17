// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PendingTxEngine` diagnostic events + emission helper (PR 5).

use std::time::Duration;

use crate::engine::error::{AmbiguousErrorKind, RetryableRejectCause, TerminalErrorKind};
use crate::engine::pending::{FeePriority, ReservationId, SnapshotId, TxHash};

use super::DiagnosticSink;

// ----------------------------------------------------------------------------
// PR 5 — `PendingTxEngine` diagnostic-stream surface
// ----------------------------------------------------------------------------
//
// The types below are PR 5's analog of `RefreshDiagnostic` + supporting
// projections. Per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0f, the
// PR 5 producer (`LocalPendingTx`) emits onto the same `DiagnosticSink`
// trait introduced in PR 4 (now `diagnostics/sink.rs`) — extended with the
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
/// [`SendError`](crate::engine::error::SendError)'s `reason: &'static str`
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
    /// Recipient failed validation (zero amount, malformed address).
    InvalidRecipient,

    /// Snapshot failed well-formedness, or Custom is out of band.
    FeeRefused,

    /// Output coverage cannot meet amount + fee.
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
    /// [`SendError`](crate::engine::error::SendError); this projection
    /// reserves the slot for C5α's classification of the cases
    /// where `build` early-rejects against an uninitialized
    /// `LedgerSnapshot`.
    LedgerNotReady,

    /// Daemon-side I/O during build (fee estimation, spend-status
    /// RPC, etc.). Mirrors [`SendError::Io`](crate::engine::error::SendError::Io).
    DaemonUnavailable,

    /// The configured `OutputSelector` returned a set whose
    /// indices were not a subset of the candidate set the engine
    /// supplied — the F4 caller-side subset re-verification
    /// rejected the result. Mirrors
    /// [`OutputSelectorError::ReturnedIndicesNotSubset`](crate::engine::error::OutputSelectorError::ReturnedIndicesNotSubset)
    /// in the projection taxonomy. Segment-2h C2β addition per
    /// §5.6.5 F4. `OutputSelector` trait lands in C4β.
    SelectorContractViolation,

    /// The wallet has the balance but the FCMP++ curve tree is still
    /// rebuilding membership data behind the synced ledger tip, so a
    /// membership proof cannot yet be built for the shortfall outputs.
    /// Mirrors
    /// [`SendError::SpendUnavailableRebuilding`](crate::engine::error::SendError::SpendUnavailableRebuilding).
    /// CT-5 §3.2.1 D3 (adopting-wallet / tree-rebuild surfacing).
    RebuildingMembershipData,

    /// The wallet has the balance and the curve tree covers it, but one or more
    /// outputs needed for the spend are **too fresh for the reference block** —
    /// `eligible_height > tip − REF_ANCHOR_AGE`, so they are not in the tree as
    /// of the reference block the proof anchors to (C2; 2A §3.7.5, CT-5 §3.2).
    /// Mirrors
    /// [`SendError::OutputNotYetSpendable`](crate::engine::error::SendError::OutputNotYetSpendable);
    /// distinct from [`Self::RebuildingMembershipData`] (tree backfill lag) — a
    /// clean wait-N-blocks signal, self-resolving as the tip advances.
    OutputNotYetSpendable,

    /// The build was refused because the F28/F37 rebuild-loop circuit
    /// breaker is tripped (`DAEMON_SUBMIT_VERDICT.md` §2.5). Mirrors
    /// [`SendError::SubmitLoopBreakerTripped`](crate::engine::error::SendError::SubmitLoopBreakerTripped);
    /// the trip itself was alarmed via
    /// [`PendingTxDiagnostic::SubmitLoopBreakerTripped`].
    SubmitLoopBreakerTripped,
}

/// Coarse-grained projection of a
/// [`TxRequest`](crate::engine::pending::TxRequest) for diagnostic emission.
///
/// Phase 0f recursive-trust-boundary projection per PR 4 §5.4.8 #4:
/// the diagnostic stream's trust boundary is in-process only, but
/// the projection still avoids exposing fingerprintable / linkable
/// material. Recipient addresses and amounts are not projected
/// (correlation-attack surface for any
/// future intra-process consumer). The projection exposes:
///
/// - `recipient_count` — the number of distinct
///   [`TxRecipient`](crate::engine::pending::TxRecipient) entries in the
///   request.
/// - `priority` — the requested
///   [`FeePriority`](crate::engine::pending::FeePriority) tier (already
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
///   [`ReservationTTLConfig`](crate::engine::pending::ReservationTTLConfig)
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
/// [`SubmitError::SnapshotInvalidated`](crate::engine::error::SubmitError::SnapshotInvalidated).
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
    /// [`ReservationTTLConfig`](crate::engine::pending::ReservationTTLConfig)
    /// budget (R8 segment-2e; V3.x `ReservationTTLActor`
    /// emitter; no V3.0 in-process emitter).
    TTLAutoDiscard,

    /// The daemon's mempool observation surface confirmed the
    /// in-flight tx has been evicted (segment-2i G1; V3.x
    /// `MempoolMonitorActor` emitter; no V3.0 in-process
    /// emitter).
    MempoolEvicted,
}

/// Why the §5.3 submit watchdog raised an operator alarm
/// (`DAEMON_SUBMIT_VERDICT.md` §5.3, rung 2), carried on
/// [`PendingTxDiagnostic::WatchdogAlarm`].
///
/// The alarm rung is the "a human decides" escalation: the wallet has
/// exhausted the automatic remedies (wait, resubmit-same-bytes probe)
/// without a definite terminal verdict, so the driver surfaces the
/// condition to the operator rather than escalating to an automatic
/// rebuild (§7.1: a rebuild is never automatic on timeout). Bounded
/// enum, no `String` payload (PR 4 §5.4.7 R6 memory-amplifier closure
/// carries to the watchdog stream verbatim).
///
/// The first four variants project the kernel's decision surface
/// ([`AlarmReason`](crate::engine::submit_watchdog::AlarmReason) plus the two
/// driver-level conditions the kernel cannot represent). The
/// `#[non_exhaustive]` discipline lets the F40 re-scan executor add its
/// own alarm reasons additively.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchdogAlarmReason {
    /// The probe found the tx present-but-unconfirmed past the escape
    /// horizon: repeating the resubmit is pointless (F31), and the
    /// censoring / eclipse case (§7.5) lands exactly here. Projects
    /// [`AlarmReason::PresentButUnconfirmedPastHorizon`](crate::engine::submit_watchdog::AlarmReason::PresentButUnconfirmedPastHorizon).
    PresentButUnconfirmedPastHorizon,

    /// Past horizon and the daemon reports no peers: relay is
    /// impossible and no wallet action can fix it. Projects
    /// [`AlarmReason::DaemonPeerless`](crate::engine::submit_watchdog::AlarmReason::DaemonPeerless).
    DaemonPeerless,

    /// The kernel called for the rung-1 resubmit-same-bytes probe, but
    /// the retained bytes are gone — a wallet restart crossed the await
    /// (`DAEMON_SUBMIT_VERDICT.md` §5.3 decision 2, ephemeral held-bytes
    /// store). The probe rung degrades to the operator-alarm rung,
    /// preserving §2.6's "every exit is verdict, confirmation, or
    /// operator alarm."
    ProbeBytesUnavailable,

    /// The probe was rejected with a **retryable** cause
    /// ([`RetryableRejectCause`]: stale root / reference too recent /
    /// reference not found). The bytes are neither admitted nor
    /// terminally dead: recovery needs a fresh reference, which is a
    /// human-authorized rebuild (§7.1), not an automatic one. The
    /// driver alarms directly (the kernel's [`ProbeOutcome`](crate::engine::submit_watchdog::ProbeOutcome)
    /// has no retryable arm by construction).
    ReferenceStaleNeedsRebuild,
}

/// The observed outcome of a §5.3 watchdog resubmit-same-bytes probe,
/// carried on [`PendingTxDiagnostic::WatchdogProbeResolved`] for
/// observability.
///
/// Projects the daemon's [`TxSubmitOutcome`](crate::engine::traits::TxSubmitOutcome)
/// onto the presence facts the ladder branches on, plus the
/// transport-ambiguous case (a failed round-trip is not a verdict; the
/// driver keeps waiting and retries next tick). Bounded enum tags only;
/// `#[non_exhaustive]` for additive growth.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchdogProbeOutcome {
    /// `Submitted`: the tx was absent and the resubmission re-offered it
    /// through full admission and fresh relay. The wait restarts.
    ReofferedAfterAbsence,

    /// `AlreadyInPool`: present-but-unconfirmed. No relay pulse (F31);
    /// the alarm rung follows.
    PresentInPool,

    /// `AlreadyInChain`: confirmation observed by verdict. Refresh
    /// remains the settlement authority; the wait epoch restarts.
    ConfirmedInChain,

    /// `Rejected{terminal}`: a definite terminal verdict — under
    /// single-egress this proves the bytes are in neither pool nor
    /// chain (§7.1), so the confirmed-absent release fires.
    RejectedTerminal,

    /// `Rejected{retryable}`: reference stale — the driver raises the
    /// [`WatchdogAlarmReason::ReferenceStaleNeedsRebuild`] alarm.
    RejectedRetryable,

    /// The daemon round-trip failed (timeout / connection drop). Not a
    /// verdict: no overlay transition, retry on the next tick.
    TransportAmbiguous,
}

/// Producer-side diagnostic event for the `PendingTxEngine` trait
/// (the trait lands in C5α).
///
/// Parallel to PR 4's [`RefreshDiagnostic`](super::RefreshDiagnostic); the variant set is
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
/// | `BuildFailed` | C5 `LocalPendingTx::build` error paths; mapped from [`SendError`](crate::engine::error::SendError) via [`BuildErrorKind`]. |
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
/// [`SubmitError`](crate::engine::error::SubmitError) into
/// [`TerminalErrorKind`] + [`AmbiguousErrorKind`] on the
/// error-return side.
///
/// # Trust boundary
///
/// In-process only per PR 4 §5.4.6 + §5.4.8 #4; the
/// [`DiagnosticSink`] trait carries no serialization surface.
/// The `tx_hash` projections on `SubmitSucceeded` and
/// `SubmitPendingResolution` are admissible at the recursive-
/// trust-boundary discipline (PR 4 §5.4.8 #4) because a hash that
/// is present was computed from a real transaction — not secret
/// material. (`SubmitPendingResolution` carries an `Option`
/// precisely so "on-chain by construction" stays true of every
/// value that IS emitted.)
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
        /// addresses / amounts).
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

    /// `build` failed; mapped from [`SendError`](crate::engine::error::SendError)
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

        /// The submitted tx's hash, when the engine still holds the
        /// bytes to compute it — segment-2i G1 projection; V3.x
        /// `MempoolMonitorActor` observes mempool-presence-disappears
        /// as one resolution path even when the daemon's eventual
        /// response is the other.
        ///
        /// `None` when the reservation is no longer in flight, so
        /// there is nothing to hash. Optional rather than synthesized:
        /// a manufactured value here is a *plausible, nonexistent*
        /// txid, and the monitor above would read "never in the
        /// mempool" as "disappeared from it" — a confident wrong
        /// verdict, where `None` is a correct absent one. Correlate
        /// through `reservation_id`, which is always present.
        tx_hash: Option<TxHash>,

        /// Which ambiguous sub-class the daemon round-trip
        /// surfaced.
        kind: AmbiguousErrorKind,
    },

    /// Daemon round-trip completed with a definite §2.5 retryable
    /// rejection (`DAEMON_SUBMIT_VERDICT.md`): the reservation was
    /// returned to `consumer_held` with its re-anchor substrate and
    /// `output_locks` intact. The consumer resubmits via
    /// `submit(rid, seen_gen)` after the per-cause wait (`StaleRoot`:
    /// reprove against a fresh root; `ReferenceTooRecent`: timed
    /// backoff; `ReferenceNotFound`: sync-gated).
    SubmitRetryablyRejected {
        /// The reservation returned to `consumer_held`.
        reservation_id: ReservationId,

        /// Which retryable cause the daemon named.
        cause: RetryableRejectCause,
    },

    /// An `AlreadyInChain` verdict claimed a confirming height at or
    /// below the wallet's synced height (F40, `DAEMON_SUBMIT_VERDICT.md`
    /// §2.5 case *b*): refresh already passed that height without
    /// observing the spend, so the ordinary path-1 release is
    /// unreachable by construction. The consumer of this diagnostic
    /// (the 2c-2b driving actor) enqueues a **targeted re-scan** of the
    /// window around `claimed_height` via the reorg-heal machinery.
    /// The re-scan is bounded by the two F40 rules: it **never
    /// releases** the F14 lock (R1 — release stays refresh- or
    /// watchdog-authoritative), and consecutive fruitless
    /// daemon-directed re-scans are breaker-bounded to an operator
    /// alarm (R2).
    TargetedRescanRequested {
        /// The reservation whose verdict carried the claim.
        reservation_id: ReservationId,

        /// The locally computed txid the daemon claims is confirmed.
        tx_hash: TxHash,

        /// The daemon-claimed confirming-block height (untrusted;
        /// damage-capped per §7.2 — a lie here costs a fruitless
        /// re-scan, counted by the R2 breaker, never a release).
        claimed_height: u64,
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
    /// [`ReservationTTLConfig`](crate::engine::pending::ReservationTTLConfig)
    /// budget. V3.x `ReservationTTLActor` emitter only; pre-
    /// pinned for the V3.x consumer-actor PR (no V3.0 in-
    /// process emitter).
    ReservationOutstanding {
        /// Which reservation has aged out.
        reservation_id: ReservationId,

        /// How long the reservation has been outstanding.
        age: Duration,
    },

    /// **Operator alarm** — the F28/F37 rebuild-loop circuit breaker
    /// tripped (`DAEMON_SUBMIT_VERDICT.md` §2.5): a second consecutive
    /// daemon rejection of the same kind. Two independent builds
    /// rejected identically is a systematic wallet/daemon rule (or
    /// fee-model) disagreement, not a bad tx; further automatic builds
    /// are refused until the operator acknowledges. Emitted exactly
    /// once per trip.
    SubmitLoopBreakerTripped {
        /// The reservation whose rejection tripped the breaker.
        reservation_id: ReservationId,

        /// The rejection kind of the consecutive streak.
        kind: TerminalErrorKind,
    },

    /// The §5.3 watchdog dispatched a rung-1 resubmit-same-bytes probe
    /// for a held tx that reached the escape horizon
    /// (`DAEMON_SUBMIT_VERDICT.md` §5.3, [`escape_ladder_step`](crate::engine::submit_watchdog::escape_ladder_step)
    /// returned `ProbeResubmitSameBytes`). Observability-only trace of
    /// the probe firing; the daemon verdict follows on
    /// [`WatchdogProbeResolved`](Self::WatchdogProbeResolved).
    WatchdogProbeDispatched {
        /// The held tx being re-offered to the daemon.
        tx_hash: TxHash,

        /// The wait-epoch baseline height the probe fires against
        /// (the height the horizon was measured from).
        baseline_height: u64,
    },

    /// The §5.3 watchdog probe returned a daemon verdict. Observability
    /// trace of the [`WatchdogProbeOutcome`] the ladder branched on
    /// (`DAEMON_SUBMIT_VERDICT.md` §5.3 presence branching); any
    /// resulting alarm is carried separately on
    /// [`WatchdogAlarm`](Self::WatchdogAlarm).
    WatchdogProbeResolved {
        /// The probed tx.
        tx_hash: TxHash,

        /// The presence fact the probe observed.
        outcome: WatchdogProbeOutcome,
    },

    /// **Operator alarm** — the §5.3 watchdog exhausted its automatic
    /// remedies for a held tx and escalated to the human-decision rung
    /// (`DAEMON_SUBMIT_VERDICT.md` §5.3 rung 2 / §7.1: a rebuild is
    /// never automatic on timeout). Edge-triggered: emitted once per tx
    /// per alarm episode, not once per tick, to bound alarm-fatigue.
    WatchdogAlarm {
        /// The held tx the operator must adjudicate.
        tx_hash: TxHash,

        /// Why the automatic ladder could not resolve the tx.
        reason: WatchdogAlarmReason,
    },

    /// **Operator alarm** — the F40-R2 fruitless-rescan breaker tripped
    /// (`DAEMON_SUBMIT_VERDICT.md` §7.2, F40-R2): a daemon claimed a tx
    /// confirmed at an already-scanned height, the targeted re-scan
    /// found the block hash matching but the spend still unobserved,
    /// and this recurred for `attempts` consecutive ticks. The lock
    /// stays placed (F40-R1 is structural; no release on this path);
    /// the operator is alerted to a daemon lying about confirmation.
    /// Emitted exactly once per trip.
    FruitlessRescanBreakerTripped {
        /// The tx the daemon falsely claims confirmed.
        tx_hash: TxHash,

        /// The consecutive fruitless-rescan count at the trip.
        attempts: u32,
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
/// [`derive_snapshot_id`](crate::engine::refresh::derive_snapshot_id) in C1
/// → C2γ (where the function was annotated with `dead_code` until
/// `build_pending_tx_in_state` consumed it; here the dead-code
/// annotation lifts at C5α). The annotation is itself a discipline
/// pin: a future maintainer who wants to remove the helper must
/// confirm no C5+ consumer exists first.
#[allow(dead_code)]
pub(crate) fn emit_pending_tx_diagnostic(sink: &dyn DiagnosticSink, event: PendingTxDiagnostic) {
    sink.emit_pending_tx(event);
}
