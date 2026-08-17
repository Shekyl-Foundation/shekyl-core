// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Refresh and ledger error vocabulary.

use super::IoError;

// --- Refresh ---------------------------------------------------------------

/// Failures from [`Engine::refresh`](crate::engine::Engine) and the
/// `apply_scan_result` merge it drives. Carries the only audited code
/// path that ever mutates the scan-result slice of `WalletLedger`.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// `apply_scan_result.start_height` did not match the wallet's
    /// current `synced_height`. The caller (likely a polling RPC client
    /// that issued `refresh` while another `refresh` was in flight)
    /// should retry.
    ///
    /// This is the type-layer enforcement of the Phase 1 lock
    /// "additive-only, scoped, snapshot-consistency-checked merge."
    #[error(
        "concurrent mutation: wallet synced_height = {wallet}, scan result start_height = {result}; retry"
    )]
    ConcurrentMutation {
        /// `wallet.synced_height` observed at merge time.
        wallet: u64,
        /// `result.start_height` in the value passed to
        /// `apply_scan_result`.
        result: u64,
    },

    /// A second `refresh` was attempted while one was already in flight.
    /// Single-flight is normally enforced by the `&mut self` borrow on
    /// `refresh`; this variant covers cases where the binary layer
    /// surfaces the violation explicitly (e.g., a `tokio::Mutex`-guarded
    /// path that does not panic on re-entry).
    #[error("refresh already running")]
    AlreadyRunning,

    /// The scanner produced a [`crate::scan::ScanResult`] that violates
    /// the merge contract. Distinct from
    /// [`Self::ConcurrentMutation`] in that it is a **producer-side
    /// defect**, not a snapshot-disagreement: re-running the scan
    /// against the same daemon will produce the same contract
    /// violation, so the [`crate::engine::Engine::refresh`] retry loop does
    /// **not** retry on this variant — it surfaces immediately.
    ///
    /// `ConcurrentMutation` and `MalformedScanResult` together close
    /// the strict-contract gap surfaced by the PR #16 Copilot review:
    /// the former is the retry signal for races against `Engine<S>`,
    /// the latter is the audit signal for a producer that emitted a
    /// `ScanResult` whose internal shape disagrees with itself
    /// (out-of-range entries, duplicate heights, missing per-height
    /// block-hash record, residual entries left behind after the
    /// per-height apply loop).
    ///
    /// See `docs/V3_WALLET_DECISION_LOG.md`
    /// (`MalformedScanResult: producer-bug signal vs. ConcurrentMutation`,
    /// 2026-04-26) for the rationale.
    #[error("malformed ScanResult: {reason}")]
    MalformedScanResult {
        /// Static description of the contract violation, named at the
        /// call site so audit can read every distinguishable defect
        /// class from source.
        reason: &'static str,
    },

    /// The refresh task was cancelled before completing a block boundary.
    /// `RefreshHandle` checkpoints between blocks, so a cancellation is
    /// always reported back to the caller as this variant rather than
    /// surfacing as a partial-state failure.
    #[error("refresh cancelled")]
    Cancelled,

    /// Daemon-side refresh failure: an RPC call into `shekyld` failed,
    /// or the daemon returned data that the scanner / merge logic could
    /// not consume. Carries an [`IoError`] for upstream detail.
    #[error("daemon/scan IO failure: {0}")]
    Io(#[from] IoError),

    /// The orchestrator state machine reached a path the developer
    /// marked as "should never happen" — a structural invariant
    /// violation, distinct from both [`Self::ConcurrentMutation`]
    /// (retry-budget exhaustion under sustained merge contention) and
    /// [`Self::MalformedScanResult`] (a producer-bug signal carrying
    /// internal-shape violations of the scanner's output contract).
    ///
    /// # Why this is its own variant
    ///
    /// The two retry-loop call sites in
    /// `Engine::refresh` and `run_refresh_task` currently fall back on
    /// `MalformedScanResult` when the loop body exits without observing
    /// a `ConcurrentMutation`, with the comment *"falling through with
    /// `None` would mean the loop body itself is broken."* That case
    /// is structurally distinct from a scanner-produced contract
    /// violation: it is an orchestrator-side state-machine failure,
    /// not a producer-side defect. Routing both through
    /// `MalformedScanResult` would conflate "the scanner emitted a
    /// `ScanResult` whose internal shape disagrees with itself" with
    /// "the engine's retry loop reached an unreachable branch";
    /// downstream consumers (telemetry; future peer-reputation
    /// actors; future user-facing error surface) need different
    /// responses for the two cases. The variant separation is
    /// correctness-preserving, not stylistic.
    ///
    /// Routing through `ConcurrentMutation` is also wrong: that
    /// variant carries the snapshot-disagreement pair (`wallet`,
    /// `result`) the caller uses to decide whether to retry. An
    /// unreached-invariant case has no such pair to report.
    ///
    /// # Field
    ///
    /// `context` is a `&'static str` named at the call site so audit
    /// can read every distinguishable invariant-violation class from
    /// source. The unit-variant discipline on the producer trait
    /// surface (`RefreshEngine::Error: Into<RefreshError>` with
    /// trait-error vocabulary restricted to `Cancelled` / `Io` /
    /// `MalformedScanResult`) exists to close the memory-amplifier
    /// and log-exfiltration vectors on attacker-influenced data;
    /// neither vector applies here, because `context` is
    /// compile-time-fixed developer content at an
    /// orchestrator-internal call site — no daemon input or
    /// scanner-emitted bytes flow in.
    ///
    /// # Lifecycle
    ///
    /// The variant is added in PR 4 C3 ahead of any call-site
    /// migration. PR 4 C5 migrates the two retry-loop call sites
    /// (the `MalformedScanResult { reason: "..." }` fallbacks in
    /// `run_refresh_task` and `Engine::refresh`) over to
    /// `InternalInvariantViolation`, preserving the existing
    /// `&'static str` content as the `context` value at each site.
    /// Future orchestrator-internal "this branch should be
    /// unreachable" paths route here categorically rather than
    /// re-litigating where they belong.
    ///
    /// See `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` §4 Phase 0c
    /// ("Why `InternalInvariantViolation` is its own variant, not
    /// an extension of `ConcurrentMutation`") for the full rationale.
    #[error("internal invariant violation: {context}")]
    InternalInvariantViolation {
        /// Compile-time-fixed name of the violated invariant. Named
        /// at the call site so audit can read every distinguishable
        /// case from source rather than parsing a runtime-synthesized
        /// message.
        context: &'static str,
    },

    /// Curve-tree ingest failed while feeding the tree the result's
    /// height range **ahead of** the ledger merge — the
    /// ack-before-commit half of CT-5 §3.2 (R1-Q2) under the fork-three
    /// genesis-anchored feed (§3.2.1). The tree is updated and
    /// acknowledged before [`crate::engine::Engine::apply_scan_result`] advances
    /// the ledger, so the ledger tip never outruns the tree (O2).
    ///
    /// **Terminal, not retried.** The refresh retry loop retries only
    /// [`Self::ConcurrentMutation`]; a retry would re-run the same
    /// cursor-driven ingest and hit the same failure. Surfacing here
    /// keeps the ledger from advancing past an un-updated tree rather
    /// than silently diverging the two tips.
    ///
    /// `context` is a compile-time-fixed classification named at the
    /// call site — no daemon/scanner bytes flow in, matching the
    /// `&'static str`-only discipline of
    /// [`Self::InternalInvariantViolation`]. Daemon transport failures
    /// during the genesis/birthday backfill fetch surface through
    /// [`Self::Io`] (the established `fetch_block_hash_at` mapping), not
    /// here; this variant covers the tree-feed-specific steps (backfill
    /// block decode, the actor ingest/rollback handshake).
    ///
    /// A fail-stopped actor ([`crate::engine::curve_tree_actor::CurveTreeHandleError::Unavailable`])
    /// or a [`ClientError::Poisoned`](shekyl_curve_tree::ClientError::Poisoned)
    /// client maps here with `recoverable_by_respawn = true`: the CT-5a commit-5
    /// engine-side respawn (R1-Q4) drops the dead actor, resumes a writer
    /// over the same open store, and retries the cursor-driven ingest once
    /// ([`Engine::ingest_scan_result_with_respawn`](crate::engine::Engine::ingest_scan_result_with_respawn)).
    /// Every other ingest failure (producer-contract, decode, a tree-state
    /// client error a resume would reproduce) is `false` and surfaces
    /// terminally.
    #[error("curve-tree ingest failed: {context}")]
    CurveTreeIngest {
        /// Compile-time-fixed name of the ingest failure class, named
        /// at the call site so audit can read every distinguishable
        /// case from source.
        context: &'static str,
        /// `true` when a resume-over-held-store respawn (R1-Q4) can heal the
        /// failure (fail-stopped actor or `ClientError::Poisoned`); `false`
        /// for failures a resume would reproduce. Read by
        /// [`Engine::ingest_scan_result_with_respawn`](crate::engine::Engine::ingest_scan_result_with_respawn)
        /// to decide whether to respawn-and-retry. The bounded retry budget +
        /// escalation for a deterministically-corrupt store (O3-sub) is CT-5d.
        recoverable_by_respawn: bool,
    },

    /// [`Engine::start_rescan`](crate::engine::Engine::start_rescan) refused: a
    /// pending-tx **reservation** (consumer-held or in-flight) is anchored
    /// to transfer rows the reset clears — its in-memory output locks are
    /// indices into the very rows the wipe destroys, and no send-journal
    /// row exists to re-derive from (nothing dispatched yet). Resolution
    /// is in-session and cheap: submit or discard, then retry.
    ///
    /// The refusal's former second half — **unconfirmed submitted** txs
    /// whose spend marking a replay cannot re-derive — retired with
    /// PR-SJ-1 (`WALLET_SEND_RECORD.md` P3-1): the send journal carries
    /// each dispatched input set across the wipe, and the merge
    /// reconciler re-derives the F14 locks as replay re-creates the
    /// rows, closing the §7.1 self-link hazard structurally rather than
    /// by refusing. The abandon surface for a never-confirming tx is
    /// PR-SJ-3 (`docs/FOLLOWUPS.md`).
    #[error(
        "cannot rescan while pending-tx reservations are held ({reservations} reservation(s))"
    )]
    RescanBlocked {
        /// Consumer-held + in-flight pending-tx reservations.
        reservations: usize,
    },

    /// Rescan emptied scan-derived state in memory but failed to persist the
    /// reset before the scan producer started. Unlike the other
    /// `start_rescan` refusals this one is *past* the point of no return:
    /// the in-memory ledger is already reset while the durable copy may
    /// still hold the pre-rescan tip. Retry `start_rescan` once the
    /// persistence fault clears; do not treat the wallet as authoritative
    /// until a rescan completes.
    #[error("rescan reset persistence failed: {0}")]
    RescanPersist(String),
}

// --- Ledger ----------------------------------------------------------------

/// Per-domain error for [`LedgerEngine`](crate::engine::traits::LedgerEngine),
/// the §2.2 trait that owns the wallet's confirmed-chain ledger.
///
/// # Empty-enum starter shape
///
/// Stage 1 PR 2 ships `LedgerError` with **no variants**. The §2.2
/// trait surface is structured so that:
///
/// - the three read methods (`synced_height`, `snapshot`, `balance`)
///   are infallible — they return `T`, not `Result<T, _>`, because
///   reading committed state under the `RwLock` read guard cannot
///   fail; and
/// - the lone mutating method (`apply_scan_result`) returns
///   [`RefreshError`] (specifically [`RefreshError::ConcurrentMutation`])
///   because the failure mode crosses the `LedgerEngine` /
///   `RefreshEngine` boundary — a snapshot-disagreement is a
///   refresh-loop concern, not a ledger-internal concern, per the
///   §1.5 actor-identity reasoning.
///
/// `LedgerError` therefore has no caller-visible variants today; it
/// exists as the named [`LedgerEngine::Error`] target so the
/// `type Error: Into<LedgerError>;` bound has somewhere to land. New
/// variants are additive (§7 / §8.2): a future read method that can
/// genuinely fail (e.g., a `transfer_details(id)` lookup that may
/// return "no such transfer") would land its variant here without
/// re-opening the trait surface.
///
/// [`LedgerEngine::Error`]: crate::engine::traits::LedgerEngine::Error
/// [`RefreshError`]: RefreshError
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub(crate) enum LedgerError {}
