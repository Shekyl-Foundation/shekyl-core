// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Refresh and ledger error vocabulary.

use std::fmt;

use shekyl_types::{BlockCount, BlockHeight};

use super::IoError;

/// Why a rollback is outside the finality window.
///
/// Two honest causes, one refusal. [`Self::Measured`] is a depth both
/// sides of the comparison actually have. [`Self::RecordEnded`] is a
/// hash record that ran out while a past-finality fork is still
/// possible — the depth is how far the record reached, not a guess at
/// the fork. A new cause is a new match arm and a contract bump: the
/// wallet message and `data.breach` name this set exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityBreach {
    /// The dropped span was measured: every stored block through the
    /// window disagreed, or the tree tip and the retained height are
    /// both known and the gap exceeds `W`.
    Measured,
    /// The hash record ended before a common ancestor was found, on a
    /// chain tall enough that the fork may lie past `W`.
    RecordEnded,
}

impl FinalityBreach {
    /// Wire spelling of [`Self`], stable for `error.data.breach`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::RecordEnded => "record_ended",
        }
    }
}

impl fmt::Display for FinalityBreach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Measured => "the depth was measured",
            Self::RecordEnded => "the hash record ended before the fork was confirmed",
        })
    }
}

/// A rollback the finality policy refused.
///
/// `depth` is a span, not a height. For [`FinalityBreach::Measured`] it
/// is the span that was compared with `W`. For
/// [`FinalityBreach::RecordEnded`] it is only how far the stored hashes
/// reached, which may be shorter than `W`. The steps that clear the tree
/// file and the scan history are the RPC message's job; this value states
/// the span that was known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityStop {
    /// Blocks the rollback would drop, or — when the record ended — the
    /// number of stored blocks that already disagreed.
    pub depth: BlockCount,
    /// `W`. [`shekyl_curve_tree::FINALITY_DEPTH_BLOCKS`].
    pub finality_depth: BlockCount,
    /// Which of the two causes produced this stop.
    pub breach: FinalityBreach,
}

impl fmt::Display for FinalityStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.breach {
            // The span was compared with `W` and lost.
            FinalityBreach::Measured => write!(
                f,
                "a rollback of {depth} blocks is outside the {window}-block finality window ({breach})",
                depth = self.depth,
                window = self.finality_depth,
                breach = self.breach,
            ),
            // `depth` is how far the record reached, which can be less than `W`.
            // Saying that span is outside the window states a comparison that did not happen.
            FinalityBreach::RecordEnded => write!(
                f,
                "the hash record ended after {depth} mismatches, before a common ancestor inside the {window}-block finality window was confirmed",
                depth = self.depth,
                window = self.finality_depth,
            ),
        }
    }
}

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
        wallet: BlockHeight,
        /// `result.start_height` in the value passed to
        /// `apply_scan_result`.
        result: BlockHeight,
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

    /// The chain the daemon serves kept reorganizing: a further reorg was
    /// detected after the attempt's rewind budget was spent, so the attempt
    /// stopped rather than scan a region it could no longer check. Nothing
    /// was merged. Retry once the chain settles.
    #[error("reorg storm: the chain diverged again after the rewind budget was spent")]
    ReorgStorm,

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
    /// Orchestrator-side "this branch should be unreachable" is
    /// structurally distinct from a scanner-produced contract
    /// violation (`MalformedScanResult`) and from snapshot-race
    /// exhaustion (`ConcurrentMutation`). The merge-retry loops
    /// (`Engine::refresh_with`, `run_refresh_task`) no longer
    /// construct this variant: the merge-retry budget type makes a
    /// fall-through-with-no-race unrepresentable, so budget
    /// exhaustion always carries the `ConcurrentMutation` that spent
    /// it. Remaining call sites are true unreachable-by-construction
    /// paths (today: [`crate::engine::RefreshHandle::join`] when the
    /// producer drops the completion oneshot without delivery).
    ///
    /// Routing those through `MalformedScanResult` would conflate
    /// "the scanner emitted a `ScanResult` whose internal shape
    /// disagrees with itself" with "the engine's control flow reached
    /// an unreachable branch". Routing through `ConcurrentMutation`
    /// is also wrong: that variant carries the snapshot-disagreement
    /// pair (`wallet`, `result`) the caller uses to decide whether to
    /// retry, and an unreached-invariant case has no such pair.
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
    /// Added in PR 4 C3; C5 migrated the retry-loop fallbacks onto
    /// this variant. The merge-retry loops have since dropped the
    /// fallback (the race that exhausts the budget is always in
    /// hand). Future orchestrator-internal "this branch should be
    /// unreachable" paths still route here rather than re-litigating
    /// where they belong.
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
    /// `fault` names the failure class; its data is compile-time-fixed —
    /// no daemon/scanner bytes flow in, matching the discipline of
    /// [`Self::InternalInvariantViolation`]. Daemon transport failures
    /// during the genesis/birthday backfill fetch surface through
    /// [`Self::Io`] (the established `fetch_block_hash_at` mapping), not
    /// here; this variant covers the tree-feed-specific steps (backfill
    /// block decode, the actor ingest/rollback handshake).
    ///
    /// Whether a respawn can heal it is a property of the fault
    /// ([`CurveTreeIngestFault::recoverable_by_respawn`]), read by
    /// [`Engine::ingest_scan_result_with_respawn`](crate::engine::Engine::ingest_scan_result_with_respawn)
    /// to decide whether to respawn-and-retry once. The bounded retry budget
    /// and escalation for a deterministically-corrupt store (O3-sub) is CT-5d.
    #[error("curve-tree ingest failed: {fault}")]
    CurveTreeIngest {
        /// Why the ingest failed, one member per remedy.
        fault: CurveTreeIngestFault,
    },

    /// A rollback would pass `W`
    /// ([`shekyl_curve_tree::FINALITY_DEPTH_BLOCKS`]), the depth at which
    /// this wallet's persisted state is final (`CT-6` C7).
    ///
    /// The store can truncate through a frozen segment — F9 requires it —
    /// and a wallet refresh must not ask. [`FinalityStop`] is the fact.
    /// The words that tell a caller to remove the curve-tree file and clear
    /// scan history are the RPC error's, not a second copy here.
    #[error("{stop}")]
    ReorgDeeperThanFinality {
        /// The span that failed the finality comparison, and why.
        stop: FinalityStop,
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

/// Why a scan result could not be ingested into the curve tree — one member
/// per remedy, so what a caller does next is read from the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CurveTreeIngestFault {
    /// The curve-tree actor fail-stopped. A respawn over the held store heals
    /// it (R1-Q4).
    #[error("curve-tree actor unavailable")]
    ActorUnavailable,
    /// A rollback committed but failed before the client's memory was
    /// rebuilt ([`ClientError::Poisoned`](shekyl_curve_tree::ClientError::Poisoned));
    /// its documented recovery is to resume over the same store.
    #[error("curve-tree client poisoned")]
    ClientPoisoned,
    /// The respawn could not resume a writer over the held store. Reopening
    /// the wallet reopens the store, which names its own fault.
    #[error("curve-tree respawn resume failed")]
    RespawnFailed,
    /// The rebuilt root disagrees with the root the block header commits to
    /// (§3.3, CT-5b O5): the daemon served leaves its own header does not
    /// commit to. A respawn re-derives the same root.
    #[error("curve-tree root mismatch vs header")]
    RootMismatch,
    /// A backfill block the daemon served did not decode into leaves.
    #[error("backfill block decode failed")]
    BackfillBlockUndecodable,
    /// The client rejected the ingest: a producer-contract or tree-state
    /// fault a resume would reproduce.
    #[error("curve-tree client rejected ingest")]
    ClientRejected,
    /// The ingested tip's successor height overflowed.
    #[error("ingested tip height overflow")]
    TipHeightOverflow,
    /// A backfill height did not fit `usize`.
    #[error("backfill height exceeds usize")]
    BackfillHeightOverflow,
}

impl From<CurveTreeIngestFault> for RefreshError {
    fn from(fault: CurveTreeIngestFault) -> Self {
        Self::CurveTreeIngest { fault }
    }
}

impl CurveTreeIngestFault {
    /// Whether a drop-and-reopen respawn of the actor can heal the failure.
    /// Every other fault reproduces on a resume, so it surfaces terminally
    /// rather than livelocking a retry.
    #[must_use]
    pub const fn recoverable_by_respawn(self) -> bool {
        matches!(self, Self::ActorUnavailable | Self::ClientPoisoned)
    }
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

#[cfg(test)]
mod tests {
    use super::CurveTreeIngestFault as F;

    /// Only a fail-stopped actor and a poisoned client heal on a respawn;
    /// every other fault reproduces on resume and must surface terminally.
    #[test]
    fn only_a_stopped_or_poisoned_client_is_respawn_recoverable() {
        for (fault, recoverable) in [
            (F::ActorUnavailable, true),
            (F::ClientPoisoned, true),
            (F::RespawnFailed, false),
            (F::RootMismatch, false),
            (F::BackfillBlockUndecodable, false),
            (F::ClientRejected, false),
            (F::TipHeightOverflow, false),
            (F::BackfillHeightOverflow, false),
        ] {
            assert_eq!(fault.recoverable_by_respawn(), recoverable, "{fault:?}");
        }
    }
}
