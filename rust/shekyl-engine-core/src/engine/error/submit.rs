// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Submit verdict + `PendingTxEngine` collaborator error vocabulary (PR 5).

use crate::engine::pending::{ReservationId, SnapshotId};

use super::KeyEngineError;

// --- Submit error vocabulary (PR 5) ----------------------------------------

/// Terminal submit-side daemon-rejection sub-discriminant. R9 closure
/// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.4: the daemon rejected
/// the transaction with a final, non-recoverable outcome. The
/// reservation is dropped from `in_flight`; its `output_locks` are
/// released; the consumer's recourse is to rebuild against the current
/// chain state.
///
/// Separation from [`AmbiguousErrorKind`] is load-bearing at the type
/// level: a terminal error means the outputs are genuinely free
/// (`DoubleSpend` — the inputs were spent elsewhere) or that the
/// transaction itself is not viable (`FeeTooLow` / `Malformed`), so the
/// engine moves the reservation to "gone" deterministically. Consumer
/// code matches on the variant rather than wildcard-handling a unified
/// enum.
///
/// `#[non_exhaustive]` per the segment-2h binding form so V3.x daemon-
/// rejection refinements (e.g., a future `DaemonOutOfMemory` triage
/// hint) land additively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TerminalErrorKind {
    /// At least one of the transaction's inputs was already spent on
    /// the chain the daemon saw. The reservation's `output_locks` are
    /// released; the consumer rebuilds against the post-spend
    /// snapshot. This is the canonical terminal-outcome case.
    DoubleSpend,

    /// The transaction's fee is below the daemon's relay floor at the
    /// time of submission. R9: terminal in the sense that this specific
    /// reservation is dropped, even though the consumer can rebuild
    /// against the same outputs with a higher fee — the rebuild is a
    /// new reservation, not a fee-bump on the existing one (transaction
    /// replacement is a V3.x consideration per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.4 R18).
    FeeTooLow,

    /// The transaction failed daemon-side structural validation
    /// (invalid signature, malformed proof, internally inconsistent
    /// commitments, …). Indicates a bug in the build path; the variant
    /// exists so audit can distinguish the structural-defect class from
    /// the spend-conflict and economic-policy classes.
    Malformed,

    /// The daemon rejected with a cause this wallet build does not
    /// know ([`RejectCause::Unrecognized`] per the §2.3 version-skew
    /// rules — an additive daemon-side cause landed before this wallet
    /// updated). Fail-safe disposition per `DAEMON_SUBMIT_VERDICT.md`
    /// §2.5: release + one-shot rebuild, same shape as [`Self::Malformed`]
    /// but named distinctly so audit and telemetry can see skew events.
    ///
    /// [`RejectCause::Unrecognized`]: shekyl_rpc_client::RejectCause::Unrecognized
    Unrecognized,
}

/// Retryable daemon-rejection sub-discriminant
/// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2.5).
///
/// A **definite** verdict (the tx is in neither pool nor chain — not
/// ambiguity), but one whose remedy preserves the reservation: the
/// input selection stays sound, so the engine returns the entry to
/// `consumer_held` with its `output_locks` retained and the consumer
/// resubmits after the per-cause wait. This is the third lifecycle
/// class next to [`TerminalErrorKind`] (reservation gone) and
/// [`AmbiguousErrorKind`] (reservation held awaiting a verdict).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RetryableRejectCause {
    /// The FCMP++ reference is no longer canonical / the curve-tree
    /// root moved (reorg). Disposition (§2.5): rebuild the **proof**
    /// over the same input selection against a fresh root — the CT-5d
    /// re-anchor path — then resubmit. This is the formerly-deferred
    /// `ProofStale` signal, now daemon-attested.
    StaleRoot,

    /// The reference block is canonical but younger than the FCMP++
    /// reference minimum age (the wallet built too close to the tip).
    /// Disposition: timed backoff, then resubmit the same bytes.
    ReferenceTooRecent,

    /// The reference block hash is unknown to this daemon (typically:
    /// daemon not yet synced to it). Disposition: sync-gated — consult
    /// daemon health context; wait for sync and resubmit-same-bytes,
    /// or treat as [`Self::StaleRoot`] if the daemon is synced and
    /// still does not know the reference (§2.5, own-daemon-gated per
    /// §7.2).
    ReferenceNotFound,
}

/// Ambiguous submit-side daemon-rejection sub-discriminant. R9
/// Finding 2 closure per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.4:
/// the daemon round-trip did not produce a definitive outcome
/// (timeout, transport failure). The reservation **remains** in
/// `in_flight` because the daemon may still relay the transaction —
/// auto-releasing the `output_locks` here would race the daemon's
/// eventual mempool-accept.
///
/// The consumer cannot force-discard an `AmbiguousErrorKind`
/// reservation per the F2 ownership-boundary adjudication; the R8
/// TTL safety-net is the eventual release path. Stage 4's actor
/// migration adds the V3.x `MempoolMonitorActor` consumer pattern
/// that observes daemon-mempool state and calls `signal_mempool_evicted`
/// on confirmed-evicted reservations (G1 per §5.6.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AmbiguousErrorKind {
    /// The daemon RPC did not return within the submit-path timeout.
    /// The reservation stays in `in_flight`; the daemon may still
    /// have accepted the transaction.
    DaemonTimeout,

    /// The daemon RPC failed at the transport layer (connection
    /// refused, dropped midway, TLS error). Same disposition as
    /// `DaemonTimeout` — the daemon's authoritative state is
    /// unknown to the engine.
    DaemonUnavailable,
}

/// Failures from `PendingTxEngine::submit` (the trait surface that
/// `LocalPendingTx::submit` implements). R9 segment-2h binding form per
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0a.
///
/// The variant set splits a unified `SubmitErrorKind` (the prior
/// Round-3 shape) into [`TerminalErrorKind`] and [`AmbiguousErrorKind`]
/// so the lifecycle distinction (reservation gone vs. reservation
/// retained in `in_flight`) is load-bearing at the type level. The
/// design rationale lives in §5.6.4 of the PR 5 doc.
///
/// `#[non_exhaustive]` per Phase 0a so V3.x submit-side refinements
/// (e.g., a `MempoolFull` advisory variant once daemon-side feedback
/// supports it) land without a major-version break.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubmitError {
    /// R5: pre-daemon staleness check failed. The reservation's
    /// `snapshot_id` no longer matches the engine's `current_snapshot`,
    /// so submitting would race a reorg. **Lazy R5 (segment-2h):** the
    /// reservation does **not** auto-release its `output_locks` —
    /// the consumer must explicitly `discard(rid, ConsumerExplicit)`
    /// to release them (or rebuild, which will overlap the same
    /// outputs and surface them again). The eager-release alternative
    /// is a V3.x opt-in (`STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.7
    /// P9 trigger).
    #[error(
        "snapshot invalidated: reservation_snapshot = {reservation_snapshot:?}, current_snapshot = {current_snapshot:?}"
    )]
    SnapshotInvalidated {
        /// The `SnapshotId` recorded on the reservation at build time.
        reservation_snapshot: SnapshotId,
        /// The engine's current `SnapshotId` at submit time.
        current_snapshot: SnapshotId,
    },

    /// R9: the daemon round-trip completed with a terminal outcome.
    /// The rid is dropped from `in_flight`; `output_locks` are
    /// released; the consumer rebuilds against the current snapshot.
    #[error("daemon rejected submission terminally: {kind:?}")]
    DaemonRejectedTerminal {
        /// The terminal sub-discriminant.
        kind: TerminalErrorKind,
    },

    /// R9: the daemon round-trip completed with an ambiguous outcome.
    /// The rid **stays** in `in_flight`; `output_locks` are retained
    /// until either the daemon resolves (mempool-accept or
    /// mempool-evict) or the R8 TTL safety-net fires. Consumer-explicit
    /// discard is blocked per F2 ownership-boundary — see
    /// [`PendingTxError::DiscardBlockedPendingDaemonAck`](super::PendingTxError::DiscardBlockedPendingDaemonAck).
    #[error("daemon submit ambiguous: {kind:?} (reservation {reservation_id:?} retained)")]
    DaemonAmbiguous {
        /// The ambiguous sub-discriminant.
        kind: AmbiguousErrorKind,
        /// The reservation that remains `in_flight`.
        reservation_id: ReservationId,
    },

    /// The daemon returned a definite rejection whose remedy preserves
    /// the reservation (`DAEMON_SUBMIT_VERDICT.md` §2.5): the entry is
    /// returned to `consumer_held` with its `output_locks` retained and
    /// its full re-anchor substrate intact; the consumer resubmits via
    /// `submit(rid, seen_gen)` after the per-cause wait. Unlike
    /// [`Self::DaemonAmbiguous`] this **is** a verdict — under
    /// single-egress it proves the bytes are in neither pool nor chain
    /// — so waiting on chain observation is unnecessary; unlike
    /// [`Self::DaemonRejectedTerminal`] the input selection remains
    /// sound, so releasing the locks would only invite a competing
    /// build over the same inputs (a same-key-image artifact, §7.1).
    #[error(
        "daemon rejected retryably: {cause:?} (reservation {reservation_id:?} returned to consumer-held)"
    )]
    DaemonRejectedRetryable {
        /// The retryable sub-discriminant.
        cause: RetryableRejectCause,
        /// The reservation returned to `consumer_held`.
        reservation_id: ReservationId,
    },

    /// P3: rid was in neither `consumer_held` nor `in_flight` at
    /// submit entry. Either the rid was never issued, or it was
    /// already resolved (terminal-error path or successful
    /// daemon-accept) by the time the consumer called `submit`.
    #[error("reservation {reservation_id:?} not found")]
    ReservationNotFound {
        /// The rid the consumer passed.
        reservation_id: ReservationId,
    },

    /// P2: rid was found in `in_flight` at submit entry — a second
    /// `submit` is being attempted while the first is still
    /// daemon-pending.
    #[error("submit already pending for reservation {reservation_id:?}")]
    SubmitAlreadyPending {
        /// The rid whose duplicate submit was refused.
        reservation_id: ReservationId,
    },

    /// CT-5d (`docs/design/CT5D_REANCHOR.md` §4): the submitted `seen_gen` does
    /// not match the reservation's current `content_gen`, so broadcast is
    /// **withheld**. This covers both cases by the same gate: a re-anchor *during
    /// this submit* advanced the content, or a *prior* re-anchor advanced it and
    /// the consumer resubmitted with a stale generation. The reservation stays
    /// `consumer_held` with the current `content_gen` and its (fresh) `tx_bytes`;
    /// the consumer reviews the current `(fee, change)` and resubmits with the
    /// current `content_gen`. This makes "broadcast content the user did not
    /// authorize" unrepresentable.
    #[error(
        "content generation mismatch for reservation {reservation_id:?}: submitted seen_gen is stale; re-confirm at content_gen {content_gen}"
    )]
    ContentChanged {
        /// The reservation whose authorized content the consumer must re-confirm.
        reservation_id: ReservationId,
        /// The reservation's current `content_gen` — the value to resubmit with.
        content_gen: u64,
    },

    /// CT-5d (§3 / §3b): the proof needs re-anchoring but the re-anchor could not
    /// complete right now. Either the curve tree cannot yet anchor a fresh
    /// reference — still resyncing (e.g. post-reorg) or lagging the chain tip too
    /// far to anchor a submittable reference (§3b) — or a transient build/sign
    /// step failed (fee-snapshot fetch, signer, or an internal re-anchor error).
    /// In all cases the reservation is preserved (`consumer_held`); the consumer
    /// retries (or discards).
    #[error(
        "reservation {reservation_id:?} cannot re-anchor right now; reservation preserved, retry later"
    )]
    ReanchorUnavailable {
        /// The reservation whose re-anchor could not complete; preserved.
        reservation_id: ReservationId,
    },

    /// CT-5d (§3, F-I): the proof cannot be content-preservingly re-anchored —
    /// a deep reorg orphaned a selected input, or the fresh-depth fee exceeds the
    /// selected inputs' coverage. Reselection is the CT-5d-deferred path
    /// (`docs/FOLLOWUPS.md` "CT-5d reselect"); the consumer discards and rebuilds.
    /// The reservation is preserved so the consumer can review it before
    /// discarding.
    #[error(
        "reservation {reservation_id:?} needs reselection (deep reorg / fee escalation); discard and rebuild"
    )]
    ReselectionRequired {
        /// The reservation that must be discarded and rebuilt.
        reservation_id: ReservationId,
    },
}

// --- PendingTxEngine collaborator-error vocabulary (PR 5) -----------------

/// Failures from `OutputSelector::select_outputs` — the trait that
/// chooses spendable outputs for a build call. Phase 0i binding form
/// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (R13 segment-2c closure).
///
/// The trait isolates output-selection policy from the build pipeline:
/// the default implementation is wallet-greedy; consumers can plug in
/// alternative selectors for testing (`FaultyOutputSelector`) or for
/// privacy-improving strategies that emerge post-V3.0.
///
/// `#[non_exhaustive]` so V3.x selectors can extend the variant set
/// with their own failure modes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OutputSelectorError {
    /// The selector could not assemble a candidate set whose sum
    /// covers `needed`. Distinct from [`SendError::InsufficientFunds`](super::SendError::InsufficientFunds)
    /// because it reports the selector's view, which may differ from
    /// the wallet's gross balance (selectors filter out
    /// locked / immature / dust outputs before reasoning about
    /// coverage).
    #[error("output selector: insufficient funds (need {needed}, available {available})")]
    InsufficientFunds {
        /// Total amount-plus-fee the selector was asked to cover.
        needed: u64,
        /// Sum of outputs the selector considered eligible.
        available: u64,
    },

    /// The selector returned an empty candidate set even though the
    /// wallet has spendable balance — typically because every output
    /// is locked by another in-flight reservation
    /// (`output_locks` filter per the (γ) three-collection lean
    /// shape's P6 disposition).
    #[error("output selector: no eligible outputs")]
    NoEligibleOutputs,

    /// F4 caller-side subset re-verification: the selector returned
    /// an output index that is **not** a subset of the filtered
    /// candidate set the engine passed in. R13 / F4 closure per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F4 — the engine
    /// re-verifies the selector's output set rather than trusting
    /// it blindly, so a buggy or malicious selector cannot bypass
    /// the `output_locks` filter the engine applied pre-selection.
    ///
    /// The variant carries the first offending index so audit can
    /// reproduce the violation deterministically. The selector
    /// surface is a trait, so the failure is a contract violation
    /// not a panic.
    #[error("output selector returned non-subset index: offending_index = {offending_index}")]
    ReturnedIndicesNotSubset {
        /// First selector-returned index that was not in the
        /// engine's candidate set. Indices are positions into the
        /// engine's wallet-output table; precise typing (e.g., a
        /// dedicated `OutputIndex` newtype) is a V3.x refinement
        /// item per `docs/FOLLOWUPS.md`.
        offending_index: usize,
    },
}

/// Failures from `Signer::sign_transfer`. Phase 0h binding form
/// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (R11 (b) segment-2b
/// closure as separate `LocalSigner` / `SigningActor`).
///
/// The trait isolates spend-key access from the build pipeline so the
/// PR 5 design can survive the eventual V3.x `SigningActor` topology
/// without re-opening the trait surface. The default V3.0 impl is
/// `LocalSigner` (synchronous, in-process); the V3.x actor variant
/// lives behind the same trait.
///
/// `#[non_exhaustive]` so V3.x signers can extend the variant set
/// (e.g., a `HardwareApprovalDeclined` variant when offline-approval
/// flows land).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The signer has no spend-key material in scope (view-only
    /// wallet; hardware wallet not connected; signing actor not yet
    /// started). Distinct from [`SendError::CannotSign`](super::SendError::CannotSign) because it
    /// is the trait-method's outcome, not the engine's pre-build
    /// capability check.
    #[error("signer unavailable")]
    Unavailable,

    /// The signer attempted to sign but a downstream failure
    /// prevented completion (hardware-device error, remote-actor
    /// disconnect, etc.). Carries a `&'static str` named at the call
    /// site.
    #[error("signer remote failure ({reason})")]
    RemoteFailure {
        /// Compile-time-fixed description of the downstream failure.
        reason: &'static str,
    },
}

impl From<KeyEngineError> for SignerError {
    fn from(err: KeyEngineError) -> Self {
        match err {
            KeyEngineError::KeyActorUnavailable => Self::Unavailable,
            KeyEngineError::Primitive { detail } => Self::RemoteFailure { reason: detail },
            KeyEngineError::InsufficientFunds { .. } => Self::RemoteFailure {
                reason: "insufficient funds for fee variant",
            },
            KeyEngineError::HandleMismatch { .. } => Self::RemoteFailure {
                reason: "output handle mismatch",
            },
            KeyEngineError::MissingKeyImage { .. } => Self::RemoteFailure {
                reason: "missing key image on spend input",
            },
            KeyEngineError::SourceCiphertextDecapsulationFailed(_) => Self::RemoteFailure {
                reason: "source ciphertext re-decapsulation failed",
            },
            // Unreachable on the signing path (proofs never route through
            // `Signer`), but the conversion must stay total.
            KeyEngineError::Proof(_) => Self::RemoteFailure {
                reason: "proof generation failure",
            },
        }
    }
}
