// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Submit verdict + `PendingTxEngine` collaborator error vocabulary (PR 5).

use shekyl_tx_builder::{InternalSignFault, SignFault};

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
pub use shekyl_engine_state::pending_post_block::CenRowName;

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

    /// A consensus row refused the transaction against the chain at the
    /// pool's commit (`Rejection::ConsensusRule`): the bytes are sound and
    /// the chain decides. Terminal; the record is held to its end date
    /// (BD-Q3 Rule 2) and the user is told the row.
    ConsensusRule {
        /// The row, as the daemon named it.
        row: CenRowName,
    },
    /// The daemon rejected with a cause this wallet build does not
    /// know ([`Rejection::Unrecognized`] per the §2.3 version-skew
    /// rules — an additive daemon-side cause landed before this wallet
    /// updated). Fail-safe disposition per `DAEMON_SUBMIT_VERDICT.md`
    /// §2.5: release + one-shot rebuild, same shape as [`Self::Malformed`]
    /// but named distinctly so audit and telemetry can see skew events.
    ///
    /// [`Rejection::Unrecognized`]: shekyl_rpc_client::Rejection::Unrecognized
    Unrecognized,
}

impl From<TerminalErrorKind> for shekyl_engine_state::pending_post_block::TerminalCause {
    /// The persisted cause a pending record keeps (BD-Q3 Rule 2). Exhaustive
    /// on purpose: a new terminal kind fails this match in review, where the
    /// persisted twin gains its variant (or the kind maps to `Unrecognized`).
    /// The twin's `JoinMarketUnsupported` has no kind here: a pre-flip
    /// daemon recorded it, and nothing produces it now.
    fn from(kind: TerminalErrorKind) -> Self {
        use shekyl_engine_state::pending_post_block::TerminalCause as C;
        match kind {
            TerminalErrorKind::DoubleSpend => C::DoubleSpend,
            TerminalErrorKind::FeeTooLow => C::FeeTooLow,
            TerminalErrorKind::Malformed => C::Malformed,
            TerminalErrorKind::ConsensusRule { row } => C::ConsensusRule { row },
            TerminalErrorKind::Unrecognized => C::Unrecognized,
        }
    }
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

    /// A19: the dispatch record (journal row with the signed bytes, the
    /// retained tx secret, the inputs the F14 lock holds) is not
    /// confirmed on disk, so **nothing was sent**. A save that failed
    /// before the rename undoes the record under the same guard. A rename
    /// whose durability was not confirmed leaves the applied
    /// record (undoing it would diverge from disk) and still sends
    /// nothing. Either way the reservation is back in `consumer_held`
    /// with its output locks; the consumer may retry the submit once the
    /// cause is fixed, or discard.
    #[error("send not saved durably, so not sent (reservation {reservation_id:?} kept): {source}")]
    DispatchNotSaved {
        /// The reservation, kept for a retry.
        reservation_id: ReservationId,
        /// Why the save failed.
        #[source]
        source: super::PersistenceError,
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

/// Where a reservation stands after a failed submit, as the engine holds
/// it. Three states, because a consumer acts differently on each: what it
/// still holds it may submit again or discard; what is in flight it must
/// leave to the engine; what is gone it forgets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationAfterSubmit {
    /// `consumer_held`, with its `output_locks`: nothing was sent. The
    /// caller still holds it, to submit again once the cause is fixed, or
    /// to discard. A consumer that forgets it leaves its inputs locked
    /// with no handle to release them.
    Held,
    /// `in_flight`: the daemon may have it. The engine holds it until the
    /// daemon's verdict or the R8 TTL; the caller's discard is refused
    /// meanwhile (F2), and a second submit is refused as pending.
    InFlight,
    /// Dropped, its locks released, or never issued.
    Gone,
}

impl SubmitError {
    /// Where the reservation stands after this failure, answered once,
    /// here, from each arm's documented lifecycle. No consumer re-derives
    /// it over this `#[non_exhaustive]` enum: a match outside the crate
    /// cannot be exhaustive, and its wildcard would read every variant
    /// added later as one answer for all. This match is exhaustive, so a
    /// new variant does not compile until its answer is written.
    #[must_use]
    pub const fn reservation_after(&self) -> ReservationAfterSubmit {
        match self {
            // Lazy R5: never sent; the locks stay until an explicit discard.
            Self::SnapshotInvalidated { .. }
            // A definite rejection whose remedy returns it to `consumer_held`.
            | Self::DaemonRejectedRetryable { .. }
            // Nothing sent; `consumer_held`, kept for a retry (A19).
            | Self::DispatchNotSaved { .. }
            // Withheld for re-confirmation; `consumer_held`.
            | Self::ContentChanged { .. }
            // Preserved for a retry.
            | Self::ReanchorUnavailable { .. }
            // Preserved for review before the consumer discards it.
            | Self::ReselectionRequired { .. } => ReservationAfterSubmit::Held,
            // Ambiguous: `in_flight` until the daemon resolves or the TTL.
            Self::DaemonAmbiguous { .. }
            // The first submit is still `in_flight`.
            | Self::SubmitAlreadyPending { .. } => ReservationAfterSubmit::InFlight,
            // Dropped from `in_flight`, its locks released.
            Self::DaemonRejectedTerminal { .. }
            // Never issued, or already resolved.
            | Self::ReservationNotFound { .. } => ReservationAfterSubmit::Gone,
        }
    }
}

#[cfg(test)]
mod reservation_after_tests {
    use super::*;
    use crate::engine::error::PersistenceError;

    /// **Every arm says where its reservation stands, as its own
    /// documentation says.** One row per variant; the match in
    /// `reservation_after` is exhaustive, so a variant added later fails to
    /// compile there, and this table names its answer. Red edits: move
    /// `DispatchNotSaved` to `InFlight` (a consumer would drop the handle
    /// of a send it still holds, its inputs locked with no way to release
    /// them); move `DaemonAmbiguous` to `Held` (a consumer would try to
    /// discard, or resubmit, a send that may be on the network).
    #[test]
    fn every_arm_says_where_its_reservation_stands() {
        use ReservationAfterSubmit::{Gone, Held, InFlight};
        let rid = ReservationId::from_raw(7);
        let cases: [(SubmitError, ReservationAfterSubmit); 10] = [
            (
                SubmitError::SnapshotInvalidated {
                    reservation_snapshot: SnapshotId([1; 16]),
                    current_snapshot: SnapshotId([2; 16]),
                },
                Held,
            ),
            (
                SubmitError::DaemonRejectedTerminal {
                    kind: TerminalErrorKind::DoubleSpend,
                },
                Gone,
            ),
            (
                SubmitError::DaemonAmbiguous {
                    kind: AmbiguousErrorKind::DaemonTimeout,
                    reservation_id: rid,
                },
                InFlight,
            ),
            (
                SubmitError::DaemonRejectedRetryable {
                    cause: RetryableRejectCause::StaleRoot,
                    reservation_id: rid,
                },
                Held,
            ),
            (
                SubmitError::ReservationNotFound {
                    reservation_id: rid,
                },
                Gone,
            ),
            (
                SubmitError::DispatchNotSaved {
                    reservation_id: rid,
                    source: PersistenceError::Prefs(
                        shekyl_engine_prefs::PrefsError::UnsupportedSchemaVersion {
                            file: 9,
                            binary: 1,
                        },
                    ),
                },
                Held,
            ),
            (
                SubmitError::SubmitAlreadyPending {
                    reservation_id: rid,
                },
                InFlight,
            ),
            (
                SubmitError::ContentChanged {
                    reservation_id: rid,
                    content_gen: 3,
                },
                Held,
            ),
            (
                SubmitError::ReanchorUnavailable {
                    reservation_id: rid,
                },
                Held,
            ),
            (
                SubmitError::ReselectionRequired {
                    reservation_id: rid,
                },
                Held,
            ),
        ];
        for (error, after) in cases {
            assert_eq!(error.reservation_after(), after, "{error:?}");
        }
    }
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

/// A wallet-side signing fault outside the transaction builder.
///
/// Closed: a new fault is a variant, and the wire carries [`Self::keyword`].
/// The builder's own faults travel as [`shekyl_tx_builder::SignFault`], not
/// as one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerFault {
    /// A structural failure during signing whose detail stays in the log.
    Primitive,
    /// An input's handle does not match its derivation.
    HandleMismatch,
    /// A spendable input has no canonical key image.
    MissingKeyImage,
    /// An input's source ciphertext does not decapsulate.
    SourceDecapsulation,
    /// A recipient id the label cannot echo reached the sign pass.
    RidNotEncodable,
    /// A proof message reached the signer, which does not serve proofs.
    Proof,
    /// The signed bulletproof bytes do not parse.
    BulletproofParse,
    /// Encoding the signed transaction failed.
    WireEncode,
    /// The OS random source failed while drawing the transaction key.
    Randomness,
}

impl SignerFault {
    /// Every wallet-side fault, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::Primitive,
        Self::HandleMismatch,
        Self::MissingKeyImage,
        Self::SourceDecapsulation,
        Self::RidNotEncodable,
        Self::Proof,
        Self::BulletproofParse,
        Self::WireEncode,
        Self::Randomness,
    ];

    /// The fault's wire keyword (`data.fault` on `-29119`).
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Primitive => "primitive",
            Self::HandleMismatch => "handle-mismatch",
            Self::MissingKeyImage => "missing-key-image",
            Self::SourceDecapsulation => "source-decapsulation",
            Self::RidNotEncodable => "rid-not-encodable",
            Self::Proof => "proof",
            Self::BulletproofParse => "bulletproof-parse",
            Self::WireEncode => "wire-encode",
            Self::Randomness => "randomness",
        }
    }
}

impl core::fmt::Display for SignerFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.keyword())
    }
}

/// Failures from `Signer::sign_transfer`. Phase 0h binding form
/// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (R11 (b) segment-2b
/// closure as separate `LocalSigner` / `SigningActor`).
///
/// Every failure here is local: the wallet signs in process. A remote
/// signer (a device, a cooperative peer) would add its own variant with
/// its own remedy, not borrow one of these.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The signer has no spend-key material in scope: its signing actor
    /// has stopped. Distinct from [`SendError::BuildInvariant`](super::SendError::BuildInvariant)
    /// because it is the trait method's outcome, not the engine's
    /// pre-build capability check.
    #[error("signer unavailable")]
    Unavailable,

    /// The transaction builder refused or failed the signing pass, by
    /// identity ([`shekyl_tx_builder::SignFault`]).
    #[error("signing failed: {0}")]
    Sign(shekyl_tx_builder::SignFault),

    /// The wallet's own state did not hold what signing needs, or encoding
    /// the signed transaction failed: a bug, named by [`SignerFault`].
    #[error("signer internal fault ({fault})")]
    Internal {
        /// The fault.
        fault: SignerFault,
    },
}

impl From<KeyEngineError> for SignerError {
    fn from(err: KeyEngineError) -> Self {
        let fault = match err {
            KeyEngineError::KeyActorUnavailable => return Self::Unavailable,
            KeyEngineError::Sign(fault) => return Self::Sign(fault),
            KeyEngineError::Primitive { detail } => {
                tracing::debug!(detail, "signer primitive failure");
                SignerFault::Primitive
            }
            // Amounts that do not balance, including a fee variant the
            // build's selection should have made unreachable. The shortfall
            // stays in the log; the fault is the builder's closed one.
            KeyEngineError::InsufficientFunds { shortfall } => {
                tracing::debug!(shortfall, "signing amounts do not balance");
                return Self::Sign(SignFault::Internal(InternalSignFault::InsufficientFunds));
            }
            KeyEngineError::HandleMismatch { .. } => SignerFault::HandleMismatch,
            KeyEngineError::MissingKeyImage { .. } => SignerFault::MissingKeyImage,
            KeyEngineError::SourceCiphertextDecapsulationFailed(_) => {
                SignerFault::SourceDecapsulation
            }
            // Unreachable for a request `build_pending_tx` admitted (it
            // refuses a rid the label cannot carry), kept total.
            KeyEngineError::RidNotEncodable(_) => SignerFault::RidNotEncodable,
            // Unreachable on the signing path (proofs never route through
            // `Signer`), but the conversion must stay total.
            KeyEngineError::Proof(_) => SignerFault::Proof,
            // The OS random source failed drawing the transaction key;
            // nothing was built.
            KeyEngineError::Randomness(_) => SignerFault::Randomness,
        };
        Self::Internal { fault }
    }
}
