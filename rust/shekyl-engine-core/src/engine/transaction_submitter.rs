// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction broadcast capability for [`super::local_pending_tx::LocalPendingTx`].

use std::sync::Arc;

use shekyl_rpc_client::{Rejection, Verdict};
use shekyl_types::PCanonicalId;
use shekyl_wire::Transaction;

use super::bond_assembly::PBoundBytes;
use super::dispatch_durability::DurableTxBytes;
use super::error::{AmbiguousErrorKind, CenRowName, RetryableRejectCause, TerminalErrorKind};
use super::pending::TxHash;
use super::traits::{DaemonEngine, TxSubmitOutcome};

/// Failure surface of a [`TransactionSubmitter`] — the round trip's outcome
/// classified by lifecycle class, **owning no reservation**.
///
/// A submitter broadcasts opaque bytes; it has no knowledge of which
/// reservation (if any) those bytes belong to. The reservation-bound error is
/// the *orchestrator's* ([`SubmitError`](super::error::SubmitError), whose
/// `DaemonRejectedRetryable` / `DaemonAmbiguous` arms carry the
/// [`ReservationId`](super::pending::ReservationId) the orchestrator names).
/// This split makes the former `ReservationId::new(0)` placeholder
/// unrepresentable: a consumer with no re-binder (the 2c `StakeEngine` submit
/// path) can no longer observe — let alone act on — a sentinel rid
/// (`docs/FOLLOWUPS.md` "Submit-error reservation-id placeholder", closed
/// with this split).
///
/// Closed enum: the three variants are the complete lifecycle partition of a
/// completed round trip (`DAEMON_SUBMIT_VERDICT.md` §2.5) — terminal
/// (rebuild), retryable (reservation-preserving resubmit), ambiguous
/// (absence of a verdict, Two Generals).
#[derive(Debug, thiserror::Error)]
pub(crate) enum SubmitterError {
    /// A definite daemon verdict whose remedy is release-and-rebuild.
    #[error("daemon rejected submission terminally: {kind:?}")]
    RejectedTerminal {
        /// The terminal sub-discriminant.
        kind: TerminalErrorKind,
    },
    /// A definite daemon verdict whose remedy preserves the input selection:
    /// resubmit after the per-cause wait.
    #[error("daemon rejected retryably: {cause:?}")]
    RejectedRetryable {
        /// The retryable sub-discriminant.
        cause: RetryableRejectCause,
    },
    /// No daemon verdict was obtained (transport failure): the bytes may or
    /// may not have propagated.
    #[error("daemon submit ambiguous: {kind:?}")]
    Ambiguous {
        /// The ambiguous sub-discriminant.
        kind: AmbiguousErrorKind,
    },
}

/// Which daemon verdict produced a [`SubmitSuccess::Broadcast`] — a
/// fresh `Accepted` or a pool-resident `AlreadyInPool` duplicate.
///
/// An **inform-only sub-fact**: both kinds share the one `Broadcast`
/// disposition (§2.5 — F14 awaiting-confirmation lock, watchdog
/// takeover), and nothing dispatches on this field internally. It exists
/// so the orchestrator can project the Engine-public
/// [`SubmitOutcome`](super::pending::SubmitOutcome) (and the wallet-RPC
/// `ALREADY_IN_POOL` verdict) without re-partitioning the disposition
/// enum — the variant set stays the §2.5 lock-lifecycle partition, so
/// the two kinds' dispositions cannot diverge by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BroadcastKind {
    /// Fresh daemon accept.
    Accepted,
    /// The daemon already held these bytes in its pool (dedup by txid);
    /// also resolves prior transport ambiguity — the earlier attempt
    /// did reach the network.
    AlreadyInPool,
}

impl BroadcastKind {
    /// Project this kind onto the Engine-public
    /// [`SubmitOutcome`](super::pending::SubmitOutcome) Broadcast-class
    /// variant, carrying `hash`.
    ///
    /// The single definition of the kind→outcome mapping, called at the
    /// orchestrator's dispatch sites **after** the accept finalizer
    /// returns — the finalizer itself is deliberately kind-blind (it
    /// never receives this value), so a kind-conditional disposition is
    /// unrepresentable inside the disposition code, not merely untested.
    pub(crate) fn into_outcome(self, hash: TxHash) -> super::pending::SubmitOutcome {
        match self {
            Self::Accepted => super::pending::SubmitOutcome::Accepted { hash },
            Self::AlreadyInPool => super::pending::SubmitOutcome::AlreadyInPool { hash },
        }
    }
}

/// Success surface of a [`TransactionSubmitter`] — the identity-bearing
/// resolutions, split by **lock-lifecycle disposition**
/// (`DAEMON_SUBMIT_VERDICT.md` §2.5).
///
/// `Accepted` and `AlreadyInPool` share a disposition (network-exposed, not
/// settled → the orchestrator places the persisted F14
/// awaiting-confirmation lock, §2.6) and so share the [`Self::Broadcast`]
/// variant, whose [`BroadcastKind`] payload records which verdict it was
/// (inform-only). `AlreadyInChain` is **distinct**: confirmation observed by
/// verdict, refresh remains the settlement authority. The F14 lock is
/// still placed (F40: fund safety first — no selectable-input window in
/// either height case), but baselined at the daemon-claimed confirming
/// `height` rather than the wallet's current height, and `height` routes
/// the *release path* (`docs/FOLLOWUPS.md` "`AlreadyInChain` submit
/// verdict", closed with this split; reshaped to F40 with the `height`
/// carve-out).
///
/// The `hash` on both variants is the **locally**-computed tx id — the
/// daemon reply carries no txid field (wire minimalism, §2.2; the F40
/// `height` is the one reasoned carve-out, and it is a release-path
/// discriminant, never identity or settlement truth).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubmitSuccess {
    /// `Accepted` / `AlreadyInPool`: the bytes are held by the daemon and
    /// network-exposed, not settled. Disposition: F14 awaiting-confirmation
    /// lock; watchdog takes over.
    Broadcast {
        /// The locally computed tx id.
        hash: TxHash,
        /// Which verdict produced this `Broadcast` (inform-only; see
        /// [`BroadcastKind`]).
        kind: BroadcastKind,
    },
    /// `AlreadyInChain`: this txid is in the main chain. Disposition
    /// (F40, §2.5): release the reservation, place the F14 awaiting-lock
    /// in **both** height cases (baselined at `height`); `height` routes
    /// the release path — above-synced waits for refresh to reach the
    /// confirming block (§2.6 path 1); at/below-synced requests a
    /// targeted re-scan (R1: the re-scan never releases; R2: fruitless
    /// re-scans are breaker-bounded).
    AlreadyInChain {
        /// The locally computed tx id.
        hash: TxHash,
        /// Daemon-claimed confirming-block height — the release-path
        /// discriminant (untrusted; damage-capped per §7.2).
        height: u64,
    },
}

/// The canonical genesis transaction id (`GENESIS_TX_WIRE_FORMAT.md` §11) for a
/// serialized blob, or `None` if it is not canonical shekyl-wire: parse the blob and
/// take its 3/4-part `hash()` — **the id the daemon computes**, not a flat
/// `keccak256` of the bytes (which only the in-process test doubles ever agreed with).
pub(crate) fn canonical_tx_id_opt(tx_bytes: &[u8]) -> Option<TxHash> {
    Transaction::from_bytes(tx_bytes).ok().map(|tx| tx.hash())
}

/// Realized fee of the wallet's own built bytes — the wire tx's
/// cleartext `Ct::Fcmp` fee field, the same value the chain sees
/// (`WALLET_SEND_RECORD.md` R-4: the journal records what happened,
/// never what an estimator predicted). Same known-valid-blob contract
/// as [`canonical_tx_id`].
pub(crate) fn wire_fee(tx_bytes: &[u8]) -> u64 {
    let tx = Transaction::from_bytes(tx_bytes)
        .expect("wallet-built tx_bytes parse as canonical shekyl-wire");
    // The transfer path builds an `Fcmp` ct. A shape with no fee field is a
    // build defect, not a fee of zero the journal could record.
    tx.fee().expect("a wallet-built transaction carries a fee")
}

/// [`canonical_tx_id_opt`] for the wallet's own built bytes, which are canonical wire by
/// construction; a parse failure is a build-path defect (panics), not a runtime
/// condition. Used wherever a *known-valid* tx blob needs its id.
pub(crate) fn canonical_tx_id(tx_bytes: &[u8]) -> TxHash {
    canonical_tx_id_opt(tx_bytes).expect("wallet-built tx_bytes parse as canonical shekyl-wire")
}

/// Map a daemon [`Verdict`] onto a [`TxSubmitOutcome`]
/// (`DAEMON_SUBMIT_VERDICT.md` §2.1 → wallet projection).
///
/// `hash` is the **locally**-computed transaction id; the daemon reply
/// is consulted only for the verdict, never for identity — the typed
/// route carries no txid field at all (wire minimalism, §2.2), so an
/// untrusted daemon cannot influence the id the wallet records.
///
/// A 1:1 structural mapping by design: the daemon's Rust admission
/// engine computes the verdict atomically at commit-check time, so
/// there is no client-side flag triage left to do (the legacy
/// `tx_submit` boolean-flag collapse this function used to
/// perform is deleted with that endpoint). The per-cause *dispositions*
/// (§2.5) are applied downstream via [`outcome_to_result`] and the
/// orchestrator's finalizers, keeping mapping and policy separable.
///
/// The wallet interprets the verdict identically over the owner socket and the channel.
pub(crate) fn submit_outcome_from_verdict(verdict: &Verdict, hash: TxHash) -> TxSubmitOutcome {
    match verdict {
        Verdict::Accepted => TxSubmitOutcome::Submitted { hash },
        Verdict::AlreadyInPool { publication } => TxSubmitOutcome::AlreadyInPool {
            hash,
            relay: *publication,
        },
        Verdict::AlreadyInChain { mined_height } => TxSubmitOutcome::AlreadyInChain {
            hash,
            height: mined_height.0,
        },
        Verdict::Rejected { cause } => TxSubmitOutcome::Rejected {
            cause: cause.clone(),
        },
    }
}

/// Collapse a resolved [`TxSubmitOutcome`] to the submitter's public
/// `Result<SubmitSuccess, SubmitterError>`. Shared by both submitters so
/// the outcome→error mapping cannot drift between the principal and per-`P`
/// paths. A daemon *verdict* only — a transport failure never reaches
/// here; it is mapped to [`SubmitterError::Ambiguous`] at the call
/// site (absence-of-verdict is not an outcome, §5.2).
///
/// The `Ok` arm splits by lock-lifecycle disposition (§2.5):
/// `AlreadyInPool` is the same disposition as a fresh accept (the bytes
/// are held; it also resolves prior transport ambiguity) →
/// [`SubmitSuccess::Broadcast`], with the verdict recorded in the
/// inform-only [`BroadcastKind`]; `AlreadyInChain` is confirmation observed
/// by verdict (refresh remains the settlement authority) →
/// [`SubmitSuccess::AlreadyInChain`]. Rejections split by remedy class:
///
/// - **Terminal** (locks released, reservation gone):
///   `Malformed` / `FeeTooLow` / `DoubleSpendConflict` / `Unrecognized`
///   → [`SubmitterError::RejectedTerminal`].
/// - **Retryable** (reservation restored to `consumer_held`, locks
///   retained): `StaleRoot` / `ReferenceTooRecent` / `ReferenceNotFound`
///   → [`SubmitterError::RejectedRetryable`]. The submitter surface is
///   reservation-unaware; the orchestrator binds its own rid when it
///   converts the class into its reservation-bound
///   [`SubmitError`](super::error::SubmitError).
pub(crate) fn outcome_to_result(outcome: TxSubmitOutcome) -> Result<SubmitSuccess, SubmitterError> {
    match outcome {
        TxSubmitOutcome::Submitted { hash } => Ok(SubmitSuccess::Broadcast {
            hash,
            kind: BroadcastKind::Accepted,
        }),
        TxSubmitOutcome::AlreadyInPool { hash, .. } => Ok(SubmitSuccess::Broadcast {
            hash,
            kind: BroadcastKind::AlreadyInPool,
        }),
        TxSubmitOutcome::AlreadyInChain { hash, height } => {
            Ok(SubmitSuccess::AlreadyInChain { hash, height })
        }
        TxSubmitOutcome::Rejected { cause } => Err(submitter_error_from_cause(&cause)),
    }
}

/// Split a [`Rejection`] into the terminal / retryable error classes
/// per the §2.5 disposition table. Factored out of [`outcome_to_result`]
/// so the cause→class mapping is a single, testable site.
fn submitter_error_from_cause(cause: &Rejection) -> SubmitterError {
    let terminal = |kind| SubmitterError::RejectedTerminal { kind };
    let retryable = |cause| SubmitterError::RejectedRetryable { cause };
    match cause {
        Rejection::Malformed => terminal(TerminalErrorKind::Malformed),
        // Terminal with its row, which rides inside the cause (IG-Q76). A
        // row this wallet cannot carry whole takes the fail-safe
        // disposition.
        Rejection::ConsensusRule(row) => match CenRowName::parse(&row.0) {
            Some(row) => terminal(TerminalErrorKind::ConsensusRule { row }),
            None => terminal(TerminalErrorKind::Unrecognized),
        },
        Rejection::FeeTooLow => terminal(TerminalErrorKind::FeeTooLow),
        Rejection::DoubleSpendConflict => terminal(TerminalErrorKind::DoubleSpend),
        Rejection::Unrecognized => terminal(TerminalErrorKind::Unrecognized),
        Rejection::StaleRoot => retryable(RetryableRejectCause::StaleRoot),
        Rejection::ReferenceTooRecent => retryable(RetryableRejectCause::ReferenceTooRecent),
        Rejection::ReferenceUnknown => retryable(RetryableRejectCause::ReferenceNotFound),
    }
}

/// Broadcast signed transaction bytes to the network.
///
/// Takes [`DurableTxBytes`], not raw bytes: a caller can only hand over
/// bytes whose record is already durably on disk
/// ([`dispatch_durability`](super::dispatch_durability), A19).
pub(crate) trait TransactionSubmitter: Send + Sync + 'static {
    fn submit(
        &self,
        tx: DurableTxBytes,
    ) -> impl std::future::Future<Output = Result<SubmitSuccess, SubmitterError>> + Send;
}

/// [`DaemonEngine`]-backed submitter (Phase 2a §5).
pub struct DaemonTransactionSubmitter<D> {
    daemon: Arc<D>,
}

impl<D> DaemonTransactionSubmitter<D> {
    pub(crate) fn new(daemon: Arc<D>) -> Self {
        Self { daemon }
    }
}

impl<D> TransactionSubmitter for DaemonTransactionSubmitter<D>
where
    D: DaemonEngine,
{
    async fn submit(&self, tx: DurableTxBytes) -> Result<SubmitSuccess, SubmitterError> {
        let tx_bytes = tx.into_bytes();
        // Debug-only consistency guard: the `DaemonEngine` impl's accept outcome must
        // carry the same hash this computes locally. Computed only in debug builds so
        // release does no extra parse. Graceful on a malformed blob (the daemon path
        // returns `Malformed`; the check below fires only on an accept outcome).
        #[cfg(debug_assertions)]
        let local_hash = canonical_tx_id_opt(&tx_bytes);
        let outcome = self
            .daemon
            .submit_transaction(tx_bytes)
            .await
            .map_err(|error| {
                // The verdict's absence is ambiguous to the caller (Two
                // Generals), but what the transport saw is not a secret:
                // the log says it, so an operator reading "unavailable"
                // can tell a refused connection from a reply that was not
                // a verdict.
                let error: crate::engine::error::IoError = error.into();
                tracing::warn!(%error, "submit: the daemon gave no verdict");
                SubmitterError::Ambiguous {
                    kind: AmbiguousErrorKind::DaemonUnavailable,
                }
            })?;
        // The typed verdict carries NO txid field — neither path reads an id back from
        // the daemon (identity is always locally computed, anti-untrusted-daemon).
        // So this compares two LOCAL hash pipelines and catches a `DaemonEngine` *impl*
        // (a test double / fault injector) that returns a divergent outcome hash — NOT
        // a remote identity assertion.
        #[cfg(debug_assertions)]
        if let TxSubmitOutcome::Submitted { hash }
        | TxSubmitOutcome::AlreadyInPool { hash, .. }
        | TxSubmitOutcome::AlreadyInChain { hash, .. } = &outcome
        {
            debug_assert_eq!(
                Some(*hash),
                local_hash,
                "DaemonEngine impl outcome hash must equal the local canonical wire tx hash"
            );
        }
        outcome_to_result(outcome)
    }
}

/// Failure surface of [`BroadcastSubmitter::submit_bound`]: either the
/// pre-flight pairing check refused the dispatch (nothing reached a wire), or
/// the delegated submit itself failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BroadcastSubmitError {
    /// The bytes' bound persona does not match the submitter's
    /// constructor-bound persona. A build-path defect (the single-mint-site
    /// P-1 pin makes it unreachable from production flow); fail-closed —
    /// the bytes never reached a transport. `Debug` on [`PCanonicalId`] is
    /// truncated, so rendering this error leaks no full persona id.
    #[error("persona mismatch: bytes bound to {bytes_persona:?} handed to a submitter bound to {submitter_persona:?}")]
    PersonaMismatch {
        /// The persona the bytes were bound to at mint.
        bytes_persona: PCanonicalId,
        /// The persona selected by the wallet for this dispatch.
        submitter_persona: PCanonicalId,
    },
    /// The pairing was sound; the delegated submit failed.
    #[error(transparent)]
    Submit(#[from] SubmitterError),
    /// The pending-store save that would seal these bytes failed, or was
    /// applied and its durability not confirmed
    /// ([`super::error::PersistenceError`] says which and names the fix).
    /// Nothing was sent, and the seal was taken back
    /// ([`PendingPostStore::seal_reporting`](super::pscan::dispatch::PendingPostStore::seal_reporting)).
    #[error("nothing was sent: {0}")]
    SealNotSaved(#[source] super::error::PersistenceError),
}

/// A [`PBoundBytes`] whose record is
/// durable enough to broadcast.
///
/// [`Self::Fresh`] carries the durability the pending-store save just
/// returned. [`Self::Loaded`] is a record read back from that store while a
/// save of it confirmed in this process covered it.
pub(crate) enum BoundForSend {
    /// Sealed by the save that returned this durability.
    Fresh(PBoundBytes, shekyl_engine_file::Durability),
    /// Read back from the pending store, under its coverage.
    Loaded(super::bond_assembly::LoadedSeal),
}

impl BoundForSend {
    /// The persona these bytes are bound to.
    pub(crate) fn persona(&self) -> &PCanonicalId {
        match self {
            Self::Fresh(bound, _) => bound.persona(),
            Self::Loaded(seal) => seal.persona(),
        }
    }

    /// The transaction bytes, before the hand-off consumes them.
    ///
    /// Test broadcasts record the bytes they were handed. Production
    /// reads them through [`Self::into_durable`].
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Fresh(bound, _) => bound.bytes(),
            Self::Loaded(seal) => seal.bytes(),
        }
    }

    fn into_durable(
        self,
    ) -> Result<super::dispatch_durability::DurableTxBytes, super::error::PersistenceError> {
        match self {
            Self::Fresh(bound, durability) => {
                super::dispatch_durability::DurableTxBytes::from_fresh_seal(bound, durability)
            }
            Self::Loaded(seal) => {
                Ok(super::dispatch_durability::DurableTxBytes::from_loaded_seal(seal))
            }
        }
    }
}

/// A persona's signed transaction goes through its wallet's operator-owned daemon.
/// Check the durable transaction's persona before handing the bytes to that daemon.
pub(crate) struct BroadcastSubmitter<D> {
    persona: PCanonicalId,
    daemon: DaemonTransactionSubmitter<D>,
}

impl<D: DaemonEngine> BroadcastSubmitter<D> {
    pub(crate) fn for_wallet(persona: PCanonicalId, daemon: Arc<D>) -> Self {
        Self {
            persona,
            daemon: DaemonTransactionSubmitter::new(daemon),
        }
    }

    /// Submit `P`-bound bytes through the dispatch, enforcing the
    /// byte↔persona pairing at the choke point (§3.1 part 4).
    ///
    /// A mismatch fails before the handoff to the daemon.
    pub(crate) async fn submit_bound(
        &self,
        handoff: BoundForSend,
    ) -> Result<SubmitSuccess, BroadcastSubmitError> {
        if handoff.persona() != &self.persona {
            debug_assert!(
                false,
                "submit_bound: bytes bound to {:?} handed to a submitter bound to {:?} — \
                     a P-bound tx must be dispatched through the submitter constructed for \
                     its own persona (§3.1 part 4; the P-1 single-mint-site pin makes this \
                     unreachable from production flow)",
                handoff.persona(),
                self.persona,
            );
            return Err(BroadcastSubmitError::PersonaMismatch {
                bytes_persona: *handoff.persona(),
                submitter_persona: self.persona,
            });
        }
        let tx = handoff.into_durable().map_err(|error| {
            tracing::warn!(%error, "submit_bound: the seal was not confirmed; nothing was sent");
            BroadcastSubmitError::SealNotSaved(error)
        })?;
        Ok(self.daemon.submit(tx).await?)
    }
}

#[cfg(test)]
#[path = "transaction_submitter_tests.rs"]
mod tests;
