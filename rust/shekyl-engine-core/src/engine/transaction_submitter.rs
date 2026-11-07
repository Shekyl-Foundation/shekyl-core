// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction broadcast capability for [`super::local_pending_tx::LocalPendingTx`].

use std::sync::Arc;

use shekyl_p_transport::{PTorClient, PTransportError, TorSocksEndpoint};
use shekyl_rpc_client::{RejectCause, Rpc, SubmitVerdict};
use shekyl_types::PCanonicalId;
use shekyl_wire::Transaction;

use super::bond_assembly::PBoundBytes;
use super::error::{AmbiguousErrorKind, CenRowName, RetryableRejectCause, TerminalErrorKind};
use super::pending::TxHash;
use super::posture::BroadcastPosture;
use super::prpc::PRpc;
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
    match tx.ct {
        shekyl_wire::Ct::Fcmp { fee, .. } => fee,
        // The transfer dispatch path never builds a Null-ct shape; a
        // fee-less shape honestly has fee 0.
        shekyl_wire::Ct::Null(_) => 0,
    }
}

/// [`canonical_tx_id_opt`] for the wallet's own built bytes, which are canonical wire by
/// construction; a parse failure is a build-path defect (panics), not a runtime
/// condition. Used wherever a *known-valid* tx blob needs its id.
pub(crate) fn canonical_tx_id(tx_bytes: &[u8]) -> TxHash {
    canonical_tx_id_opt(tx_bytes).expect("wallet-built tx_bytes parse as canonical shekyl-wire")
}

/// Map a daemon [`SubmitVerdict`] onto a [`TxSubmitOutcome`]
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
/// `send_raw_transaction` boolean-flag collapse this function used to
/// perform is deleted with that endpoint). The per-cause *dispositions*
/// (§2.5) are applied downstream via [`outcome_to_result`] and the
/// orchestrator's finalizers, keeping mapping and policy separable.
///
/// Transport-agnostic: shared by the principal `DaemonClient` and the
/// per-`P` [`PTransactionSubmitter`] (SP-T4a) — a daemon verdict is
/// interpreted the same regardless of which circuit carried it.
pub(crate) fn submit_outcome_from_verdict(
    verdict: &SubmitVerdict,
    hash: TxHash,
) -> TxSubmitOutcome {
    match verdict {
        SubmitVerdict::Accepted => TxSubmitOutcome::Submitted { hash },
        SubmitVerdict::AlreadyInPool { relay } => TxSubmitOutcome::AlreadyInPool {
            hash,
            relay: *relay,
        },
        SubmitVerdict::AlreadyInChain { height } => TxSubmitOutcome::AlreadyInChain {
            hash,
            height: *height,
        },
        SubmitVerdict::Rejected { cause, row } => TxSubmitOutcome::Rejected {
            cause: *cause,
            row: row.as_deref().and_then(CenRowName::parse),
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
        TxSubmitOutcome::Rejected { cause, row } => Err(submitter_error_from_cause(cause, row)),
    }
}

/// Split a [`RejectCause`] into the terminal / retryable error classes
/// per the §2.5 disposition table. Factored out of [`outcome_to_result`]
/// so the cause→class mapping is a single, testable site.
fn submitter_error_from_cause(cause: RejectCause, row: Option<CenRowName>) -> SubmitterError {
    let terminal = |kind| SubmitterError::RejectedTerminal { kind };
    let retryable = |cause| SubmitterError::RejectedRetryable { cause };
    match cause {
        RejectCause::Malformed => terminal(TerminalErrorKind::Malformed),
        // Terminal with its row. A reply that names no row, or one this
        // wallet cannot carry whole, takes the fail-safe disposition.
        RejectCause::ConsensusRule => match row {
            Some(row) => terminal(TerminalErrorKind::ConsensusRule { row }),
            None => terminal(TerminalErrorKind::Unrecognized),
        },
        RejectCause::FeeTooLow => terminal(TerminalErrorKind::FeeTooLow),
        RejectCause::DoubleSpendConflict => terminal(TerminalErrorKind::DoubleSpend),
        RejectCause::Unrecognized => terminal(TerminalErrorKind::Unrecognized),
        RejectCause::StaleRoot => retryable(RetryableRejectCause::StaleRoot),
        RejectCause::ReferenceTooRecent => retryable(RetryableRejectCause::ReferenceTooRecent),
        RejectCause::ReferenceNotFound => retryable(RetryableRejectCause::ReferenceNotFound),
    }
}

/// Broadcast signed transaction bytes to the network.
pub(crate) trait TransactionSubmitter: Send + Sync + 'static {
    fn submit(
        &self,
        tx_bytes: Vec<u8>,
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
    async fn submit(&self, tx_bytes: Vec<u8>) -> Result<SubmitSuccess, SubmitterError> {
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
        // a lying daemon. `DaemonEngine`-path-specific: the per-`P` submitter feeds its
        // own locally-computed hash straight into the shared mapper, nothing to check.
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

/// The 2d-2 **remote-posture** transaction submitter: broadcasts `P`'s signed
/// transactions over `P`'s **own** Tor circuit via [`PRpc`] — the write-side
/// mirror of `PBlockSource` (SP-T4a, CX-2; `ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md`).
///
/// Constructed **only** via [`Self::for_persona`], which builds the circuit-bound
/// [`PTorClient`] internally from the persona id: no principal-`DaemonClient`
/// path, no `Default`, and no constructor accepting a pre-built transport whose
/// circuit could belong to a *different* persona — persona↔circuit binding is by
/// construction (mirrors `PBlockSource`, one direction over, tightened per §3.1
/// part 4). The submitter retains the bound [`PCanonicalId`] so the
/// [`BroadcastSubmitter`] choke point can equality-check byte↔persona pairing.
/// **Honest scope (§3A):** construction-closure does **not** stop handing `P`'s
/// tx **bytes** to the *principal* `DaemonTransactionSubmitter` (the
/// `submit(Vec<u8>)` trait takes opaque, persona-unbound bytes); that routing is
/// closed by the [`BroadcastSubmitter`] constructor choke point (②→here, never
/// the principal) plus the [`PBoundBytes`] pairing check at its façade.
//
// Lint-visible: the claim, drain and pscan dispatch paths exercise this, so no
// suppression applies. The gated **2c-2b** bond-assembly + request-path wiring
// (`stake_engine.rs` `TODO(2d)`) is the remaining consumer — NOT the posture
// selector, which resolves a posture and never a submitter.
pub(crate) struct PTransactionSubmitter {
    persona: PCanonicalId,
    rpc: PRpc,
}

impl PTransactionSubmitter {
    /// Build a remote-posture submitter broadcasting over `persona`'s **own**
    /// circuit (through `socks`) to `base_url`. The transport is constructed
    /// here from the persona id, so the circuit and the retained
    /// [`Self::persona`] cannot disagree.
    pub(crate) fn for_persona(
        persona: PCanonicalId,
        socks: &TorSocksEndpoint,
        base_url: String,
    ) -> Result<Self, PTransportError> {
        let client = PTorClient::for_persona(&persona, socks)?;
        Ok(Self {
            persona,
            rpc: PRpc::new(client, base_url),
        })
    }

    /// The persona whose circuit carries this submitter's broadcasts.
    pub(crate) fn persona(&self) -> &PCanonicalId {
        &self.persona
    }
}

impl TransactionSubmitter for PTransactionSubmitter {
    async fn submit(&self, tx_bytes: Vec<u8>) -> Result<SubmitSuccess, SubmitterError> {
        // Local, fail-closed tx id. The bytes are a wallet-built, fully-assembled
        // signed transaction (for the bond path, the tx carrying the bond vin), so a
        // parse failure is a build-path defect — map it to the same `Malformed`
        // terminal the `DaemonEngine` path returns rather than panicking, and never
        // reach the network with an unparseable blob.
        let Some(hash) = canonical_tx_id_opt(&tx_bytes) else {
            return Err(SubmitterError::RejectedTerminal {
                kind: TerminalErrorKind::Malformed,
            });
        };
        // Broadcast over `P`'s own circuit. **SP-T4a axis 4 (ambiguous partial
        // failure):** ANY transport error → [`SubmitterError::Ambiguous`], never
        // a retry decision derived from `PRpc`'s fetch-style `classify`. A dropped
        // connection does not tell us whether the tx propagated, so absence-of-a-
        // daemon-verdict is *ambiguous*, not a retryable transient — the write-side
        // inversion of the fetch default.
        //
        // This submitter's job ENDS here: map honestly and stop. Under the typed
        // verdict the post-ambiguity retry is a *status query* (§2.5): a same-bytes
        // resubmit of a pool-resident tx returns `AlreadyInPool` (no relay pulse,
        // F31), a mined one `AlreadyInChain`, and the dangerous windows are now
        // named verdicts rather than flag-triage guesses — a tx evicted under pool
        // pressure returns `Rejected{FeeTooLow}`, an aged-out reference
        // `Rejected{StaleRoot}`. And dropping this future detaches the
        // `spawn_blocking` POST, which may still broadcast — a cancelled submit is
        // ambiguous too. (See `ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §2 axis 4 +
        // the 2c submit-outcome-partition obligation in `FOLLOWUPS.md`.)
        let resp = self.rpc.publish_transaction(&tx_bytes).await.map_err(|_| {
            // The submitter owns no reservation, and now cannot claim one:
            // `SubmitterError` carries no rid, so the P seam's 2c consumer
            // (StakeEngine, which has no orchestrator re-binder) can no longer
            // observe a sentinel reservation (`docs/FOLLOWUPS.md` closure).
            SubmitterError::Ambiguous {
                kind: AmbiguousErrorKind::DaemonUnavailable,
            }
        })?;
        // A daemon *verdict* is mapped by the shared helpers — identical to the
        // principal path, so the two cannot drift.
        outcome_to_result(submit_outcome_from_verdict(&resp, hash))
    }
}

// ============================================================================
// Posture→submitter dispatch (SP-T4a §3.1, FROZEN 2026-07-04, user-ratified)
// ============================================================================

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
        /// The persona whose circuit this submitter carries.
        submitter_persona: PCanonicalId,
    },
    /// The pairing was sound; the delegated submit failed.
    #[error(transparent)]
    Submit(#[from] SubmitterError),
}

/// Tor's conventional local SOCKS port. A **placeholder** feeding
/// [`BroadcastSubmitter::local`]'s pre-bound ① construction: the `Local`
/// arm never dials SOCKS (it ignores the endpoint entirely), but
/// construction must stay on the audited posture→submitter choke point
/// rather than reach around it to a bare submitter.
const TOR_SOCKS_PLACEHOLDER_PORT: u16 = 9050;

/// The closed-set posture→submitter dispatch
/// (`ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §3.1, frozen 2026-07-04): the
/// broadcast submitter set is closed *by type* — [`BroadcastPosture`] has no
/// `ThirdParty` variant (invariant B), so this enum states the closed set for
/// free where a boxed `dyn` shim would pay allocation to erase it.
/// Match-delegation is output-agnostic (§3.1 part 5): it carries through the
/// `SubmitVerdict` reshapes unchanged, and "both submitters share the
/// mapping" is literal — one [`outcome_to_result`], two transports, one
/// dispatch type.
///
/// Construction goes through [`Self::for_posture`] — the single choke point
/// that owns the ②→[`Self::PerP`] routing guard (invariant A's open
/// obligation, closed here).
//
// Lint-visible: exercised by the dispatch paths, so no suppression applies.
// The 2c-2b bond-assembly + request-path wiring (`stake_engine.rs` `TODO(2d)`)
// is the remaining consumer.
pub(crate) enum BroadcastSubmitter<D> {
    /// ① The principal's loopback submitter. The wallet's own local daemon
    /// observing `P`'s tx is conceded (§3.1 part 3): it is the operator's
    /// node, and loopback never crosses the network — so this arm carries no
    /// persona binding and [`Self::submit_bound`]'s pairing check is
    /// inapplicable here by design, not by omission.
    Local(DaemonTransactionSubmitter<D>),
    /// ② `P`'s own circuit to the operator's remote node. The arm the
    /// routing guard protects: an `OwnRemote` posture resolves here and
    /// never to the principal submitter.
    PerP(PTransactionSubmitter),
}

impl<D: DaemonEngine> BroadcastSubmitter<D> {
    /// The single construction choke point: posture in, submitter out
    /// (§3.1 part 2). [`super::posture::select_broadcast`] stays
    /// posture-only (it resolves a posture, never a submitter); the
    /// posture→submitter binding lives here so the routing guard —
    /// ②→[`Self::PerP`], **never** the principal submitter — is a property
    /// of one audited constructor, not a convention at call sites.
    ///
    /// `local_daemon` feeds the ① arm; `persona` + `socks` feed the ② arm
    /// (the `DaemonUrl` newtype slots into the ② construction path when it
    /// lands — FOLLOWUPS, 2c config-source slice).
    ///
    /// # Errors
    ///
    /// [`PTransportError`] when the ② arm's SOCKS proxy configuration is
    /// rejected; the ① arm is infallible.
    pub(crate) fn for_posture(
        posture: BroadcastPosture,
        persona: PCanonicalId,
        local_daemon: Arc<D>,
        socks: &TorSocksEndpoint,
    ) -> Result<Self, PTransportError> {
        match posture {
            // ① — the operator's own loopback node (conceded observer).
            BroadcastPosture::Local => {
                Ok(Self::Local(DaemonTransactionSubmitter::new(local_daemon)))
            }
            // ② — ALWAYS the per-`P` submitter over `P`'s own circuit. Do
            // not add a principal-submitter shortcut here: routing an
            // OwnRemote broadcast over the shared principal connection is
            // the first-seen-origin leak the whole dispatch exists to close.
            BroadcastPosture::OwnRemote { base_url } => Ok(Self::PerP(
                PTransactionSubmitter::for_persona(persona, socks, base_url)?,
            )),
        }
    }

    /// The hardwired ① `Local`-posture construction — the operator's own
    /// loopback node, the privacy default — shared by every seam that
    /// dispatches through it today (the WI-3 bond broadcast, the CB-3
    /// claim dispatch, the regtest harness), so the placeholder-endpoint
    /// idiom exists once instead of as drifting copies. Still the audited
    /// choke point: this is [`Self::for_posture`] with the ① arm's inputs
    /// pre-bound. The operator's explicit ② posture choice plugs in via
    /// the 2c config-source slice, which swaps the call sites' posture,
    /// not this constructor.
    pub(crate) fn local(persona: PCanonicalId, local_daemon: Arc<D>) -> Self {
        Self::for_posture(
            BroadcastPosture::Local,
            persona,
            local_daemon,
            // Tor's conventional local SOCKS port — a placeholder feeding
            // the signature: the ① arm never dials SOCKS.
            &TorSocksEndpoint::loopback(TOR_SOCKS_PLACEHOLDER_PORT),
        )
        // The ① arm is infallible (`for_posture` docs): only the ② arm's
        // SOCKS proxy configuration can be rejected, and ① never builds one.
        .expect("the Local arm of for_posture is infallible")
    }

    /// Submit `P`-bound bytes through the dispatch, enforcing the
    /// byte↔persona pairing at the choke point (§3.1 part 4).
    ///
    /// On the [`Self::PerP`] arm the bytes' bound persona is
    /// equality-checked against the submitter's constructor-bound persona —
    /// the `validate_handle` discipline: `debug_assert` loud in dev,
    /// fail-closed [`BroadcastSubmitError::PersonaMismatch`] in release. On
    /// the [`Self::Local`] arm the check is inapplicable (conceded loopback,
    /// see the variant docs) and the bytes delegate directly.
    pub(crate) async fn submit_bound(
        &self,
        bound: PBoundBytes,
    ) -> Result<SubmitSuccess, BroadcastSubmitError> {
        if let Self::PerP(submitter) = self {
            if bound.persona() != submitter.persona() {
                debug_assert!(
                    false,
                    "submit_bound: bytes bound to {:?} handed to a submitter bound to {:?} — \
                     a P-bound tx must be dispatched through the submitter constructed for \
                     its own persona (§3.1 part 4; the P-1 single-mint-site pin makes this \
                     unreachable from production flow)",
                    bound.persona(),
                    submitter.persona(),
                );
                return Err(BroadcastSubmitError::PersonaMismatch {
                    bytes_persona: *bound.persona(),
                    submitter_persona: *submitter.persona(),
                });
            }
        }
        Ok(self.submit(bound.into_bytes()).await?)
    }
}

impl<D: DaemonEngine> TransactionSubmitter for BroadcastSubmitter<D> {
    /// Match-delegation (§3.1 part 1): one unified `Send` future, no `Box`.
    /// The trait surface takes persona-unbound bytes for generic consumers
    /// (the shared verdict mapping, the watchdog probe rung); the `P`-bound
    /// path goes through [`Self::submit_bound`], and the P-2 store-wrapped
    /// pin keeps retries on that façade.
    async fn submit(&self, tx_bytes: Vec<u8>) -> Result<SubmitSuccess, SubmitterError> {
        match self {
            Self::Local(submitter) => submitter.submit(tx_bytes).await,
            Self::PerP(submitter) => submitter.submit(tx_bytes).await,
        }
    }
}

#[cfg(test)]
#[path = "transaction_submitter_tests.rs"]
mod tests;
