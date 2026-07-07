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
use super::error::{AmbiguousErrorKind, RetryableRejectCause, TerminalErrorKind};
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

/// Success surface of a [`TransactionSubmitter`] — the identity-bearing
/// resolutions, split by **lock-lifecycle disposition**
/// (`DAEMON_SUBMIT_VERDICT.md` §2.5).
///
/// `Accepted` and `AlreadyInPool` share a disposition (network-exposed, not
/// settled → the orchestrator places the persisted F14
/// awaiting-confirmation lock, §2.6) and so share the [`Self::Broadcast`]
/// variant. `AlreadyInChain` is **distinct**: confirmation observed by
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
/// `cn_fast_hash` of the bytes (which only the in-process test doubles ever agreed with).
pub(crate) fn canonical_tx_id_opt(tx_bytes: &[u8]) -> Option<TxHash> {
    Transaction::from_bytes(tx_bytes)
        .ok()
        .map(|tx| TxHash::from_bytes(tx.hash()))
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
        SubmitVerdict::AlreadyInPool => TxSubmitOutcome::AlreadyInPool { hash },
        SubmitVerdict::AlreadyInChain { height } => TxSubmitOutcome::AlreadyInChain {
            hash,
            height: *height,
        },
        SubmitVerdict::Rejected { cause } => TxSubmitOutcome::Rejected { cause: *cause },
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
/// [`SubmitSuccess::Broadcast`]; `AlreadyInChain` is confirmation observed
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
        TxSubmitOutcome::Submitted { hash } | TxSubmitOutcome::AlreadyInPool { hash } => {
            Ok(SubmitSuccess::Broadcast { hash })
        }
        TxSubmitOutcome::AlreadyInChain { hash, height } => {
            Ok(SubmitSuccess::AlreadyInChain { hash, height })
        }
        TxSubmitOutcome::Rejected { cause } => Err(submitter_error_from_cause(cause)),
    }
}

/// Split a [`RejectCause`] into the terminal / retryable error classes
/// per the §2.5 disposition table. Factored out of [`outcome_to_result`]
/// so the cause→class mapping is a single, testable site.
fn submitter_error_from_cause(cause: RejectCause) -> SubmitterError {
    let terminal = |kind| SubmitterError::RejectedTerminal { kind };
    let retryable = |cause| SubmitterError::RejectedRetryable { cause };
    match cause {
        RejectCause::Malformed => terminal(TerminalErrorKind::Malformed),
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
            .map_err(|_| SubmitterError::Ambiguous {
                kind: AmbiguousErrorKind::DaemonUnavailable,
            })?;
        // The typed verdict carries NO txid field — neither path reads an id back from
        // the daemon (identity is always locally computed, anti-untrusted-daemon).
        // So this compares two LOCAL hash pipelines and catches a `DaemonEngine` *impl*
        // (a test double / fault injector) that returns a divergent outcome hash — NOT
        // a lying daemon. `DaemonEngine`-path-specific: the per-`P` submitter feeds its
        // own locally-computed hash straight into the shared mapper, nothing to check.
        #[cfg(debug_assertions)]
        if let TxSubmitOutcome::Submitted { hash }
        | TxSubmitOutcome::AlreadyInPool { hash }
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
// `allow(dead_code)`: transient — the non-test consumer is the gated **2c-2b**
// bond-assembly + request-path wiring (see `stake_engine.rs` `TODO(2d)`), NOT the
// posture selector (which resolves a posture, never a submitter). The dead-proxy
// proving test ships with the enabler; not deferred.
#[allow(dead_code)]
pub(crate) struct PTransactionSubmitter {
    persona: PCanonicalId,
    rpc: PRpc,
}

#[allow(dead_code)]
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
#[allow(dead_code)] // transient — the non-test consumer is the 2c-2b request path.
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
// `allow(dead_code)`: transient — the non-test consumer is the 2c-2b
// bond-assembly + request-path wiring (`stake_engine.rs` `TODO(2d)`).
#[allow(dead_code)]
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

#[allow(dead_code)]
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
mod tests {
    //! Submit-path tests: the transport-agnostic verdict → outcome →
    //! error-class mapping regressions (`DAEMON_SUBMIT_VERDICT.md` §2.1 /
    //! §2.5, exercised directly against `SubmitVerdict` values — no live
    //! daemon), plus the per-`P` `PTransactionSubmitter`'s
    //! ambiguous-failure + username-non-leak proof (SP-T4a).
    use super::*;

    /// Every identity-bearing verdict maps 1:1 and carries the locally
    /// computed hash — never a daemon-supplied id.
    #[test]
    fn verdicts_map_structurally() {
        let hash = TxHash::from_bytes([7u8; 32]);
        assert_eq!(
            submit_outcome_from_verdict(&SubmitVerdict::Accepted, hash),
            TxSubmitOutcome::Submitted { hash }
        );
        assert_eq!(
            submit_outcome_from_verdict(&SubmitVerdict::AlreadyInPool, hash),
            TxSubmitOutcome::AlreadyInPool { hash }
        );
        assert_eq!(
            submit_outcome_from_verdict(&SubmitVerdict::AlreadyInChain { height: 42 }, hash),
            TxSubmitOutcome::AlreadyInChain { hash, height: 42 },
            "the F40 height passes through the projection untouched"
        );
        assert_eq!(
            submit_outcome_from_verdict(
                &SubmitVerdict::Rejected {
                    cause: RejectCause::Malformed
                },
                hash
            ),
            TxSubmitOutcome::Rejected {
                cause: RejectCause::Malformed
            }
        );
    }

    /// All three identity-bearing outcomes resolve `Ok`, split by
    /// lock-lifecycle disposition (§2.5): a fresh accept and a
    /// pool-resident duplicate share `Broadcast` (network-exposed, F14
    /// lock placed); a mined duplicate is the distinct `AlreadyInChain`
    /// (F40: lock placed too, baselined at the carried `height`, which
    /// routes the release path). All carry the locally computed hash.
    #[test]
    fn identity_outcomes_resolve_ok_split_by_disposition() {
        let hash = TxHash::from_bytes([9u8; 32]);
        for outcome in [
            TxSubmitOutcome::Submitted { hash },
            TxSubmitOutcome::AlreadyInPool { hash },
        ] {
            assert_eq!(
                outcome_to_result(outcome).expect("identity outcome"),
                SubmitSuccess::Broadcast { hash }
            );
        }
        assert_eq!(
            outcome_to_result(TxSubmitOutcome::AlreadyInChain { hash, height: 77 })
                .expect("identity outcome"),
            SubmitSuccess::AlreadyInChain { hash, height: 77 }
        );
    }

    /// Terminal causes (release + rebuild recourse) map to
    /// `DaemonRejectedTerminal` with the matching kind.
    #[test]
    fn terminal_causes_map_to_terminal_kinds() {
        for (cause, expected) in [
            (RejectCause::Malformed, TerminalErrorKind::Malformed),
            (RejectCause::FeeTooLow, TerminalErrorKind::FeeTooLow),
            (
                RejectCause::DoubleSpendConflict,
                TerminalErrorKind::DoubleSpend,
            ),
            (RejectCause::Unrecognized, TerminalErrorKind::Unrecognized),
        ] {
            let err =
                outcome_to_result(TxSubmitOutcome::Rejected { cause }).expect_err("terminal cause");
            assert!(
                matches!(err, SubmitterError::RejectedTerminal { kind } if kind == expected),
                "cause {cause:?} must map to terminal kind {expected:?}, got {err:?}"
            );
        }
    }

    /// Retryable causes (reservation preserved, resubmit after the
    /// per-cause wait) map to `DaemonRejectedRetryable`.
    #[test]
    fn retryable_causes_map_to_retryable_class() {
        for (cause, expected) in [
            (RejectCause::StaleRoot, RetryableRejectCause::StaleRoot),
            (
                RejectCause::ReferenceTooRecent,
                RetryableRejectCause::ReferenceTooRecent,
            ),
            (
                RejectCause::ReferenceNotFound,
                RetryableRejectCause::ReferenceNotFound,
            ),
        ] {
            let err = outcome_to_result(TxSubmitOutcome::Rejected { cause })
                .expect_err("retryable cause");
            assert!(
                matches!(
                    err,
                    SubmitterError::RejectedRetryable { cause: got } if got == expected
                ),
                "cause {cause:?} must map to retryable {expected:?}, got {err:?}"
            );
        }
    }

    /// SP-T4a axis 4 + invariant (a): a broadcast whose **transport** fails
    /// surfaces as [`SubmitterError::Ambiguous`] — we cannot know whether it
    /// propagated, so it is *not* a retryable transient — and the error rendering
    /// must never leak the SOCKS username. No Tor: a closed SOCKS port (`:1`)
    /// refuses immediately, so the `spawn_blocking` bridge + error mapping run
    /// fast. The tx bytes are a serialized synthetic coinbase — valid wire, so the
    /// submitter reaches the transport rather than short-circuiting on the local
    /// parse guard (which would return `Malformed`, a different arm).
    #[tokio::test(flavor = "multi_thread")]
    async fn broadcast_over_a_dead_proxy_is_a_username_free_ambiguous_error() {
        use shekyl_p_transport::TorSocksEndpoint;
        use shekyl_types::PCanonicalId;

        use crate::engine::test_support::make_synthetic_block;

        let mut tx_bytes = Vec::new();
        make_synthetic_block(0, [0u8; 32])
            .block
            .miner_transaction
            .write(&mut tx_bytes)
            .expect("serialize synthetic coinbase to canonical wire");

        let persona = PCanonicalId::from_bytes([5u8; 32]);
        // A parallel client for the same persona: `derive_socks_user` is
        // deterministic, so its username equals the one the submitter's
        // internally-built transport carries.
        let username = PTorClient::for_persona(&persona, &TorSocksEndpoint::loopback(1))
            .expect("proxy config is well-formed")
            .username()
            .as_str()
            .to_owned();
        let submitter = PTransactionSubmitter::for_persona(
            persona,
            &TorSocksEndpoint::loopback(1),
            "http://127.0.0.1:18081".to_string(),
        )
        .expect("proxy config is well-formed");

        let err = submitter
            .submit(tx_bytes)
            .await
            .expect_err("a dead SOCKS proxy must fail the broadcast");
        assert!(
            matches!(err, SubmitterError::Ambiguous { .. }),
            "a broadcast transport failure is ambiguous (maybe-propagated), never a \
             retryable transient: expected Ambiguous, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(&username),
            "invariant (a): a submit error must never render the SOCKS username"
        );
    }

    /// The local parse-guard: unparseable bytes are a build-path defect that
    /// **never reaches the network** — `submit` short-circuits to
    /// `RejectedTerminal { Malformed }` *before* any transport. This guards
    /// the arm the dead-proxy test deliberately routes around (it feeds valid wire
    /// to reach the transport). The dead SOCKS port (`:1`) is the tell: if a
    /// refactor let the guard fall through to the network, the outcome would be
    /// `Ambiguous`, not `Malformed` — so the assertion distinguishes
    /// "guarded before the wire" from "reached it" (and a swap to the panicking
    /// `canonical_tx_id` would panic here instead of returning).
    #[tokio::test(flavor = "multi_thread")]
    async fn broadcast_of_unparseable_bytes_is_a_local_malformed_never_reaching_the_network() {
        use shekyl_p_transport::TorSocksEndpoint;
        use shekyl_types::PCanonicalId;

        let submitter = PTransactionSubmitter::for_persona(
            PCanonicalId::from_bytes([3u8; 32]),
            &TorSocksEndpoint::loopback(1),
            "http://127.0.0.1:18081".to_string(),
        )
        .expect("proxy config is well-formed");

        let err = submitter
            .submit(b"not a canonical shekyl-wire transaction".to_vec())
            .await
            .expect_err("unparseable bytes must fail");
        assert!(
            matches!(
                err,
                SubmitterError::RejectedTerminal {
                    kind: TerminalErrorKind::Malformed
                }
            ),
            "a build-path defect is a local Malformed terminal, never a transport \
             outcome (would be Ambiguous if the guard fell through): got {err:?}"
        );
    }

    // ── Posture→submitter dispatch (SP-T4a §3.1) ──

    /// Canonical-wire tx bytes for dispatch tests: a serialized synthetic
    /// coinbase, so the `DaemonTransactionSubmitter` debug hash-consistency
    /// guard and the per-`P` parse guard are both satisfied.
    fn wire_tx_bytes() -> Vec<u8> {
        use crate::engine::test_support::make_synthetic_block;

        let mut tx_bytes = Vec::new();
        make_synthetic_block(0, [0u8; 32])
            .block
            .miner_transaction
            .write(&mut tx_bytes)
            .expect("serialize synthetic coinbase to canonical wire");
        tx_bytes
    }

    fn dead_proxy_socks() -> shekyl_p_transport::TorSocksEndpoint {
        // A closed SOCKS port (`:1`): loopback refuses immediately, so the ②
        // arm's transport path is exercised fast with no Tor and no timeout.
        shekyl_p_transport::TorSocksEndpoint::loopback(1)
    }

    /// The choke point's routing guard, both directions of the fence: a
    /// `Local` posture resolves to the ① principal arm, and an `OwnRemote`
    /// posture resolves to the ② per-`P` arm — **never** the principal
    /// submitter (the first-seen-origin leak the dispatch closes). Fence by
    /// enumeration: the match names every variant, no catch-all, so a new
    /// arm cannot slip through unasserted.
    #[tokio::test]
    async fn choke_point_routes_each_posture_to_its_own_arm() {
        use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

        let persona = PCanonicalId::from_bytes([11u8; 32]);
        let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));

        fn arm_name<D>(submitter: &BroadcastSubmitter<D>) -> &'static str {
            match submitter {
                BroadcastSubmitter::Local(_) => "local",
                BroadcastSubmitter::PerP(_) => "per-p",
            }
        }

        let local = BroadcastSubmitter::for_posture(
            BroadcastPosture::Local,
            persona,
            Arc::clone(&daemon),
            &dead_proxy_socks(),
        )
        .expect("① construction is infallible");
        assert_eq!(arm_name(&local), "local");

        let remote = BroadcastSubmitter::for_posture(
            BroadcastPosture::OwnRemote {
                base_url: "http://127.0.0.1:18081".to_string(),
            },
            persona,
            daemon,
            &dead_proxy_socks(),
        )
        .expect("proxy config is well-formed");
        assert_eq!(
            arm_name(&remote),
            "per-p",
            "②→PerP, never the principal submitter (§3.1 part 2 routing guard)"
        );
    }

    /// Match-delegation through the ① arm reaches the wrapped principal
    /// submitter: a `P`-bound submit over the `Local` posture lands on the
    /// wallet's own daemon (conceded observer) and resolves `Broadcast`,
    /// with no pairing constraint on this arm by design.
    #[tokio::test]
    async fn local_arm_delegates_bound_bytes_to_the_principal_daemon() {
        use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

        let daemon = Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        let submitter = BroadcastSubmitter::for_posture(
            BroadcastPosture::Local,
            PCanonicalId::from_bytes([13u8; 32]),
            Arc::clone(&daemon),
            &dead_proxy_socks(),
        )
        .expect("① construction is infallible");

        let bytes = wire_tx_bytes();
        let expected = canonical_tx_id(&bytes);
        let success = submitter
            .submit_bound(PBoundBytes::bind_for_test(
                PCanonicalId::from_bytes([14u8; 32]),
                bytes,
            ))
            .await
            .expect("loopback submit succeeds");
        assert_eq!(success, SubmitSuccess::Broadcast { hash: expected });
        assert_eq!(daemon.submitted_count(), 1);
    }

    /// The §3.1 part 4 pairing check on the ② arm: matched bytes pass the
    /// choke point and reach `P`'s transport (the dead proxy proves the
    /// delegation got that far — `Ambiguous`, not a pre-flight refusal).
    #[tokio::test(flavor = "multi_thread")]
    async fn per_p_arm_dispatches_matched_bytes_over_p_s_own_circuit() {
        use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

        let persona = PCanonicalId::from_bytes([17u8; 32]);
        let submitter = BroadcastSubmitter::for_posture(
            BroadcastPosture::OwnRemote {
                base_url: "http://127.0.0.1:18081".to_string(),
            },
            persona,
            Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED)),
            &dead_proxy_socks(),
        )
        .expect("proxy config is well-formed");

        let err = submitter
            .submit_bound(PBoundBytes::bind_for_test(persona, wire_tx_bytes()))
            .await
            .expect_err("a dead SOCKS proxy must fail the broadcast");
        assert!(
            matches!(
                err,
                BroadcastSubmitError::Submit(SubmitterError::Ambiguous { .. })
            ),
            "matched pairing must delegate to the transport (whose dead proxy is \
             ambiguous), never be refused pre-flight: got {err:?}"
        );
    }

    /// The pairing check refuses a cross-persona dispatch **before any
    /// transport** — the `validate_handle` discipline's loud half: in a
    /// debug build the mismatch is a panic (the fail-closed
    /// `PersonaMismatch` return is the release-build behavior of the same
    /// guard). The dead proxy is the tell: if the check fell through to the
    /// wire, the outcome would be an `Ambiguous` error, not this panic.
    #[tokio::test(flavor = "multi_thread")]
    #[should_panic(expected = "submit_bound: bytes bound to")]
    async fn per_p_arm_refuses_cross_persona_bytes_before_any_transport() {
        use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

        let submitter = BroadcastSubmitter::for_posture(
            BroadcastPosture::OwnRemote {
                base_url: "http://127.0.0.1:18081".to_string(),
            },
            PCanonicalId::from_bytes([19u8; 32]),
            Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED)),
            &dead_proxy_socks(),
        )
        .expect("proxy config is well-formed");

        // A *different* persona's bytes: the §3.1 part 4 equality check must
        // fire (panic, in this debug build) before the transport is reached —
        // this `expect_err` is never evaluated.
        submitter
            .submit_bound(PBoundBytes::bind_for_test(
                PCanonicalId::from_bytes([23u8; 32]),
                wire_tx_bytes(),
            ))
            .await
            .expect_err("unreachable in a debug build: the pairing check panics first");
    }
}
