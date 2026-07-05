// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction broadcast capability for [`super::local_pending_tx::LocalPendingTx`].

use std::sync::Arc;

use shekyl_p_transport::PTorClient;
use shekyl_rpc_client::{RejectCause, Rpc, SubmitVerdict};
use shekyl_wire::Transaction;

use super::error::{AmbiguousErrorKind, RetryableRejectCause, TerminalErrorKind};
use super::pending::TxHash;
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
        SubmitVerdict::AlreadyInChain => TxSubmitOutcome::AlreadyInChain { hash },
        SubmitVerdict::Rejected { cause } => TxSubmitOutcome::Rejected { cause: *cause },
    }
}

/// Collapse a resolved [`TxSubmitOutcome`] to the submitter's public
/// `Result<TxHash, SubmitterError>`. Shared by both submitters so the
/// outcome→error mapping cannot drift between the principal and per-`P`
/// paths. A daemon *verdict* only — a transport failure never reaches
/// here; it is mapped to [`SubmitterError::Ambiguous`] at the call
/// site (absence-of-verdict is not an outcome, §5.2).
///
/// The `Ok` arm covers all three identity-bearing verdicts:
/// `AlreadyInPool` is the same disposition as a fresh accept (§2.5 —
/// the bytes are held; it also resolves prior transport ambiguity), and
/// `AlreadyInChain` is confirmation observed by verdict (refresh
/// remains the settlement authority). Rejections split by remedy class:
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
pub(crate) fn outcome_to_result(outcome: TxSubmitOutcome) -> Result<TxHash, SubmitterError> {
    match outcome {
        TxSubmitOutcome::Submitted { hash }
        | TxSubmitOutcome::AlreadyInPool { hash }
        | TxSubmitOutcome::AlreadyInChain { hash } => Ok(hash),
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
    ) -> impl std::future::Future<Output = Result<TxHash, SubmitterError>> + Send;
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
    async fn submit(&self, tx_bytes: Vec<u8>) -> Result<TxHash, SubmitterError> {
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
        | TxSubmitOutcome::AlreadyInChain { hash } = &outcome
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
/// Constructed **only** from a [`PTorClient`] + the daemon base URL: no
/// principal-`DaemonClient` path, no `Default`, so *this* submitter cannot be built
/// over the shared principal connection (mirrors `PBlockSource::new`, one direction
/// over). **Honest scope (§3A):** that closes *construction* — it does **not** stop
/// handing `P`'s tx **bytes** to the *principal* `DaemonTransactionSubmitter` (the
/// `submit(Vec<u8>)` trait takes opaque, persona-unbound bytes), nor pairing `P1`'s
/// bytes with a submitter built from `P2`'s circuit. This binds the *circuit* to a
/// persona (via `PTorClient::for_persona`), not the *bytes*; the posture→submitter
/// routing (②→here, never the principal) and the byte↔persona pairing are
/// **2c-2b's** obligation (a `P`-bound-bytes newtype only this `submit` accepts is
/// the make-bad-states-unrepresentable option).
//
// `allow(dead_code)`: transient — the non-test consumer is the gated **2c-2a/2c-2b**
// bond-assembly + request-path wiring (see `stake_engine.rs` `TODO(2d)`), NOT the
// posture selector (which resolves a posture, never a submitter). The dead-proxy
// proving test ships with the enabler; not deferred.
#[allow(dead_code)]
pub(crate) struct PTransactionSubmitter {
    rpc: PRpc,
}

#[allow(dead_code)]
impl PTransactionSubmitter {
    /// Build a remote-posture submitter broadcasting over `client`'s circuit to
    /// `base_url`.
    pub(crate) fn new(client: PTorClient, base_url: String) -> Self {
        Self {
            rpc: PRpc::new(client, base_url),
        }
    }
}

impl TransactionSubmitter for PTransactionSubmitter {
    async fn submit(&self, tx_bytes: Vec<u8>) -> Result<TxHash, SubmitterError> {
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
            submit_outcome_from_verdict(&SubmitVerdict::AlreadyInChain, hash),
            TxSubmitOutcome::AlreadyInChain { hash }
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

    /// All three identity-bearing outcomes resolve `Ok(hash)`: a fresh
    /// accept, a pool-resident duplicate (§2.5: same disposition), and a
    /// mined duplicate (confirmation observed by verdict).
    #[test]
    fn identity_outcomes_resolve_ok() {
        let hash = TxHash::from_bytes([9u8; 32]);
        for outcome in [
            TxSubmitOutcome::Submitted { hash },
            TxSubmitOutcome::AlreadyInPool { hash },
            TxSubmitOutcome::AlreadyInChain { hash },
        ] {
            assert_eq!(outcome_to_result(outcome).expect("identity outcome"), hash);
        }
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

        let client = PTorClient::for_persona(
            &PCanonicalId::from_bytes([5u8; 32]),
            &TorSocksEndpoint::loopback(1),
        )
        .expect("proxy config is well-formed");
        let username = client.username().as_str().to_owned();
        let submitter = PTransactionSubmitter::new(client, "http://127.0.0.1:18081".to_string());

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

        let client = PTorClient::for_persona(
            &PCanonicalId::from_bytes([3u8; 32]),
            &TorSocksEndpoint::loopback(1),
        )
        .expect("proxy config is well-formed");
        let submitter = PTransactionSubmitter::new(client, "http://127.0.0.1:18081".to_string());

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
}
