// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction broadcast capability for [`super::local_pending_tx::LocalPendingTx`].

use std::sync::Arc;

use shekyl_rpc_client::TxRelayResponse;
use shekyl_wire::Transaction;

use super::error::{AmbiguousErrorKind, SubmitError, TerminalErrorKind};
use super::pending::{ReservationId, TxHash};
use super::traits::{DaemonEngine, TxSubmitOutcome};

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

/// Map a daemon `send_raw_transaction` reply onto a [`TxSubmitOutcome`]
/// (§3.6, honest-subset mapping).
///
/// `hash` is the **locally**-computed transaction id (§3.6 step 2); the
/// daemon reply is consulted only for the accept/reject verdict, never
/// for identity.
///
/// The daemon (`on_send_raw_transaction`, `core_rpc_server.cpp`) sets a
/// dedicated boolean for ~10 rejection classes (`double_spend`,
/// `fee_too_low`, `invalid_input`, `invalid_output`, `too_big`,
/// `overspend`, `too_few_outputs`, `sanity_check_failed`,
/// `tx_extra_too_big`, `nonzero_unlock_time`). The mapping is narrow by
/// **wallet choice**, not daemon limitation: 2a-1 needs only two distinct
/// terminal outcomes (`double_spend` → [`TerminalErrorKind::DoubleSpend`],
/// `fee_too_low` → [`TerminalErrorKind::FeeTooLow`]); every other
/// rejection — the other flagged classes plus the **unflagged** generics
/// (an **already-known** duplicate and a **stale FCMP++ root**, which set
/// no dedicated flag and yield an empty `reason`) — collapses to
/// [`TerminalErrorKind::Malformed`].
///
/// The indistinguishability that blocks finer wallet handling is
/// specifically among the **unflagged** generics: an already-known
/// duplicate and a stale FCMP++ root are not separable client-side
/// without a daemon-side signal (`docs/FOLLOWUPS.md` —
/// `fcmp_root_stale`). Consequently this function never produces
/// [`TxSubmitOutcome::AlreadyKnown`] (the orchestrator derives that
/// wallet-side per §5.2) nor [`TxSubmitOutcome::ProofStale`] (detection
/// deferred to Phase 6). Both are documented on the enum.
///
/// Transport-agnostic: shared by the principal `DaemonClient` and the
/// per-`P` [`PTransactionSubmitter`] (SP-T4a) — a daemon reply is
/// interpreted the same regardless of which circuit carried it.
pub(crate) fn submit_outcome_from_response(
    resp: &TxRelayResponse,
    hash: TxHash,
) -> TxSubmitOutcome {
    if resp.status == "OK" {
        // `not_relayed` (daemon relayed locally only) is still an
        // accept into the pool; the wallet's broadcast landed.
        return TxSubmitOutcome::Submitted { hash };
    }

    let kind = if resp.double_spend {
        TerminalErrorKind::DoubleSpend
    } else if resp.fee_too_low {
        TerminalErrorKind::FeeTooLow
    } else {
        // Generic verification failure: maps to `Malformed` until a
        // daemon-side stale-root signal lets `ProofStale` split out
        // (Phase 6, SHEKYLD_PREREQUISITE).
        TerminalErrorKind::Malformed
    };
    TxSubmitOutcome::DaemonRejectedTerminal { kind }
}

/// Collapse a resolved [`TxSubmitOutcome`] to the submitter's public
/// `Result<TxHash, SubmitError>`. Shared by both submitters so the
/// outcome→error mapping cannot drift between the principal and per-`P`
/// paths. A daemon *verdict* only — a transport failure never reaches
/// here; it is mapped to [`SubmitError::DaemonAmbiguous`] at the call
/// site (absence-of-verdict is not an outcome, §5.2).
pub(crate) fn outcome_to_result(outcome: TxSubmitOutcome) -> Result<TxHash, SubmitError> {
    match outcome {
        TxSubmitOutcome::Submitted { hash } | TxSubmitOutcome::AlreadyKnown { hash } => Ok(hash),
        TxSubmitOutcome::ProofStale { .. } => Err(SubmitError::DaemonRejectedTerminal {
            // Phase 6 splits stale-root detection; until then treat as malformed.
            kind: TerminalErrorKind::Malformed,
        }),
        TxSubmitOutcome::DaemonRejectedTerminal { kind } => {
            Err(SubmitError::DaemonRejectedTerminal { kind })
        }
    }
}

/// Broadcast signed transaction bytes to the network.
pub(crate) trait TransactionSubmitter: Send + Sync + 'static {
    fn submit(
        &self,
        tx_bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<TxHash, SubmitError>> + Send;
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
    async fn submit(&self, tx_bytes: Vec<u8>) -> Result<TxHash, SubmitError> {
        // Debug-only plumbing cross-check that the daemon impl returns the canonical
        // wire id. Computed only in debug builds so release does no extra parse — the
        // daemon path parses the blob again, and this is its sole consumer. Graceful on a
        // malformed blob (the daemon path returns `Malformed`; the matched arms below are
        // reached only for a valid tx).
        #[cfg(debug_assertions)]
        let local_hash = canonical_tx_id_opt(&tx_bytes);
        let outcome = self
            .daemon
            .submit_transaction(tx_bytes)
            .await
            .map_err(|_| SubmitError::DaemonAmbiguous {
                kind: AmbiguousErrorKind::DaemonUnavailable,
                // `LocalPendingTx::submit_async` re-binds the active reservation id.
                reservation_id: ReservationId::new(0),
            })?;
        // Cross-check the daemon-returned id against the canonical wire hash on an
        // accept outcome (debug only). This is `DaemonEngine`-path-specific: the
        // per-`P` submitter computes the hash locally and never reads it back, so it
        // has nothing to cross-check.
        #[cfg(debug_assertions)]
        if let TxSubmitOutcome::Submitted { hash } | TxSubmitOutcome::AlreadyKnown { hash } =
            &outcome
        {
            debug_assert_eq!(
                Some(*hash),
                local_hash,
                "daemon-returned id must equal the canonical wire tx hash"
            );
        }
        outcome_to_result(outcome)
    }
}

#[cfg(test)]
mod tests {
    //! `submit_outcome_from_response` mapping regression (§3.6) — the
    //! transport-agnostic daemon-reply→outcome mapping shared by the
    //! principal `DaemonClient` and the per-`P` `PTransactionSubmitter`.
    //! Pure function; exercised directly against synthetic `TxRelayResponse`
    //! values (no live daemon).
    use super::*;
    use serde_json::json;

    /// A `status == "OK"` reply is a fresh accept into the pool.
    #[test]
    fn submit_ok_maps_to_submitted() {
        let hash = TxHash::from_bytes([7u8; 32]);
        let resp = TxRelayResponse {
            status: "OK".to_string(),
            ..Default::default()
        };
        assert_eq!(
            submit_outcome_from_response(&resp, hash),
            TxSubmitOutcome::Submitted { hash }
        );
    }

    /// An `OK` reply carrying daemon fields the wallet does **not** model
    /// (`not_relayed`, `reason`, …) parses without error and still maps to
    /// `Submitted` — `#[serde(default)]` deserialize-and-ignores the
    /// unmodeled surface (the F1 trim contract).
    #[test]
    fn submit_ok_tolerates_unmodeled_daemon_fields() {
        let hash = TxHash::from_bytes([1u8; 32]);
        let resp: TxRelayResponse = serde_json::from_value(json!({
            "status": "OK",
            "not_relayed": true,
            "reason": "",
            "sanity_check_failed": false,
        }))
        .expect("unmodeled daemon fields tolerated");
        assert_eq!(
            submit_outcome_from_response(&resp, hash),
            TxSubmitOutcome::Submitted { hash }
        );
    }

    #[test]
    fn submit_double_spend_is_terminal_double_spend() {
        let resp = TxRelayResponse {
            status: "Failed".to_string(),
            double_spend: true,
            ..Default::default()
        };
        assert_eq!(
            submit_outcome_from_response(&resp, TxHash::from_bytes([0u8; 32])),
            TxSubmitOutcome::DaemonRejectedTerminal {
                kind: TerminalErrorKind::DoubleSpend
            }
        );
    }

    #[test]
    fn submit_fee_too_low_is_terminal_fee_too_low() {
        let resp = TxRelayResponse {
            status: "Failed".to_string(),
            fee_too_low: true,
            ..Default::default()
        };
        assert_eq!(
            submit_outcome_from_response(&resp, TxHash::from_bytes([0u8; 32])),
            TxSubmitOutcome::DaemonRejectedTerminal {
                kind: TerminalErrorKind::FeeTooLow
            }
        );
    }

    /// `status != "OK"` with no recognized flag and an empty `reason`
    /// is the generic-verification-failure bucket — the same bucket an
    /// already-known duplicate and a stale FCMP++ root land in. It maps
    /// to `Malformed` until Phase 6 splits `ProofStale` out.
    #[test]
    fn submit_generic_failure_is_terminal_malformed() {
        let resp = TxRelayResponse {
            status: "Failed".to_string(),
            ..Default::default()
        };
        assert_eq!(
            submit_outcome_from_response(&resp, TxHash::from_bytes([0u8; 32])),
            TxSubmitOutcome::DaemonRejectedTerminal {
                kind: TerminalErrorKind::Malformed
            }
        );
    }

    /// A daemon rejection flagged with a class the wallet does **not**
    /// model (e.g. `invalid_input`) deserialize-and-ignores that flag and
    /// collapses to `Malformed` — the deliberate honest-subset mapping,
    /// not a parse failure.
    #[test]
    fn submit_unmodeled_rejection_flag_is_terminal_malformed() {
        let resp: TxRelayResponse = serde_json::from_value(json!({
            "status": "Failed",
            "invalid_input": true,
            "reason": "invalid input",
        }))
        .expect("unmodeled rejection flag tolerated");
        assert_eq!(
            submit_outcome_from_response(&resp, TxHash::from_bytes([0u8; 32])),
            TxSubmitOutcome::DaemonRejectedTerminal {
                kind: TerminalErrorKind::Malformed
            }
        );
    }

    /// When both `double_spend` and `fee_too_low` are set, double-spend
    /// wins: it is the stronger (output-conflict) terminal signal.
    #[test]
    fn submit_double_spend_precedes_fee_too_low() {
        let resp = TxRelayResponse {
            status: "Failed".to_string(),
            double_spend: true,
            fee_too_low: true,
        };
        assert_eq!(
            submit_outcome_from_response(&resp, TxHash::from_bytes([0u8; 32])),
            TxSubmitOutcome::DaemonRejectedTerminal {
                kind: TerminalErrorKind::DoubleSpend
            }
        );
    }
}
