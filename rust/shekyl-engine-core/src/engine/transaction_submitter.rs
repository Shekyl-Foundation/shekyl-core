// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction broadcast capability for [`super::local_pending_tx::LocalPendingTx`].

use std::sync::Arc;

use shekyl_p_transport::PTorClient;
use shekyl_rpc_client::{Rpc, TxRelayResponse};
use shekyl_wire::Transaction;

use super::error::{AmbiguousErrorKind, SubmitError, TerminalErrorKind};
use super::pending::{ReservationId, TxHash};
use super::prpc::PRpc;
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
            .map_err(|_| SubmitError::DaemonAmbiguous {
                kind: AmbiguousErrorKind::DaemonUnavailable,
                // `LocalPendingTx::submit_async` re-binds the active reservation id.
                reservation_id: ReservationId::new(0),
            })?;
        // `TxRelayResponse` carries NO txid field — neither path reads an id back from
        // the daemon (§3.6: identity is always locally computed, anti-untrusted-daemon).
        // So this compares two LOCAL hash pipelines and catches a `DaemonEngine` *impl*
        // (a test double / fault injector) that returns a divergent outcome hash — NOT
        // a lying daemon. `DaemonEngine`-path-specific: the per-`P` submitter feeds its
        // own locally-computed hash straight into the shared mapper, nothing to check.
        #[cfg(debug_assertions)]
        if let TxSubmitOutcome::Submitted { hash } | TxSubmitOutcome::AlreadyKnown { hash } =
            &outcome
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
    async fn submit(&self, tx_bytes: Vec<u8>) -> Result<TxHash, SubmitError> {
        // Local, fail-closed tx id. The bytes are a wallet-built, fully-assembled
        // signed transaction (for the bond path, the tx carrying the bond vin), so a
        // parse failure is a build-path defect — map it to the same `Malformed`
        // terminal the `DaemonEngine` path returns rather than panicking, and never
        // reach the network with an unparseable blob.
        let Some(hash) = canonical_tx_id_opt(&tx_bytes) else {
            return Err(SubmitError::DaemonRejectedTerminal {
                kind: TerminalErrorKind::Malformed,
            });
        };
        // Broadcast over `P`'s own circuit. **SP-T4a axis 4 (ambiguous partial
        // failure):** ANY transport error → [`SubmitError::DaemonAmbiguous`], never
        // a retry decision derived from `PRpc`'s fetch-style `classify`. A dropped
        // connection does not tell us whether the tx propagated, so absence-of-a-
        // daemon-verdict is *ambiguous*, not a retryable transient — the write-side
        // inversion of the fetch default.
        //
        // This submitter's job ENDS here: map honestly and stop. The recovery
        // contract — what a post-ambiguity retry means — is the **consumer's §5.2
        // orchestrator** (2c-2a/2c-2b) to write, from the daemon's REAL reply
        // surface, NOT an `AlreadyKnown` dedupe: no production code derives
        // `AlreadyKnown` (only the test double constructs it). A same-bytes retry of
        // a *healthy* duplicate returns `OK + not_relayed` → `Submitted`; the
        // dangerous windows are a tx timed out of the pool (→ `Malformed`), a fee
        // floor risen since send (→ `FeeTooLow` **while the original is still
        // mineable** — a false-terminal that must NOT release output locks), and a
        // stale FCMP++ root. And dropping this future detaches the `spawn_blocking`
        // POST, which may still broadcast — a cancelled submit is ambiguous too.
        // (See `ARCHIVAL_BOND_2D2_SP_T4_BROADCAST.md` §2 axis 4 + the 2c
        // submit-outcome-partition obligation in `FOLLOWUPS.md`.)
        let resp = self.rpc.publish_transaction(&tx_bytes).await.map_err(|_| {
            SubmitError::DaemonAmbiguous {
                kind: AmbiguousErrorKind::DaemonUnavailable,
                // Placeholder: the submitter owns no reservation. The *current*
                // caller (`LocalPendingTx::submit_async`) re-binds this rid — but the
                // P seam's future consumer (StakeEngine, 2c) has no re-binder, so the
                // rid-0 sentinel is meaningless until re-bound and MUST NOT be trusted
                // as a real reservation. (2c: split the submitter error (no rid) from
                // the reservation-bound orchestrator error so `0` is unrepresentable.)
                reservation_id: ReservationId::new(0),
            }
        })?;
        // A daemon *verdict* is mapped by the shared helpers — identical to the
        // principal path, so the two cannot drift.
        outcome_to_result(submit_outcome_from_response(&resp, hash))
    }
}

#[cfg(test)]
mod tests {
    //! Submit-path tests: the transport-agnostic `submit_outcome_from_response`
    //! mapping regression (§3.6, exercised directly against synthetic
    //! `TxRelayResponse` values — no live daemon), plus the per-`P`
    //! `PTransactionSubmitter`'s ambiguous-failure + username-non-leak proof
    //! (SP-T4a).
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

    /// SP-T4a axis 4 + invariant (a): a broadcast whose **transport** fails
    /// surfaces as [`SubmitError::DaemonAmbiguous`] — we cannot know whether it
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
            matches!(err, SubmitError::DaemonAmbiguous { .. }),
            "a broadcast transport failure is ambiguous (maybe-propagated), never a \
             retryable transient: expected DaemonAmbiguous, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(&username),
            "invariant (a): a submit error must never render the SOCKS username"
        );
    }

    /// The local parse-guard: unparseable bytes are a build-path defect that
    /// **never reaches the network** — `submit` short-circuits to
    /// `DaemonRejectedTerminal { Malformed }` *before* any transport. This guards
    /// the arm the dead-proxy test deliberately routes around (it feeds valid wire
    /// to reach the transport). The dead SOCKS port (`:1`) is the tell: if a
    /// refactor let the guard fall through to the network, the outcome would be
    /// `DaemonAmbiguous`, not `Malformed` — so the assertion distinguishes
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
                SubmitError::DaemonRejectedTerminal {
                    kind: TerminalErrorKind::Malformed
                }
            ),
            "a build-path defect is a local Malformed terminal, never a transport \
             outcome (would be DaemonAmbiguous if the guard fell through): got {err:?}"
        );
    }
}
