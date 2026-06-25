// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction broadcast capability for [`super::local_pending_tx::LocalPendingTx`].

use std::sync::Arc;

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
        // Graceful on a malformed blob (the daemon path returns `Malformed`); the
        // `Submitted`/`AlreadyKnown` arms below are only reached for a valid tx.
        let local_hash = canonical_tx_id_opt(&tx_bytes);
        let outcome = self
            .daemon
            .submit_transaction(tx_bytes)
            .await
            .map_err(|_| {
                SubmitError::DaemonAmbiguous {
                    kind: AmbiguousErrorKind::DaemonUnavailable,
                    // `LocalPendingTx::submit_async` re-binds the active reservation id.
                    reservation_id: ReservationId::new(0),
                }
            })?;
        match outcome {
            TxSubmitOutcome::Submitted { hash } | TxSubmitOutcome::AlreadyKnown { hash } => {
                debug_assert_eq!(
                    Some(hash),
                    local_hash,
                    "daemon-returned id must equal the canonical wire tx hash"
                );
                Ok(hash)
            }
            TxSubmitOutcome::ProofStale { .. } => Err(SubmitError::DaemonRejectedTerminal {
                // Phase 6 splits stale-root detection; until then treat as malformed.
                kind: TerminalErrorKind::Malformed,
            }),
            TxSubmitOutcome::DaemonRejectedTerminal { kind } => {
                Err(SubmitError::DaemonRejectedTerminal { kind })
            }
        }
    }
}
