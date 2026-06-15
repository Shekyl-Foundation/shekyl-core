// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction broadcast capability for [`super::local_pending_tx::LocalPendingTx`].

use std::sync::Arc;

use shekyl_crypto_hash::cn_fast_hash;

use super::error::{AmbiguousErrorKind, SubmitError, TerminalErrorKind};
use super::pending::{ReservationId, TxHash};
use super::traits::{DaemonEngine, TxSubmitOutcome};

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
        let local_hash = TxHash::from_bytes(cn_fast_hash(&tx_bytes));
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
                    hash, local_hash,
                    "daemon hash must match cn_fast_hash(tx_bytes)"
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
