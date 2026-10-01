// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee-snapshot source for the Phase 2a two-pass build pipeline (§3.2 / PF2).
//!
//! Narrowed capability held alongside the synchronous [`super::FeeEstimator`]:
//! `build`'s async block fetches one atomic snapshot per attempt and
//! constructs [`ValidatedFeeEstimates`] at this boundary so quote and
//! build cannot drift.

use std::future::Future;
use std::sync::Arc;

use super::error::{FeeEstimatorError, IoError};
use super::fee_policy::ValidatedFeeEstimates;
use super::traits::DaemonEngine;

/// A failed fee query, classified by the fault it carries. The fault was
/// named where the failure was raised, so this reads a value, never the
/// message.
pub(crate) fn map_daemon_engine_fee_error<E: Into<IoError>>(err: E) -> FeeEstimatorError {
    match err.into() {
        IoError::Daemon { fault, detail } => {
            tracing::debug!(%detail, "fee query failed");
            FeeEstimatorError::Daemon(fault)
        }
        // A `DaemonEngine` error that is not a daemon failure: the
        // implementor's own fault, not the daemon's.
        other => {
            tracing::warn!(error = %other, "fee query failed outside the daemon RPC");
            FeeEstimatorError::Daemon(shekyl_rpc_client::DaemonFault::Internal)
        }
    }
}

/// Fetches one atomic multi-tier fee snapshot per build and validates it.
pub(crate) trait FeeSnapshotSource: Send + Sync + Clone + 'static {
    /// Single-RPC `get_fee_estimates` (§3.3), then
    /// [`ValidatedFeeEstimates::try_new`].
    fn fetch(
        &self,
    ) -> impl Future<Output = Result<ValidatedFeeEstimates, FeeEstimatorError>> + Send;
}

/// Production source: delegates to [`DaemonEngine::get_fee_estimates`].
///
/// `pub` because this type appears in the default for `Engine`'s pending-tx
/// parameter (same discipline as [`super::LocalLedger`] and
/// [`super::DaemonClient`]); benches and external `Engine<SoloSigner>`
/// defaults must resolve it.
#[derive(Clone)]
pub struct DaemonFeeSnapshotSource<D> {
    daemon: Arc<D>,
}

impl<D> DaemonFeeSnapshotSource<D> {
    pub(crate) fn new(daemon: D) -> Self {
        Self {
            daemon: Arc::new(daemon),
        }
    }

    #[allow(dead_code)] // lifecycle uses `new`; `from_arc` for future actor wiring.
    pub(crate) fn from_arc(daemon: Arc<D>) -> Self {
        Self { daemon }
    }
}

impl<D> FeeSnapshotSource for DaemonFeeSnapshotSource<D>
where
    D: DaemonEngine,
{
    fn fetch(
        &self,
    ) -> impl Future<Output = Result<ValidatedFeeEstimates, FeeEstimatorError>> + Send {
        let daemon = Arc::clone(&self.daemon);
        async move {
            let raw = daemon
                .get_fee_estimates()
                .await
                .map_err(map_daemon_engine_fee_error)?;
            ValidatedFeeEstimates::try_new(raw)
        }
    }
}

/// Test / unit-build source returning a fixed, already-validated snapshot.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FixedFeeSnapshotSource {
    snapshot: ValidatedFeeEstimates,
}

impl FixedFeeSnapshotSource {
    #[allow(dead_code)] // `local_pending_tx` tests construct this source.
    pub(crate) const fn new(snapshot: ValidatedFeeEstimates) -> Self {
        Self { snapshot }
    }
}

impl FeeSnapshotSource for FixedFeeSnapshotSource {
    fn fetch(
        &self,
    ) -> impl Future<Output = Result<ValidatedFeeEstimates, FeeEstimatorError>> + Send {
        let snapshot = self.snapshot;
        async move { Ok(snapshot) }
    }
}

#[cfg(test)]
mod tests {
    use shekyl_rpc_client::{DaemonFault, DaemonNetwork, IdentityMismatch, RpcError};

    use super::*;

    /// The classification reads the fault, never the message: a daemon that
    /// echoes a transport-looking phrase inside its reply is still a
    /// contract fault, and the identity verdict survives intact.
    #[test]
    fn a_failed_fee_query_is_classified_by_its_fault_not_its_text() {
        let wrong_network = IdentityMismatch::Network {
            ours: DaemonNetwork::Mainnet,
            theirs: DaemonNetwork::Testnet,
        };
        for (err, fault) in [
            (
                RpcError::ConnectionError("refused".into()),
                DaemonFault::Unreachable,
            ),
            (
                RpcError::InvalidNode("connection error (spoofed by the reply)".into()),
                DaemonFault::Protocol,
            ),
            (RpcError::InvalidFee, DaemonFault::FeeResponse),
            (
                RpcError::IdentityMismatch(wrong_network),
                DaemonFault::Identity(wrong_network),
            ),
        ] {
            assert_eq!(
                map_daemon_engine_fee_error(err.clone()),
                FeeEstimatorError::Daemon(fault),
                "{err:?}"
            );
        }
    }
}
