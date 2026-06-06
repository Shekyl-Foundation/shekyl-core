// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee-snapshot source for the Phase 2a two-pass build pipeline (§3.2 / PF2).
//!
//! Narrowed capability held alongside the synchronous [`super::FeeEstimator`]:
//! `build`'s async block fetches one atomic [`FeeEstimates`] snapshot per
//! attempt; the estimator reads it from [`super::FeeEstimationContext`].

use std::future::Future;
use std::sync::Arc;

use super::error::{FeeEstimatorError, IoError};
use super::traits::{DaemonEngine, FeeEstimates};

fn map_daemon_engine_fee_error<E: Into<IoError>>(err: E) -> FeeEstimatorError {
    match err.into() {
        IoError::Daemon { detail } if detail.contains("connection error") => {
            FeeEstimatorError::DaemonUnreachable
        }
        IoError::Daemon { detail } if detail.contains("invalid fee") => {
            FeeEstimatorError::DaemonResponseInvalid {
                reason: "daemon returned invalid fee estimate",
            }
        }
        IoError::Daemon { .. } => FeeEstimatorError::DaemonResponseInvalid {
            reason: "get_fee_estimate response unusable",
        },
        _ => FeeEstimatorError::DaemonResponseInvalid {
            reason: "get_fee_estimate response unusable",
        },
    }
}

/// Fetches one atomic multi-tier fee snapshot per build.
pub(crate) trait FeeSnapshotSource: Send + Sync + Clone + 'static {
    /// Single-RPC `get_fee_estimates` (§3.3).
    fn fetch(
        &self,
    ) -> impl Future<Output = Result<FeeEstimates, FeeEstimatorError>> + Send;
}

/// Production source: delegates to [`DaemonEngine::get_fee_estimates`].
#[derive(Clone)]
pub(crate) struct DaemonFeeSnapshotSource<D> {
    daemon: Arc<D>,
}

impl<D> DaemonFeeSnapshotSource<D> {
    pub(crate) fn new(daemon: D) -> Self {
        Self {
            daemon: Arc::new(daemon),
        }
    }

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
    ) -> impl Future<Output = Result<FeeEstimates, FeeEstimatorError>> + Send {
        let daemon = Arc::clone(&self.daemon);
        async move {
            daemon
                .get_fee_estimates()
                .await
                .map_err(map_daemon_engine_fee_error)
        }
    }
}

/// Test / unit-build source returning a fixed snapshot.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FixedFeeSnapshotSource {
    snapshot: FeeEstimates,
}

impl FixedFeeSnapshotSource {
    pub(crate) const fn new(snapshot: FeeEstimates) -> Self {
        Self { snapshot }
    }
}

impl FeeSnapshotSource for FixedFeeSnapshotSource {
    fn fetch(
        &self,
    ) -> impl Future<Output = Result<FeeEstimates, FeeEstimatorError>> + Send {
        let snapshot = self.snapshot;
        async move { Ok(snapshot) }
    }
}
