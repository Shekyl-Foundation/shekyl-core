// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read-only fee/weight query surface (WI-RPC-1).
//!
//! Projects the existing Phase-2a fee substrate — [`predict_weight`]'s
//! wire-exact byte model and the daemon's multi-tier
//! [`FeeEstimates`](super::traits::FeeEstimates) snapshot — as `&self` Engine
//! queries for the wallet-RPC layer, **without** re-deriving any byte model
//! or fee rule (pin: fee single-source). Nothing here mutates state, builds a
//! transaction, or touches key material.

use shekyl_tx_builder::MAX_TREE_DEPTH;
use shekyl_units::AtomicUnits;

use super::error::FeeEstimatorError;
use super::fee_snapshot::map_daemon_engine_fee_error;
use super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};
use super::tx_counts::{InputCount, OutputCount};
use super::tx_fee_model::{converge_fee, predict_size_and_weight};
use super::{Engine, EngineSignerKind};

/// Predicted byte size and fee weight for a hypothetical tx shape.
///
/// `weight` equals `shekyl_wire::Transaction::weight()` for the tx the
/// builder would produce from the same counts (it includes the Bp+
/// verification clawback); `size` is the serialized wire bytes (`weight`
/// minus the clawback). Both come from the one
/// [`predict_weight`](super::tx_fee_model::predict_weight) byte model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxShapeEstimate {
    /// Serialized transaction size in bytes.
    pub size: usize,
    /// Fee weight in bytes (size + Bp+ verification clawback).
    pub weight: usize,
    /// The curve-tree depth the FCMP++ proof-size term was evaluated at.
    pub tree_depth: u8,
}

/// Per-tier converged fees for one tx shape, plus the default tier.
///
/// Projected from one atomic daemon [`FeeEstimates`](super::traits::FeeEstimates)
/// snapshot through the same [`converge_fee`](super::tx_fee_model::converge_fee)
/// fixpoint the build path uses, so a quote here equals what a build at the
/// same snapshot/shape/depth would charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeTierQuote {
    /// Converged fee at the daemon's economy rate.
    pub economy_fee: AtomicUnits,
    /// Converged fee at the daemon's standard rate (the default tier).
    pub standard_fee: AtomicUnits,
    /// Converged fee at the daemon's priority rate.
    pub priority_fee: AtomicUnits,
    /// The curve-tree depth the quotes were evaluated at.
    pub tree_depth: u8,
}

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        L: LedgerEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
        F: PersistenceEngine,
    > Engine<S, D, L, E, R, P, F>
{
    /// The curve-tree depth to size FCMP++ proof-weight estimates at: the
    /// depth at the tree's ingested tip, or [`MAX_TREE_DEPTH`] when the tree
    /// is fresh/unavailable.
    ///
    /// The send path evaluates depth at the `REF_ANCHOR_AGE`-lagged reference
    /// height; for an estimate the tip depth is the same value in practice
    /// (depth grows by whole layers over millions of leaves), and the
    /// fallback direction is conservative — a deeper tree only *over*-states
    /// weight/fee, never under-pays.
    async fn estimate_tree_depth(&self) -> u8 {
        if let Ok(Some(tip)) = self.curve_tree.ingested_tip_height().await {
            if let Ok((_root, depth)) = self.curve_tree.reference_root_and_depth(tip).await {
                return depth;
            }
        }
        MAX_TREE_DEPTH
    }

    /// Predict the serialized size and fee weight of a tx with `n_in` inputs
    /// and `n_out` outputs at the wallet's current curve-tree depth.
    ///
    /// Pure structural projection of the Phase-2a byte model
    /// ([`predict_weight`](super::tx_fee_model::predict_weight), which equals
    /// `Transaction::weight()` by KAT) — no daemon round-trip, no state
    /// mutation. `fee` feeds the weight's own `varint(fee)` term; pass the
    /// expected fee when known, `0` for a floor estimate (the difference is
    /// bounded by the varint width, ≤ 9 bytes).
    pub async fn estimate_tx_size_and_weight(
        &self,
        n_in: InputCount,
        n_out: OutputCount,
        fee: u64,
    ) -> TxShapeEstimate {
        let tree_depth = self.estimate_tree_depth().await;
        let (size, weight) = predict_size_and_weight(n_in, n_out, tree_depth, fee);
        TxShapeEstimate {
            size,
            weight,
            tree_depth,
        }
    }

    /// Quote the converged fee at each daemon tier for a tx with `n_in`
    /// inputs and `n_out` outputs, from one atomic
    /// [`FeeEstimates`](super::traits::FeeEstimates) snapshot.
    ///
    /// Read-only: one daemon `get_fee_estimates` RPC plus the same
    /// [`converge_fee`](super::tx_fee_model::converge_fee) fixpoint the build
    /// path runs. The default tier is **standard**
    /// ([`FeePriority::Standard`](super::fee_estimator::FeePriority)).
    ///
    /// # Errors
    ///
    /// [`FeeEstimatorError::DaemonUnreachable`] /
    /// [`FeeEstimatorError::DaemonResponseInvalid`] when the snapshot cannot
    /// be fetched or is unusable — the same mapping the build path applies.
    pub async fn quote_fee_tiers(
        &self,
        n_in: InputCount,
        n_out: OutputCount,
    ) -> Result<FeeTierQuote, FeeEstimatorError> {
        let snapshot = self
            .daemon()
            .get_fee_estimates()
            .await
            .map_err(map_daemon_engine_fee_error)?;
        let tree_depth = self.estimate_tree_depth().await;

        let quote_at = |rate| AtomicUnits::from_raw(converge_fee(rate, n_in, n_out, tree_depth, 0));
        Ok(FeeTierQuote {
            economy_fee: quote_at(&snapshot.economy),
            standard_fee: quote_at(&snapshot.standard),
            priority_fee: quote_at(&snapshot.priority),
            tree_depth,
        })
    }
}
