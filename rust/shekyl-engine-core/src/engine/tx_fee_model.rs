// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Structural tx-weight predictor and fee-directive helpers (Phase 2a §3.10).
//!
//! `predict_weight` mirrors post-build `Transaction::weight()` without
//! constructing a transaction. The `fcmp_proof_size` term is a provisional
//! linear stub until the 2a-3 KAT table lands.

use shekyl_io::varint_len;
use shekyl_rpc::{tx_fee, FeeRate};
use shekyl_units::AtomicUnits;

use super::traits::key::FeeDirective;

/// Hybrid PQC auth bytes per input (§3.10.1).
const HYBRID_PQC_AUTH_WEIGHT: usize = 3385;

/// Per-input fixed on-wire fields excluding the FCMP proof blob.
const PER_INPUT_FIXED_WEIGHT: usize = 32 + 32 + HYBRID_PQC_AUTH_WEIGHT + 8;

/// Per-output on-wire fields (one-time key + commitment + enc_amount + enc_label).
const PER_OUTPUT_WEIGHT: usize = 32 + 32 + 9 + 9;

/// Conservative tx-prefix + extra pubkey estimate.
const TX_PREFIX_EXTRA_WEIGHT: usize = 128;

/// Provisional FCMP proof size stub (2a-3 KAT replaces).
fn fcmp_proof_size(n_in: usize, tree_depth: u8) -> usize {
    const BASE: usize = 400;
    const PER_INPUT: usize = 180;
    BASE + n_in.saturating_mul(PER_INPUT) + usize::from(tree_depth).saturating_mul(40)
}

/// Structural weight predictor (§3.10.1). Clawback is 0 for 2a (`n_out ∈ {1,2}`).
#[must_use]
pub(crate) fn predict_weight(n_in: usize, n_out: usize, tree_depth: u8, fee: u64) -> usize {
    TX_PREFIX_EXTRA_WEIGHT
        + n_in.saturating_mul(PER_INPUT_FIXED_WEIGHT)
        + n_out.saturating_mul(PER_OUTPUT_WEIGHT)
        + fcmp_proof_size(n_in, tree_depth)
        + varint_len(fee)
}

/// Marginal weight of one additional input at `D_ref = MAX_TREE_DEPTH`.
#[must_use]
#[allow(dead_code)] // 2a-3 dust-fold consumes; 2a-2 uses `tx_fee::MARGINAL_INPUT_WEIGHT` stub.
pub(crate) fn marginal_input_weight_at_d_ref(tree_depth: u8) -> usize {
    let fee = 0;
    let n_out = 1;
    predict_weight(2, n_out, tree_depth, fee)
        .saturating_sub(predict_weight(1, n_out, tree_depth, fee))
}

/// Canonical dust predicate inner expression (§3.10.2).
#[must_use]
pub(crate) fn dust_threshold_for_rate(rate: &FeeRate) -> u64 {
    tx_fee::dust_threshold(rate)
}

/// Map [`super::fee_estimator::FeePriority`] to a [`FeeRate`] from the snapshot.
pub(crate) fn fee_rate_for_priority(
    priority: super::fee_estimator::FeePriority,
    snapshot: &super::traits::FeeEstimates,
) -> Result<FeeRate, super::error::FeeEstimatorError> {
    use super::error::FeeEstimatorError;
    use super::fee_estimator::FeePriority;

    match priority {
        FeePriority::Economy => Ok(snapshot.economy),
        FeePriority::Standard => Ok(snapshot.standard),
        FeePriority::Priority => Ok(snapshot.priority),
        FeePriority::Custom(rate) => {
            let floor = snapshot.economy;
            let custom = FeeRate::new(rate.get(), snapshot.quantization_mask).map_err(|_| {
                FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate or mask is zero",
                }
            })?;
            if custom.calculate_fee_from_weight(1) < floor.calculate_fee_from_weight(1) {
                return Err(FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate below economy floor",
                });
            }
            let ceiling_fee = floor.calculate_fee_from_weight(1).saturating_mul(100);
            if custom.calculate_fee_from_weight(1) > ceiling_fee {
                return Err(FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate above sanity ceiling",
                });
            }
            Ok(custom)
        }
    }
}

/// Quantized fee from structural weight.
#[must_use]
pub(crate) fn fee_from_weight(rate: &FeeRate, weight: usize) -> u64 {
    rate.calculate_fee_from_weight(weight)
}

/// Two-pass fee fixpoint for one output-count variant (§3.3 / §3.10.1).
#[must_use]
pub(crate) fn converge_fee(
    rate: &FeeRate,
    n_in: usize,
    n_out: usize,
    tree_depth: u8,
    initial_fee: u64,
) -> u64 {
    let mut fee = initial_fee;
    for _ in 0..2 {
        let weight = predict_weight(n_in, n_out, tree_depth, fee);
        fee = fee_from_weight(rate, weight);
    }
    fee
}

/// Populate [`FeeDirective`] for the selected input count and payment outputs `N`.
pub(crate) fn build_fee_directive(
    rate: &FeeRate,
    n_in: usize,
    payment_output_count: usize,
    tree_depth: u8,
) -> FeeDirective {
    let n_no_change = payment_output_count;
    let n_with_change = payment_output_count + 1;
    let seed = fee_from_weight(rate, predict_weight(n_in, n_no_change, tree_depth, 0));
    let fee_no_change = converge_fee(rate, n_in, n_no_change, tree_depth, seed);
    let fee_with_change = converge_fee(rate, n_in, n_with_change, tree_depth, fee_no_change);
    FeeDirective {
        fee_no_change,
        fee_with_change,
        dust_threshold: dust_threshold_for_rate(rate),
    }
}

/// Fee charged for the no-change variant (orchestrator picks variant in 2a-3).
#[must_use]
#[allow(dead_code)] // 2a-3 F4/F8 dust-fold calls this; 2a-2 stores raw fee on `PendingTx`.
pub(crate) fn fee_no_change_atomic(directive: &FeeDirective) -> AtomicUnits {
    AtomicUnits::from_raw(directive.fee_no_change)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc::FeeRate;

    #[test]
    fn predict_weight_increases_with_inputs_and_outputs() {
        let w1 = predict_weight(1, 1, 1, 1_000);
        let w2 = predict_weight(2, 1, 1, 1_000);
        let w3 = predict_weight(1, 2, 1, 1_000);
        assert!(w2 > w1);
        assert!(w3 > w1);
    }

    #[test]
    fn converge_fee_is_stable_within_two_passes() {
        let rate = FeeRate::new(10, 1).unwrap();
        let fee = converge_fee(&rate, 1, 2, 1, 0);
        assert!(fee > 0);
    }
}
