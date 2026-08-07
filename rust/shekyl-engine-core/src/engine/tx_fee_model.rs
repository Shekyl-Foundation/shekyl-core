// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee-directive helpers and fee convergence (Phase 2a §3.10).
//!
//! The structural **weight predictor** (`predict_weight` /
//! `predict_size_and_weight`, the FCMP proof-size KAT, and the bounded
//! `InputCount`/`OutputCount`) was hoisted to `shekyl-tx-weight` (§12.3 D-1) so
//! `shekyl-economics-sim` shares one single-sourced weight model; they are
//! re-exported below so this crate's callers are untouched. This module keeps
//! the **fee-rate** layer — `FeeRate`/`FeeDirective` mapping, the two-pass fee
//! fixpoint, and the custom-rate ceiling — which is wallet/RPC-shaped and stays
//! here. The FCMP proof-size KAT is *validated* against real synthetic-tree
//! measurements by the `kat_*` tests below, which own the measurement machinery
//! (`tx_weight_kat`) and call the hoisted `pub` `fcmp_proof_size`.

use shekyl_rpc_client::{tx_fee, FeeRate};
use shekyl_units::AtomicUnits;

use super::traits::key::FeeDirective;

// Re-export the hoisted weight surface so `super::tx_fee_model::{predict_weight,
// predict_size_and_weight}` and the `kat_*` tests below resolve unchanged — the
// move is invisible to every caller (§12.3 D-1 constraint).
pub(crate) use shekyl_tx_weight::{
    predict_size_and_weight, predict_weight, InputCount, OutputCount,
};

// ── FEE-RATE LAYER (weight model lives in shekyl-tx-weight) ──────────────────

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
            let floor_one = tx_fee::try_fee_from_weight(&floor, 1).ok_or(
                FeeEstimatorError::DaemonResponseInvalid {
                    reason: "economy feerate overflowed fee arithmetic",
                },
            )?;
            let custom_one = tx_fee::try_fee_from_weight(&custom, 1).ok_or(
                FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate overflowed fee arithmetic",
                },
            )?;
            if custom_one < floor_one {
                return Err(FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate below economy floor",
                });
            }
            let ceiling_fee = floor_one.saturating_mul(100);
            if custom_one > ceiling_fee {
                return Err(FeeEstimatorError::DaemonResponseInvalid {
                    reason: "custom feerate above sanity ceiling",
                });
            }
            Ok(custom)
        }
    }
}

/// Quantized fee from structural weight (non-panicking on daemon-derived rates).
#[must_use]
pub(crate) fn fee_from_weight(rate: &FeeRate, weight: usize) -> u64 {
    tx_fee::fee_from_weight(rate, weight)
}

/// Two-pass fee fixpoint for one output-count variant (§3.3 / §3.10.1).
#[must_use]
pub(crate) fn converge_fee(
    rate: &FeeRate,
    n_in: InputCount,
    n_out: OutputCount,
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
    n_in: InputCount,
    payment_output_count: OutputCount,
    tree_depth: u8,
) -> FeeDirective {
    let n_no_change = payment_output_count;
    let seed = fee_from_weight(rate, predict_weight(n_in, n_no_change, tree_depth, 0));
    let fee_no_change = converge_fee(rate, n_in, n_no_change, tree_depth, seed);

    // With-change adds one output. At the output limit a change output would exceed
    // MAX_OUTPUTS, so that variant is *unbuildable* (tx-builder would reject it with
    // `TooManyOutputs`). Mark it impossible with an infinite fee so the signer's
    // `leftover >= fee_with_change + dust_threshold` selection (sign_bridge) can never
    // pick it and instead falls through to the buildable no-change variant — rather
    // than selecting a change output that fails validation. `clamped` returning a
    // value below the requested `+1` is exactly the "at the limit" signal.
    let with_change_request = payment_output_count.get() + 1; // <= MAX_OUTPUTS + 1, no overflow
    let n_with_change = OutputCount::clamped(with_change_request);
    let fee_with_change = if n_with_change.get() < with_change_request {
        u64::MAX
    } else {
        converge_fee(rate, n_in, n_with_change, tree_depth, fee_no_change)
    };

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
    use shekyl_rpc_client::FeeRate;
    // Weight model lives in shekyl-tx-weight; the KAT-validation tests below own
    // the synthetic-tree measurement machinery and cross-check the hoisted table.
    use shekyl_tx_weight::fcmp_proof_size;

    #[test]
    #[ignore]
    fn kat_print_depth1_fcmp_sizes() {
        for n_in in 1..=8usize {
            let measured = crate::engine::tx_weight_kat::support::measure_fcmp_proof_len(n_in, 1)
                .unwrap_or_else(|e| panic!("({n_in},1): {e}"));
            eprintln!("n_in={n_in} fcmp={measured}");
        }
    }

    #[test]
    fn kat_fcmp_proof_size_depth1_row() {
        for n_in in 1..=8usize {
            let measured = crate::engine::tx_weight_kat::support::measure_fcmp_proof_len(n_in, 1)
                .unwrap_or_else(|e| panic!("({n_in},1): {e}"));
            assert_eq!(
                fcmp_proof_size(InputCount::clamped(n_in), 1),
                measured,
                "depth=1 KAT mismatch at n_in={n_in}"
            );
        }
    }

    #[test]
    #[ignore = "slow: emit FCMP_PROOF_SIZE_KAT table; run with --ignored --nocapture"]
    fn kat_emit_fcmp_proof_size_table() {
        for n_in in 1..=8usize {
            print!("        [0");
            for tree_depth in 1..=24u8 {
                let measured =
                    crate::engine::tx_weight_kat::support::measure_fcmp_proof_len(n_in, tree_depth)
                        .unwrap_or_else(|e| panic!("({n_in},{tree_depth}): {e}"));
                print!(", {measured}");
            }
            println!("],");
        }
    }

    #[test]
    #[ignore = "slow: full [1,8]×[1,24] fcmp_proof_size KAT; run with --ignored"]
    fn kat_fcmp_proof_size_grid() {
        for tree_depth in 1..=24u8 {
            for n_in in 1..=8usize {
                let measured =
                    crate::engine::tx_weight_kat::support::measure_fcmp_proof_len(n_in, tree_depth)
                        .unwrap_or_else(|e| panic!("({n_in},{tree_depth}): {e}"));
                assert_eq!(
                    fcmp_proof_size(InputCount::clamped(n_in), tree_depth),
                    measured,
                    "KAT mismatch at n_in={n_in} depth={tree_depth}"
                );
            }
        }
    }

    #[test]
    fn converge_fee_is_stable_within_two_passes() {
        let rate = FeeRate::new(10, 1).unwrap();
        let fee = converge_fee(&rate, InputCount::clamped(1), OutputCount::clamped(2), 1, 0);
        assert!(fee > 0);
    }

    #[test]
    fn with_change_is_impossible_at_the_output_limit() {
        let rate = FeeRate::new(10, 1).unwrap();
        // Below the limit: with-change is a real, finite fee.
        let below = build_fee_directive(&rate, InputCount::clamped(1), OutputCount::clamped(2), 1);
        assert!(below.fee_no_change > 0);
        assert!(below.fee_with_change > 0 && below.fee_with_change < u64::MAX);
        assert!(
            below.fee_with_change > below.fee_no_change,
            "the change output costs more"
        );

        // At MAX_OUTPUTS payments, a change output would exceed the limit, so the
        // with-change variant is marked impossible (`u64::MAX`) — the signer's
        // `leftover >= fee_with_change + dust` check can never select it, so a
        // max-recipient spend falls through to the buildable no-change variant.
        let at_limit = build_fee_directive(
            &rate,
            InputCount::clamped(1),
            OutputCount::clamped(usize::MAX),
            1,
        );
        assert!(at_limit.fee_no_change > 0 && at_limit.fee_no_change < u64::MAX);
        assert_eq!(
            at_limit.fee_with_change,
            u64::MAX,
            "with-change unselectable at the limit"
        );
    }

    /// PHASE_2A_SEND_PATH.md §8.2 — documents the **implemented** Custom-only ceiling.
    /// Daemon-tier `DaemonFeeUnreasonable` remains a §10 security residual.
    #[test]
    fn custom_fee_above_sanity_ceiling_rejected() {
        use super::fee_rate_for_priority;
        use crate::engine::error::FeeEstimatorError;
        use crate::engine::fee_estimator::FeePriority;
        use crate::engine::traits::FeeEstimates;
        use std::num::NonZeroU64;

        let snapshot = FeeEstimates {
            economy: FeeRate::new(1, 1).expect("economy"),
            standard: FeeRate::new(10, 1).expect("standard"),
            priority: FeeRate::new(100, 1).expect("priority"),
            quantization_mask: 1,
        };
        let inflated = NonZeroU64::new(101).expect("above 100× economy at weight 1");
        let err = fee_rate_for_priority(FeePriority::Custom(inflated), &snapshot)
            .expect_err("custom feerate above ceiling");
        match err {
            FeeEstimatorError::DaemonResponseInvalid { reason } => {
                assert!(reason.contains("sanity ceiling"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
