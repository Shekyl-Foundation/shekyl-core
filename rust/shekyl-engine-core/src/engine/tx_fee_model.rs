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

use super::fee_policy::{
    absolute_fee_rate_cap, CustomFeeBand, FeeEstimatorError, ValidatedFeeEstimates,
};
use super::traits::key::FeeDirective;

// Re-export the hoisted weight surface so `super::tx_fee_model::{predict_weight,
// predict_size_and_weight}` and the `kat_*` tests below resolve unchanged — the
// move is invisible to every caller (§12.3 D-1 constraint).
pub(crate) use shekyl_tx_weight::{
    predict_size_and_weight, predict_weight, InputCount, OutputCount,
};

// ── FEE-RATE LAYER (weight model lives in shekyl-tx-weight) ──────────────────

/// Canonical dust predicate inner expression (§3.10.2): the shared dust
/// formula (`shekyl_rpc_client::tx_fee`) composed with the weight
/// model's own marginal-input weight — the 2a-3 replacement
/// (`marginal_input_weight_at_d_ref`) that landed with the proof-size
/// KAT but was never wired, leaving the zero-proof-increment stub
/// understating the dust bar until 2026-08-16.
#[must_use]
pub(crate) fn dust_threshold_for_rate(rate: &FeeRate) -> u64 {
    tx_fee::dust_threshold(rate, shekyl_tx_weight::marginal_input_weight_at_d_ref())
}

/// Map [`super::fee_estimator::FeePriority`] to a [`FeeRate`] from an
/// already-validated snapshot. Named tiers are a lookup; `Custom` is
/// the caller's band — the snapshot's economy floor below, and above
/// it exactly the [`absolute_fee_rate_cap()`] every named tier obeys.
///
/// There is deliberately no `Custom`-only relative ceiling. One
/// anchored on economy (the shipped "100× economy") banned the
/// snapshot's own Priority rate: on the pinned KAT row
/// `(340, 1400, 67_000)` it refused `Custom(67_000)` as the caller's
/// error while `FeePriority::Priority` succeeded at that identical
/// rate. Economy is the market *floor* and honest 2021-scaling
/// `Fh / Fl` reaches 1077×, so no economy multiple can separate
/// "user typo" from "honest top tier" — the same reason the 10×
/// named-tier lock was withdrawn.
///
/// Snapshot well-formedness lives in
/// [`ValidatedFeeEstimates::try_new`] — this function must not
/// re-litigate it, or Custom dies when honest `Fh / Fl` is large.
pub(crate) fn fee_rate_for_priority(
    priority: super::fee_estimator::FeePriority,
    snapshot: &ValidatedFeeEstimates,
) -> Result<FeeRate, FeeEstimatorError> {
    use super::fee_estimator::FeePriority;

    match priority {
        FeePriority::Economy => Ok(snapshot.economy()),
        FeePriority::Standard => Ok(snapshot.standard()),
        FeePriority::Priority => Ok(snapshot.priority()),
        FeePriority::Custom(rate) => {
            // Total: the caller's rate arrived as `NonZeroU64` and the
            // validated snapshot carries its mask's non-zero proof.
            let custom = FeeRate::from_nonzero(rate, snapshot.quantization_mask());

            // The two bounds read DIFFERENT quantities, deliberately,
            // because they ask different questions of the same rate.
            //
            // Floor — raw `per_weight`. "Does this undercut the
            // daemon's cheapest tier?" is a per-weight question: mask
            // rounding dominates only at tiny weights, and at a real
            // transaction's weight the raw rate is what is charged.
            // Reading the floor at weight 1 would collapse the
            // comparison — under a 10,000 mask every rate in `1..=10_000`
            // quantizes to the same 10,000 charge, so a weight-1 floor
            // would admit a rate of 1 against an economy tier of 340 and
            // then undercut it at every weight that matters.
            if custom.per_weight() < snapshot.economy().per_weight() {
                return Err(FeeEstimatorError::CustomFeeOutOfRange(
                    CustomFeeBand::BelowEconomyFloor,
                ));
            }
            // Ceiling — EFFECTIVE weight-1 charge, the same quantity
            // `ValidatedFeeEstimates::try_new` caps on every named tier.
            // "What is the most this can cost per weight?" is maximized
            // exactly where mask rounding dominates, so weight 1 is the
            // conservative read for a ceiling and the collapse above is
            // the property that makes it one. An overflow is above any
            // finite cap, so it lands in this band rather than inventing
            // a class for arithmetic.
            match tx_fee::try_fee_from_weight(&custom, 1) {
                Some(one) if one <= absolute_fee_rate_cap() => Ok(custom),
                _ => Err(FeeEstimatorError::CustomFeeOutOfRange(
                    CustomFeeBand::AboveAbsoluteCap,
                )),
            }
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

    /// Custom-rate refusals are the CALLER's error class
    /// (`CustomFeeOutOfRange`), never blamed on the daemon — the
    /// pre-2026-08-16 code misfiled them as `DaemonResponseInvalid`.
    /// This bites against a Custom rate being blamed on the daemon; it
    /// does NOT cover snapshot well-formedness (that is
    /// `fee_policy::tests`).
    #[test]
    fn custom_fee_out_of_band_is_the_callers_error() {
        use super::fee_rate_for_priority;
        use crate::engine::error::FeeEstimatorError;
        use crate::engine::fee_estimator::FeePriority;
        use crate::engine::fee_policy::{CustomFeeBand, ValidatedFeeEstimates};
        use crate::engine::traits::FeeEstimates;
        use std::num::NonZeroU64;

        let validated = |e: u64, s: u64, p: u64| {
            ValidatedFeeEstimates::try_new(FeeEstimates {
                economy: FeeRate::new(e, 1).expect("economy"),
                standard: FeeRate::new(s, 1).expect("standard"),
                priority: FeeRate::new(p, 1).expect("priority"),
                quantization_mask: 1,
            })
            .expect("named tiers inside the snapshot ceiling")
        };

        let snapshot = validated(10, 20, 50);

        let low = NonZeroU64::new(9).expect("nonzero");
        match fee_rate_for_priority(FeePriority::Custom(low), &snapshot) {
            Err(FeeEstimatorError::CustomFeeOutOfRange(CustomFeeBand::BelowEconomyFloor)) => {}
            other => panic!("unexpected: {other:?}"),
        }

        // Exactly the floor is IN band — the negative control that
        // stops the comparison drifting to `<=`.
        let at_floor = NonZeroU64::new(10).expect("nonzero");
        fee_rate_for_priority(FeePriority::Custom(at_floor), &snapshot)
            .expect("the economy floor itself is payable");

        // The floor reads the RAW rate and the ceiling the EFFECTIVE
        // weight-1 charge. Under a large mask that distinction is the
        // whole guard: every rate in `1..=10_000` quantizes to the same
        // 10,000 charge at weight 1, so a floor read there would admit a
        // rate of 1 against an economy tier of 340 — and then undercut
        // it at every weight a real transaction has.
        let masked = ValidatedFeeEstimates::try_new(FeeEstimates {
            economy: FeeRate::new(340, 10_000).expect("economy"),
            standard: FeeRate::new(1_400, 10_000).expect("standard"),
            priority: FeeRate::new(67_000, 10_000).expect("priority"),
            quantization_mask: 10_000,
        })
        .expect("KAT row under an honest 10k mask");
        assert_eq!(
            tx_fee::try_fee_from_weight(&FeeRate::new(1, 10_000).expect("rate"), 1),
            tx_fee::try_fee_from_weight(&masked.economy(), 1),
            "the weight-1 charges are indistinguishable — this is why the floor is not read there"
        );
        let undercut = NonZeroU64::new(1).expect("nonzero");
        match fee_rate_for_priority(FeePriority::Custom(undercut), &masked) {
            Err(FeeEstimatorError::CustomFeeOutOfRange(CustomFeeBand::BelowEconomyFloor)) => {}
            other => panic!("a rate 340x under economy must be refused, got: {other:?}"),
        }
        // The masked snapshot's own Priority tier is still reachable.
        let top = NonZeroU64::new(67_000).expect("nonzero");
        fee_rate_for_priority(FeePriority::Custom(top), &masked)
            .expect("Custom reaches Priority under a mask too");

        let wide = validated(2_000, 2_000, 2_000);
        let cap = absolute_fee_rate_cap();
        let over_abs = NonZeroU64::new(cap + 1).expect("nonzero");
        match fee_rate_for_priority(FeePriority::Custom(over_abs), &wide) {
            Err(FeeEstimatorError::CustomFeeOutOfRange(CustomFeeBand::AboveAbsoluteCap)) => {}
            other => panic!("unexpected: {other:?}"),
        }
        let at_abs = NonZeroU64::new(cap).expect("nonzero");
        fee_rate_for_priority(FeePriority::Custom(at_abs), &wide)
            .expect("exactly the absolute cap is payable");
    }

    /// The withdrawn ceiling's exact vector: a `Custom` rate that the
    /// snapshot's OWN `Priority` tier already charges must resolve. The
    /// shipped "100× economy" band refused this as the *caller's*
    /// error (`-32602`) while `FeePriority::Priority` returned the same
    /// rate successfully — the wallet told the user their parameter was
    /// invalid for asking to pay what the daemon was quoting.
    ///
    /// This bites against an economy-anchored ceiling returning; it
    /// does NOT cover the absolute cap (that is the test above).
    #[test]
    fn custom_can_reach_the_snapshots_own_priority_tier() {
        use super::fee_rate_for_priority;
        use crate::engine::fee_estimator::FeePriority;
        use crate::engine::fee_policy::ValidatedFeeEstimates;
        use crate::engine::traits::FeeEstimates;
        use std::num::NonZeroU64;

        let validated = |e: u64, s: u64, p: u64| {
            ValidatedFeeEstimates::try_new(FeeEstimates {
                economy: FeeRate::new(e, 1).expect("economy"),
                standard: FeeRate::new(s, 1).expect("standard"),
                priority: FeeRate::new(p, 1).expect("priority"),
                quantization_mask: 1,
            })
            .expect("named tiers inside the snapshot ceiling")
        };

        // Every 2021-scaling KAT row, at its own Priority rate and just
        // above it ("priority, plus a little" — the ask the old band
        // made inexpressible). 197×, 65×, and 1077× economy.
        for (e, s, p) in [(340, 1400, 67_000), (340, 1400, 22_000), (13, 53, 14_000)] {
            let snapshot = validated(e, s, p);
            let named = fee_rate_for_priority(FeePriority::Priority, &snapshot)
                .expect("the named tier resolves");
            assert_eq!(named.per_weight(), p, "the named tier IS this rate");

            let same = NonZeroU64::new(p).expect("nonzero");
            let custom = fee_rate_for_priority(FeePriority::Custom(same), &snapshot)
                .unwrap_or_else(|err| panic!("Custom at the Priority rate {p} refused: {err:?}"));
            assert_eq!(
                custom.per_weight(),
                named.per_weight(),
                "Custom and Priority must agree at the same rate"
            );

            let bump = NonZeroU64::new(p + 1).expect("nonzero");
            fee_rate_for_priority(FeePriority::Custom(bump), &snapshot)
                .unwrap_or_else(|err| panic!("Custom just above Priority refused: {err:?}"));
        }
    }
}
