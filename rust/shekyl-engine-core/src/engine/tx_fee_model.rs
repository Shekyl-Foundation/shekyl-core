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

use super::traits::key::FeeDirective;

// Re-export the hoisted weight surface so `super::tx_fee_model::{predict_weight,
// predict_size_and_weight}` and the `kat_*` tests below resolve unchanged — the
// move is invisible to every caller (§12.3 D-1 constraint).
pub(crate) use shekyl_tx_weight::{
    converge_spend_fee_by, predict_size_and_weight, predict_weight, GroupSize, InputCount,
    OutputCount, Signer, SpendShape,
};

// ── FEE-RATE LAYER (weight model lives in shekyl-tx-weight) ──────────────────

/// Fee from structural weight on the lattice (non-panicking on daemon-derived rates).
#[must_use]
pub(crate) fn fee_from_weight(rate: &FeeRate, weight: usize) -> u64 {
    tx_fee::fee_from_weight(rate, weight)
}

/// Fee fixpoint for one output-count variant (§3.3 / §3.10.1) of a solo
/// spend paying `group_payees`, one size per output paying a group.
///
/// The body is [`converge_spend_fee_by`] with the lattice pricer
/// `quantized_fee`, so each group payee's `0x0D` entry is priced (R-37):
/// a solo spend paying a group is heavier than one paying an address.
/// `None` is a fee that does not fit in `u64`, or a shape paying more
/// groups than it has outputs; it is not a number, and it is not the
/// unbuildable with-change sentinel.
///
/// A non-zero seed is the with-change call, which starts from the no-change
/// fee. That seed is at or below this variant's least fixed point; a higher
/// seed would stick above it. The check runs in debug only, where a second
/// convergence from zero is the least point; a release build does not run
/// that second convergence, since nothing there would read it.
#[must_use]
pub(crate) fn converge_fee(
    rate: &FeeRate,
    n_in: InputCount,
    n_out: OutputCount,
    tree_depth: u8,
    group_payees: &[GroupSize],
    initial_fee: u64,
) -> Option<u64> {
    let per_weight = rate.per_weight();
    let price = |weight: u64| shekyl_economics::quantized_fee(weight, per_weight);
    let shape = SpendShape {
        n_in,
        n_out,
        tree_depth,
        signer: Signer::Solo,
        group_payees,
    };
    let fee = converge_spend_fee_by(&shape, initial_fee, price)?;
    if cfg!(debug_assertions) && initial_fee != 0 {
        let least = converge_spend_fee_by(&shape, 0, price)?;
        debug_assert!(
            initial_fee <= least && fee == least,
            "seed {initial_fee} is above the least fixed point {least}"
        );
    }
    Some(fee)
}

/// Populate [`FeeDirective`] for the selected input count and payment
/// outputs `N`, `group_payees` among them. The change output is the
/// wallet's own, never a group's.
pub(crate) fn build_fee_directive(
    rate: &FeeRate,
    n_in: InputCount,
    payment_output_count: OutputCount,
    tree_depth: u8,
    group_payees: &[GroupSize],
) -> Option<FeeDirective> {
    let n_no_change = payment_output_count;
    let fee_no_change = converge_fee(rate, n_in, n_no_change, tree_depth, group_payees, 0)?;

    // With-change adds one output. At the output limit a change output would exceed
    // MAX_OUTPUTS, so that variant is *unbuildable* (tx-builder would reject it with
    // `TooManyOutputs`): it has no fee, and the signer's choice
    // (`fee_variant::fee_and_change`) has only the no-change fee to match. `clamped`
    // returning a value below the requested `+1` is exactly the "at the limit"
    // signal. The send path never reaches it: `TxRequest::check_recipients` refuses
    // more payments than leave room for a change output.
    let with_change_request = payment_output_count.get() + 1; // <= MAX_OUTPUTS + 1, no overflow
    let n_with_change = OutputCount::clamped(with_change_request);
    let fee_with_change = if n_with_change.get() < with_change_request {
        None
    } else {
        Some(converge_fee(
            rate,
            n_in,
            n_with_change,
            tree_depth,
            group_payees,
            fee_no_change,
        )?)
    };

    Some(FeeDirective {
        fee_no_change,
        fee_with_change,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_client::FeeRate;
    // Weight model lives in shekyl-tx-weight; the KAT-validation tests below own
    // the synthetic-tree measurement machinery and cross-check the hoisted table.
    use shekyl_tx_weight::fcmp_proof_size;

    #[test]
    #[ignore = "diagnostic printer for measured depth-1 FCMP proof sizes; not a gate — run with --ignored --nocapture"]
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

    /// The fee is an *argument* to the weight predictor — the wire carries
    /// `varint(fee)` — so `fee = rate x weight(fee)` is a fixed point, not a
    /// formula. Pinned case, found by sweeping the rate space against the
    /// varint boundaries: at `pw = 24_184`, a one-in one-out spend's fee lands
    /// just under `2^28`, the second pass pushes it over, and the varint grows
    /// from four bytes to five. A fee returned before the fixed point does not
    /// cover the weight of the transaction that carries it.
    ///
    /// The value is the *fixed point*, computed from the rate and the shape;
    /// it is pinned so a change to the weight model has to restate it
    /// deliberately rather than absorb a regression.
    #[test]
    fn converge_fee_reaches_the_fee_varint_fixed_point() {
        let rate = FeeRate::new(24_184).unwrap();
        let (n_in, n_out, depth) = (InputCount::clamped(1), OutputCount::clamped(1), 1u8);

        let fee = converge_fee(&rate, n_in, n_out, depth, &[], 0).expect("the fee fits");
        // The (1,1,depth 1) weight at this rate prices just over 2^28, so
        // the varint grows from four bytes to five; the fixed point is that
        // product rounded up to the fee lattice (`FEE_QUANTIZATION_MASK`).
        assert_eq!(fee, 272_337_000, "the fee-varint fixed point for this rate");
        assert_eq!(fee % shekyl_economics::FEE_QUANTIZATION_MASK, 0);

        // The defining property, stated on its own axis: the returned fee is
        // what its own predicted weight prices. A fee returned one pass
        // early prices one varint byte's worth of rate short.
        assert_eq!(
            fee_from_weight(&rate, predict_weight(n_in, n_out, depth, fee)),
            fee,
            "converge_fee returned a fee its own weight does not price"
        );
    }

    /// Seed-independence: `converge_fee` must not depend on the caller warming
    /// it up. Three call sites seed it differently — `fee_query` passes 0,
    /// `fee_estimator` and `build_fee_directive` pass `fee_from_weight(rate,
    /// predict_weight(.., 0))`, and the with-change variant passes the
    /// no-change fee — and a fee quote that disagrees with the fee the build
    /// path charges is a defect regardless of which one is larger.
    #[test]
    fn converge_fee_is_independent_of_its_seed() {
        let rate = FeeRate::new(24_184).unwrap();
        let (n_in, n_out, depth) = (InputCount::clamped(1), OutputCount::clamped(1), 1u8);
        let warm = fee_from_weight(&rate, predict_weight(n_in, n_out, depth, 0));
        assert_eq!(
            converge_fee(&rate, n_in, n_out, depth, &[], 0),
            converge_fee(&rate, n_in, n_out, depth, &[], warm),
            "the quote path and the build path must converge to one fee"
        );
    }

    /// Sweep the rate space where the defect lives — the bands around each
    /// varint boundary, for a spread of shapes and quantization masks — and
    /// assert the fixed-point property everywhere. Brute-forcing the whole
    /// rate range finds the same cases at 0.004% density; aiming at the
    /// boundaries is both faster and denser in true positives.
    #[test]
    fn converge_fee_is_a_fixed_point_across_the_rate_and_shape_space() {
        use shekyl_tx_weight::{MAX_OUTPUTS, MAX_TREE_DEPTH};

        let shapes: [(usize, usize, u8); 8] = [
            (1, 1, 1),
            (1, 2, 8),
            (2, 2, 16),
            (8, 16, MAX_TREE_DEPTH),
            (1, MAX_OUTPUTS, 24),
            (4, 3, 12),
            (3, 5, 3),
            (8, 2, 1),
        ];
        // How many cases needed more than a single pass. Without this the
        // sweep could pass by never leaving the trivial band (rule 47: a gate
        // asserts its own subject is present).
        let mut multi_pass = 0usize;

        for &mask in &[1u64, 2, 4, 8, 10, 100, 1000, 10_000] {
            for &(ni, no, depth) in &shapes {
                let n_in = InputCount::clamped(ni);
                let n_out = OutputCount::clamped(no);
                let w0 = predict_weight(n_in, n_out, depth, 0) as u64;
                for bits in [7u32, 14, 21, 28, 35, 42, 49, 56] {
                    let centre = (1u64 << bits) / w0;
                    for delta in -8i64..=8 {
                        let pw = centre.saturating_add_signed(delta);
                        let Ok(rate) = FeeRate::new(pw) else {
                            continue;
                        };
                        let Some(fee) = converge_fee(&rate, n_in, n_out, depth, &[], 0) else {
                            continue;
                        };
                        let priced =
                            fee_from_weight(&rate, predict_weight(n_in, n_out, depth, fee));
                        assert_eq!(
                            priced, fee,
                            "not a fixed point: pw={pw} mask={mask} shape=({ni},{no},{depth}) \
                             fee={fee} prices at {priced}"
                        );
                        if fee != fee_from_weight(&rate, predict_weight(n_in, n_out, depth, 0)) {
                            multi_pass += 1;
                        }
                    }
                }
            }
        }
        assert!(
            multi_pass > 0,
            "the sweep never left the single-pass band, so it asserts nothing"
        );
    }

    #[test]
    fn with_change_is_impossible_at_the_output_limit() {
        let rate = FeeRate::new(10).unwrap();
        // Below the limit: with-change is a real, finite fee.
        let below = build_fee_directive(
            &rate,
            InputCount::clamped(1),
            OutputCount::clamped(2),
            1,
            &[],
        )
        .expect("the fee fits");
        assert!(below.fee_no_change > 0);
        let with_change = below.fee_with_change.expect("a change output fits");
        assert!(
            with_change > below.fee_no_change,
            "the change output costs more"
        );

        // At MAX_OUTPUTS payments, a change output would exceed the limit, so the
        // with-change variant has no fee and the signer can take only the
        // no-change variant.
        let at_limit = build_fee_directive(
            &rate,
            InputCount::clamped(1),
            OutputCount::clamped(usize::MAX),
            1,
            &[],
        )
        .expect("the no-change fee fits");
        assert!(at_limit.fee_no_change > 0 && at_limit.fee_no_change < u64::MAX);
        assert_eq!(
            at_limit.fee_with_change, None,
            "no with-change fee at the limit"
        );
    }

    /// A seed above the least fixed point sticks there. The with-change
    /// call must not pass one. Red: seed that call from `2 × fee_no_change`.
    /// Debug only, as the check is: a release build has no behaviour here to
    /// assert but the stuck fee the check exists to forbid, which no caller
    /// can reach (the with-change call is seeded from the no-change fee).
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "least fixed point")]
    fn a_seed_above_the_least_fixed_point_is_refused() {
        let rate = FeeRate::new(24_184).unwrap();
        let (n_in, n_out) = (InputCount::clamped(1), OutputCount::clamped(2));
        let least = converge_fee(&rate, n_in, n_out, 1, &[], 0).unwrap();
        let refused = converge_fee(&rate, n_in, n_out, 1, &[], least.saturating_mul(2));
        panic!("seed above {least} was accepted as {refused:?}");
    }
}
