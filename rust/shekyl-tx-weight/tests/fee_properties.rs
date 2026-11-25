// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fee loop against `FEE_LADDER_DERIVATION.md` §12.
//!
//! Each assertion names the edit that turns it red. The lattice pricer is
//! `shekyl_economics::quantized_fee`; the unrounded pricer is
//! `checked_mul`. This file does not round an unrounded fixed point and
//! call that the loop.

use shekyl_economics::{quantized_fee, relay_floor_admits, FEE_QUANTIZATION_MASK};
use shekyl_tx_weight::{
    converge_fee_by, converge_weight_fee, converge_weight_fee_by, predict_weight, weight_at_fee,
    InputCount, OutputCount, ProofLayers, MAX_OUTPUTS, MAX_TREE_DEPTH,
};
use shekyl_wire::transaction::MAX_FCMP_INPUTS as MAX_INPUTS;

fn shape(n_in: usize, n_out: usize) -> (InputCount, OutputCount) {
    (InputCount::clamped(n_in), OutputCount::clamped(n_out))
}

fn lattice(rate: u64) -> impl Fn(u64) -> Option<u64> {
    move |weight| quantized_fee(weight, rate)
}

/// Rates aimed at each `u64` varint boundary for this weight, plus the two
/// pinned neighbours from the unrounded fixed-point test.
fn rates_for(weight_at_zero: u64) -> Vec<u64> {
    let mut rates = vec![1u64, 23_840, 24_184];
    if weight_at_zero == 0 {
        return rates;
    }
    for bits in [7u32, 14, 21, 28, 35, 42, 49, 56] {
        let centre = (1u64 << bits) / weight_at_zero;
        if centre == 0 {
            continue;
        }
        for delta in -2i64..=2 {
            rates.push(centre.saturating_add_signed(delta).max(1));
        }
    }
    rates.sort_unstable();
    rates.dedup();
    rates
}

fn loop_lattice(
    n_in: InputCount,
    n_out: OutputCount,
    depth: u8,
    rate: u64,
    seed: u64,
) -> Option<u64> {
    converge_weight_fee_by(n_in, n_out, ProofLayers::known(depth), seed, lattice(rate))
}

#[test]
fn a_measured_weight_converges_to_the_predicted_fee() {
    // A caller that cannot predict its shape measures one build at a probe
    // fee and converges on `weight_at_fee` (the chain forge's bond posts and
    // claims). Wherever the predictor models the shape, that fee is the
    // wallet's, whatever the probe's varint width. Red: `weight_at_fee`
    // keeping the probe's varint, or adding instead of replacing it.
    for (n_in, n_out) in [shape(1, 2), shape(2, 2), shape(MAX_INPUTS, MAX_OUTPUTS)] {
        for depth in [1u8, 7, MAX_TREE_DEPTH] {
            let weight = predict_weight(n_in, n_out, ProofLayers::known(depth), 0) as u64;
            for rate in rates_for(weight) {
                let predicted = converge_weight_fee_by(
                    n_in,
                    n_out,
                    ProofLayers::known(depth),
                    0,
                    lattice(rate),
                );
                for probe in [0u64, 1, 1 << 7, 1 << 21, 1 << 42, u64::MAX] {
                    let measured =
                        predict_weight(n_in, n_out, ProofLayers::known(depth), probe) as u64;
                    let fee = converge_fee_by(
                        |fee| weight_at_fee(measured, probe, fee),
                        0,
                        lattice(rate),
                    );
                    assert_eq!(
                        fee, predicted,
                        "{n_in:?} {n_out:?} depth {depth} rate {rate} probe {probe}"
                    );
                    if let Some(fee) = fee {
                        assert_eq!(
                            weight_at_fee(measured, probe, fee),
                            Some(predict_weight(n_in, n_out, ProofLayers::known(depth), fee) as u64)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn the_unrounded_fee_is_the_product() {
    // Red: `saturating_mul`, which can return a fee no product equals.
    // Over-payment is 0: the fixed point is `rate × weight(fee)`.
    let (n_in, n_out) = shape(1, 2);
    for depth in [0u8, 1, MAX_TREE_DEPTH] {
        let weight = predict_weight(n_in, n_out, ProofLayers::known(depth), 0) as u64;
        for rate in rates_for(weight) {
            let Some(fee) = converge_weight_fee(rate, n_in, n_out, ProofLayers::known(depth))
            else {
                continue;
            };
            let at_fee = predict_weight(n_in, n_out, ProofLayers::known(depth), fee) as u64;
            assert_eq!(fee, at_fee.checked_mul(rate).unwrap());
        }
    }
}

#[test]
fn the_lattice_fee_never_under_pays_and_admission_accepts_it() {
    // Red: return from the loop one pass before `next == fee`.
    let (n_in, n_out) = shape(1, 2);
    for depth in [1u8, 8, MAX_TREE_DEPTH] {
        let weight = predict_weight(n_in, n_out, ProofLayers::known(depth), 0) as u64;
        for rate in rates_for(weight) {
            let Some(fee) = loop_lattice(n_in, n_out, depth, rate, 0) else {
                continue;
            };
            let at_fee = predict_weight(n_in, n_out, ProofLayers::known(depth), fee) as u64;
            let product = at_fee
                .checked_mul(rate)
                .expect("a represented fee's product fits");
            assert!(
                fee >= product,
                "under-pay at rate {rate} depth {depth}: {fee} < {product}"
            );
            assert!(
                relay_floor_admits(fee, at_fee, &[rate]),
                "admission refuses the lattice fee {fee} at rate {rate}"
            );
        }
    }
}

#[test]
fn the_lattice_fee_is_the_least_on_small_cells() {
    // Red: seed the with-change call from `2 × fee_no_change` and drop the
    // seed assert. Brute force is the small cells only.
    let (n_in, n_out) = shape(1, 1);
    let rate = 3u64;
    let fee = loop_lattice(n_in, n_out, 1, rate, 0).expect("a small fee fits");
    assert!(
        fee / FEE_QUANTIZATION_MASK <= 80,
        "the brute-force cell grew: {fee}"
    );
    let at = |candidate: u64| {
        let weight = predict_weight(n_in, n_out, ProofLayers::ONE, candidate) as u64;
        candidate >= weight * rate
    };
    assert!(at(fee));
    let mut below = 0u64;
    while below < fee {
        assert!(
            !at(below),
            "lattice value {below} already clears, so {fee} is not least"
        );
        below += FEE_QUANTIZATION_MASK;
    }
}

#[test]
fn over_payment_stays_inside_one_lattice_step() {
    // Red: round once after the unrounded loop and return that.
    let mut worst = 0u64;
    for n_in in 1..=MAX_INPUTS {
        for n_out in 1..=MAX_OUTPUTS {
            for depth in [0u8, 1, MAX_TREE_DEPTH] {
                let (n_in, n_out) = shape(n_in, n_out);
                let weight = predict_weight(n_in, n_out, ProofLayers::known(depth), 0) as u64;
                for rate in rates_for(weight) {
                    let Some(fee) = loop_lattice(n_in, n_out, depth, rate, 0) else {
                        continue;
                    };
                    let at_fee = predict_weight(n_in, n_out, ProofLayers::known(depth), fee) as u64;
                    let product = at_fee.checked_mul(rate).unwrap();
                    let over = fee - product;
                    assert!(
                        over < FEE_QUANTIZATION_MASK,
                        "over-pay {over} at rate {rate}"
                    );
                    worst = worst.max(over);
                }
            }
        }
    }
    assert_eq!(worst, 999, "worst lattice over-payment on this grid moved");
}

#[test]
fn the_loop_returns_only_when_two_passes_agree() {
    // Red: return the last pass when the bound runs out.
    let (n_in, n_out) = shape(2, 2);
    for depth in [0u8, 1, MAX_TREE_DEPTH] {
        let weight = predict_weight(n_in, n_out, ProofLayers::known(depth), 0) as u64;
        for rate in rates_for(weight) {
            let Some(fee) = loop_lattice(n_in, n_out, depth, rate, 0) else {
                continue;
            };
            let again =
                lattice(rate)(predict_weight(n_in, n_out, ProofLayers::known(depth), fee) as u64);
            assert_eq!(again, Some(fee));
        }
    }
}

/// A rate whose unrounded product at `weight` sits in the last lattice step
/// below a varint boundary. Rounding that product up crosses the boundary.
fn rate_in_the_last_step_below(weight: u64, boundary: u64) -> Option<u64> {
    if weight == 0 || boundary <= FEE_QUANTIZATION_MASK {
        return None;
    }
    let rate = (boundary - 1) / weight;
    if rate < FEE_QUANTIZATION_MASK {
        return None;
    }
    let product = rate.checked_mul(weight)?;
    if product <= boundary - FEE_QUANTIZATION_MASK || product >= boundary {
        return None;
    }
    Some(rate)
}

#[test]
fn the_in_loop_fixed_point_is_not_the_rounded_unrounded_fee() {
    // Rounding the unrounded fixed point up is a third fee when that
    // rounding crosses a varint boundary the unrounded point does not.
    // Red: delete the boundary search and keep only `rates_for`, which
    // aims the zero-fee weight at the boundary and lands above it.
    let cells = (1..=MAX_INPUTS).flat_map(|inputs| {
        (1..=MAX_TREE_DEPTH).flat_map(move |depth| {
            [14u32, 21, 28, 35, 42]
                .into_iter()
                .map(move |bits| (inputs, depth, bits))
        })
    });
    let found = cells.into_iter().any(|(inputs, depth, bits)| {
        let (n_in, n_out) = shape(inputs, 1);
        let boundary = 1u64 << bits;
        let weight = predict_weight(n_in, n_out, ProofLayers::known(depth), boundary - 1) as u64;
        let Some(rate) = rate_in_the_last_step_below(weight, boundary) else {
            return false;
        };
        let Some(unrounded) = converge_weight_fee(rate, n_in, n_out, ProofLayers::known(depth))
        else {
            return false;
        };
        let Some(third) = unrounded.checked_next_multiple_of(FEE_QUANTIZATION_MASK) else {
            return false;
        };
        loop_lattice(n_in, n_out, depth, rate, 0).is_some_and(|looped| looped != third)
    });
    assert!(
        found,
        "no cell differed: rounding the unrounded fee matched the loop on this grid"
    );
}

#[test]
fn the_payer_and_admission_share_one_mask() {
    // Red: a second mask constant used by either call.
    let weight = 11_097u64;
    let rate = 333u64;
    let fee = quantized_fee(weight, rate).unwrap();
    assert_eq!(fee % FEE_QUANTIZATION_MASK, 0);
    assert!(relay_floor_admits(fee, weight, &[rate]));
    assert!(!relay_floor_admits(fee - 1, weight, &[rate]));
}
