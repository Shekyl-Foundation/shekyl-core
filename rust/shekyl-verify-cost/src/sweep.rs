// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shapes the block-verification sweep measures at each depth
//! (`CEN_I4_INPUT_CAP_DERIVATION.md` §3 and §8, the GAP-7 sweep at the new
//! shapes).
//!
//! The surge factor is bounded by the costliest legal shape per weight byte
//! at the deepest depth a spend can take. That shape is not read off a slope:
//! the proof pads its rows to powers of two (`Fcmp::ipa_rows`), so its cost
//! moves in steps, and the costliest shape per byte is the first input count
//! past a step, which pays a whole padded tier for one input's weight
//! (`ICD-F9`, `ICD-F21`). So the candidates at each depth are derived from
//! the row function and the weight limit, not chosen:
//!
//! - one input and the most inputs the weight limit admits at that depth
//!   (the density extremes);
//! - each first count past a Selene or Helios step;
//! - the count just before each step, as an off-step control that should
//!   cost less per byte than the step it precedes.
//!
//! The sweep measures every candidate's per-slot terms, finds the argmax per
//! depth from them, and fills whole blocks only at that argmax.

use shekyl_curve_generators::SpendLayers;
use shekyl_fcmp_proofs::fcmps::Fcmp;
use shekyl_wire::transaction::weight::{
    max_inputs_at, pqc_auth_weight, spend_weight, NonCoinbaseOutputs,
};

/// Outputs on every sweep shape: the fewest a non-coinbase spend carries.
/// The output axis is GAP-7's other density extreme, measured by the
/// existing `block_connect_terms` shapes, not by this sweep.
pub const SWEEP_OUTPUTS: NonCoinbaseOutputs = NonCoinbaseOutputs::FEWEST;

/// Why a count is a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepRole {
    /// One input: the lowest density.
    OneInput,
    /// The most inputs the weight limit admits at this depth.
    MostInputs,
    /// The first count past a step in the proof's padded rows.
    PastStep,
    /// The count just before a step: the control beside it.
    BeforeStep,
}

/// One shape the sweep measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepShape {
    /// Input count.
    pub n_in: usize,
    /// Tree depth (spend layers).
    pub layers: SpendLayers,
    /// Transaction weight at the widest fee varint, the weight a block's
    /// budget is charged.
    pub weight: usize,
    /// The proof's padded rows, Selene then Helios.
    pub rows: (usize, usize),
    /// Why this count is a candidate; the first reason when it has several.
    pub role: SweepRole,
}

/// The proof's padded rows for `n_in` inputs at `layers`.
#[must_use]
pub fn padded_rows(n_in: usize, layers: SpendLayers) -> (usize, usize) {
    Fcmp::<()>::ipa_rows(n_in, usize::from(layers.get()))
}

/// The weight of a two-output spend of `n_in` inputs at `layers`, at the
/// widest fee varint.
#[must_use]
pub fn sweep_weight(n_in: usize, layers: SpendLayers) -> usize {
    spend_weight(
        n_in,
        SWEEP_OUTPUTS.get(),
        layers.as_proof(),
        u64::MAX,
        pqc_auth_weight(),
        0,
    )
}

/// The candidate shapes at `layers`, ascending by input count, each once.
#[must_use]
pub fn sweep_candidates(layers: SpendLayers) -> Vec<SweepShape> {
    let most = max_inputs_at(SWEEP_OUTPUTS, layers);
    let mut chosen: Vec<(usize, SweepRole)> = Vec::new();
    let mut take = |n_in: usize, role: SweepRole| {
        if n_in >= 1 && n_in <= most && !chosen.iter().any(|(n, _)| *n == n_in) {
            chosen.push((n_in, role));
        }
    };
    take(1, SweepRole::OneInput);
    take(most, SweepRole::MostInputs);
    for n_in in 2..=most {
        if padded_rows(n_in, layers) != padded_rows(n_in - 1, layers) {
            take(n_in, SweepRole::PastStep);
            take(n_in - 1, SweepRole::BeforeStep);
        }
    }
    chosen.sort_by_key(|(n, _)| *n);
    chosen
        .into_iter()
        .map(|(n_in, role)| SweepShape {
            n_in,
            layers,
            weight: sweep_weight(n_in, layers),
            rows: padded_rows(n_in, layers),
            role,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every step in the padded rows has its first count and the count
    /// before it among the candidates, both density extremes are there, and
    /// nothing past the weight limit is.
    #[test]
    fn the_candidates_hold_every_step_and_both_extremes() {
        for depth in SpendLayers::SHALLOWEST.get()..=shekyl_curve_generators::MAX_TREE_DEPTH {
            let layers = SpendLayers::new(depth).expect("a spend depth");
            let most = max_inputs_at(SWEEP_OUTPUTS, layers);
            let shapes = sweep_candidates(layers);
            let counts: Vec<usize> = shapes.iter().map(|s| s.n_in).collect();
            assert!(
                counts.contains(&1) && counts.contains(&most),
                "depth {depth}"
            );
            assert!(
                counts.iter().all(|n| (1..=most).contains(n)),
                "depth {depth}"
            );
            for n_in in 2..=most {
                if padded_rows(n_in, layers) != padded_rows(n_in - 1, layers) {
                    assert!(
                        counts.contains(&n_in) && counts.contains(&(n_in - 1)),
                        "depth {depth}: the step at {n_in} inputs is not swept"
                    );
                }
            }
            assert!(
                counts.windows(2).all(|w| w[0] < w[1]),
                "depth {depth}: sorted, once each"
            );
        }
    }

    /// The table the sweep plan is read from, printed under `--nocapture`.
    #[test]
    fn the_candidate_table() {
        for depth in SpendLayers::SHALLOWEST.get()..=shekyl_curve_generators::MAX_TREE_DEPTH {
            let layers = SpendLayers::new(depth).expect("a spend depth");
            for s in sweep_candidates(layers) {
                println!(
                    "SWEEP depth={depth} n_in={} weight={} rows={:?} role={:?}",
                    s.n_in, s.weight, s.rows, s.role
                );
            }
        }
    }
}
