// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The declared step's up edge, read as window means
//! (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.34).
//!
//! The endpoints are the mean of `M_r` over the window before the edge
//! and over the trace's last window. The settle time is that same mean,
//! walked forward one block at a time, until it covers 95 % of the move.
//! A single block cannot settle a move the endpoints defined as averages.
//! The year-1 ratio histogram belongs to the fold, not to an edge.

use std::collections::BTreeMap;
use std::ops::Range;

use shekyl_economics::params::TX_VOLUME_WINDOW;

use crate::engine::SimParams;
use crate::eup4::release_multiplier_at;
use crate::stage2::{a1_year_aggs_probed, BlockSeen, FoldProbe};
use crate::step_response::{step_scenario, TRACE_AFTER};
use crate::window_stuffer::{ratio_at, scaled, years_through};

/// The up edge of the declared step.
pub(crate) struct StepRead {
    /// `M_r` over the window before the edge, and over the trace's last window.
    pub(crate) before: f64,
    pub(crate) after: f64,
    /// Blocks from the edge until the window mean covers 95 % of that move.
    pub(crate) settles: Option<u64>,
    /// The operand over the baseline, unclamped, over the window before the edge.
    pub(crate) resting_ratio: f64,
}

/// The up edge, and the unclamped ratio's values over year 1 after the
/// window's first fill.
pub(crate) struct HonestStep {
    pub(crate) up: StepRead,
    /// Ratio, scaled, to the blocks that read it.
    pub(crate) year_one_ratios: BTreeMap<u64, u64>,
}

struct Sample {
    m_r: u64,
    ratio: u64,
}

struct StepProbe<'p> {
    params: &'p SimParams,
    /// Blocks whose `M_r` and ratio the window means read, `[from, to)`.
    trace: Range<u64>,
    samples: BTreeMap<u64, Sample>,
    /// Blocks whose ratio is counted, value by value. Year 1 after the
    /// window's first fill: not an edge.
    counted: Range<u64>,
    year_one_ratios: BTreeMap<u64, u64>,
}

impl FoldProbe for StepProbe<'_> {
    fn seen(&mut self, seen: &BlockSeen<'_, '_>) {
        if self.trace.contains(&seen.block) {
            self.samples.insert(
                seen.block,
                Sample {
                    m_r: release_multiplier_at(seen, self.params),
                    ratio: ratio_at(seen, self.params),
                },
            );
        }
        if self.counted.contains(&seen.block) {
            let ratio = ratio_at(seen, self.params);
            *self.year_one_ratios.entry(ratio).or_insert(0) += 1;
        }
    }
}

/// The mean of `pick` over `[end - TX_VOLUME_WINDOW, end)`.
fn window_mean(samples: &BTreeMap<u64, Sample>, end: u64, pick: impl Fn(&Sample) -> u64) -> u64 {
    let window = u128::from(TX_VOLUME_WINDOW);
    let sum: u128 = (end - TX_VOLUME_WINDOW..end)
        .map(|block| {
            u128::from(pick(
                samples
                    .get(&block)
                    .expect("the trace holds every block of the window"),
            ))
        })
        .sum();
    u64::try_from(sum / window).expect("a mean of u64s fits")
}

/// `value` has covered 95 % of the signed move from `old` to `new`.
fn covers_ninety_five(value: u64, old: u64, new: u64) -> bool {
    let span = i128::from(new) - i128::from(old);
    span != 0 && 20 * (i128::from(value) - i128::from(old)) * span.signum() >= 19 * span.abs()
}

/// The up edge's window means, and the blocks until the rolling mean covers
/// 95 % of the move from the first to the last. `None` when they are equal.
fn settle_up(samples: &BTreeMap<u64, Sample>, edge: u64) -> StepRead {
    let before_m = window_mean(samples, edge, |s| s.m_r);
    let after_m = window_mean(samples, edge + TRACE_AFTER, |s| s.m_r);
    let resting = window_mean(samples, edge, |s| s.ratio);
    let window = u128::from(TX_VOLUME_WINDOW);
    let mut sum: u128 = (edge - TX_VOLUME_WINDOW..edge)
        .map(|block| u128::from(samples[&block].m_r))
        .sum();
    let settles = (1..=TRACE_AFTER).find(|&t| {
        let end = edge + t;
        sum = sum - u128::from(samples[&(end - 1 - TX_VOLUME_WINDOW)].m_r)
            + u128::from(samples[&(end - 1)].m_r);
        covers_ninety_five(
            u64::try_from(sum / window).expect("a mean of u64s fits"),
            before_m,
            after_m,
        )
    });
    StepRead {
        before: scaled(before_m),
        after: scaled(after_m),
        settles,
        resting_ratio: scaled(resting),
    }
}

/// The declared step's up edge at one parameter set.
///
/// The schedule steps up at the end of year 1 and back at the end of
/// year 2. The narration reads the up edge, so the fold runs through
/// that edge's trace and no further.
pub(crate) fn honest_step(params: &SimParams) -> HonestStep {
    let bpy = params.blocks_per_year();
    let mut config = step_scenario(params);
    let edge = bpy;
    assert!(
        edge >= TX_VOLUME_WINDOW,
        "the up edge has a full window before it"
    );
    config.sim_years = years_through(edge + TRACE_AFTER, bpy);
    let mut probe = StepProbe {
        params,
        trace: edge - TX_VOLUME_WINDOW..edge + TRACE_AFTER,
        samples: BTreeMap::new(),
        counted: TX_VOLUME_WINDOW..edge,
        year_one_ratios: BTreeMap::new(),
    };
    a1_year_aggs_probed(params, &config, &mut probe);
    HonestStep {
        up: settle_up(&probe.samples, edge),
        year_one_ratios: probe.year_one_ratios,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(m_r: u64, ratio: u64) -> Sample {
        Sample { m_r, ratio }
    }

    /// A jump that is immediate in the blocks settles only once the window
    /// mean has covered 95 % of it. A flat series does not settle.
    #[test]
    fn the_window_mean_settles_when_it_covers_ninety_five_percent() {
        let edge = 10_000;
        let mut jumped = BTreeMap::new();
        let mut flat = BTreeMap::new();
        for block in edge - TX_VOLUME_WINDOW..edge + TRACE_AFTER {
            let m_r = if block < edge { 0 } else { 100 };
            jumped.insert(block, sample(m_r, m_r));
            flat.insert(block, sample(5, 5));
        }
        let up = settle_up(&jumped, edge);
        let window = TX_VOLUME_WINDOW;
        // The mean is `100 * t / window` after `t` new blocks. 95 % of the
        // move is a mean of at least 95.
        let expected = (95 * window).div_ceil(100);
        assert_eq!(up.settles, Some(expected));
        assert_eq!(up.before, 0.0);
        assert_eq!(up.after, scaled(100));
        assert_eq!(settle_up(&flat, edge).settles, None);
    }
}
