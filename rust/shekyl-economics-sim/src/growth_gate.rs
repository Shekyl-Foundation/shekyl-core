// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether one more Standard transaction is admitted past the median.
//!
//! Verification instrument. [`rho_scaled`] is production
//! [`fee_correction`](shekyl_economics::fee_correction) divided by production
//! [`calc_release_multiplier`](shekyl_economics::calc_release_multiplier), and
//! the rung in the comparison is [`STANDARD_RUNG_OVER_ECONOMY`], the same
//! ratio the served ladder multiplies by. A sweep of other fee multipliers
//! is ESR-10 and is not built here.
//!
//! `m` in the printed inequality is the effective median. The fee multiplier
//! ESR-10 writes as `m` is a different operand and does not appear here.

use std::fmt;

use shekyl_economics::{
    calc_release_multiplier, fee_correction, params::SCALE, EconomicParams, TxVolume,
    RELAY_FLOOR_REFERENCE_TX_WEIGHT, STANDARD_RUNG_OVER_ECONOMY,
};

use crate::engine::SimParams;
use crate::scenarios::BASELINE_STEADY_STATE;
use crate::stage2::{trunc, A1YearAgg, FoldedScenario};

/// Years of the baseline table. Covers the crossing (year 19 on the
/// 2026-10-17 run) and the step in `theta` at year 23, when the ordinary
/// transaction's weight grows with the tree.
const BASELINE_TABLE_YEARS: usize = 25;

/// One transaction in a block. The escape grain is this times the year's
/// block count: a carried total has to clear the constrained ceiling by
/// more than one transaction a block. The `1` is the fill's unit, not a
/// tuning knob.
const ONE_TRANSACTION_PER_BLOCK: u64 = 1;

/// One year's carried and expired transactions, in counts over the year.
struct BlockTraffic {
    year: u64,
    carried_txs: u128,
    expired_txs: u128,
}

/// The year's last block, reduced to the operands the gate reads.
struct GateBlock {
    sigma_scaled: u64,
    burn_pct_scaled: u64,
    volume: TxVolume,
    /// Net supply in atomic units. `s` in the report is this over the
    /// curve asymptote, the burn's supply operand before `calc_burn_pct`
    /// clamps the ratio at 1.
    supply_raw: u64,
    weight: u64,
    /// Effective median `m` (CEN-G6b), bytes.
    effective_median: u64,
    /// Long-term effective median `M` (CEN-G6), bytes.
    long_term_median: u64,
}

/// One block's gate, with the ratios the report prints and the integer
/// admission verdict.
struct FeeGate {
    sigma: f64,
    supply_ratio: f64,
    burn: f64,
    rho: f64,
    theta_at_equal_medians: f64,
    /// Effective median over the long-term median. `0` when the long-term
    /// median is `0` (the penalty is then undefined and nothing is admitted).
    median_ratio: f64,
    admits_one_more: bool,
}

impl GateBlock {
    fn from_agg(agg: &A1YearAgg) -> Self {
        let last = &agg.last_block;
        Self {
            sigma_scaled: last.sigma_scaled,
            burn_pct_scaled: last.burn_pct_scaled,
            volume: last.volume,
            supply_raw: last.supply.to_raw(),
            weight: last.honest_tx.weight,
            effective_median: last.medians.effective_median.to_raw(),
            long_term_median: last.medians.long_term_effective_median.to_raw(),
        }
    }
}

/// `ρ` in SCALE units: `C · SCALE / M_r`, both factors from production.
///
/// `M_r` of `0` is not a release multiplier the rails produce. The
/// comparison treats it as 1 so a zero divisor cannot invent a ratio.
fn rho_scaled(block: &GateBlock, params: &EconomicParams) -> u64 {
    let release = calc_release_multiplier(
        block.volume,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    )
    .max(1);
    let correction = fee_correction(
        block.volume,
        block.sigma_scaled,
        block.burn_pct_scaled,
        params,
    );
    u64::try_from(u128::from(correction.as_scaled()) * u128::from(SCALE) / u128::from(release))
        .expect("rho fits u64: C is bounded by release_max and the divisor is at least 1")
}

/// `w · M² · SCALE ≤ rung · ρ · w_ref · m²`, in integers.
///
/// `M == 0` does not admit: the penalty divides by the long-term median.
/// A product that does not fit in `u128` does not admit either. The
/// weights and medians a fold actually prices sit far under that rail.
fn admits_one_more(block: &GateBlock, rho_scaled: u64, rung_over_economy: u64) -> bool {
    let long_term = block.long_term_median;
    if long_term == 0 {
        return false;
    }
    let long_term = u128::from(long_term);
    let effective = u128::from(block.effective_median);
    let Some(left) = u128::from(block.weight)
        .checked_mul(long_term)
        .and_then(|product| product.checked_mul(long_term))
        .and_then(|product| product.checked_mul(u128::from(SCALE)))
    else {
        return false;
    };
    let Some(right) = u128::from(rung_over_economy)
        .checked_mul(u128::from(rho_scaled))
        .and_then(|product| product.checked_mul(u128::from(RELAY_FLOOR_REFERENCE_TX_WEIGHT)))
        .and_then(|product| product.checked_mul(effective))
        .and_then(|product| product.checked_mul(effective))
    else {
        return false;
    };
    left <= right
}

/// `θ = w / (rung · w_ref)`: the admission test when the two medians are equal.
fn theta_at_equal_medians(weight: u64) -> f64 {
    weight as f64 / (STANDARD_RUNG_OVER_ECONOMY as f64 * RELAY_FLOOR_REFERENCE_TX_WEIGHT as f64)
}

fn fee_gate(block: &GateBlock, params: &SimParams, economic: &EconomicParams) -> FeeGate {
    let scaled = rho_scaled(block, economic);
    let scale = SCALE as f64;
    let supply_ratio = if params.emission_curve_asymptote == 0 {
        0.0
    } else {
        block.supply_raw as f64 / params.emission_curve_asymptote as f64
    };
    let median_ratio = if block.long_term_median == 0 {
        0.0
    } else {
        block.effective_median as f64 / block.long_term_median as f64
    };
    FeeGate {
        sigma: block.sigma_scaled as f64 / scale,
        supply_ratio,
        burn: block.burn_pct_scaled as f64 / scale,
        rho: scaled as f64 / scale,
        theta_at_equal_medians: theta_at_equal_medians(block.weight),
        median_ratio,
        admits_one_more: admits_one_more(block, scaled, STANDARD_RUNG_OVER_ECONOMY),
    }
}

/// First year whose carried count exceeds the constrained ceiling by more
/// than one transaction a block.
///
/// A year raises the ceiling only when it expires more than one transaction
/// a block. The comparison is strict, so a climb of exactly that grain is
/// still the same congestion. `None` when no year was constrained, or when
/// `blocks_per_year` is `0` (there is no per-block grain to compare).
fn congestion_escape_year(years: &[BlockTraffic], blocks_per_year: u64) -> Option<u64> {
    if blocks_per_year == 0 {
        return None;
    }
    let grain = u128::from(blocks_per_year) * u128::from(ONE_TRANSACTION_PER_BLOCK);
    let mut ceiling: Option<u128> = None;
    for year in years {
        if let Some(room) = ceiling {
            if year.carried_txs > room.saturating_add(grain) {
                return Some(year.year);
            }
        }
        if year.expired_txs > grain {
            ceiling = Some(ceiling.map_or(year.carried_txs, |room| room.max(year.carried_txs)));
        }
    }
    None
}

fn per_block(txs: u128, blocks_per_year: u64) -> f64 {
    if blocks_per_year == 0 {
        0.0
    } else {
        txs as f64 / blocks_per_year as f64
    }
}

fn year_label(year: Option<u64>) -> String {
    year.map_or_else(|| "-".to_owned(), |year| format!("y{year}"))
}

/// The growth-gate section of the stage-2 narration.
///
/// The caller prints this only for [`crate::fee_model::FeeModel::PRODUCTION_DEFAULT`].
pub(crate) fn write_report(
    out: &mut impl fmt::Write,
    params: &SimParams,
    folded: &[FoldedScenario],
) -> fmt::Result {
    let rung = STANDARD_RUNG_OVER_ECONOMY;
    let w_ref = RELAY_FLOOR_REFERENCE_TX_WEIGHT;
    let economic = params.economic();
    writeln!(
        out,
        "  -> GROWTH GATE (reading-pass finding 2), production Standard rung."
    )?;
    writeln!(
        out,
        "     Admitted when w*M^2 <= {rung}*rho*w_ref*m^2. rho = (1-sigma)/(1-b),"
    )?;
    writeln!(
        out,
        "     from fee_correction / M_r. theta = w/({rung}*w_ref) is that test at m = M."
    )?;
    writeln!(
        out,
        "     w_ref = {w_ref} B. Operands at the year's last block. s = net supply / asymptote,"
    )?;
    writeln!(out, "     before the burn clamps that ratio at 1.")?;
    writeln!(
        out,
        "     {BASELINE_STEADY_STATE} through year {BASELINE_TABLE_YEARS}. admits is the inequality."
    )?;
    writeln!(
        out,
        "     blocks grow: carried exceeds the constrained ceiling by more than one tx/block"
    )?;
    writeln!(
        out,
        "     ('-' when no year expired more than one tx/block)."
    )?;
    writeln!(
        out,
        "       {:>6} {:>8} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>6}",
        "year", "carried", "LTM KB", "sigma", "s", "b", "rho", "theta", "m/M", "admits",
    )?;

    match folded
        .iter()
        .find(|scenario| scenario.name == BASELINE_STEADY_STATE)
    {
        Some(baseline) => {
            for agg in baseline.aggs.iter().take(BASELINE_TABLE_YEARS) {
                let gate = fee_gate(&GateBlock::from_agg(agg), params, &economic);
                writeln!(
                    out,
                    "       {:>6} {:>8.1} {:>7.0} {:>7.3} {:>7.3} {:>7.3} {:>7.3} {:>7.3} {:>7.3} {:>6}",
                    agg.year,
                    per_block(agg.carried_txs, params.blocks_per_year),
                    agg.long_term_median as f64 / 1_000.0,
                    gate.sigma,
                    gate.supply_ratio,
                    gate.burn,
                    gate.rho,
                    gate.theta_at_equal_medians,
                    gate.median_ratio,
                    if gate.admits_one_more { "yes" } else { "no" },
                )?;
            }
        }
        None => writeln!(out, "       {BASELINE_STEADY_STATE} is not in this run.")?,
    }

    for scenario in folded {
        let gates: Vec<FeeGate> = scenario
            .aggs
            .iter()
            .map(|agg| fee_gate(&GateBlock::from_agg(agg), params, &economic))
            .collect();
        let zone = scenario
            .aggs
            .iter()
            .zip(&gates)
            .find(|(_, gate)| gate.rho >= gate.theta_at_equal_medians)
            .map(|(agg, _)| agg.year);
        let admitted = scenario
            .aggs
            .iter()
            .zip(&gates)
            .find(|(_, gate)| gate.admits_one_more)
            .map(|(agg, _)| agg.year);
        let traffic: Vec<BlockTraffic> = scenario
            .aggs
            .iter()
            .map(|agg| BlockTraffic {
                year: agg.year,
                carried_txs: agg.carried_txs,
                expired_txs: agg.expired_txs,
            })
            .collect();
        let growth = congestion_escape_year(&traffic, params.blocks_per_year);
        writeln!(
            out,
            "       {:<20} zone theta from {}, admitted from {}, blocks grow from {}",
            trunc(&scenario.name, 20),
            year_label(zone),
            year_label(admitted),
            year_label(growth),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_at(weight: u64, effective_median: u64, long_term_median: u64) -> GateBlock {
        GateBlock {
            sigma_scaled: 0,
            burn_pct_scaled: 0,
            volume: TxVolume::ZERO,
            supply_raw: 0,
            weight,
            effective_median,
            long_term_median,
        }
    }

    fn traffic(year: u64, carried_txs: u128, expired_txs: u128) -> BlockTraffic {
        BlockTraffic {
            year,
            carried_txs,
            expired_txs,
        }
    }

    #[test]
    fn rho_is_fee_correction_divided_by_the_release_multiplier() {
        let params = EconomicParams::default();
        let sigma = 135_000;
        let burn = 16_000;
        let block = GateBlock {
            sigma_scaled: sigma,
            burn_pct_scaled: burn,
            volume: TxVolume::per_block(params.tx_volume_baseline),
            supply_raw: 0,
            weight: 14_256,
            effective_median: 322_000,
            long_term_median: 322_000,
        };
        let release = calc_release_multiplier(
            block.volume,
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        );
        assert_eq!(release, SCALE);
        let correction = fee_correction(block.volume, sigma, burn, &params);
        let rho = rho_scaled(&block, &params);
        assert_eq!(
            u128::from(rho),
            u128::from(correction.as_scaled()) * u128::from(SCALE) / u128::from(release)
        );
        let direct = (SCALE - sigma) * SCALE / (SCALE - burn);
        assert_eq!(rho, direct);

        let off_baseline = GateBlock {
            volume: TxVolume::window(params.tx_volume_baseline * 10 + 1, 10),
            ..block
        };
        let off = rho_scaled(&off_baseline, &params);
        assert!(
            off.abs_diff(direct) <= 1,
            "unclamped rho {off} differs from the direct quotient {direct} by more than 1 SCALE unit"
        );
    }

    #[test]
    fn equal_medians_admit_iff_weight_is_at_the_zone_threshold() {
        let admits = |weight| {
            admits_one_more(
                &block_at(weight, 1_000, 1_000),
                SCALE,
                STANDARD_RUNG_OVER_ECONOMY,
            )
        };
        // w_ref = 3000 and the rung is 4, so theta = 1 at weight 12_000.
        assert!(admits(12_000));
        assert!(!admits(12_001));
    }

    #[test]
    fn an_effective_median_twice_the_long_term_admits_four_times_the_weight() {
        let admits = |weight| {
            admits_one_more(
                &block_at(weight, 2_000, 1_000),
                SCALE,
                STANDARD_RUNG_OVER_ECONOMY,
            )
        };
        assert!(admits(12_001));
        assert!(admits(48_000));
        assert!(!admits(48_001));
    }

    #[test]
    fn a_zero_long_term_median_does_not_admit() {
        assert!(!admits_one_more(
            &block_at(12_000, 1_000, 0),
            SCALE,
            STANDARD_RUNG_OVER_ECONOMY,
        ));
    }

    #[test]
    fn congestion_escape_fires_when_carried_jumps_past_one_tx_per_block() {
        let years = [traffic(1, 220, 280), traffic(2, 225, 0), traffic(3, 231, 0)];
        assert_eq!(congestion_escape_year(&years, 10), Some(3));
    }

    #[test]
    fn exactly_one_tx_per_block_above_the_ceiling_does_not_escape() {
        assert_eq!(
            congestion_escape_year(&[traffic(1, 220, 280), traffic(2, 230, 0)], 10),
            None
        );
        assert_eq!(
            congestion_escape_year(&[traffic(1, 220, 280), traffic(2, 231, 0)], 10),
            Some(2)
        );
    }

    #[test]
    fn a_climb_under_one_tx_per_block_never_escapes() {
        let years: Vec<_> = (1..=20)
            .map(|year| traffic(year, 200 + u128::from(year) * 5, 100))
            .collect();
        assert_eq!(congestion_escape_year(&years, 10), None);
    }

    #[test]
    fn a_year_that_never_expires_a_tx_per_block_is_not_constrained() {
        assert_eq!(
            congestion_escape_year(&[traffic(1, 10, 0), traffic(2, 10_000, 0)], 10),
            None
        );
    }

    #[test]
    fn expiring_one_tx_per_block_does_not_raise_the_ceiling() {
        assert_eq!(
            congestion_escape_year(&[traffic(1, 100, 10), traffic(2, 10_000, 0)], 10),
            None
        );
        // The ceiling stays at year 1. Updating it from year 2's carried
        // count before the comparison would hide the jump.
        assert_eq!(
            congestion_escape_year(&[traffic(1, 100, 11), traffic(2, 200, 5)], 10),
            Some(2)
        );
    }

    #[test]
    fn no_blocks_in_the_year_has_no_escape_grain() {
        assert_eq!(congestion_escape_year(&[traffic(1, 1, 100)], 0), None);
    }

    #[test]
    fn the_header_names_the_equal_median_case_and_a_missing_baseline() {
        let mut out = String::new();
        write_report(&mut out, &SimParams::default(), &[]).unwrap();
        assert!(out.contains("m = M"), "{out}");
        assert!(out.contains(BASELINE_STEADY_STATE), "{out}");
        assert!(out.contains("is not in this run"), "{out}");
        assert!(out.contains("fee_correction"), "{out}");
    }
}
