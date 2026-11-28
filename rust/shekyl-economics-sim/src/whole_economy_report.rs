// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The whole-economy narration and the derived table.
//!
//! Child of [`super`]: it renders the rows the fold produced. The narration
//! and the table share [`median_and_range`] and keep their own sentences.

use std::fmt::{self, Write};

use shekyl_economics::params::TX_VOLUME_WINDOW;

use crate::rng::HONEST_SEEDS;
use crate::scenarios::SUSTAINED_GROWTH;

use super::*;

/// The median and range of `values`, formatted with `digits` decimals.
fn mr(values: &[f64], digits: usize) -> String {
    let Some((median, low, high)) = median_and_range(values) else {
        return "-".into();
    };
    if (low - high).abs() < f64::EPSILON {
        return format!("{median:.digits$}");
    }
    format!("{median:.digits$} [{low:.digits$}, {high:.digits$}]")
}

/// The lower median of `values`' finite members, and their least and
/// greatest; nothing when none is finite. The narration and the derived
/// table both read their medians here.
fn median_and_range(values: &[f64]) -> Option<(f64, f64, f64)> {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    Some((v[(v.len() - 1) / 2], v[0], v[v.len() - 1]))
}

/// Each fold's figure at `year`, or nothing past its stop.
fn at_year<'r>(row: &'r Row, year: u64) -> impl Iterator<Item = &'r YearFig> + 'r {
    row.folds
        .iter()
        .filter_map(move |f| f.years.get(year as usize - 1))
}

pub(super) fn write_report(out: &mut impl Write, rows: &[Row], scope: Scope) -> fmt::Result {
    writeln!(
        out,
        "THREE ECONOMIES GRADED WHOLE (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.37, WE-1..WE-12).\n\
         Measures only, never a verdict. Scope: {}. Standard traffic; each figure is the median\n\
         [range] across the row's seeds ({:?}). Horizon y{HORIZON_YEARS}; a fold that reaches its\n\
         supply break or the edge of the reward's arithmetic stops there and prints which, the\n\
         year and the median. {SUSTAINED_GROWTH} is a stress of the mechanism, not a forecast:\n\
         its folds run until the arithmetic or the supply runs out. Read the tail columns from\n\
         the other scenarios. SKL per block unless named.",
        match scope {
            Scope::Full => "full",
            Scope::Nightly => "nightly slice",
        },
        HONEST_SEEDS
    )?;
    let mut last: Option<(&str, &str, u64)> = None;
    for row in rows {
        let key = (
            row.scenario.as_str(),
            row.place.zone.as_str(),
            row.place.w_ref,
        );
        if last != Some(key) {
            writeln!(
                out,
                "\n== {}{} | zone {} ({} B) | w_ref {} ==",
                row.scenario,
                stress_tag(&row.scenario),
                row.place.zone,
                row.place.zone_bytes,
                row.place.w_ref
            )?;
            last = Some(key);
        }
        write_row(out, row, scope)?;
    }
    Ok(())
}

/// The stress scenario's mark on its sections and tail lines: the
/// sustained growth's demand compounds without a ceiling, so its folds
/// show where the mechanism's arithmetic or supply runs out, and the tail
/// is read from the other scenarios (§5.37.1).
fn stress_tag(scenario: &str) -> &'static str {
    if is_stress(scenario) {
        " (stress: runs to its edge; not read for the tail)"
    } else {
        ""
    }
}

/// Whether `scenario` is a stress: run to its edge, labelled so, and not
/// read for the tail (Rick, 2026-11-21).
fn is_stress(scenario: &str) -> bool {
    scenario == SUSTAINED_GROWTH
}

#[allow(clippy::cast_precision_loss)]
fn write_row(out: &mut impl Write, row: &Row, scope: Scope) -> fmt::Result {
    let fig = |year: u64, f: &dyn Fn(&YearFig) -> f64, digits: usize| -> String {
        let v: Vec<f64> = at_year(row, year).map(f).collect();
        mr(&v, digits)
    };
    let stops: Vec<String> = row
        .folds
        .iter()
        .map(|f| f.stop.map_or("-".into(), |stop| stop.label()))
        .collect();
    writeln!(
        out,
        "-- {} | {} | stops {}",
        row.economy,
        row.rule,
        stops.join(",")
    )?;
    let half: Vec<f64> = row.folds.iter().filter_map(|f| f.half_year).collect();
    let mut security = format!("   security: 50% year {}", mr(&half, 2));
    for year in SAMPLE_YEARS {
        write!(
            security,
            " | y{year} income {} fee {}",
            fig(year, &|y| y.miner_income, 2),
            fig(year, &|y| y.miner_fee, 4)
        )?;
    }
    writeln!(out, "{security}")?;
    // Every year in the nightly slice and in the JSON summary: STD-5 could
    // not be graded because no report carried these means (§5.35.1). The
    // full table prints the sample years, which keeps its narration at
    // 8.4 MB instead of about 15 MB; every year of every cell is in its
    // JSON (§5.37.1).
    let years: Vec<u64> = match scope {
        Scope::Nightly => (1..=HORIZON_YEARS).collect(),
        Scope::Full => SAMPLE_YEARS.to_vec(),
    };
    let mut release = format!(
        "   release and burn (yearly means, {}):",
        match scope {
            Scope::Nightly => "every year",
            Scope::Full => "sample years; every year in the JSON",
        }
    );
    for year in years {
        write!(
            release,
            " | y{year} M_r {} burn {}",
            fig(year, &|y| y.release_mean, 3),
            fig(year, &|y| y.burn_mean, 3)
        )?;
    }
    writeln!(out, "{release}")?;
    let mut template = String::from("   median and fee:");
    for year in SAMPLE_YEARS {
        write!(
            template,
            " | y{year} LTEM {} KB carried {} own {} Standard {} SKL {} B penalty {}",
            fig(year, &|y| y.ltem as f64 / BYTES_PER_KB, 0),
            fig(year, &|y| y.carried, 1),
            fig(year, &|y| y.own, 1),
            fig(year, &|y| y.standard_fee, 5),
            fig(year, &|y| y.standard_weight, 0),
            fig(year, &|y| y.penalty, 1)
        )?;
    }
    writeln!(out, "{template}")?;
    let mut tail = format!(
        "   tail{} (miner's-net tail over miner's-net fees p50/p95/p99):",
        stress_tag(&row.scenario)
    );
    for year in SAMPLE_YEARS {
        let ratio = |p: fn(&Spread) -> f64| {
            move |y: &YearFig| {
                let fees = p(&y.fee_net);
                if fees > 0.0 {
                    y.tail_net / fees
                } else {
                    f64::INFINITY
                }
            }
        };
        write!(
            tail,
            " | y{year}{} {} / {} / {} (fees gross p95 {} net p95 {} var {})",
            if at_year(row, year).any(YearFig::in_tail_era) {
                " tail-era"
            } else {
                ""
            },
            fig(year, &ratio(|s| s.p50), 1),
            fig(year, &ratio(|s| s.p95), 1),
            fig(year, &ratio(|s| s.p99), 1),
            fig(year, &|y| y.fee_gross.p95, 4),
            fig(year, &|y| y.fee_net.p95, 4),
            fig(year, &|y| y.fee_net.variance, 6)
        )?;
    }
    writeln!(out, "{tail}")?;
    for year in DECILE_YEARS {
        let deciles: Vec<String> = (0..9)
            .map(|i| {
                fig(
                    year,
                    &move |y: &YearFig| y.fee_net_deciles.map_or(f64::NAN, |d| d[i]),
                    5,
                )
            })
            .collect();
        writeln!(
            out,
            "   y{year} net fee deciles: {} | p95 {} p99 {}",
            deciles.join(" "),
            fig(year, &|y| y.fee_net.p95, 5),
            fig(year, &|y| y.fee_net.p99, 5)
        )?;
    }
    let mut inclusion = format!(
        "   inclusion tau* ms/KB (sweep {}-{}):",
        TAU_SWEEP_MS_PER_KB[0], TAU_SWEEP_MS_PER_KB[1]
    );
    for year in SAMPLE_YEARS {
        write!(
            inclusion,
            " | y{year} gross {} net {}",
            fig(year, &|y| y.tau_gross, 3),
            fig(year, &|y| y.tau_net, 3)
        )?;
    }
    writeln!(out, "{inclusion}")?;
    let gb = BYTES_PER_GB as f64;
    let crossing = |design: bool| -> Vec<f64> {
        row.folds
            .iter()
            .map(|f| {
                if design {
                    if f.design_load_bytes_a_day >= gb {
                        1.0
                    } else {
                        f64::INFINITY
                    }
                } else {
                    f.years
                        .iter()
                        .find(|y| y.bytes_a_day >= gb)
                        .map_or(f64::INFINITY, |y| y.year as f64)
                }
            })
            .collect()
    };
    let design: Vec<f64> = row
        .folds
        .iter()
        .map(|f| f.design_load_bytes_a_day / gb)
        .collect();
    let mut bloat = format!(
        "   bloat: 1 GB/day first in year {} (cell's load), design load {} GB/day (first {})",
        mr(&crossing(false), 0),
        mr(&design, 3),
        mr(&crossing(true), 0)
    );
    for year in SAMPLE_YEARS {
        write!(
            bloat,
            " | y{year} {} GB/day {} outputs/day archive {} GB",
            fig(year, &|y| y.bytes_a_day / gb, 3),
            fig(year, &|y| y.outputs_a_day, 0),
            fig(year, &|y| y.archival_bytes as f64 / gb, 1)
        )?;
    }
    writeln!(out, "{bloat}")?;
    let adoption: Vec<f64> = row
        .folds
        .iter()
        .filter_map(|f| f.adoption.map(|a| a.0))
        .collect();
    let adoption_year: Vec<f64> = row
        .folds
        .iter()
        .filter_map(|f| f.adoption.map(|a| a.1))
        .collect();
    writeln!(
        out,
        "   distribution: emitted before blocks first carry the baseline {} (at year {})",
        mr(&adoption, 4),
        mr(&adoption_year, 3)
    )?;
    let bond: Vec<f64> = row.folds.iter().map(|f| f.bond_per_gb).collect();
    let mut archival = format!("   archival (bond {} SKL per GB held):", mr(&bond, 2));
    for year in SAMPLE_YEARS {
        write!(
            archival,
            " | y{year} stakers: emission {} pool {} penalty {}; per GB-year {}; bytes <10y/10-40y/>40y {}/{}/{} GB",
            fig(year, &|y| y.staker_emission, 3),
            fig(year, &|y| y.staker_pool, 4),
            fig(year, &|y| y.staker_penalty, 4),
            fig(year, &|y| y.staker_income_per_gb_year, 6),
            fig(year, &|y| y.bytes_by_age[0] as f64 / gb, 0),
            fig(year, &|y| y.bytes_by_age[1] as f64 / gb, 0),
            fig(year, &|y| y.bytes_by_age[2] as f64 / gb, 0)
        )?;
    }
    writeln!(out, "{archival}")?;
    let mut predictability = String::from("   emitted fraction:");
    for year in SAMPLE_YEARS {
        write!(
            predictability,
            " | y{year} {}",
            fig(year, &|y| y.emitted_fraction, 4)
        )?;
    }
    writeln!(out, "{predictability}")?;
    for (i, year) in ADVERSARY_YEARS.iter().enumerate() {
        let pick = |f: &dyn Fn(&Adversaries) -> f64| -> String {
            let v: Vec<f64> = row
                .folds
                .iter()
                .filter_map(|fo| fo.adversaries.get(i))
                .map(f)
                .collect();
            mr(&v, 3)
        };
        writeln!(
            out,
            "   adversaries y{year}: ratchet cost/production at f 0/5/20/33% {} / {} / {} / {} (production {} SKL) | inducer net/penalty at 0.5/5/20% {} / {} / {} | shard advance cost {} gain {} SKL",
            pick(&|a| a.ratchet_ratio[0]),
            pick(&|a| a.ratchet_ratio[1]),
            pick(&|a| a.ratchet_ratio[2]),
            pick(&|a| a.ratchet_ratio[3]),
            pick(&|a| a.ratchet_cost),
            pick(&|a| a.inducer_net[0]),
            pick(&|a| a.inducer_net[1]),
            pick(&|a| a.inducer_net[2]),
            pick(&|a| a.shard_advance_cost),
            pick(&|a| a.shard_advance_gain)
        )?;
    }
    Ok(())
}

/// The derived table (§5.37.1, Rick 2026-11-21 and 2026-11-22): one CSV
/// line per row, the figures the rulings read, each the median across the
/// row's seeds as the narration prints it. The full run's narration and JSON
/// summary are the record behind it; neither is committed, and the repo keeps
/// the SHA-256 of each. The nightly slice's table and the full table are
/// each rebuilt from their run by a pin. A slice cell prints its table
/// beside production's (§5.38).
pub(super) fn table(summary: &Summary) -> String {
    let mut out = String::new();
    write_table(&mut out, &summary.rows).expect("String sink is infallible");
    out
}

/// The derived table's columns, in order: the row's names, then security,
/// release and burn, inclusion, bloat, distribution, archival, and the
/// reward against the fees with the year the tail era begins.
pub(super) const TABLE_COLUMNS: [&str; 41] = [
    "scenario",
    "zone",
    "w_ref",
    "economy",
    "rule",
    "role",
    "stops",
    "half_year",
    "income_y1",
    "income_y10",
    "income_y30",
    "income_y60",
    "income_y135",
    "fee_share_y10",
    "m_r_y1",
    "m_r_y10",
    "m_r_y30",
    "burn_y1",
    "burn_y10",
    "burn_y30",
    "ltem_kb_y30",
    "standard_fee_y1",
    "tau_gross_y1",
    "tau_gross_y30",
    "tau_net_y1",
    "tau_net_y30",
    "gb_day_y1",
    "gb_day_y10",
    "gb_day_y30",
    "first_1gb_day_year",
    "archive_gb_y135",
    "adoption_fraction",
    "adoption_year",
    "stakers_per_gb_year_y10",
    "stakers_per_gb_year_y30",
    "staker_pool_y10",
    "staker_penalty_y10",
    "reward_net_over_fees_p95_y60",
    "reward_net_over_fees_p95_y100",
    "reward_net_over_fees_p95_y135",
    "tail_era_year",
];

/// The narration's median of `values` ([`median_and_range`]), as `digits`
/// decimals, or `-`.
fn med(values: &[f64], digits: usize) -> String {
    median_and_range(values)
        .map_or_else(|| "-".into(), |(median, _, _)| format!("{median:.digits$}"))
}

#[allow(clippy::cast_precision_loss)]
fn write_table(out: &mut impl Write, rows: &[Row]) -> fmt::Result {
    writeln!(
        out,
        "# THREE ECONOMIES GRADED WHOLE, the derived table (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.37.1).\n\
         # One line per economy, template rule, scenario, zone and w_ref; each figure is the median\n\
         # across the row's seeds, '-' where no seed has it (past a stop, or never reached). SKL per\n\
         # block unless named; tau in ms/KB; m_r and burn are yearly means. reward_net_over_fees_p95 is\n\
         # a ratio with no unit: the miner's-net emission (the paid reward's miner leg, a yearly mean,\n\
         # SKL a block) over the 95th-percentile block's miner's-net fees (SKL a block). tail_era_year is\n\
         # the first year more than half a fold's blocks pay the tail; from it on, the emission is the\n\
         # tail and the ratio is the tail test, read against k = 1; before it, the ratio is the emission\n\
         # a miner is paid then. adoption_year is the year the honest carried count's trailing mean over\n\
         # {TX_VOLUME_WINDOW} blocks first reaches the baseline: the year blocks first carry it, not the\n\
         # year demand reaches it ({SLOW_ADOPTION}'s demand reaches it at year {SLOW_ADOPTION_YEARS});\n\
         # adoption_fraction is the supply emitted by then. role 'stress' marks {SUSTAINED_GROWTH}: it\n\
         # runs to its edge and is not read for the tail, which is read from the 'read' rows. stops\n\
         # names, per seed, where the fold ended: the horizon (year {HORIZON_YEARS}), the supply's break,\n\
         # or the reward's domain edge. The narration and the JSON summary are the full record."
    )?;
    writeln!(out, "{}", TABLE_COLUMNS.join(","))?;
    let gb = BYTES_PER_GB as f64;
    for row in rows {
        let fig = |year: u64, f: &dyn Fn(&YearFig) -> f64, digits: usize| -> String {
            let v: Vec<f64> = at_year(row, year).map(f).collect();
            med(&v, digits)
        };
        let stops: Vec<String> = row
            .folds
            .iter()
            .map(|f| f.stop.map_or("horizon".into(), |stop| stop.label()))
            .collect();
        let half: Vec<f64> = row.folds.iter().filter_map(|f| f.half_year).collect();
        let first_gb: Vec<f64> = row
            .folds
            .iter()
            .map(|f| {
                f.years
                    .iter()
                    .find(|y| y.bytes_a_day >= gb)
                    .map_or(f64::INFINITY, |y| y.year as f64)
            })
            .collect();
        let adoption: Vec<f64> = row
            .folds
            .iter()
            .filter_map(|f| f.adoption.map(|a| a.0))
            .collect();
        let adoption_year: Vec<f64> = row
            .folds
            .iter()
            .filter_map(|f| f.adoption.map(|a| a.1))
            .collect();
        let reward = |y: &YearFig| {
            if y.fee_net.p95 > 0.0 {
                (y.miner_income - y.miner_fee) / y.fee_net.p95
            } else {
                f64::INFINITY
            }
        };
        let tail_era: Vec<f64> = row
            .folds
            .iter()
            .map(|f| {
                f.years
                    .iter()
                    .find(|y| y.in_tail_era())
                    .map_or(f64::INFINITY, |y| y.year as f64)
            })
            .collect();
        let cells = [
            row.scenario.clone(),
            row.place.zone.clone(),
            row.place.w_ref.to_string(),
            row.economy.clone(),
            row.rule.clone(),
            if is_stress(&row.scenario) {
                "stress"
            } else {
                "read"
            }
            .to_owned(),
            stops.join(";"),
            med(&half, 2),
            fig(1, &|y| y.miner_income, 2),
            fig(10, &|y| y.miner_income, 2),
            fig(30, &|y| y.miner_income, 2),
            fig(60, &|y| y.miner_income, 2),
            fig(135, &|y| y.miner_income, 2),
            fig(10, &|y| y.miner_fee / y.miner_income, 4),
            fig(1, &|y| y.release_mean, 3),
            fig(10, &|y| y.release_mean, 3),
            fig(30, &|y| y.release_mean, 3),
            fig(1, &|y| y.burn_mean, 3),
            fig(10, &|y| y.burn_mean, 3),
            fig(30, &|y| y.burn_mean, 3),
            fig(30, &|y| y.ltem as f64 / BYTES_PER_KB, 0),
            fig(1, &|y| y.standard_fee, 5),
            fig(1, &|y| y.tau_gross, 3),
            fig(30, &|y| y.tau_gross, 3),
            fig(1, &|y| y.tau_net, 3),
            fig(30, &|y| y.tau_net, 3),
            fig(1, &|y| y.bytes_a_day / gb, 3),
            fig(10, &|y| y.bytes_a_day / gb, 3),
            fig(30, &|y| y.bytes_a_day / gb, 3),
            med(&first_gb, 0),
            fig(135, &|y| y.archival_bytes as f64 / gb, 1),
            med(&adoption, 4),
            med(&adoption_year, 3),
            fig(10, &|y| y.staker_income_per_gb_year, 3),
            fig(30, &|y| y.staker_income_per_gb_year, 3),
            fig(10, &|y| y.staker_pool, 4),
            fig(10, &|y| y.staker_penalty, 4),
            fig(60, &reward, 1),
            fig(100, &reward, 1),
            fig(135, &reward, 1),
            med(&tail_era, 0),
        ];
        writeln!(out, "{}", cells.join(","))?;
    }
    Ok(())
}
