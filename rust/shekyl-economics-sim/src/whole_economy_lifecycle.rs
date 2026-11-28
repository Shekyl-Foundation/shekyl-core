// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The staker emission share's first look: the lifecycle view
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.38).
//!
//! Child of [`super`]. It reads two nightly-slice summaries, a cell's and
//! production's. It takes four series: A-honest and B under the gross rule,
//! at N = 90 and in the inherited zone, on the baseline at the base `w_ref`.
//! For each it gives every year to the horizon, production's figure beside
//! the cell's.
//!
//! Every figure comes from the summary's own yearly means, so the record
//! gains no field and no recorded digest moves:
//!
//! - `emission` is the paid (penalised) reward a block: its miner leg (the
//!   miner's income less its fee part) plus the stakers' emission.
//! - The two emission shares are each leg over `emission`. They are measured
//!   from the fold, not read from the schedule.
//! - `destroyed` is the fees less the miner's part and the stakers' pool
//!   part: the burn split's third leg. The split's three legs sum to the
//!   fees exactly (`shekyl_economics::compute_burn_split`).
//! - `net_issuance_pct` is the year's emission less the coins it destroyed,
//!   over the coins generated to the year's start less those destroyed to
//!   it. The record holds no coin count before year 1's end, so year 1
//!   prints `-`.
//!
//! It prints measures, never a verdict.

use std::fmt::{self, Write};

use super::report::table;
use super::*;

/// The years the narration prints the view at. The CSV carries every year.
const VIEW_YEARS: [u64; 11] = [1, 2, 5, 10, 15, 20, 30, 45, 60, 100, 135];

/// One series of the view: an economy under the gross rule, at a zone.
#[derive(Debug, Clone, Copy)]
struct Series {
    economy: Economy,
    zone_bytes: u64,
}

/// The view's four series, in its order. Each zone is identified by its byte
/// size, not by its label.
fn series(base: &SimParams) -> [Series; 4] {
    let n90 = spend_zone_bytes(reference_spend_weight(base), SPENDS[0]);
    [
        (Economy::AHonest, n90),
        (Economy::Decoupled, n90),
        (Economy::AHonest, INHERITED_ZONE),
        (Economy::Decoupled, INHERITED_ZONE),
    ]
    .map(|(economy, zone_bytes)| Series {
        economy,
        zone_bytes,
    })
}

/// The series' row in `summary`: the baseline at the base `w_ref`, gross.
/// Every slice carries it; a summary without it is not a slice's.
fn row_of(summary: &Summary, series: Series, w_ref: u64) -> &Row {
    summary
        .rows
        .iter()
        .find(|r| {
            r.economy == series.economy.name()
                && r.rule == TemplateRule::Gross.name()
                && r.scenario == BASELINE_STEADY_STATE
                && r.place.zone_bytes == series.zone_bytes
                && r.place.w_ref == w_ref
        })
        .unwrap_or_else(|| {
            panic!(
                "the summary has no {} gross row at {} B and w_ref {w_ref}: it is not a nightly slice's",
                series.economy.name(),
                series.zone_bytes
            )
        })
}

/// A row's one fold: the slice folds one seed per row.
fn the_fold(row: &Row) -> &Folded {
    match row.folds.as_slice() {
        [fold] => fold,
        folds => panic!(
            "the lifecycle view reads one seed per row, the slice's; {} {} has {}",
            row.economy,
            row.place.zone,
            folds.len()
        ),
    }
}

/// One year of one series in one arm.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Life {
    year: u64,
    emitted_fraction: f64,
    tail_share: f64,
    emission: f64,
    miner_emission_share: f64,
    staker_emission_share: f64,
    burn_of_fees: f64,
    destroyed: f64,
    destroyed_over_emission: f64,
    /// `None` in year 1: the record holds no coin count before it.
    net_issuance_pct: Option<f64>,
    miner_income: f64,
    miner_fee: f64,
    staker_emission: f64,
    staker_pool: f64,
    staker_penalty: f64,
    staker_income_per_gb_year: f64,
    archival_bytes: u64,
    standard_fee: f64,
}

/// Percent.
const PER_CENT: f64 = 100.0;

/// `fold`'s years as [`Life`]s. `blocks_per_year` and the asymptote (SKL)
/// are the run's.
#[allow(clippy::cast_precision_loss)]
fn lives(fold: &Folded, blocks_per_year: u64, asymptote: f64) -> Vec<Life> {
    let blocks = blocks_per_year as f64;
    let mut generated_before: Option<f64> = None;
    let mut destroyed_before = 0.0;
    fold.years
        .iter()
        .map(|y| {
            let miner_emission = y.miner_income - y.miner_fee;
            let emission = miner_emission + y.staker_emission;
            let destroyed = y.fee_gross.mean - y.miner_fee - y.staker_pool;
            let share = |leg: f64| {
                if emission > 0.0 {
                    leg / emission
                } else {
                    f64::NAN
                }
            };
            let net_issuance_pct = generated_before.map(|generated| {
                (emission - destroyed) * blocks / (generated - destroyed_before) * PER_CENT
            });
            destroyed_before += destroyed * blocks;
            generated_before = Some(y.emitted_fraction * asymptote);
            Life {
                year: y.year,
                emitted_fraction: y.emitted_fraction,
                tail_share: y.tail_share,
                emission,
                miner_emission_share: share(miner_emission),
                staker_emission_share: share(y.staker_emission),
                burn_of_fees: y.burn_mean,
                destroyed,
                destroyed_over_emission: share(destroyed),
                net_issuance_pct,
                miner_income: y.miner_income,
                miner_fee: y.miner_fee,
                staker_emission: y.staker_emission,
                staker_pool: y.staker_pool,
                staker_penalty: y.staker_penalty,
                staker_income_per_gb_year: y.staker_income_per_gb_year,
                archival_bytes: y.archival_bytes,
                standard_fee: y.standard_fee,
            }
        })
        .collect()
}

/// One series, both arms: production's lives and the cell's.
struct Pair {
    series: Series,
    zone: String,
    w_ref: u64,
    production: Vec<Life>,
    cell: Vec<Life>,
}

/// The four series, each in both arms.
fn pairs(cell: &Summary, production: &Summary, base: &SimParams) -> Vec<Pair> {
    let w_ref = base.relay().ref_tx_weight;
    let blocks_per_year = base.blocks_per_year();
    let asymptote = skl(u128::from(base.economic().emission_curve_asymptote));
    series(base)
        .into_iter()
        .map(|s| {
            let row = row_of(production, s, w_ref);
            Pair {
                series: s,
                zone: row.place.zone.clone(),
                w_ref,
                production: lives(the_fold(row), blocks_per_year, asymptote),
                cell: lives(the_fold(row_of(cell, s, w_ref)), blocks_per_year, asymptote),
            }
        })
        .collect()
}

/// `value` with `digits` decimals, or `-` when it is not finite.
fn num(value: f64, digits: usize) -> String {
    if value.is_finite() {
        format!("{value:.digits$}")
    } else {
        "-".into()
    }
}

/// `production / cell`, each with `digits` decimals.
fn both(production: f64, cell: f64, digits: usize) -> String {
    format!("{} / {}", num(production, digits), num(cell, digits))
}

/// The lifecycle view at [`VIEW_YEARS`], then the slice's derived table with
/// the cell beside production. `cell` and `production` are two nightly-slice
/// summaries, and `base` is the run's parameters.
///
/// # Errors
///
/// Only `out`'s.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn write_view(
    out: &mut impl Write,
    cell: &Summary,
    production: &Summary,
    base: &SimParams,
) -> fmt::Result {
    writeln!(
        out,
        "\nTHE LIFECYCLE VIEW (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.38). Measures only, never a\n\
         verdict. Each figure is production / the cell. Yearly means, SKL a block unless named.\n\
         emission is the paid (penalised) reward; the shares are its legs over it, measured from\n\
         the fold; destroyed is the fees less the miner's part and the stakers' pool part; net\n\
         issuance is the year's emission less what it destroyed, over the coins generated to the\n\
         year's start less those destroyed to it ('-' in year 1, which the record cannot start).\n\
         Every year is in the CSV the on-demand helper derives from the two summaries."
    )?;
    for pair in pairs(cell, production, base) {
        writeln!(
            out,
            "\n== {} | gross | baseline_steady_state | zone {} ({} B) | w_ref {} ==",
            pair.series.economy.name(),
            pair.zone,
            pair.series.zone_bytes,
            pair.w_ref
        )?;
        for year in VIEW_YEARS {
            let at = |lives: &[Life]| lives.iter().find(|l| l.year == year).copied();
            let (Some(p), Some(c)) = (at(&pair.production), at(&pair.cell)) else {
                writeln!(out, "  y{year}: past a fold's stop")?;
                continue;
            };
            let net = |l: &Life| l.net_issuance_pct.unwrap_or(f64::NAN);
            writeln!(
                out,
                "  y{year} | emitted {} | tail share {} | emission {} | miner share {} | staker share {} \
                 | burn {} | destroyed {} | destroyed/emission {} | net issuance % {}",
                both(p.emitted_fraction, c.emitted_fraction, 4),
                both(p.tail_share, c.tail_share, 3),
                both(p.emission, c.emission, 3),
                both(p.miner_emission_share, c.miner_emission_share, 4),
                both(p.staker_emission_share, c.staker_emission_share, 4),
                both(p.burn_of_fees, c.burn_of_fees, 3),
                both(p.destroyed, c.destroyed, 6),
                both(p.destroyed_over_emission, c.destroyed_over_emission, 6),
                both(net(&p), net(&c), 4),
            )?;
            writeln!(
                out,
                "      | miner income {} fee {} | stakers emission {} pool {} penalty {} \
                 | per GB-year {} | archive GB {} | Standard fee {}",
                both(p.miner_income, c.miner_income, 3),
                both(p.miner_fee, c.miner_fee, 4),
                both(p.staker_emission, c.staker_emission, 3),
                both(p.staker_pool, c.staker_pool, 4),
                both(p.staker_penalty, c.staker_penalty, 4),
                both(p.staker_income_per_gb_year, c.staker_income_per_gb_year, 3),
                both(
                    p.archival_bytes as f64 / BYTES_PER_GB as f64,
                    c.archival_bytes as f64 / BYTES_PER_GB as f64,
                    1
                ),
                both(p.standard_fee, c.standard_fee, 6),
            )?;
        }
    }
    writeln!(
        out,
        "\nTHE SLICE'S TABLE, the cell beside production: each line that moved is the cell's, then\n\
         production's as 'baseline', then each number that moved."
    )?;
    out.write_str(&crate::baseline::beside_baseline(
        &table(cell),
        &table(production),
    ))
}

/// The CSV's measures, in order: each is two columns, production's then the
/// cell's.
#[cfg(test)]
const CSV_MEASURES: [&str; 17] = [
    "emitted_fraction",
    "tail_share",
    "emission",
    "miner_emission_share",
    "staker_emission_share",
    "burn_of_fees",
    "destroyed",
    "destroyed_over_emission",
    "net_issuance_pct",
    "miner_income",
    "miner_fee",
    "staker_emission",
    "staker_pool",
    "staker_penalty",
    "staker_income_per_gb_year",
    "archival_bytes",
    "standard_fee",
];

/// A [`Life`]'s figures in [`CSV_MEASURES`]' order. Each f64 is written in
/// its shortest exact form; `-` where it is not finite or not in the record.
#[cfg(test)]
fn csv_figures(l: &Life) -> [String; 17] {
    let f = |v: f64| {
        if v.is_finite() {
            format!("{v}")
        } else {
            "-".into()
        }
    };
    [
        f(l.emitted_fraction),
        f(l.tail_share),
        f(l.emission),
        f(l.miner_emission_share),
        f(l.staker_emission_share),
        f(l.burn_of_fees),
        f(l.destroyed),
        f(l.destroyed_over_emission),
        l.net_issuance_pct.map_or_else(|| "-".into(), f),
        f(l.miner_income),
        f(l.miner_fee),
        f(l.staker_emission),
        f(l.staker_pool),
        f(l.staker_penalty),
        f(l.staker_income_per_gb_year),
        l.archival_bytes.to_string(),
        f(l.standard_fee),
    ]
}

/// The lifecycle view's every year as CSV: one line per series and year,
/// each measure as production's column then the cell's. Derived on demand
/// from two slice summaries (`lifecycle_csv_from_two_summaries`).
#[cfg(test)]
pub(super) fn csv(cell: &Summary, production: &Summary, base: &SimParams) -> String {
    let mut out = String::from(
        "# THE LIFECYCLE VIEW, every year (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.38). One line per\n\
         # series and year; each measure is two columns, production's then the cell's. Yearly means,\n\
         # SKL a block unless named; archival_bytes is bytes held at the year's end; '-' where the\n\
         # record has no figure (net issuance in year 1, a share of a zero emission).\n",
    );
    let mut header = vec![
        "economy".to_owned(),
        "rule".to_owned(),
        "scenario".to_owned(),
        "zone".to_owned(),
        "zone_bytes".to_owned(),
        "w_ref".to_owned(),
        "year".to_owned(),
    ];
    for m in CSV_MEASURES {
        header.push(format!("{m}_production"));
        header.push(format!("{m}_cell"));
    }
    out.push_str(&header.join(","));
    out.push('\n');
    for pair in pairs(cell, production, base) {
        assert_eq!(
            pair.production.len(),
            pair.cell.len(),
            "{} at {} B: the two arms fold the same years",
            pair.series.economy.name(),
            pair.series.zone_bytes
        );
        for (p, c) in pair.production.iter().zip(&pair.cell) {
            assert_eq!(p.year, c.year, "the two arms name one year");
            let mut line = vec![
                pair.series.economy.name(),
                TemplateRule::Gross.name().to_owned(),
                BASELINE_STEADY_STATE.to_owned(),
                pair.zone.clone(),
                pair.series.zone_bytes.to_string(),
                pair.w_ref.to_string(),
                p.year.to_string(),
            ];
            for (pf, cf) in csv_figures(p).into_iter().zip(csv_figures(c)) {
                line.push(pf);
                line.push(cf);
            }
            out.push_str(&line.join(","));
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committed_fixture;

    /// A year whose figures the derivation reads, the rest default.
    fn year(year: u64, emitted_fraction: f64, fees: f64) -> YearFig {
        YearFig {
            year,
            burn_mean: 0.4,
            miner_income: 90.0 + 0.6 * fees,
            miner_fee: 0.6 * fees,
            fee_gross: Spread {
                mean: fees,
                ..Spread::default()
            },
            staker_emission: 10.0,
            staker_pool: 0.1 * fees,
            emitted_fraction,
            archival_bytes: year * BYTES_PER_GB,
            staker_income_per_gb_year: 1.0,
            ..YearFig::default()
        }
    }

    fn fold_of(years: Vec<YearFig>) -> Folded {
        Folded {
            years,
            stop: None,
            half_year: None,
            adoption: None,
            adversaries: Vec::new(),
            design_load_bytes_a_day: 0.0,
            bond_per_gb: 0.0,
        }
    }

    /// The new measures, from the yearly means alone. The emission is the
    /// miner's leg plus the stakers'; the shares are its legs. Destroyed is
    /// the burn split's third leg. Net issuance starts at year 2 and nets the
    /// coins destroyed in every year before.
    #[test]
    #[allow(clippy::float_cmp)]
    fn the_new_measures_derive_from_the_yearly_means() {
        let blocks = 1_000;
        let asymptote = 1.0e9;
        let lives = lives(
            &fold_of(vec![
                year(1, 0.1, 50.0),
                year(2, 0.2, 100.0),
                year(3, 0.3, 0.0),
            ]),
            blocks,
            asymptote,
        );
        let [y1, y2, y3] = lives.as_slice() else {
            panic!("three years in, three out")
        };
        assert!((y1.emission - 100.0).abs() < 1e-9, "{}", y1.emission);
        assert!((y1.miner_emission_share - 0.9).abs() < 1e-12);
        assert!((y1.staker_emission_share - 0.1).abs() < 1e-12);
        // Fees 50: the miner's 30, the pool's 5, so 15 destroyed.
        assert!((y1.destroyed - 15.0).abs() < 1e-9, "{}", y1.destroyed);
        assert!((y1.destroyed_over_emission - 0.15).abs() < 1e-12);
        assert_eq!(y1.net_issuance_pct, None, "no coin count before year 1");
        // Year 2: 100 emitted less 30 destroyed, a block, over the 1e8
        // generated by year 1's end less year 1's 15 x 1 000 destroyed.
        let expected = (100.0 - 30.0) * 1_000.0 / (1.0e8 - 15_000.0) * 100.0;
        let got = y2.net_issuance_pct.expect("year 2 has a start");
        assert!((got - expected).abs() < 1e-12, "{got} against {expected}");
        // Year 3 nets both earlier years' coins destroyed.
        let expected = 100.0 * 1_000.0 / (2.0e8 - 45_000.0) * 100.0;
        let got = y3.net_issuance_pct.expect("year 3 has a start");
        assert!((got - expected).abs() < 1e-12, "{got} against {expected}");
        assert_eq!(y3.destroyed, 0.0);
        assert_eq!(y3.burn_of_fees, 0.4);
    }

    /// A summary with the view's four series at the slice's zone sizes,
    /// under labels the view must not read, and a miner's-net row it must
    /// pass over.
    fn slice_like(base: &SimParams, emission_scale: f64) -> Summary {
        let w_ref = base.relay().ref_tx_weight;
        let mut rows: Vec<Row> = series(base)
            .into_iter()
            .map(|s| Row {
                economy: s.economy.name(),
                rule: TemplateRule::Gross.name().into(),
                scenario: BASELINE_STEADY_STATE.into(),
                place: Place {
                    zone: format!("label {}", s.zone_bytes % 7),
                    zone_bytes: s.zone_bytes,
                    w_ref,
                },
                seeds: vec![HONEST_SEEDS[0]],
                folds: vec![fold_of(
                    (1..=3)
                        .map(|y| {
                            let mut fig = year(y, 0.1 * y as f64, 10.0);
                            fig.staker_emission *= emission_scale;
                            fig
                        })
                        .collect(),
                )],
            })
            .collect();
        let mut net = rows[0].clone();
        net.rule = TemplateRule::MinerNet.name().into();
        net.folds[0].years[0].miner_income = f64::NAN;
        rows.insert(0, net);
        Summary {
            horizon_years: HORIZON_YEARS,
            tau_sweep_ms_per_kb: TAU_SWEEP_MS_PER_KB,
            rows,
        }
    }

    /// The four series are found by byte size, gross only, and the CSV has
    /// a line per series and year, with both arms' column for every measure.
    #[test]
    fn the_csv_has_both_arms_for_every_series_and_year() {
        let base = SimParams::default();
        let csv = csv(&slice_like(&base, 3.0), &slice_like(&base, 1.0), &base);
        let lines: Vec<&str> = csv.lines().filter(|l| !l.starts_with('#')).collect();
        let columns = 7 + 2 * CSV_MEASURES.len();
        assert_eq!(
            lines.len(),
            1 + 4 * 3,
            "a header, then four series of three years"
        );
        for line in &lines {
            assert_eq!(line.split(',').count(), columns, "{line}");
        }
        let header: Vec<&str> = lines[0].split(',').collect();
        let at = |name: &str| {
            header
                .iter()
                .position(|h| *h == name)
                .unwrap_or_else(|| panic!("no column {name}"))
        };
        let first: Vec<&str> = lines[1].split(',').collect();
        assert_eq!(first[0], "A-honest");
        assert_eq!(first[1], "gross");
        assert_eq!(first[at("net_issuance_pct_production")], "-");
        assert_eq!(first[at("staker_emission_production")], "10");
        assert_eq!(first[at("staker_emission_cell")], "30");
        assert_eq!(
            first[at("miner_income_production")],
            "96",
            "not the net row's NaN"
        );
    }

    /// A summary without one of the four series is not a slice's: the view
    /// refuses it, naming the row.
    #[test]
    #[should_panic(expected = "it is not a nightly slice's")]
    fn a_summary_without_a_series_is_refused() {
        let base = SimParams::default();
        let mut cell = slice_like(&base, 3.0);
        cell.rows.retain(|r| r.economy != "B");
        let _ = csv(&cell, &slice_like(&base, 1.0), &base);
    }

    /// The view prints each series at its years, production then the cell.
    #[test]
    fn the_view_prints_production_beside_the_cell() {
        let base = SimParams::default();
        let mut out = String::new();
        write_view(
            &mut out,
            &slice_like(&base, 3.0),
            &slice_like(&base, 1.0),
            &base,
        )
        .expect("String sink is infallible");
        assert_eq!(out.matches("\n== ").count(), 4, "{out}");
        assert!(out.contains("staker share 0.1000 / 0.2500"), "{out}");
        assert!(out.contains("  y5: past a fold's stop"), "{out}");
        assert!(out.contains("THE SLICE'S TABLE"), "{out}");
    }

    /// Names the cell's slice summary (the JSON `--economies-slice --set …`
    /// writes to stdout).
    const CELL_SUMMARY_ENV: &str = "SHEKYL_LIFECYCLE_CELL_SUMMARY";
    /// Names production's slice summary (`--economies-slice` alone).
    const PRODUCTION_SUMMARY_ENV: &str = "SHEKYL_LIFECYCLE_PRODUCTION_SUMMARY";
    /// Names the file the CSV is written to.
    const CSV_PATH_ENV: &str = "SHEKYL_LIFECYCLE_CSV";

    fn summary_at(env: &str) -> Summary {
        let path = std::env::var(env).unwrap_or_else(|_| panic!("{env} names no slice summary"));
        let json = std::fs::read_to_string(&path).expect("read the slice summary");
        serde_json::from_str(&json).expect("the slice summary parses")
    }

    /// On demand: the lifecycle view's every year, as CSV, from two slice
    /// summaries on disk. Production's must be the committed slice's (its
    /// derived table matches the committed one), and the cell's must not
    /// be production's: the helper has no subject otherwise (rule 47).
    #[test]
    #[ignore = "on demand: writes the lifecycle CSV from the two slice summaries SHEKYL_LIFECYCLE_CELL_SUMMARY and SHEKYL_LIFECYCLE_PRODUCTION_SUMMARY name, to SHEKYL_LIFECYCLE_CSV"]
    fn lifecycle_csv_from_two_summaries() {
        let cell = summary_at(CELL_SUMMARY_ENV);
        let production = summary_at(PRODUCTION_SUMMARY_ENV);
        committed_fixture::assert_matches(
            "the production slice's derived table",
            super::super::tests::NIGHTLY_TABLE_FIXTURE,
            &table(&production),
        );
        assert_ne!(
            table(&cell),
            table(&production),
            "{CELL_SUMMARY_ENV} names production's slice, not a cell's"
        );
        let path = std::env::var(CSV_PATH_ENV)
            .unwrap_or_else(|_| panic!("{CSV_PATH_ENV} names no file for the CSV"));
        std::fs::write(&path, csv(&cell, &production, &SimParams::default()))
            .expect("write the lifecycle CSV");
        eprintln!("wrote {path}");
    }
}
