// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for the whole-economy fold, its narration and its derived table.

#![cfg(test)]

use super::report::{table, write_report, TABLE_COLUMNS};
use super::*;
use crate::committed_fixture::{self, regenerate, Output};
use serde::Deserialize;

/// The nightly slice's committed narration.
const NIGHTLY_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/economies_nightly_narration.txt"
);
/// The nightly slice's committed derived table.
pub(super) const NIGHTLY_TABLE_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/economies_nightly_table.csv"
);
/// The SHA-256 of the full run's narration and JSON summary, in
/// `sha256sum`'s format. The two files are not committed (Rick,
/// 2026-11-22). The narration's pin renders the recorded summary and
/// checks it here. [`regen_economies_full_fixtures`] replaces the record
/// from a fresh fold.
const FULL_DIGESTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/economies_full_digests.txt"
);
/// The full run's narration's name, in [`FULL_DIGESTS`] and in
/// [`FULL_OUTPUT_DIR_ENV`]'s directory.
const FULL_NARRATION_NAME: &str = "economies_narration.txt";
/// The full run's JSON summary's name, likewise.
const FULL_SUMMARY_NAME: &str = "economies_summary.json";
/// A directory a full run writes its narration and JSON summary into,
/// under the names above, before it is checked: a run that fails leaves
/// what it made to read.
const FULL_OUTPUT_DIR_ENV: &str = "SHEKYL_ECONOMIES_FULL_DIR";

/// One run's narration, its JSON summary and its derived table.
struct Outputs {
    narration: String,
    json: String,
    table: String,
}

fn outputs(scope: Scope) -> Outputs {
    let mut narration = String::new();
    let summary =
        run(&mut narration, &SimParams::default(), scope).expect("String sink is infallible");
    Outputs {
        json: summary_json(&summary),
        table: table(&summary),
        narration,
    }
}

/// The nightly slice's outputs, folded once for its pin and its
/// regeneration alike.
fn nightly() -> &'static Outputs {
    static NIGHTLY: std::sync::OnceLock<Outputs> = std::sync::OnceLock::new();
    NIGHTLY.get_or_init(|| outputs(Scope::Nightly))
}

/// The full run's outputs, folded once, written to
/// [`FULL_OUTPUT_DIR_ENV`]'s directory when it names one.
fn full() -> &'static Outputs {
    static FULL: std::sync::OnceLock<Outputs> = std::sync::OnceLock::new();
    FULL.get_or_init(|| {
        let full = outputs(Scope::Full);
        if let Ok(dir) = std::env::var(FULL_OUTPUT_DIR_ENV) {
            for (name, bytes) in [
                (FULL_NARRATION_NAME, &full.narration),
                (FULL_SUMMARY_NAME, &full.json),
            ] {
                let path = std::path::Path::new(&dir).join(name);
                std::fs::write(&path, bytes).expect("write the full run's output");
                eprintln!("wrote {}", path.display());
            }
        }
        full
    })
}

fn sha256_hex(bytes: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// [`FULL_DIGESTS`]'s content for `narration` and `json`.
fn digests(narration: &str, json: &str) -> String {
    digest_lines(&sha256_hex(narration), &sha256_hex(json))
}

/// [`FULL_DIGESTS`]'s content for the two files' SHA-256, in
/// `sha256sum`'s format.
fn digest_lines(narration_sha: &str, summary_sha: &str) -> String {
    format!("{narration_sha}  {FULL_NARRATION_NAME}\n{summary_sha}  {FULL_SUMMARY_NAME}\n")
}

/// The recorded SHA-256 of the full run's file `name`
/// ([`FULL_NARRATION_NAME`] or [`FULL_SUMMARY_NAME`]), read from
/// [`FULL_DIGESTS`].
fn recorded_digest(name: &str) -> String {
    let digests = std::fs::read_to_string(FULL_DIGESTS).expect("read the recorded digests");
    digests
        .lines()
        .find_map(|line| line.strip_suffix(&format!("  {name}")))
        .unwrap_or_else(|| panic!("{FULL_DIGESTS} records no {name}"))
        .to_owned()
}

#[test]
fn the_economies_are_fifteen_with_production_first() {
    let all = Economy::all();
    assert_eq!(all.len(), 15);
    assert_eq!(all[0], Economy::AHonest);
    let names: Vec<String> = all.iter().map(|e| e.name()).collect();
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        names.len(),
        "each economy prints its own name: {names:?}"
    );
}

/// Each economy sets what it names and nothing else.
#[test]
fn each_economy_sets_what_it_names() {
    let cell = SimParams::default();
    for rule in TemplateRule::ALL {
        let honest = Economy::AHonest.params(&cell, rule);
        assert_eq!(honest.volume_signal, VolumeSignal::Sum);
        assert_eq!(honest.economy.penalty, PenaltyDestination::Deferred);
        assert_eq!(honest.economy.burn, BurnSignal::Count);
        assert_eq!(honest.economy.template, rule);
        assert!(honest.overrides().is_empty());
        assert!(Economy::AStuffed.stuffs() && !Economy::AHonest.stuffs());

        let decoupled = Economy::Decoupled.params(&cell, rule);
        assert_eq!(decoupled.volume_signal, VolumeSignal::Fixed);
        assert_eq!(decoupled.economy.penalty, PenaltyDestination::Deferred);
        assert!(decoupled.overrides().is_empty());

        for d in C1_DESTINATIONS {
            let c1 = Economy::C1(d).params(&cell, rule);
            assert_eq!(
                (c1.volume_signal, c1.economy.penalty),
                (VolumeSignal::Fixed, d)
            );
            assert_eq!(c1.economy.burn, BurnSignal::Count);
            let together = Economy::CTogether(d).params(&cell, rule);
            assert_eq!(together.economy.penalty, d);
            assert_eq!(together.economy.burn, BurnSignal::FeesPaid);
            assert_eq!(
                together.overrides().len(),
                EscalationCurve::overrides(C3_ASYMPTOTE, C_TOGETHER_KNEE).len()
            );
        }
        let c2 = Economy::C2.params(&cell, rule);
        assert_eq!(
            (c2.volume_signal, c2.economy.burn),
            (VolumeSignal::Fixed, BurnSignal::FeesPaid)
        );
        for knee in KNEE_BAND {
            let c3 = Economy::C3(knee).params(&cell, rule);
            assert_eq!(c3.volume_signal, VolumeSignal::Fixed);
            assert_eq!(c3.economy.penalty, PenaltyDestination::Deferred);
            assert_eq!(c3.economic().escalation_knee_n, knee);
            assert_eq!(c3.economic().escalation_asymptote_share, C3_ASYMPTOTE);
        }
    }
}

#[test]
fn slow_adoption_is_a_tenth_then_the_baseline() {
    let params = SimParams::default();
    let config = slow_adoption(&params);
    let year = params.blocks_per_year();
    let baseline = params.economic().tx_volume_baseline;
    assert_eq!(config.name, SLOW_ADOPTION);
    assert_eq!(
        (config.volume.get_volume)(0, year),
        baseline / SLOW_ADOPTION_DIVISOR
    );
    assert_eq!(
        (config.volume.get_volume)(SLOW_ADOPTION_YEARS * year - 1, year),
        baseline / SLOW_ADOPTION_DIVISOR
    );
    assert_eq!(
        (config.volume.get_volume)(SLOW_ADOPTION_YEARS * year, year),
        baseline
    );
    assert_eq!(scenario(&params, SLOW_ADOPTION).sim_years, HORIZON_YEARS);
    assert_eq!(
        scenario(&params, BASELINE_STEADY_STATE).sim_years,
        HORIZON_YEARS
    );
}

#[test]
fn the_quantiles_are_nearest_rank() {
    let v: Vec<u64> = (1..=100).collect();
    assert_eq!(quantile(&v, 0.5), 50);
    assert_eq!(quantile(&v, 0.95), 95);
    assert_eq!(quantile(&v, 0.99), 99);
    assert_eq!(quantile(&v, 0.1), 10);
    assert_eq!(quantile(&[], 0.5), 0);
    assert_eq!(quantile(&[7], 0.99), 7);
}

/// The scopes' cells: the full table's count, and the nightly slice's
/// cells named in §5.37.
#[test]
fn the_scopes_fold_the_cells_they_name() {
    let base = SimParams::default();
    let full = cells(&base, Scope::Full);
    assert_eq!(full.len(), 15 * 2 * 4 * 8 * 3);
    let nightly = cells(&base, Scope::Nightly);
    assert_eq!(nightly.len(), 15 * 2 + 2 * 2);
    let spend = spend_zone_bytes(reference_spend_weight(&base), SPENDS[0]);
    assert!(nightly.iter().all(|c| {
        c.scenario == BASELINE_STEADY_STATE
            && c.seed == HONEST_SEEDS[0]
            && c.place.w_ref == base.relay().ref_tx_weight
            && (c.place.zone_bytes == spend
                || (c.place.zone_bytes == INHERITED_ZONE
                    && matches!(c.economy, Economy::AHonest | Economy::Decoupled)))
    }));
}

/// The pre-flight: every scenario but the baseline (which the nightly
/// slice folds) at seed 1, every economy, rule and place (720 folds),
/// each to where it stops. No cell refuses a body outside the reward's
/// domain: each ends at the horizon or at a named edge, and reads only
/// the whole years before it (§5.37.1). Each fold prints a heartbeat
/// every five years and a line when it ends, with its wall time, so a
/// slow cell is named while the run goes on. It runs before the full
/// table, whose cells these are at one seed of three.
#[test]
#[ignore = "--economies pre-flight: 720 folds at seed 1 — on demand, before the full table; run with --release --ignored --nocapture"]
fn every_preflight_cell_ends_at_the_horizon_or_a_named_edge() {
    let base = SimParams::default();
    let preflight: Vec<Cell> = cells(&base, Scope::Full)
        .into_iter()
        .filter(|cell| cell.scenario != BASELINE_STEADY_STATE && cell.seed == HONEST_SEEDS[0])
        .collect();
    assert_eq!(preflight.len(), 15 * 2 * 8 * (SCENARIOS.len() - 1));
    let label = |cell: &Cell| {
        format!(
            "{} | {} | {} | {} at w_ref {}",
            cell.scenario,
            cell.economy.name(),
            cell.rule.name(),
            cell.place.zone,
            cell.place.w_ref
        )
    };
    let folded = crate::parallel::map(&preflight, |cell| {
        let started = std::time::Instant::now();
        let folded = fold_beating(&base, cell, Some(label(cell)));
        let stop = folded
            .stop
            .map_or_else(|| format!("y{HORIZON_YEARS}"), |stop| stop.label());
        eprintln!(
            "done | {} | {} | {stop} | {:.0} s",
            utc_clock(),
            label(cell),
            started.elapsed().as_secs_f64()
        );
        folded
    });
    for folded in &folded {
        match folded.stop {
            None => assert_eq!(folded.years.len() as u64, HORIZON_YEARS),
            Some(stop) => {
                assert_eq!(folded.years.len() as u64 + 1, stop.year);
                if stop.edge == FoldEdge::RewardDomain {
                    assert!(stop.median_bytes as f64 >= BYTES_PER_TB);
                }
            }
        }
    }
}

/// The nightly slice, folded once: its narration and the table derived
/// from its own summary, each against its committed copy. The derive
/// function runs on real output every night, with nothing fetched.
#[test]
#[ignore = "--economies nightly slice: 34 folds to y135 — nightly; run with --release --ignored; fixtures generated and checked on Linux x86-64"]
fn economies_nightly_slice_matches_its_narration_and_table() {
    let nightly = nightly();
    committed_fixture::assert_matches(
        "--economies nightly narration",
        NIGHTLY_FIXTURE,
        &nightly.narration,
    );
    committed_fixture::assert_matches(
        "--economies nightly derived table",
        NIGHTLY_TABLE_FIXTURE,
        &nightly.table,
    );
}

/// The derived table's committed copy (§5.37.1): [`table`] of the
/// recorded summary. The 60 growth rows are stale from year 69
/// (§5.37.2). [`regen_economies_full_fixtures`] replaces the file.
const TABLE_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/economies_table.csv"
);

/// A fold whose every year to `years` carries `scale`, stopped at the
/// reward's edge when `stop` says so.
fn synthetic_fold(years: u64, scale: f64, stop: Option<FoldStop>) -> Folded {
    Folded {
        years: (1..=years)
            .map(|year| YearFig {
                year,
                release_mean: scale,
                burn_mean: scale / 10.0,
                miner_income: 100.0 * scale,
                miner_fee: scale,
                fee_net: Spread {
                    p95: scale,
                    ..Spread::default()
                },
                tail_net: 2.0 * scale,
                tail_share: if year > 100 { 1.0 } else { 0.0 },
                bytes_a_day: if year >= 3 { 2.0e9 } else { 1.0e8 },
                ..YearFig::default()
            })
            .collect(),
        stop,
        half_year: Some(11.0 * scale),
        adoption: None,
        adversaries: Vec::new(),
        design_load_bytes_a_day: 4.3e8,
        bond_per_gb: 250.0,
    }
}

fn synthetic_summary() -> Summary {
    let place = Place {
        zone: "N = 90".into(),
        zone_bytes: 1_795_896,
        w_ref: 3_000,
    };
    let edge = FoldStop {
        edge: FoldEdge::RewardDomain,
        year: 8,
        median_bytes: 4_000_000_000_000,
    };
    Summary {
        horizon_years: HORIZON_YEARS,
        tau_sweep_ms_per_kb: TAU_SWEEP_MS_PER_KB,
        rows: vec![
            Row {
                economy: "A-honest".into(),
                rule: "gross".into(),
                scenario: BASELINE_STEADY_STATE.into(),
                place: place.clone(),
                seeds: HONEST_SEEDS.to_vec(),
                folds: vec![
                    synthetic_fold(HORIZON_YEARS, 1.0, None),
                    synthetic_fold(HORIZON_YEARS, 2.0, None),
                    synthetic_fold(HORIZON_YEARS, 3.0, None),
                ],
            },
            Row {
                economy: "B".into(),
                rule: "miner's net".into(),
                scenario: SUSTAINED_GROWTH.into(),
                place,
                seeds: HONEST_SEEDS.to_vec(),
                folds: vec![
                    synthetic_fold(7, 1.0, Some(edge)),
                    synthetic_fold(7, 2.0, Some(edge)),
                    synthetic_fold(7, 3.0, Some(edge)),
                ],
            },
        ],
    }
}

/// The derived table: its header, one line per row with every column,
/// the seeds' median, and `-` past a fold's stop.
#[test]
fn the_derived_table_has_a_line_per_row_and_every_column() {
    let table = table(&synthetic_summary());
    let lines: Vec<&str> = table.lines().filter(|l| !l.starts_with('#')).collect();
    assert_eq!(lines.len(), 3, "the header and two rows");
    assert_eq!(lines[0], TABLE_COLUMNS.join(","));
    let column = |line: &str, name: &str| -> String {
        let at = TABLE_COLUMNS
            .iter()
            .position(|c| *c == name)
            .expect("a column");
        line.split(',')
            .nth(at)
            .expect("the column's cell")
            .to_owned()
    };
    for line in &lines[1..] {
        assert_eq!(line.split(',').count(), TABLE_COLUMNS.len(), "{line}");
    }
    // The seeds carry 1, 2 and 3: the median is 2.
    assert_eq!(column(lines[1], "income_y10"), "200.00");
    assert_eq!(column(lines[1], "half_year"), "22.00");
    assert_eq!(column(lines[1], "first_1gb_day_year"), "3");
    // Each seed's emission is 99 times its p95 fees, and its tail era
    // begins at year 101.
    assert_eq!(column(lines[1], "reward_net_over_fees_p95_y60"), "99.0");
    assert_eq!(column(lines[1], "reward_net_over_fees_p95_y135"), "99.0");
    assert_eq!(column(lines[1], "tail_era_year"), "101");
    assert_eq!(column(lines[1], "role"), "read");
    assert_eq!(column(lines[1], "stops"), "horizon;horizon;horizon");
    // The growth row is a stress, and reads nothing past year 7.
    assert_eq!(column(lines[2], "role"), "stress");
    assert_eq!(column(lines[2], "income_y1"), "200.00");
    assert_eq!(column(lines[2], "income_y10"), "-");
    assert_eq!(column(lines[2], "tail_era_year"), "-");
    assert_eq!(
        column(lines[2], "stops"),
        "domain y8 at 4.0 TB;domain y8 at 4.0 TB;domain y8 at 4.0 TB"
    );
}

/// The heartbeat's stamp is the UTC date and time, through a leap day
/// and a century's end.
#[test]
fn the_utc_stamp_reads_the_calendar() {
    let at = |seconds: i64| {
        utc_stamp(time::OffsetDateTime::from_unix_timestamp(seconds).expect("in range"))
    };
    assert_eq!(at(0), "1970-01-01T00:00:00Z");
    assert_eq!(at(951_786_061), "2000-02-29T01:01:01Z");
    assert_eq!(at(1_795_391_999), "2026-11-22T23:59:59Z");
    assert_eq!(at(4_102_444_799), "2099-12-31T23:59:59Z");
}

/// The JSON summary `--economies` writes reads back to the same table.
#[test]
fn the_summary_reads_back_to_the_same_table() {
    let summary = synthetic_summary();
    let json = serde_json::to_string(&summary).expect("serialize");
    let back: Summary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(table(&back), table(&summary));
}

/// A summary's f64 reads back bit for bit from the decimal text it was
/// written as. The literal is a fee variance from the recorded full run.
/// serde_json's default parse reads it one ULP off, and the narration
/// prints it to six decimals, past an f64's precision.
#[test]
fn a_summary_float_reads_back_bit_for_bit() {
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Wrap(#[serde(deserialize_with = "crate::exact_f64::de_f64")] f64);

    let recorded = "21231060353.333294";
    let x: f64 = recorded.parse().expect("std parses a decimal exactly");
    let json = serde_json::to_string(&x).expect("serialize");
    assert_eq!(json, recorded);
    let back: Wrap = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back.0.to_bits(),
        x.to_bits(),
        "{recorded} read back as {}",
        back.0
    );
}

/// Names a full run's JSON summary on disk, for deriving the table
/// without folding it again (a 13.9-hour run, §5.37.1).
const SUMMARY_PATH_ENV: &str = "SHEKYL_ECONOMIES_SUMMARY";

/// The JSON summary [`SUMMARY_PATH_ENV`] names, read whole. Refuses,
/// naming the variable, when it names none, and when the file is not the
/// summary whose SHA-256 the repo records: the pin and the helper below
/// have no subject without it (rule 47).
fn recorded_summary() -> Summary {
    let path = std::env::var(SUMMARY_PATH_ENV).unwrap_or_else(|_| {
        panic!("{SUMMARY_PATH_ENV} names no JSON summary: name a full run's {FULL_SUMMARY_NAME}")
    });
    let json = std::fs::read_to_string(&path).expect("read the JSON summary");
    assert_eq!(
        sha256_hex(&json),
        recorded_digest(FULL_SUMMARY_NAME),
        "{path} is not the JSON summary whose SHA-256 {FULL_DIGESTS} records"
    );
    serde_json::from_str(&json).expect("the JSON summary parses")
}

/// The committed full table: [`table`] of the recorded JSON summary.
fn recorded_table() -> String {
    table(&recorded_summary())
}

/// The derived table against the recorded full run, read from its JSON
/// summary on disk: seconds, where the full pin above takes hours.
#[test]
#[ignore = "--economies, the derived table: reads the recorded JSON summary (379 MB) SHEKYL_ECONOMIES_SUMMARY names — on demand"]
fn economies_table_matches_the_recorded_summary() {
    committed_fixture::assert_matches(
        "--economies derived table",
        TABLE_FIXTURE,
        &recorded_table(),
    );
}

/// The full narration, rendered from the recorded JSON summary
/// [`SUMMARY_PATH_ENV`] names.
fn narration_from_recorded_summary() -> String {
    let mut narration = String::new();
    write_report(&mut narration, &recorded_summary().rows, Scope::Full)
        .expect("String sink is infallible");
    narration
}

/// The full narration rendered from the recorded JSON summary, against
/// the narration's recorded SHA-256: the summary is the run's record, so
/// it renders the run's narration byte for byte without folding again.
#[test]
#[ignore = "--economies, the full narration: renders the recorded JSON summary (379 MB) SHEKYL_ECONOMIES_SUMMARY names — on demand"]
fn economies_narration_renders_from_the_recorded_summary() {
    assert_eq!(
        sha256_hex(&narration_from_recorded_summary()),
        recorded_digest(FULL_NARRATION_NAME),
        "the narration rendered from the recorded JSON summary is not the one {FULL_DIGESTS} records"
    );
}

/// Armed: rewrites the derived table from the recorded JSON summary on
/// disk under a cited decision, for a change to the table's form.
#[test]
#[ignore = "armed regeneration helper; writes the derived table from the recorded JSON summary SHEKYL_ECONOMIES_SUMMARY names; requires SHEKYL_PINNED_REGEN_DECISION"]
fn regen_economies_table_fixture() {
    regenerate(
        "the --economies derived table",
        &[Output {
            path: TABLE_FIXTURE,
            build: recorded_table,
        }],
    );
}

/// Armed: rewrites the nightly slice's narration and table, from one
/// fold of the slice, under a cited decision.
#[test]
#[ignore = "armed regeneration helper; writes the nightly slice's committed narration and table; requires SHEKYL_PINNED_REGEN_DECISION"]
fn regen_economies_nightly_fixtures() {
    regenerate(
        "the --economies nightly narration and table",
        &[
            Output {
                path: NIGHTLY_FIXTURE,
                build: || nightly().narration.clone(),
            },
            Output {
                path: NIGHTLY_TABLE_FIXTURE,
                build: || nightly().table.clone(),
            },
        ],
    );
}

/// Armed: re-renders the full narration from the recorded JSON summary
/// under a cited decision, for a change to the narration's wording, and
/// rewrites its SHA-256 in [`FULL_DIGESTS`]. The summary and its SHA-256
/// stay: nothing is folded again. The narration is written to
/// [`FULL_OUTPUT_DIR_ENV`]'s directory, to be kept beside the summary.
#[test]
#[ignore = "armed regeneration helper; re-renders the full narration from the recorded JSON summary SHEKYL_ECONOMIES_SUMMARY names and rewrites its digest; requires SHEKYL_PINNED_REGEN_DECISION and SHEKYL_ECONOMIES_FULL_DIR"]
fn regen_economies_full_narration_digest() {
    assert!(
        std::env::var(FULL_OUTPUT_DIR_ENV).is_ok(),
        "{FULL_OUTPUT_DIR_ENV} names no directory for the re-rendered narration"
    );
    regenerate(
        "the --economies full narration's digest, re-rendered from the recorded JSON summary",
        &[Output {
            path: FULL_DIGESTS,
            build: || {
                let narration = narration_from_recorded_summary();
                let dir = std::env::var(FULL_OUTPUT_DIR_ENV).expect("checked above");
                let path = std::path::Path::new(&dir).join(FULL_NARRATION_NAME);
                std::fs::write(&path, &narration).expect("write the re-rendered narration");
                eprintln!("wrote {}", path.display());
                digest_lines(&sha256_hex(&narration), &recorded_digest(FULL_SUMMARY_NAME))
            },
        }],
    );
}

/// Armed: rewrites the full run's recorded digests and the derived
/// table, from one full fold, under a cited decision. Refuses unless
/// [`FULL_OUTPUT_DIR_ENV`] names where the two files go: a digest of
/// bytes nobody kept proves nothing.
#[test]
#[ignore = "armed regeneration helper; writes the full run's digests and the derived table, and the run's narration and JSON summary into SHEKYL_ECONOMIES_FULL_DIR; requires SHEKYL_PINNED_REGEN_DECISION"]
fn regen_economies_full_fixtures() {
    assert!(
        std::env::var(FULL_OUTPUT_DIR_ENV).is_ok(),
        "{FULL_OUTPUT_DIR_ENV} names no directory for the full run's narration and JSON summary"
    );
    regenerate(
        "the --economies full run's digests and derived table",
        &[
            Output {
                path: FULL_DIGESTS,
                build: || digests(&full().narration, &full().json),
            },
            Output {
                path: TABLE_FIXTURE,
                build: || full().table.clone(),
            },
        ],
    );
}
