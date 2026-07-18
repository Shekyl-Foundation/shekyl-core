// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `--gf7-seal <artifact>` — the sealing-form grader for the GF-7 leg-(b)
//! wall-clock sweep-phase channel (`ARCHIVAL_BOND_WI4_MEASUREMENT.md` §19.8;
//! K_COVER seal input #2).
//!
//! The harness (`shekyl-engine-core` `gf7_sealing_run.rs`, `gf7-hooks`
//! feature) drives the **production** P-scan task + dispatch driver against a
//! live `shekyld --regtest` and writes a receipts artifact (JSON lines). This
//! module is the sim-owned *judgment* half of the §19.8.1 split: it consumes
//! the artifact and grades it with the **same** circular statistic
//! ([`wallclock_leg`](crate::wallclock_leg) `circular_mean` /
//! `circular_distance`) and the **same** committed bound
//! ([`RATIO_BOUND`](crate::wallclock_leg::RATIO_BOUND), `r < 2`) — the
//! statistic stays single-sourced in the sim, per the layer-2 containment
//! wording.
//!
//! Everything graded here was pre-committed in §19.8.2–§19.8.4 before the
//! harness existed: the naming-task construction, both controls (a failed
//! control grades the whole session INVALID), the clustered run-level SE,
//! and the two-SE escalation rule (a pooled estimate within two clustered
//! SEs of the bound defers the verdict and extends `R` — the bar never
//! moves, only the sample size).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::wallclock_leg::{
    circular_distance, circular_mean, NEGATIVE_CONTROL_TOL, POSITIVE_CONTROL_MIN, RATIO_BOUND,
    TICK_MS,
};

/// Anonymity set `N` (§19.8.2): wallets per run. The naming task presents
/// `N − 1` candidates, so chance is `1/(N − 1)`.
const WALLETS: usize = 10;
/// Wallet size `K` (§19.8.2): personas (slots) per wallet.
const PERSONAS_PER_WALLET: u64 = 2;
/// Posts per persona `m` (§19.8.2): the gate row's accumulation.
const POSTS_PER_PERSONA: usize = 4;
/// The arm labels the harness writes (`gf7_sealing_run.rs`).
const PRODUCTION_ARM: &str = "production";
const POSITIVE_CONTROL_ARM: &str = "positive-control";

/// One artifact row (§19.8.1 schema). `sibling_group` is the ground-truth
/// sibling designation — by construction the wallet ordinal, and validated
/// as such on load (a mismatch means the artifact is corrupt, not that the
/// grader should trust either field).
#[derive(Deserialize)]
struct ReceiptRow {
    arm: String,
    run: usize,
    wallet: usize,
    slot: u64,
    receipt_ms: u64,
    sibling_group: usize,
}

/// One run's receipts, keyed `(wallet, slot) → arrival instants (ms from the
/// run epoch)`, arrival-ordered.
type RunReceipts = BTreeMap<(usize, u64), Vec<u64>>;

/// Load and shape the artifact: `arm → run ordinal → run receipts`. Fails
/// loudly on any malformed line, schema violation, or incomplete run —
/// a silent partial artifact would corrupt the pooled statistic.
fn load_artifact(path: &str) -> BTreeMap<String, BTreeMap<usize, RunReceipts>> {
    let body = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("gf7-seal: cannot read artifact {path}: {e}"));
    let mut arms: BTreeMap<String, BTreeMap<usize, RunReceipts>> = BTreeMap::new();
    for (idx, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: ReceiptRow = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("gf7-seal: bad artifact line {}: {e}", idx + 1));
        assert_eq!(
            row.sibling_group,
            row.wallet,
            "gf7-seal: line {}: sibling_group {} != wallet {} — corrupt artifact",
            idx + 1,
            row.sibling_group,
            row.wallet
        );
        assert!(
            row.wallet < WALLETS && row.slot < PERSONAS_PER_WALLET,
            "gf7-seal: line {}: persona ({}, {}) outside the committed geometry",
            idx + 1,
            row.wallet,
            row.slot
        );
        arms.entry(row.arm)
            .or_default()
            .entry(row.run)
            .or_default()
            .entry((row.wallet, row.slot))
            .or_default()
            .push(row.receipt_ms);
    }
    for (arm, runs) in &arms {
        for (run, receipts) in runs {
            assert_eq!(
                receipts.len(),
                WALLETS * usize::try_from(PERSONAS_PER_WALLET).expect("K fits usize"),
                "gf7-seal: {arm} run {run}: persona count mismatch — incomplete run"
            );
            for ((wallet, slot), arrivals) in receipts {
                assert_eq!(
                    arrivals.len(),
                    POSTS_PER_PERSONA,
                    "gf7-seal: {arm} run {run} persona ({wallet}, {slot}): expected m = \
                     {POSTS_PER_PERSONA} receipts, got {} — incomplete run",
                    arrivals.len()
                );
            }
        }
    }
    arms
}

/// A persona's estimated cadence phase: circular mean of its arrival
/// instants mod `T` (§19.8.4 statistic). `first_only` is the `m = 1`
/// context sub-row (first arrival per persona).
fn persona_phase(arrivals: &[u64], first_only: bool) -> f64 {
    let phases: Vec<u64> = if first_only {
        vec![arrivals.iter().copied().min().expect("m >= 1") % TICK_MS]
    } else {
        arrivals.iter().map(|a| a % TICK_MS).collect()
    };
    circular_mean(&phases)
}

/// One run's naming-task hit count for the **sibling** task (§19.8.4): for
/// each wallet `w`, the probe is persona `(w, 0)`; the `N − 1` candidates
/// are the true sibling `(w, 1)` plus the slot-0 personas of the next
/// `N − 2` wallets (mod `N`); a hit is naming the sibling. Deterministic
/// candidate selection keeps chance exactly `1/(N − 1)` per task.
fn run_sibling_hits(receipts: &RunReceipts, first_only: bool) -> usize {
    let mut hits = 0;
    for w in 0..WALLETS {
        let probe = persona_phase(&receipts[&(w, 0)], first_only);
        let mut candidates: Vec<(bool, f64)> = Vec::with_capacity(WALLETS - 1);
        candidates.push((true, persona_phase(&receipts[&(w, 1)], first_only)));
        for step in 1..=(WALLETS - 2) {
            let x = (w + step) % WALLETS;
            candidates.push((false, persona_phase(&receipts[&(x, 0)], first_only)));
        }
        if names_marked(probe, &candidates) {
            hits += 1;
        }
    }
    hits
}

/// One run's naming-task hit count for the **negative control** (§19.8.3
/// control 2): the probe `(w, 0)` is paired with a cross-wallet
/// *pseudo-sibling* `((w + 1) mod N, 1)` — independent wallet, independent
/// `φ` — plus the slot-0 personas of the remaining `N − 2` wallets. Chance
/// stays `1/(N − 1)`; any systematic hit rate above tolerance means the
/// harness itself (shared daemon, shared host) couples phases across
/// wallets, and the session is INVALID.
fn run_pseudo_sibling_hits(receipts: &RunReceipts) -> usize {
    let mut hits = 0;
    for w in 0..WALLETS {
        let pseudo = (w + 1) % WALLETS;
        let probe = persona_phase(&receipts[&(w, 0)], false);
        let mut candidates: Vec<(bool, f64)> = Vec::with_capacity(WALLETS - 1);
        candidates.push((true, persona_phase(&receipts[&(pseudo, 1)], false)));
        for x in 0..WALLETS {
            if x != w && x != pseudo {
                candidates.push((false, persona_phase(&receipts[&(x, 0)], false)));
            }
        }
        if names_marked(probe, &candidates) {
            hits += 1;
        }
    }
    hits
}

/// The §19.2 observer: names the minimum-circular-distance candidate.
/// Returns whether it named the marked (ground-truth) one.
fn names_marked(probe: f64, candidates: &[(bool, f64)]) -> bool {
    let mut best_marked = false;
    let mut best_d = f64::INFINITY;
    for &(marked, phase) in candidates {
        let d = circular_distance(probe, phase);
        if d < best_d {
            best_d = d;
            best_marked = marked;
        }
    }
    best_marked
}

/// Pooled `P(link)` + the §19.8.4 clustered dispersion over per-run means.
#[derive(Serialize)]
pub struct PooledEstimate {
    pub runs: usize,
    pub tasks: usize,
    pub hits: usize,
    pub p_link: f64,
    /// `p_link · (N − 1)` against [`RATIO_BOUND`].
    pub ratio: f64,
    /// Run-level clustered SE of `p_link` (SD of per-run means / √R) —
    /// the 10 tasks within a run share arrivals, so the binomial SE is
    /// too small; this is the dispersion the escalation rule reads.
    pub clustered_se_p: f64,
    /// The same SE on the `r` scale (`× (N − 1)`).
    pub clustered_se_ratio: f64,
}

fn pool(per_run_hits: &[usize]) -> PooledEstimate {
    let runs = per_run_hits.len();
    let tasks = runs * WALLETS;
    let hits: usize = per_run_hits.iter().sum();
    let p_link = hits as f64 / tasks as f64;
    let run_means: Vec<f64> = per_run_hits
        .iter()
        .map(|&h| h as f64 / WALLETS as f64)
        .collect();
    let var = if runs > 1 {
        let mean = run_means.iter().sum::<f64>() / runs as f64;
        run_means.iter().map(|m| (m - mean).powi(2)).sum::<f64>() / (runs as f64 - 1.0)
    } else {
        0.0
    };
    let clustered_se_p = (var / runs as f64).sqrt();
    let n_minus_1 = (WALLETS - 1) as f64;
    PooledEstimate {
        runs,
        tasks,
        hits,
        p_link,
        ratio: p_link * n_minus_1,
        clustered_se_p,
        clustered_se_ratio: clustered_se_p * n_minus_1,
    }
}

/// A §19.8.3 control result.
#[derive(Serialize)]
pub struct SealControl {
    pub name: &'static str,
    pub p_link: f64,
    pub baseline: f64,
    pub expectation: String,
    pub passed: bool,
}

/// The full sealing-form report (stdout JSON).
#[derive(Serialize)]
pub struct GF7SealReport {
    pub tick_ms: u64,
    pub ratio_bound: f64,
    /// The gate row: production arm, `m = 4`.
    pub production: PooledEstimate,
    /// Context sub-row (§19.8.2 posts row): production arm, first arrival
    /// per persona (`m = 1`). Reported, never graded.
    pub production_m1_context: PooledEstimate,
    pub controls: Vec<SealControl>,
    /// Receipt-noise floor (§19.8.3 control 1 rider): mean circular
    /// distance between true-sibling phase means at `dispersal = 0`,
    /// converted to ms. The §19.1 reopening criterion compares this to the
    /// phase resolution.
    pub noise_floor_ms: f64,
    /// `PASS` / `FAIL` / `INVALID (…)` / `DEFERRED (…)` per §19.8.4.
    pub verdict: String,
}

/// Grade the artifact per §19.8.4 and render the report (summary to stderr,
/// JSON to stdout — the binary's established convention).
pub fn run(artifact_path: &str) -> GF7SealReport {
    let arms = load_artifact(artifact_path);
    let production_runs = arms
        .get(PRODUCTION_ARM)
        .unwrap_or_else(|| panic!("gf7-seal: no `{PRODUCTION_ARM}` rows in the artifact"));
    let control_runs = arms
        .get(POSITIVE_CONTROL_ARM)
        .unwrap_or_else(|| panic!("gf7-seal: no `{POSITIVE_CONTROL_ARM}` rows in the artifact"));

    // The gate row + the m = 1 context sub-row.
    let prod_hits: Vec<usize> = production_runs
        .values()
        .map(|r| run_sibling_hits(r, false))
        .collect();
    let prod_m1_hits: Vec<usize> = production_runs
        .values()
        .map(|r| run_sibling_hits(r, true))
        .collect();
    let production = pool(&prod_hits);
    let production_m1_context = pool(&prod_m1_hits);

    // Control 1 (positive, phase-lock caught): dispersal = 0 runs must link.
    let pos_hits: Vec<usize> = control_runs
        .values()
        .map(|r| run_sibling_hits(r, false))
        .collect();
    let positive = pool(&pos_hits);

    // Control 1 rider: the receipt-noise floor — sibling phase-mean spread
    // at dispersal = 0 IS the scheduler/seal-latency noise.
    let mut floor_sum = 0.0;
    let mut floor_n = 0usize;
    for receipts in control_runs.values() {
        for w in 0..WALLETS {
            let a = persona_phase(&receipts[&(w, 0)], false);
            let b = persona_phase(&receipts[&(w, 1)], false);
            floor_sum += circular_distance(a, b) / std::f64::consts::TAU * TICK_MS as f64;
            floor_n += 1;
        }
    }
    let noise_floor_ms = floor_sum / floor_n as f64;

    // Control 2 (negative, severed pairing): pseudo-siblings from the same
    // production runs at zero extra runtime.
    let neg_hits: Vec<usize> = production_runs
        .values()
        .map(run_pseudo_sibling_hits)
        .collect();
    let negative = pool(&neg_hits);

    let baseline = 1.0 / (WALLETS - 1) as f64;
    let controls = vec![
        SealControl {
            name: "positive: dispersal 0 (phase-lock caught)",
            p_link: positive.p_link,
            baseline,
            expectation: format!("P(link) >= {POSITIVE_CONTROL_MIN}"),
            passed: positive.p_link >= POSITIVE_CONTROL_MIN,
        },
        SealControl {
            name: "negative: cross-wallet pseudo-siblings",
            p_link: negative.p_link,
            baseline,
            expectation: format!("|P(link) - {baseline:.3}| <= {NEGATIVE_CONTROL_TOL}"),
            passed: (negative.p_link - baseline).abs() <= NEGATIVE_CONTROL_TOL,
        },
    ];

    // §19.8.4 verdict: controls gate validity; the two-clustered-SE band
    // around the bound defers (extend R — the bar never moves).
    let verdict = if let Some(failed) = controls.iter().find(|c| !c.passed) {
        format!("INVALID ({} failed)", failed.name)
    } else if (production.ratio - RATIO_BOUND).abs() <= 2.0 * production.clustered_se_ratio {
        format!(
            "DEFERRED (r = {:.3} within 2 clustered SEs ({:.3}) of the bound {RATIO_BOUND} — \
             extend R, same geometry)",
            production.ratio, production.clustered_se_ratio
        )
    } else if production.ratio < RATIO_BOUND {
        "PASS".to_string()
    } else {
        "FAIL".to_string()
    };

    GF7SealReport {
        tick_ms: TICK_MS,
        ratio_bound: RATIO_BOUND,
        production,
        production_m1_context,
        controls,
        noise_floor_ms,
        verdict,
    }
}

/// Render the report: interpretation + table to stderr, JSON to stdout.
pub fn print_report(report: &GF7SealReport) {
    eprintln!(
        "shekyl-staking-sim — GF-7 leg-(b) SEALING form (ARCHIVAL_BOND_WI4_MEASUREMENT.md §19.8)"
    );
    eprintln!(
        "Receipt-timestamped live-driver re-run: production task+dispatch code path against a"
    );
    eprintln!(
        "  live shekyld --regtest (harness: shekyl-engine-core gf7_sealing_run.rs, gf7-hooks)."
    );
    eprintln!(
        "  Same statistic and bound as §19.4 (circular mean/distance; r = P(link)·(N−1) < {:.1});",
        report.ratio_bound
    );
    eprintln!(
        "  T = {} ms; N = {WALLETS}; chance 1/(N−1) = {:.3}. Clustered SE is run-level (the 10",
        report.tick_ms,
        1.0 / (WALLETS - 1) as f64
    );
    eprintln!("  tasks within a run share arrivals); the two-SE escalation band defers, never");
    eprintln!("  moves the bar (§19.8.4).");
    eprintln!();
    eprintln!("Controls (§19.8.3; either failing grades the session INVALID):");
    for c in &report.controls {
        eprintln!(
            "  [{}] {:<42} P(link)={:.3} baseline={:.3}  ({})",
            if c.passed { "ok" } else { "FAIL" },
            c.name,
            c.p_link,
            c.baseline,
            c.expectation,
        );
    }
    eprintln!(
        "  Receipt-noise floor (sibling phase spread at dispersal 0): {:.1} ms of T = {} ms",
        report.noise_floor_ms, report.tick_ms
    );
    eprintln!();
    eprintln!(
        "  {:<24} {:>4} {:>5} {:>4} | {:>7} {:>6} {:>6} {:>6}",
        "row", "runs", "tasks", "m", "P(link)", "seP", "r", "se_r",
    );
    let row = |label: &str, m: usize, e: &PooledEstimate| {
        eprintln!(
            "  {:<24} {:>4} {:>5} {:>4} | {:>7.3} {:>6.3} {:>6.3} {:>6.3}",
            label, e.runs, e.tasks, m, e.p_link, e.clustered_se_p, e.ratio, e.clustered_se_ratio,
        );
    };
    row("production (GATE)", POSTS_PER_PERSONA, &report.production);
    row("production m=1 context", 1, &report.production_m1_context);
    eprintln!();
    eprintln!("Sealing verdict: {}", report.verdict);

    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing gf7-seal report: {e}"),
    }
}
