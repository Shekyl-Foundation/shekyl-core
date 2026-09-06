//! Render-latency matrix for ruling B's performance thresholds.
//!
//! Two profiles, because they do different jobs (`docs/V3_SHARD_VISUALIZATION.md`,
//! *Performance targets*, amended 2026-09-06):
//!
//! - **`floor`** (default) — the amended targets, which are **regression
//!   bounds**: they assert that rendering has not regressed from the measured
//!   floor baseline, not that the design fits a UX target. Meaningful only when
//!   run ON the floor device (rule 76: Pi 4). GAP-7 measured x86:A72 per-term
//!   ratios spanning 3.86×–12× with one axis changing sign, so an x86 run of
//!   this profile is orientation, never evidence.
//! - **`x86-smoke`** — separate, x86-derived thresholds for the CI gate of the
//!   same name. It catches gross regressions early and **cannot bound the
//!   floor**; the disclaimer rides in its pass line so a green checkmark cannot
//!   be read as "performance is fine".
//!
//! Method (both profiles, and the quantity the amended thresholds name):
//! single-threaded wall clock (`std::time::Instant`) around the full consumer
//! call `render_candidate_png_from_params` (render + PNG encode — what a wallet
//! actually waits on); one untimed warm-up render per cell, then the **median
//! of 5** timed runs. Run with `--release`; a debug-profile matrix is
//! meaningless.

use std::time::Instant;

use shekyl_shard_visual::{fixtures, parameters_from_aggregate, render_candidate_png_from_params};

const TIMED_RUNS: usize = 5;

/// Amended floor targets (spec *Performance targets*, 2026-09-06): 2× over the
/// corpus-worst median measured on skl-pi, capture
/// `docs/benchmarks/shard_visual_budget_matrix_pi4_20260906T090000Z.txt`.
/// Changing these requires a recorded amendment citing a new measurement.
const FLOOR_TARGETS: [(u32, u128); 4] = [(128, 350), (256, 800), (512, 4_000), (1024, 25_000)];

/// x86 smoke thresholds: 3× over the corpus-worst median measured on the
/// reference dev machine (i9-11950H: 33/91/451/3405 ms). The margin is wider
/// than the floor profile's 2× on purpose — CI runners are shared virtualized
/// hardware with far more run-to-run variance than a dedicated box, and this
/// gate's job is catching gross (order-of-magnitude) regressions, not close
/// calls. A smoke gate that flakes is a gate people learn to ignore.
const X86_SMOKE_TARGETS: [(u32, u128); 4] = [(128, 100), (256, 300), (512, 1_500), (1024, 10_000)];

/// The muzzle, printed on SUCCESS as well as failure. A green CI line reads as
/// "performance is fine" to every human and every dashboard, and a paragraph in
/// a design doc three files away does not travel with the checkmark.
const X86_SMOKE_DISCLAIMER: &str = "does not bound Pi 4 floor performance \
     (x86:A72 ratios 3.86×–12×, one axis sign-flipping); the floor is re-run by \
     trigger — see docs/V3_SHARD_VISUALIZATION.md 'Where the bound is enforced'";

enum Profile {
    Floor,
    X86Smoke,
}

impl Profile {
    fn targets(&self) -> [(u32, u128); 4] {
        match self {
            Profile::Floor => FLOOR_TARGETS,
            Profile::X86Smoke => X86_SMOKE_TARGETS,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Profile::Floor => "floor",
            Profile::X86Smoke => "x86-smoke",
        }
    }
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!(
            "budget matrix must run under --release; a debug-profile measurement is meaningless"
        );
        std::process::exit(2);
    }

    let profile = match std::env::args().nth(1).as_deref() {
        None | Some("floor") => Profile::Floor,
        Some("x86-smoke") => Profile::X86Smoke,
        Some(other) => {
            eprintln!("unknown profile {other:?}; expected `floor` or `x86-smoke`");
            std::process::exit(2);
        }
    };

    println!(
        "shard-visual render matrix: profile={}, {} timed runs per cell (median), 1 warm-up, \
         single-threaded, arch={} os={}",
        profile.name(),
        TIMED_RUNS,
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!();
    println!("| fixture | size | threshold ms | median ms | verdict |");
    println!("|---|---|---|---|---|");

    let mut over_budget = 0u32;
    for fixture in fixtures::all() {
        let params = parameters_from_aggregate(&fixture.aggregate);
        for (size, threshold_ms) in profile.targets() {
            // Warm-up render: not timed, primes caches/allocator.
            render_candidate_png_from_params(&params, size).expect("warm-up render");

            let mut samples_ms: Vec<u128> = (0..TIMED_RUNS)
                .map(|_| {
                    let start = Instant::now();
                    let png = render_candidate_png_from_params(&params, size).expect("render");
                    let elapsed = start.elapsed().as_millis();
                    std::hint::black_box(png);
                    elapsed
                })
                .collect();
            samples_ms.sort_unstable();
            let median = samples_ms[TIMED_RUNS / 2];

            let verdict = if median <= threshold_ms {
                "within"
            } else {
                over_budget += 1;
                "OVER"
            };
            println!(
                "| {} | {}px | {} | {} | {} |",
                fixture.id, size, threshold_ms, median, verdict
            );
        }
    }

    println!();
    match (&profile, over_budget) {
        (Profile::X86Smoke, 0) => {
            println!("shard-visual-x86-smoke PASS — {X86_SMOKE_DISCLAIMER}");
        }
        (Profile::X86Smoke, n) => {
            println!(
                "shard-visual-x86-smoke FAIL — {n} cell(s) over the x86 smoke threshold; \
                 {X86_SMOKE_DISCLAIMER}"
            );
            std::process::exit(1);
        }
        (Profile::Floor, 0) => {
            println!(
                "all cells within the amended floor regression bounds (valid only if this ran \
                 ON the floor device)"
            );
        }
        (Profile::Floor, n) => {
            println!(
                "{n} cell(s) over the amended floor bound — on the floor device this is a \
                 REGRESSION from the 2026-09-06 baseline, and the spec's amendment discipline \
                 applies (record the measurement; do not retune the threshold)"
            );
            std::process::exit(1);
        }
    }
}
