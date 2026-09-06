//! Floor-device budget matrix for ruling B's performance falsifier.
//!
//! Ruling B (`docs/V3_SHARD_VISUALIZATION.md`, *Floor-device budget*): the
//! spec's performance targets are provisioned at the floor device (rule 76:
//! Pi 4) and measured **on the floor only** — GAP-7 measured x86:A72
//! per-term ratios spanning 3.86×–12× with one axis changing sign, so an
//! x86 run of this binary is orientation, never evidence. Any (fixture,
//! size) cell over budget on the floor falsifies candidate.v1's fitness at
//! that tier.
//!
//! Method: single-threaded wall clock (`std::time::Instant`) around the
//! full consumer call `render_candidate_png_from_params` (render + PNG
//! encode — what a wallet actually waits on); one untimed warm-up render
//! per cell, then the **median of 5** timed runs, to shed scheduler and
//! thermal noise. Run with `--release`; a debug-profile matrix is
//! meaningless.

use std::time::Instant;

use shekyl_shard_visual::{fixtures, parameters_from_aggregate, render_candidate_png_from_params};

/// (size, budget in milliseconds) — the spec's *Performance targets*,
/// which predate any measurement.
const TARGETS: [(u32, u128); 4] = [(128, 50), (256, 100), (512, 300), (1024, 2000)];
const TIMED_RUNS: usize = 5;

fn main() {
    if cfg!(debug_assertions) {
        eprintln!(
            "budget matrix must run under --release; a debug-profile measurement is meaningless"
        );
        std::process::exit(2);
    }

    println!(
        "budget matrix: {} timed runs per cell (median), 1 warm-up, single-threaded, arch={} os={}",
        TIMED_RUNS,
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!();
    println!("| fixture | size | budget ms | median ms | verdict |");
    println!("|---|---|---|---|---|");

    let mut over_budget = 0u32;
    for fixture in fixtures::all() {
        let params = parameters_from_aggregate(&fixture.aggregate);
        for (size, budget_ms) in TARGETS {
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

            let verdict = if median <= budget_ms {
                "within"
            } else {
                over_budget += 1;
                "OVER BUDGET"
            };
            println!(
                "| {} | {}px | {} | {} | {} |",
                fixture.id, size, budget_ms, median, verdict
            );
        }
    }

    println!();
    if over_budget == 0 {
        println!("all cells within budget");
    } else {
        println!(
            "{over_budget} cell(s) over budget — on the floor device this falsifies \
             candidate.v1's fitness at those tiers (spec consequence: drop or restrict)"
        );
        std::process::exit(1);
    }
}
