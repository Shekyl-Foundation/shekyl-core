// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `F'` at the boundary of a stated admissible region, rather than at a
//! realized degree distribution.
//!
//! # Why not simply measure the distribution
//!
//! `fluff_return_ms` has been treated as a quantity to measure: run a fleet,
//! read its degree distribution, derive `F'`. The `A = 60` arm
//! (`Q12_D6A_PEER_DISCOVERY_RUN.md` §13) did exactly that and the result does
//! not generalize. It is one fleet, on one day, with `--tx-proxy N` capping
//! out-degree at the floor, and its below-floor tail mass **drifted 8.3 % to
//! 23.3 % across eleven samples** with no adversary present. Genesis is not
//! that fleet. A longer arm buys a better histogram of the same non-general
//! object.
//!
//! The network has no instantaneous degree distribution to derive a point
//! value from — but [`converged_fluff_return_mixed`] consumes exactly that, a
//! static `degrees` vector. Feeding it a realized histogram silently converts
//! "one fleet at one moment" into "the value".
//!
//! # The move this file makes instead
//!
//! §90.3's monotonicity argument runs both ways: out-edges above the floor only
//! *add* paths and pull `F'` down; below-floor nodes *remove* paths and push it
//! up. So `F'` is monotone in the tail, and a bound on the tail bounds `F'`.
//!
//! State an **admissible region** — at most `beta` of nodes below the floor,
//! none below `d_min` — derive `F'` at its boundary, and record the condition
//! beside the constant. Every network inside the region is then covered by
//! construction, with no claim that any particular network was measured. This
//! is the shape §16.4's alpha gate used: it did not measure `E` and `L`, it
//! found the region `E + R <= L` under which the decision is invariant and
//! armed the bound at the supremum over it.
//!
//! # What this file answers
//!
//! **How sharp is `F'` in `beta`.** If flat, the tail is not a derivation input
//! at all and `F' = 3500` carries an admissibility statement stronger than the
//! "lower bound" the record currently claims. If sharp, `beta` is a design
//! parameter that must be stated, and the fleet's job changes from measuring it
//! to characterizing its variance.
//!
//! # Placement convention, and why it needs its own control
//!
//! Tail nodes are placed by stride (`n % k == 0`), matching
//! `flood_convergence::uniform_at_the_floor_is_the_conservative_topology` so
//! the readings here are directly comparable to the 3000 / 3500 / 4750 table
//! §90.3 records. That convention always selects index 0 — the flood source.
//!
//! **That is a confound, and it is measured rather than assumed away**
//! (`the_step_is_not_a_degraded_source_artifact`). Because index 0 is selected
//! at every stride, every tail row carries a degraded source while `beta = 0`
//! does not, so the sweep's shape is two effects superimposed:
//!
//! - a **source penalty**, roughly constant at +500 ms, present whenever the
//!   originator is itself below the floor — which under
//!   `simulate_fluff_return_mixed`'s own split is "how a degraded source slows
//!   *everyone else's* first passage", not the source's own return; and
//! - a **tail effect**, a smooth ramp of +250 ms at `beta = 0.083` rising to
//!   +1000 ms at `beta = 0.5`.
//!
//! Read naively the on-source sweep looks like a step at any tail followed by a
//! plateau. It is not: the control shows the step is mostly the source term.
//! The on-source rows are still the right **provisioning** curve — a below-floor
//! node originating a transaction is the D9 case, and the embargo has to cover a
//! transaction that originated anywhere — but they overstate the typical case,
//! since a real network at tail mass `beta` has a degraded source with
//! probability `beta`, not certainty.

// Reporting-only arithmetic: `beta` and the percentage columns are printed for
// the reader, never compared against. Every value the assertions act on stays
// an integer millisecond reading. Same disposition as `d9_alpha.rs`.
#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::{
    converged_fluff_return_mixed, ConvergenceBudget, FloodParams, FloodReach, FLOOD_TICK_MS,
};
use shekyl_relay_privacy::schedule::DelayFamily;
use shekyl_relay_privacy::SplitMix64;

/// `f7_directed.rs`'s inputs, so this runs on the measurement it governs.
const MEAN_QUARTER_SECS: u32 = 20;
const FAMILY: DelayFamily = DelayFamily::Geometric;
const SEEDS: [u64; 6] = [
    0xC0FF_EE01,
    0xC0FF_EE02,
    0xC0FF_EE03,
    0xC0FF_EE04,
    0xC0FF_EE05,
    0xC0FF_EE06,
];

/// The F-8b floor, and the degree the `--tx-proxy` cap holds a healthy node at.
const FLOOR: usize = 12;

/// The worst per-sample minimum the `A = 60` arm observed (§13.2: minima run
/// 8-11 across the eleven settled samples).
const MEASURED_D_MIN: usize = 8;

fn shipped_topology() -> FloodParams {
    FloodParams {
        nodes: 512,
        // Inert for the `_mixed` entry point, which reads `degrees` instead;
        // set to the floor so the struct does not misdescribe the run.
        peers: FLOOR,
        reach: FloodReach::OutboundOnly,
    }
}

fn budget() -> ConvergenceBudget {
    ConvergenceBudget {
        start_trials: 32,
        max_trials: 1024,
        tolerance_ms: FLOOD_TICK_MS,
    }
}

fn read(flood: FloodParams, degrees: &[usize], label: &str) -> u64 {
    let c = converged_fluff_return_mixed(
        flood,
        degrees,
        MEAN_QUARTER_SECS,
        FAMILY,
        &SEEDS,
        budget(),
        SplitMix64::new,
    )
    .unwrap_or_else(|e| panic!("{label} did not converge: {e}"));
    println!(
        "  {label:38} p90 {:5} ms   ({} trials/seed, spread {})",
        c.p90_ms, c.trials_per_seed, c.spread_ms
    );
    c.p90_ms
}

/// Every `stride`-th node at `tail_degree`, the rest at the floor.
fn strided_tail(nodes: usize, stride: usize, tail_degree: usize) -> Vec<usize> {
    (0..nodes)
        .map(|n| if n % stride == 0 { tail_degree } else { FLOOR })
        .collect()
}

/// Every `stride`-th node drawn from `tail_degrees` in rotation, the rest at
/// the floor — a tail with *shape*, not a spike at one degree.
fn strided_tail_spread(nodes: usize, stride: usize, tail_degrees: &[usize]) -> Vec<usize> {
    let mut which = 0;
    (0..nodes)
        .map(|n| {
            if n % stride == 0 {
                let d = tail_degrees[which % tail_degrees.len()];
                which += 1;
                d
            } else {
                FLOOR
            }
        })
        .collect()
}

/// **The sweep.** `F'` against tail mass, at the measured worst minimum.
///
/// Strides are chosen so `beta = 1/stride` brackets the `A = 60` arm's observed
/// range: its best sample was a 8.3 % tail (~1/12) and its worst 23.3 % (~1/4).
#[test]
fn f_prime_against_tail_mass_at_the_measured_minimum() {
    let flood = shipped_topology();

    println!(
        "\n  F' against below-floor tail mass (tail at the measured d_min = {MEASURED_D_MIN})"
    );
    println!("  ------------------------------------------------------------------");

    let uniform = read(
        flood,
        &vec![FLOOR; flood.nodes],
        "beta = 0     uniform at 12",
    );

    // 1/12 and 1/4 bracket the `A = 60` arm's observed tail range; 1/3 is
    // §90.3's recorded row; 1/2 is the `A = 15` arm's condition (§14.2: 52.1 %
    // of settled samples at or above the floor, so beta ~ 0.48), which is the
    // young-network state §11.13 is about and must not be silently outside the
    // region.
    let strides = [12_usize, 8, 6, 5, 4, 3, 2];
    let mut rows: Vec<(usize, f64, u64)> = Vec::new();
    for stride in strides {
        let beta = 1.0 / stride as f64;
        let degrees = strided_tail(flood.nodes, stride, MEASURED_D_MIN);
        let label = format!("beta = 1/{stride:<3} ({beta:.3}) tail at {MEASURED_D_MIN}");
        let p90 = read(flood, &degrees, &label);
        rows.push((stride, beta, p90));
    }

    println!("\n  uniform-at-floor reading = {uniform} ms (the value §90.3 records as 3500)");
    let worst = rows.last().expect("the sweep ran at least one stride").2;
    println!(
        "  spread across the swept region = {} ms ({:+.1} % over uniform)",
        worst.saturating_sub(uniform),
        ((worst as f64 / uniform as f64) - 1.0) * 100.0
    );

    // The structural claim, asserted rather than eyeballed: removing out-edges
    // removes paths, so more tail mass cannot READ FASTER. A violation means
    // the placement convention or the builder changed under this file, not
    // that the network got quicker.
    for w in rows.windows(2) {
        let (s_lo, b_lo, p_lo) = w[0];
        let (s_hi, b_hi, p_hi) = w[1];
        assert!(
            p_hi >= p_lo,
            "F' fell as tail mass ROSE: beta 1/{s_lo} ({b_lo:.3}) read {p_lo} ms, \
             beta 1/{s_hi} ({b_hi:.3}) read {p_hi} ms. Below-floor nodes remove \
             paths and first passage is a min over paths, so this is the sign \
             inverted — the topology builder or the placement convention moved"
        );
    }
    assert!(
        rows[0].2 >= uniform,
        "any below-floor tail must not read below uniform-at-the-floor: got {} vs {uniform}",
        rows[0].2
    );
}

/// **Does the tail's SHAPE matter, or only its mass?**
///
/// The `A = 60` arm's minima run 8-11, so a tail spiked at 8 is more
/// pessimistic than what it observed. If shape barely moves the reading, then
/// `d_min` can be pinned at the worst observed minimum without costing
/// anything, and the region needs only `beta` stated carefully.
#[test]
fn tail_shape_at_the_boundary_mass() {
    let flood = shipped_topology();
    // 1/4 = 0.25, just above the arm's worst observed tail of 23.3 %.
    const STRIDE: usize = 4;

    println!("\n  tail SHAPE at beta = 1/{STRIDE} (0.250, just above the arm's worst 0.233)");
    println!("  ------------------------------------------------------------------");

    let uniform = read(
        flood,
        &vec![FLOOR; flood.nodes],
        "beta = 0     uniform at 12",
    );
    let all_at_8 = read(
        flood,
        &strided_tail(flood.nodes, STRIDE, 8),
        "tail all at 8        (most pessimistic)",
    );
    let spread = read(
        flood,
        &strided_tail_spread(flood.nodes, STRIDE, &[8, 9, 10, 11]),
        "tail spread 8,9,10,11 (as measured)",
    );
    let all_at_11 = read(
        flood,
        &strided_tail(flood.nodes, STRIDE, 11),
        "tail all at 11       (least pessimistic)",
    );

    println!(
        "\n  shape range at fixed mass = {} ms (all-at-8 minus all-at-11)",
        all_at_8.saturating_sub(all_at_11)
    );
    println!(
        "  measured-shape cost over uniform = {} ms",
        spread.saturating_sub(uniform)
    );

    // A deeper tail at the same mass removes more paths, so it cannot read
    // faster. This orders the three shapes and is the oracle for the claim
    // that pinning `d_min` at the worst observed minimum is conservative.
    assert!(
        all_at_8 >= spread,
        "a tail spiked at 8 must not read faster than one spread over 8-11 at the \
         same mass: {all_at_8} vs {spread}"
    );
    assert!(
        spread >= all_at_11,
        "a tail spread over 8-11 must not read faster than one held at 11 at the \
         same mass: {spread} vs {all_at_11}"
    );
}

/// **The dependents, at each candidate region boundary.**
///
/// `F'` is not a constant that moves alone: the per-zone embargo is *solved*
/// from it at [`EMBARGO_FULL_TRAVEL_PROBABILITY`], and the wallet's failed-send
/// wait is a quantile over the worst zone's resulting table. Printing them
/// together is what makes the region choice a decision about a system rather
/// than about one integer.
///
/// The block-interval crossing count is here because §44 checked it explicitly
/// at 190 s ("still crosses exactly one 120 s block interval") and a longer
/// embargo can cross more. That reconciliation is a property of the value, not
/// of the derivation, so it has to be re-read at every candidate.
#[test]
fn dependents_at_each_candidate_boundary() {
    use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
    use shekyl_relay_privacy::schedule::{EmbargoTimer, PROPAGATION_FALSE_FAIL_ONE_IN};
    use shekyl_relay_privacy::zone::RelayZone;

    /// `DIFFICULTY_TARGET` — the block interval §44/§15 reconcile against.
    const BLOCK_INTERVAL_SECS: u32 = 120;

    println!("\n  dependents at each candidate F' (shipped F' = 3250)");
    println!("  F' ms   region                       clearnet E   anon E   wallet wait   E/120s");
    println!("  -----   --------------------------   ----------   ------   -----------   ------");

    for (f_prime, region) in [
        (3_250_u32, "SHIPPED (single draw)"),
        (3_500, "beta = 0 (uniform at floor)"),
        (4_500, "beta <= 1/4, d_min >= 8"),
        (4_750, "beta <= 1/3, d_min >= 8"),
        (5_000, "beta <= 1/2, d_min >= 8"),
    ] {
        let mut secs = [0_u32; 2];
        for (i, zone) in DandelionParams::CLASS_REPRESENTATIVES.iter().enumerate() {
            let params = DandelionParams {
                fluff_return_ms: f_prime,
                ..DandelionParams::adopted_for(*zone)
            };
            secs[i] = EmbargoTimer::adopted(&params).mean_secs();
        }
        // The wallet wait is taken over the WORST zone, per §89.2.
        let worst_zone = if secs[1] >= secs[0] {
            RelayZone::Tor
        } else {
            RelayZone::Public
        };
        let worst = DandelionParams {
            fluff_return_ms: f_prime,
            ..DandelionParams::adopted_for(worst_zone)
        };
        let wait =
            EmbargoTimer::adopted(&worst).judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN);
        let crossings = secs[0] / BLOCK_INTERVAL_SECS;
        println!(
            "  {f_prime:5}   {region:26}   {:8} s   {:4} s   {wait:8} s   {crossings:5}",
            secs[0], secs[1]
        );
    }

    println!(
        "\n  solved at EMBARGO_FULL_TRAVEL_PROBABILITY = {EMBARGO_FULL_TRAVEL_PROBABILITY}; \
         wallet wait at 1-in-{PROPAGATION_FALSE_FAIL_ONE_IN}"
    );
    println!(
        "  §44 checked that the clearnet embargo crosses exactly ONE {BLOCK_INTERVAL_SECS} s \
         block interval at 190 s; read the last column at each candidate."
    );
}

/// **The liveness cost of the region choice** — §15.3's recovery distribution.
///
/// §15's banner is explicit that *"crosses exactly one block interval"* is an
/// **observation about where 190 s landed, never an invariant**, and §15.6
/// forbids block time as a term at any level. So the crossing count is not a
/// constraint on this decision and must not be read as one.
///
/// What a longer embargo does move is §15.3: a first-hop black-holed tx stays
/// invisible until an upstream embargo fires, the embargo is memoryless, so
/// `P(recover within one block interval)` falls as the mean grows. That is the
/// real price of a wider admissible region — a liveness cost, which the
/// priority order accepts in exchange for correct privacy provisioning.
///
/// §15.3's own two rows are recomputed here as the oracle: a formula that does
/// not reproduce 0.657 at 112 s and 0.565 at 144 s is not the one the record
/// used, and every other row it prints would be wrong in the same way.
#[test]
fn recovery_within_one_block_interval_at_each_candidate() {
    const BLOCK_INTERVAL_SECS: f64 = 120.0;
    let p_recover = |mean_secs: f64| -> f64 { 1.0 - (-BLOCK_INTERVAL_SECS / mean_secs).exp() };

    // Oracle first: reproduce §15.3's recorded rows before printing new ones.
    for (mean, recorded) in [(112.0_f64, 0.657_f64), (144.0, 0.565)] {
        let got = p_recover(mean);
        assert!(
            (got - recorded).abs() < 0.001,
            "§15.3 records P(recover < 120 s) = {recorded} at a {mean} s embargo; this \
             formula gives {got:.3}. The rows below would be wrong the same way"
        );
    }

    println!("\n  §15.3 first-hop black-hole recovery within one 120 s block interval");
    println!("  clearnet E   P(recover < 120 s)   note");
    println!("  ----------   ------------------   ----------------------------------");
    for (mean, note) in [
        (112_u32, "pre-RD-4 (§15.3 recorded 0.657)"),
        (144, "RD-4 (§15.3 recorded 0.565)"),
        (190, "SHIPPED today"),
        (201, "beta = 0 (uniform at floor)"),
        (247, "beta <= 1/4, d_min >= 8"),
        (258, "beta <= 1/3, d_min >= 8"),
        (270, "beta <= 1/2, d_min >= 8"),
    ] {
        println!(
            "  {mean:8} s   {:16.3}   {note}",
            p_recover(f64::from(mean))
        );
    }
    println!(
        "\n  RD-4 was accepted at a ~9-point drop (0.657 -> 0.565); read the shipped-to-\
         candidate drop against that precedent."
    );
}

/// **Placement control — is the step a tail effect or a SOURCE effect?**
///
/// The stride convention `n % stride == 0` always selects index 0, which is the
/// flood source (`best[0] = 0`). `simulate_fluff_return_mixed`'s own docs
/// separate these: a reduced `degrees[0]` measures "how a degraded *source*
/// slows everyone else's first passage", which is not the same quantity as a
/// tail node thinning the graph. So every row of the sweep above — including
/// the smallest tail — carries a crippled source, and `beta = 0` is the only
/// row without one.
///
/// That confound would put the discontinuity at *"is the source degraded"*
/// rather than at *"does a tail exist"*, which is a materially different
/// finding. Re-read with the tail shifted off the source (`n % stride == 1`)
/// and compare.
#[test]
fn the_step_is_not_a_degraded_source_artifact() {
    let flood = shipped_topology();

    // Same as `strided_tail` but offset so index 0 — the source — stays at the
    // floor and only non-source nodes carry the tail.
    let off_source = |stride: usize, tail_degree: usize| -> Vec<usize> {
        (0..flood.nodes)
            .map(|n| if n % stride == 1 { tail_degree } else { FLOOR })
            .collect()
    };

    println!("\n  placement control: tail ON the source (n%k==0) vs OFF it (n%k==1)");
    println!("  ------------------------------------------------------------------");
    let uniform = read(
        flood,
        &vec![FLOOR; flood.nodes],
        "beta = 0     uniform at 12",
    );

    let mut rows = Vec::new();
    for stride in [12_usize, 8, 6, 4, 3, 2] {
        let on = read(
            flood,
            &strided_tail(flood.nodes, stride, MEASURED_D_MIN),
            &format!("beta = 1/{stride:<3} tail ON source"),
        );
        let off = read(
            flood,
            &off_source(stride, MEASURED_D_MIN),
            &format!("beta = 1/{stride:<3} tail OFF source"),
        );
        rows.push((stride, on, off));
    }

    // Signed difference of two millisecond readings. `try_from` rather than
    // `as`: a reading that does not fit i64 is a measurement to refuse, not a
    // value to wrap — the same disposition the sweep above takes on u32.
    let delta = |a: u64, b: u64| -> i64 {
        let (a, b) = (
            i64::try_from(a).expect("a p90 reading in ms must fit i64"),
            i64::try_from(b).expect("a p90 reading in ms must fit i64"),
        );
        a - b
    };

    println!("\n  stride   ON source   OFF source   source contribution");
    println!("  ------   ---------   ----------   -------------------");
    for (stride, on, off) in &rows {
        println!(
            "  1/{stride:<5}   {on:6} ms   {off:7} ms   {:+} ms",
            delta(*on, *off)
        );
    }
    let smallest = rows.first().expect("the control swept at least one stride");
    println!(
        "\n  step from uniform at the SMALLEST tail: ON source {:+} ms, OFF source {:+} ms",
        delta(smallest.1, uniform),
        delta(smallest.2, uniform)
    );
    println!(
        "  If the OFF-source step is ~0, the discontinuity was the source, not the tail, \
         and 'presence not amount' does not hold."
    );

    // Whatever the magnitude, the ordering is structural: a degraded source can
    // only slow first passage relative to the same tail mass placed elsewhere,
    // because node 0's out-edges gate EVERY path in an OutboundOnly flood.
    for (stride, on, off) in &rows {
        assert!(
            on >= off,
            "at stride 1/{stride} the tail placed ON the source read {on} ms, FASTER than \
             the same mass placed off it ({off} ms) — the source gates every path, so this \
             is the sign inverted"
        );
    }
}
