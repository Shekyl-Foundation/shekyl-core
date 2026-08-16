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

/// The `beta = 0` reference reading every sweep anchors on.
///
/// Named rather than repeated, but deliberately **not** cached across tests: a
/// shared `OnceLock` would couple the sweeps to each other, and each one
/// re-establishing this independently is what makes a divergence between them
/// a signal instead of something an optimization hid.
fn uniform_baseline(flood: FloodParams) -> u64 {
    read(
        flood,
        &vec![FLOOR; flood.nodes],
        "beta = 0     uniform at 12",
    )
}

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

    let uniform = uniform_baseline(flood);

    // 1/12 and 1/4 bracket the `A = 60` arm's observed tail range; 1/3 is
    // §90.3's recorded row; 1/2 is the `A = 15` arm's condition (§14.2: 52.1 %
    // of settled samples at or above the floor, so beta ~ 0.48).
    //
    // **Retraction, recorded where it is consumed.** An earlier revision of
    // this comment said the `A = 15` state "must not be silently outside the
    // region", and the menu that followed recommended the most conservative row
    // on that basis. That is exactly the *"set it to the worst"* policy §43.2
    // says must be defended rather than inherited, and it is wrong here on its
    // own terms: `A = 15` is *below* §15's launch condition of ~30
    // anonymity-capable nodes, so it is a state the network is not supposed to
    // launch in. The region declines to cover it deliberately — see
    // `the_region_is_consistent_with_the_launch_condition`.
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

    let uniform = uniform_baseline(flood);
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
    use shekyl_relay_privacy::schedule::{
        EmbargoTimer, ADOPTED_PROPAGATION_TIMEOUT_SECS, PROPAGATION_FALSE_FAIL_ONE_IN,
    };
    // No `RelayZone` import: every zone this test touches now comes from
    // `CLASS_REPRESENTATIVES` itself, so there is no way to name a zone the
    // measured columns did not come from.

    /// `DIFFICULTY_TARGET` — the block interval §44/§15 reconcile against.
    const BLOCK_INTERVAL_SECS: u32 = 120;

    // (F', clearnet secs, anon secs, wallet wait) per candidate.
    let mut rows: Vec<(u32, u32, u32, u32)> = Vec::new();

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
        // **The two classes are DESTRUCTURED, not indexed — the pattern is the
        // pin.** §89.2 splits the adopted parameter sets into exactly two
        // transit classes, and this test is binary all the way down: two named
        // columns, a pairwise comparison between them, and a calibration
        // against the two embargo constants the FFI pins. Sizing a container to
        // `CLASS_REPRESENTATIVES.len()` would let a third class compile and
        // then silently vanish from the table — a loud failure traded for a
        // quiet omission. This pattern instead fails to COMPILE if the set ever
        // grows, which is the signal to rewrite the test rather than widen it.
        let [clearnet_zone, anon_zone] = DandelionParams::CLASS_REPRESENTATIVES;
        let embargo_secs = |zone| {
            EmbargoTimer::adopted(&DandelionParams {
                fluff_return_ms: f_prime,
                ..DandelionParams::adopted_for(zone)
            })
            .mean_secs()
        };
        let clearnet = embargo_secs(clearnet_zone);
        let anon = embargo_secs(anon_zone);

        // The wallet wait is taken over the WORST zone, per §89.2 — picked from
        // the representatives just measured rather than re-named independently,
        // so the wait can never be drawn from a zone the columns did not read.
        let worst_zone = if anon >= clearnet {
            anon_zone
        } else {
            clearnet_zone
        };
        let wait = EmbargoTimer::adopted(&DandelionParams {
            fluff_return_ms: f_prime,
            ..DandelionParams::adopted_for(worst_zone)
        })
        .judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN);
        let crossings = clearnet / BLOCK_INTERVAL_SECS;
        println!(
            "  {f_prime:5}   {region:26}   {clearnet:8} s   {anon:4} s   {wait:8} s   {crossings:5}"
        );

        // The anonymity zone takes the longer hop (§89.2's per-zone split, the
        // ONLY term that differs between the two parameter sets), so its solve
        // must exceed clearnet's at every candidate. Equal values would mean
        // `adopted_for` stopped distinguishing the classes and the whole
        // two-column table is one column printed twice.
        assert!(
            anon > clearnet,
            "the anonymity embargo ({anon} s) must exceed clearnet's ({clearnet} s) at \
             F' = {f_prime}: the zones differ only in transit class, and a tie means \
             `adopted_for` is no longer splitting them"
        );
        // The wallet wait is a 1-in-N SURVIVAL quantile of the worst zone's
        // table, so it cannot come in at or under that table's mean.
        assert!(
            wait > anon,
            "the wallet wait ({wait} s) is a 1-in-{PROPAGATION_FALSE_FAIL_ONE_IN} survival \
             quantile of the worst zone's table and must exceed its mean ({anon} s) at \
             F' = {f_prime}"
        );
        rows.push((f_prime, clearnet, anon, wait));
    }

    // **Calibration against the shipped constants, which is what makes this a
    // test rather than a report.** The first row is the pair in force today, so
    // it must reproduce the three values the tree pins independently — the FFI's
    // 190 s and 499 s and `ADOPTED_PROPAGATION_TIMEOUT_SECS`. If the derivation
    // drifts, every other row is wrong by the same amount and nothing else here
    // would notice.
    let (shipped_f, shipped_clear, shipped_anon, shipped_wait) = rows[0];
    assert_eq!(
        shipped_f, 3_250,
        "the first row must be the shipped pair for the calibration below to mean anything"
    );
    assert_eq!(
        shipped_clear, 190,
        "the shipped clearnet embargo is pinned at 190 s (dandelionpp_ffi.rs); this \
         derivation gives {shipped_clear} s"
    );
    assert_eq!(
        shipped_anon, 499,
        "the shipped anonymity embargo is pinned at 499 s (dandelionpp_ffi.rs); this \
         derivation gives {shipped_anon} s"
    );
    assert_eq!(
        shipped_wait, ADOPTED_PROPAGATION_TIMEOUT_SECS,
        "the shipped wallet wait is pinned at {ADOPTED_PROPAGATION_TIMEOUT_SECS} s \
         (schedule.rs); this derivation gives {shipped_wait} s"
    );

    // Monotonicity: a longer fluff return cannot shorten any dependent. This is
    // the structural claim the whole menu rests on — if it failed, the region
    // boundary would not bound the dependents and reading them off a `beta`
    // bound would be unsound.
    for w in rows.windows(2) {
        let (f_lo, c_lo, a_lo, w_lo) = w[0];
        let (f_hi, c_hi, a_hi, w_hi) = w[1];
        assert!(
            c_hi >= c_lo && a_hi >= a_lo && w_hi >= w_lo,
            "dependents must not FALL as F' rises ({f_lo} -> {f_hi} ms): clearnet \
             {c_lo} -> {c_hi}, anon {a_lo} -> {a_hi}, wallet {w_lo} -> {w_hi}. The menu \
             reads a bound off a region boundary, which is only sound if each dependent \
             is monotone in F'"
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
    let uniform = uniform_baseline(flood);

    let mut rows = Vec::new();
    // Range ends plus the middle. The claim is that the source term is a
    // roughly CONSTANT offset across the tail range, and three points spanning
    // that range test it as sharply as six while halving the debug CI cost —
    // a non-constant offset would have to be flat at 1/12, 1/4 and 1/2 and bend
    // only between them.
    for stride in [12_usize, 4, 2] {
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

/// **The leak column §43.2 requires before this lands.**
///
/// §43.2: *"over-estimating `F` is safe on the disarm axis and adverse on the
/// leak axis. The policy names one consumer, and was written when only one
/// existed."* A menu of `F'` candidates carrying only disarm-side dependents is
/// the incomplete policy being inherited through the unit that rests on it.
///
/// The two terms genuinely oppose, and `simulate_passive_neighbor_leak` sees
/// both: a leak is counted when a neighboured prefix node's embargo fires
/// **before `trace.disarm_ms`**. Raising `F'` pushes `disarm_ms` out (more
/// window, more leak) *and* lengthens the derived embargo (lower firing rate,
/// less leak). Neither §6.6 nor §6.7 fixes the net sign on its own, because
/// each holds the other term still. Moving both together is the only reading
/// that answers §43.2.
///
/// Note the asymmetry this exposes, which is the whole of the per-zone
/// question: the leak is **structurally zero on Tor/I2P** (§6.6 — fluff never
/// traverses the supernode's inbound edges), so every millisecond of `beta`
/// margin is derived from an anonymity-zone statistic and paid on the clearnet
/// axis.
#[test]
fn leak_at_each_candidate_region() {
    use shekyl_relay_privacy::conformance::{simulate_passive_neighbor_leak, Transport};
    use shekyl_relay_privacy::derive::derive_embargo;
    use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
    use shekyl_relay_privacy::schedule::{EmbargoTimer, DEFAULT_EMBARGO_TICK_MILLIS};
    use shekyl_relay_privacy::zone::RelayZone;

    // **Trials are matched to the claim each row makes, not set uniformly.**
    // Uniform 1e6 across every row cost ~20 s in a debug CI test to buy
    // precision on rows whose claims are qualitative, which is budget spent
    // where it proves nothing.
    //
    // The candidate rows carry the FLATNESS claim, and a null result is only as
    // good as the noise floor under it: at p ~ 0.011 the binomial standard
    // error is ~1.0e-4 at 1e6 against ~2.3e-4 at §6.6's 2e5, which is what makes
    // the tolerance below a real bound instead of a restatement of the sampling
    // error. This one does not move.
    const CANDIDATE_TRIALS: usize = 1_000_000;
    // The anonymity rows assert a STRUCTURAL zero (§6.6: fluff never traverses
    // the supernode's inbound edges). Any nonzero reading is a defect whatever
    // the count, so precision buys nothing — this is not a statistical claim.
    const STRUCTURAL_TRIALS: usize = 100_000;
    // The sensitivity control demonstrates a ~14x separation; at p ~ 0.06 that
    // is some eighty standard errors at this count. Raising it would not make
    // the control more convincing, only slower.
    const CONTROL_TRIALS: usize = 100_000;
    const PHI: f64 = 0.10;
    /// Three binomial standard errors at `CANDIDATE_TRIALS` and `p ~ 0.011`,
    /// rounded up.
    /// A band inside this is flat as far as this instrument can see; a band
    /// outside it is a real movement on §43.2's axis.
    const NOISE_3SIGMA: f64 = 3.2e-4;

    println!("\n  §6.6 passive inbound-supernode leak at each candidate (phi = {PHI})");
    println!("  F' ms   clearnet E   leak rate   origin share   tor leak");
    println!("  -----   ----------   ---------   ------------   --------");

    let mut rows = Vec::new();
    for f_prime in [3_250_u32, 3_500, 4_500, 4_750, 5_000] {
        let params = DandelionParams {
            fluff_return_ms: f_prime,
            ..DandelionParams::adopted_for(RelayZone::Public)
        };
        let e = EmbargoTimer::adopted(&params);
        let mut cr = SplitMix64::new(0x1EA4_0000 + u64::from(f_prime));
        let c = simulate_passive_neighbor_leak(
            &params,
            &e,
            PHI,
            Transport::Clearnet,
            CANDIDATE_TRIALS,
            &mut cr,
        );
        let mut tr = SplitMix64::new(0x1EA4_7919 + u64::from(f_prime));
        let t = simulate_passive_neighbor_leak(
            &params,
            &e,
            PHI,
            Transport::Anonymity,
            STRUCTURAL_TRIALS,
            &mut tr,
        );
        println!(
            "  {f_prime:5}   {:8} s   {:9.5}   {:12.4}   {:8.5}",
            e.mean_secs(),
            c.leak_rate,
            c.origin_share_of_leaks,
            t.leak_rate
        );
        // §6.6's structural claim, re-armed at every candidate rather than
        // assumed to survive the re-baselining.
        assert!(
            t.leak_rate < 1e-12,
            "the anonymity-zone leak must be structurally zero at F' = {f_prime}, got {}",
            t.leak_rate
        );
        rows.push((f_prime, c.leak_rate));
    }

    let base = rows[0].1;
    // **Calibration against the record.** §6.6's banner re-measured the adopted
    // row at the F-7-corrected pair and recorded 1.08 %. This run must land on
    // it, or the column below is measuring a channel the record does not have.
    assert!(
        (base - 0.0108).abs() < NOISE_3SIGMA,
        "the shipped pair (F' = 3250, embargo 190 s) reads {base:.5}; §6.6's banner \
         records 0.0108 at exactly this pair. A mismatch means this is not the \
         channel §43.2 names"
    );
    println!("\n  shipped F' = 3250 reads {base:.5} (§6.6 banner records 0.0108)");
    for (f_prime, rate) in &rows[1..] {
        println!(
            "  F' = {f_prime}: {:+.1} % against shipped",
            ((rate / base) - 1.0) * 100.0
        );
    }
    println!(
        "\n  §43.2 predicts the disarm-window term pushes this UP while the longer\n  \
         embargo pushes it DOWN. The sign of the net is the column it asked for."
    );

    // **The sensitivity control, and it decides whether the flat band above is
    // a finding or an instrument that cannot see.** A null result on an
    // unvalidated instrument is indistinguishable from a broken one, so the
    // same call is made across §6.6's own embargo range, where the recorded
    // answer is a ~4x move (0.0465 at 31 s against 0.0108 at 190 s).
    let control = |secs: u32| -> f64 {
        let ticks = u32::try_from(u64::from(secs) * 1000 / DEFAULT_EMBARGO_TICK_MILLIS)
            .expect("control embargo in ticks must fit u32");
        let e = EmbargoTimer::geometric_from_ticks(ticks, DEFAULT_EMBARGO_TICK_MILLIS);
        let params = DandelionParams::adopted_for(RelayZone::Public);
        let mut r = SplitMix64::new(0x0C0C_7201 ^ u64::from(secs));
        simulate_passive_neighbor_leak(
            &params,
            &e,
            PHI,
            Transport::Clearnet,
            CONTROL_TRIALS,
            &mut r,
        )
        .leak_rate
    };
    let short = control(31);
    let long = control(500);
    println!("\n  sensitivity control (embargo alone, §6.6's range)");
    println!("  embargo  31 s -> leak {short:.5}");
    println!("  embargo 500 s -> leak {long:.5}");
    println!(
        "  (§6.6's 0.0465 / 0.0032 rows were taken at the PRE-correction pair, so they\n  \
         are not the comparison — the calibration is the adopted row asserted below.)"
    );
    assert!(
        short > long * 3.0,
        "the leak instrument must move sharply across §6.6's embargo range — got \
         {short:.5} at 31 s against {long:.5} at 500 s. Without this the flat band \
         above is an instrument that cannot see, not a finding"
    );

    // With the instrument shown sensitive, the band's flatness is the reading.
    let (lo, hi) = rows
        .iter()
        .map(|(_, r)| *r)
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), r| {
            (lo.min(r), hi.max(r))
        });
    println!(
        "\n  candidate band spans {:.5} ({lo:.5}..{hi:.5}) against a 3-sigma noise \
         floor of {NOISE_3SIGMA:.5}",
        hi - lo
    );
    assert!(
        hi - lo < NOISE_3SIGMA,
        "the leak band across the candidates spans {:.5}, beyond the {NOISE_3SIGMA:.5} \
         noise floor — §43.2's adverse term does NOT cancel here, and the region \
         choice is a privacy-against-privacy trade that this file must price rather \
         than report as flat",
        hi - lo
    );

    // Whatever the sign, `derive_embargo` must be answering at the pinned
    // target for every row; a silently unreachable solve would make the whole
    // column a reading against the wrong embargo.
    for (f_prime, _) in &rows {
        let p = DandelionParams {
            fluff_return_ms: *f_prime,
            ..DandelionParams::adopted_for(RelayZone::Public)
        };
        let d = derive_embargo(
            &p,
            DEFAULT_EMBARGO_TICK_MILLIS,
            EMBARGO_FULL_TRAVEL_PROBABILITY,
        )
        .expect("the full-travel target must be reachable at every candidate");
        assert!(d.achieved >= EMBARGO_FULL_TRAVEL_PROBABILITY);
    }
}

/// **What the region choice actually buys: the alpha miss when the network
/// leaves it.**
///
/// Choosing `beta` looks like a free parameter, and it is not decidable as one.
/// [`EMBARGO_FULL_TRAVEL_PROBABILITY`] is pinned at 0.90 and `derive_embargo`
/// searches for the smallest embargo achieving it *at the `F'` handed to it* —
/// so picking `beta` picks `F'` picks `E`, and 0.90 holds by construction at
/// whatever `F'` it was derived from. Asking "is 0.90 met?" of the pair that
/// was solved for 0.90 is a round trip.
///
/// The non-circular quantity is the **miss**: fix `E` at the region boundary,
/// then read alpha against the `F'` a network *outside* the region actually
/// produces. That curve is the cost of the bound being wrong, and it converts
/// the region choice from a taste question into one about a pinned invariant —
/// how far below 0.90 is acceptable when `beta` exceeds the bound.
#[test]
fn alpha_degradation_when_the_network_leaves_the_region() {
    use shekyl_relay_privacy::derive::derive_embargo;
    use shekyl_relay_privacy::full_travel_probability;
    use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
    use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
    use shekyl_relay_privacy::zone::RelayZone;

    // (beta, F') from `f_prime_against_tail_mass_at_the_measured_minimum`.
    const SWEEP: [(f64, u32); 7] = [
        (0.000, 3_500),
        (0.083, 4_250),
        (0.125, 4_250),
        (0.167, 4_500),
        (0.250, 4_500),
        (0.333, 4_750),
        (0.500, 5_000),
    ];

    let params_at = |f_prime: u32| DandelionParams {
        fluff_return_ms: f_prime,
        ..DandelionParams::adopted_for(RelayZone::Public)
    };

    for (beta_star, f_star) in [(0.250_f64, 4_500_u32), (0.333, 4_750), (0.500, 5_000)] {
        let fixed = derive_embargo(
            &params_at(f_star),
            DEFAULT_EMBARGO_TICK_MILLIS,
            EMBARGO_FULL_TRAVEL_PROBABILITY,
        )
        .expect("the target is reachable at every candidate")
        .mean_ticks;

        println!(
            "\n  region beta* = {beta_star:.3} (F' = {f_star} ms), embargo FIXED at {fixed} ticks"
        );
        println!("  beta     F' ms   alpha at the fixed embargo   miss vs 0.90");
        println!("  -----    -----   --------------------------   ------------");
        for (beta, f_prime) in SWEEP {
            let a =
                full_travel_probability(&params_at(f_prime), fixed, DEFAULT_EMBARGO_TICK_MILLIS);
            let outside = if beta > beta_star { " <- OUTSIDE" } else { "" };
            println!(
                "  {beta:.3}    {f_prime:5}   {a:26.6}   {:+.6}{outside}",
                a - EMBARGO_FULL_TRAVEL_PROBABILITY
            );
        }

        // At the boundary itself the invariant must hold — that is what
        // `derive_embargo` solved for, and a failure here means the fixed
        // embargo was taken from the wrong row.
        let at_boundary =
            full_travel_probability(&params_at(f_star), fixed, DEFAULT_EMBARGO_TICK_MILLIS);
        assert!(
            at_boundary >= EMBARGO_FULL_TRAVEL_PROBABILITY,
            "at its own boundary the region must meet the pinned target: got \
             {at_boundary} at F' = {f_star}"
        );

        // And outside it the invariant must actually be MISSED, or the region
        // bound is not doing any work and `beta` is not a design parameter at
        // all — the same vacuity trap the alpha gate's control exists to catch.
        let worst = full_travel_probability(&params_at(5_000), fixed, DEFAULT_EMBARGO_TICK_MILLIS);
        if f_star < 5_000 {
            assert!(
                worst < EMBARGO_FULL_TRAVEL_PROBABILITY,
                "beta* = {beta_star:.3} must be MISSED at the worst swept tail, else the \
                 bound constrains nothing: got {worst} at F' = 5000"
            );
        }

        // **The invariant, stated so it can be quoted and re-checked.** At the
        // chosen region this reads: the bound holds for 90 % of the A = 60
        // arm's observed samples, and where it does not, alpha degrades to no
        // worse than DEGRADED_FLOOR at the worst tail any arm has recorded.
        // "The miss is small" is not re-checkable and gets quoted without its
        // number; this does not.
        if (beta_star - 0.250).abs() < 1e-9 {
            /// The floor the chosen region commits to outside its own bound.
            const DEGRADED_FLOOR: f64 = 0.891;
            println!(
                "\n  INVARIANT at the chosen region: alpha >= {DEGRADED_FLOOR} at the worst \
                 recorded tail\n  (beta = 0.500, F' = 5000); measured {worst:.6}, against the \
                 pinned {EMBARGO_FULL_TRAVEL_PROBABILITY}."
            );
            assert!(
                worst >= DEGRADED_FLOOR,
                "the chosen region commits to alpha >= {DEGRADED_FLOOR} outside its bound; \
                 the worst recorded tail now reads {worst:.6}. Either a constant moved or \
                 the commitment must be restated at its true strength — it must not be \
                 quietly weakened to whatever the run produced"
            );
        }
    }
}

/// **`beta*` is a quantile of the measured series, not its mean.**
///
/// A region is a bound, so the statistic that sets it has to be a bound. §13.2
/// names the observation-level rate as the cross-arm statistic, and the `A = 60`
/// arm's eleven settled samples give a *series* — so the bound can be read off
/// it at the quantile matching the invariant being protected, rather than
/// chosen. At [`EMBARGO_FULL_TRAVEL_PROBABILITY`] = 0.90 the matching read is
/// the p90.
///
/// The `A = 15` arm cannot answer the same way: §14.2 records only the pooled
/// 52.1 % (86/165), not the per-sample series, so its beta has a mean and no
/// quantile. That is a recording gap, not a measurement gap — and it is the
/// concrete reason the young-network region cannot be set from what exists.
#[test]
fn beta_star_is_a_quantile_of_the_measured_series_not_its_mean() {
    /// §13.2's eleven settled samples: nodes at or above the floor, of 60.
    const AT_OR_ABOVE: [u32; 11] = [55, 52, 49, 54, 56, 54, 50, 49, 47, 50, 46];
    const FLEET: f64 = 60.0;

    let mut betas: Vec<f64> = AT_OR_ABOVE
        .iter()
        .map(|at| (FLEET - f64::from(*at)) / FLEET)
        .collect();
    let mean = betas.iter().sum::<f64>() / betas.len() as f64;
    betas.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a ratio of counts"));

    // Nearest-rank, the definition that keeps the answer inside the observed
    // set rather than interpolating a value no sample produced. The rank is
    // computed in integer arithmetic — a quantile index is a count, and
    // rounding it through f64 is how an off-by-one enters a bound silently.
    let nearest_rank = |q_num: usize, q_den: usize| -> f64 {
        let n = betas.len();
        let rank = (q_num * n).div_ceil(q_den).max(1).min(n);
        betas[rank - 1]
    };

    let p50 = nearest_rank(1, 2);
    let p90 = nearest_rank(9, 10);
    let max = *betas.last().expect("eleven samples");

    println!("\n  A = 60 below-floor tail, eleven settled samples (§13.2)");
    println!("  mean {mean:.4}   p50 {p50:.4}   p90 {p90:.4}   max {max:.4}");
    println!(
        "  the p90 is the read matching the pinned 0.90 invariant; on the sweep it \
         lands\n  between beta = 0.200 and 0.250, both of which read F' = 4500 ms."
    );

    // The point of the test: mean and p90 are DIFFERENT, so "which statistic"
    // is a real choice and not a distinction without a difference.
    assert!(
        p90 > mean,
        "p90 {p90} must exceed the mean {mean} for a right-skewed tail — if these \
         coincide, reading a bound off the mean was harmless here and this test is \
         asserting nothing"
    );
    // And the quantile must not be read as covering the worst sample: it does
    // not, by construction, which is exactly what a p90 bound means.
    assert!(
        p90 <= max,
        "a p90 cannot exceed the observed maximum: {p90} against {max}"
    );
}

/// **The region and §15's launch condition are the same condition, and neither
/// section says so.**
///
/// `beta* = 0.2167` was picked as the statistic-matched read of the `A = 60`
/// series, on its own merits. It also lands exactly where §15's sweep does, and
/// that coupling is load-bearing but recorded nowhere:
///
/// | arm | at-or-above floor | mean `beta` | vs region |
/// | --- | --- | --- | --- |
/// | `A = 15` (§14.2) | 52.1 % | 0.479 | **outside** |
/// | `A = 30` (§15.1) | 84.2 % | 0.158 | inside |
/// | `A = 60` (§13.2) | 85.2 % | 0.148 (p90 0.217) | inside |
///
/// §15's operational reading is **~30 anonymity-capable nodes**, and `A = 15`
/// is the state below it. So the region does not fail to cover a state the
/// network will be in — it declines to cover a state §15 says the network
/// should not launch in. The two are consistent by construction, which is a
/// better answer to the young-network worry than the recording gap is.
///
/// **The obligation this creates runs both ways**, and it is the reason this
/// test exists rather than a comment: a future reader who relaxes the launch
/// condition below ~30 is also invalidating `F'`, and nothing in §15 or §90
/// currently tells them. Registered in `FOLLOWUPS.md` for the doc side; armed
/// here so the numeric half fails rather than drifts.
///
/// # What this test deliberately does NOT claim
///
/// `beta*` is a **p90**; the comparisons for `A = 15` and `A = 30` are against
/// **means**, because §14.2 and §15.1 recorded only pooled aggregates. Only
/// `A = 60` (§13.2) published a per-sample series. The like-for-like check at
/// the launch figure is therefore unavailable — and `A = 30`'s mean tail
/// (0.158) is marginally *worse* than `A = 60`'s (0.148), so its p90 cannot be
/// assumed to sit under `A = 60`'s. That gap is the instrument fix registered
/// in `FOLLOWUPS.md`, not something to argue around here.
#[test]
fn the_region_is_consistent_with_the_launch_condition() {
    /// The chosen region bound: `A = 60`'s p90, from
    /// `beta_star_is_a_quantile_of_the_measured_series_not_its_mean`.
    const BETA_STAR: f64 = 0.2167;
    /// (`A`, at-or-above-floor rate) as §14.2 / §15.1 / §13.2 record them.
    const ARMS: [(u32, f64); 3] = [(15, 0.521), (30, 0.842), (60, 0.852)];
    /// §15's operational launch reading, in anonymity-capable nodes.
    const LAUNCH_A: u32 = 30;

    println!("\n  region (beta* = {BETA_STAR:.4}) against §15's sweep");
    println!("  A     at-floor   mean beta   vs region");
    println!("  ---   --------   ---------   ---------");
    for (a, at_floor) in ARMS {
        let beta = 1.0 - at_floor;
        let inside = beta <= BETA_STAR;
        println!(
            "  {a:3}   {:7.1} %   {beta:9.4}   {}",
            at_floor * 100.0,
            if inside { "inside" } else { "OUTSIDE" }
        );
    }

    // Every arm at or above the launch condition must sit inside the region:
    // if one did not, the region would be rejecting a network state the launch
    // condition explicitly permits, and F' would be under-provisioned for a
    // supported configuration.
    for (a, at_floor) in ARMS {
        if a >= LAUNCH_A {
            let beta = 1.0 - at_floor;
            assert!(
                beta <= BETA_STAR,
                "A = {a} is at or above the launch condition ({LAUNCH_A}) but its mean \
                 tail {beta:.4} falls OUTSIDE the region {BETA_STAR:.4} — the region \
                 rejects a state the launch condition permits, so F' is under-provisioned \
                 for a supported network"
            );
        }
    }

    // And the arm below the launch condition must sit outside it — otherwise
    // the region is not the launch condition's counterpart at all, and the
    // coupling this test exists to pin is a coincidence of one revision.
    let (below_a, below_at_floor) = ARMS[0];
    assert!(
        below_a < LAUNCH_A,
        "the sweep's smallest arm must be below the launch condition for this test \
         to have a negative side; got A = {below_a} against {LAUNCH_A}"
    );
    assert!(
        1.0 - below_at_floor > BETA_STAR,
        "A = {below_a} is below the launch condition, so its tail {:.4} must fall \
         OUTSIDE the region {BETA_STAR:.4}. If it does not, the region covers a state \
         §15 says not to launch in, and the two conditions are unrelated rather than \
         coupled",
        1.0 - below_at_floor
    );
}
