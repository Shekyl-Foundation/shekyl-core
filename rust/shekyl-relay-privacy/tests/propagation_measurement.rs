// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The measurement PR-1 exists to produce: what do the inherited Dandelion++
//! parameters actually deliver, and would deriving them change anything?
//!
//! Run with output visible:
//!
//! ```text
//! cargo test -p shekyl-relay-privacy --all-features --test propagation_measurement -- --nocapture
//! ```
//!
//! Every number below is measured, not asserted from the paper. The assertions
//! are deliberately loose bands around the measured values — they exist to
//! catch a regression in the instrument, not to re-state the finding.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::{
    coefficient_of_variation, inference_precision, residual_masses, simulate_fluff_return,
    simulate_propagation, solve_embargo_secs_for_target, FloodParams, PropagationSummary,
};
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::{derive_embargo, full_travel_probability, GeometricTable, PoissonTable};
use shekyl_relay_privacy::{EmbargoDistribution, EmbargoTimer, SplitMix64};

const TRIALS: usize = 200_000;

fn row(label: &str, embargo_secs: u32, s: &PropagationSummary) {
    row_ticked(label, embargo_secs, DEFAULT_EMBARGO_TICK_MILLIS, s);
}

fn row_ticked(label: &str, embargo_secs: u32, tick_ms: u64, s: &PropagationSummary) {
    println!(
        "{label:<28} {embargo_secs:>7}s {tick_ms:>6}ms {:>9.2} {:>12.0}ms {:>12}ms {:>13.4} {:>12.4}",
        s.mean_stem_hops,
        s.mean_natural_fluff_ms,
        s.p99_natural_fluff_ms,
        s.full_travel_rate,
        s.preemption_rate,
    );
}

fn header(title: &str) {
    println!("\n{title}");
    println!(
        "{:<28} {:>8} {:>8} {:>9} {:>14} {:>14} {:>13} {:>12}",
        "parameter set",
        "embargo",
        "tick",
        "hops",
        "mean fluff",
        "p99 fluff",
        "full-travel",
        "preempted"
    );
    println!("{}", "-".repeat(112));
}

/// The headline comparison, three configurations:
///
/// 1. what the daemon ships — 39 s, Poisson;
/// 2. the same distribution with the mean corrected to what the formula
///    yields — 17 s, Poisson;
/// 3. what the derivation actually describes — 17 s, memoryless.
///
/// Isolating the two variables separately is the point: correcting the
/// constant alone does not fix the mechanism.
#[test]
fn inherited_versus_derived_versus_paper_faithful_embargo() {
    let params = DandelionParams::inherited();
    let derived_secs = params.average_embargo_secs();

    header("Dandelion++ embargo, three configurations (q=20%, hop=175ms)");

    // RD-3: every row states its tick. The Poisson rows run at the whole
    // second `crypto::random_poisson_seconds` gives; the memoryless rows are
    // shown at BOTH one second and 250ms so the distribution fix (D-1) is
    // never conflated with the granularity fix (D-4).
    let mut rng = SplitMix64::new(0xD11D_2026);
    let inherited = simulate_propagation(&params, &EmbargoTimer::inherited(), TRIALS, &mut rng);
    row_ticked(
        "shipped: 39s Poisson",
        DandelionParams::INHERITED_EMBARGO_SECS,
        1_000,
        &inherited,
    );

    let mut rng = SplitMix64::new(0xD11D_2026);
    let derived = simulate_propagation(&params, &EmbargoTimer::derived(&params), TRIALS, &mut rng);
    row_ticked("constant fixed: 17s Poisson", derived_secs, 1_000, &derived);

    // Distribution changed, granularity held at the inherited whole second.
    let mut rng = SplitMix64::new(0xD11D_2026);
    let memoryless_1s = simulate_propagation(
        &params,
        &EmbargoTimer::geometric_with_tick(derived_secs, 1_000),
        TRIALS,
        &mut rng,
    );
    row_ticked(
        "17s memoryless (tick held)",
        derived_secs,
        1_000,
        &memoryless_1s,
    );

    // Then, additionally, the granularity fix.
    let mut rng = SplitMix64::new(0xD11D_2026);
    let faithful = simulate_propagation(
        &params,
        &EmbargoTimer::paper_faithful(&params),
        TRIALS,
        &mut rng,
    );
    row_ticked(
        "17s memoryless + fine tick",
        derived_secs,
        DEFAULT_EMBARGO_TICK_MILLIS,
        &faithful,
    );

    println!("\n  target full-travel probability (1 - ep): {EMBARGO_FULL_TRAVEL_PROBABILITY:.4}");
    for (label, s) in [
        ("shipped                   ", &inherited),
        ("constant fixed            ", &derived),
        ("memoryless, tick held     ", &memoryless_1s),
        ("memoryless + fine tick    ", &faithful),
    ] {
        println!(
            "  {label} full-travel {:.4}  (target {:+.4})",
            s.full_travel_rate,
            s.full_travel_rate - EMBARGO_FULL_TRAVEL_PROBABILITY
        );
    }
    println!(
        "\n  Both Poisson rows sit at ~1.0000 — the embargo effectively never\n  \
         fires. It is dimensioned against a stem that finishes in {:.0}ms on\n  \
         average and {}ms at p99, so a near-deterministic {}s or {}s timer is\n  \
         not a backstop, it is a formality.\n\n  \
         Rows three and four separate the two fixes (RD-3). Changing the\n  \
         distribution alone, at the inherited whole-second tick, moves\n  \
         full-travel {:.4} -> {:.4}: that is D-1 doing essentially all the\n  \
         work. Adding the finer tick moves it a further {:+.4}, which is D-4\n  \
         being a fidelity refinement rather than a mechanism change.\n\n  \
         All three corrected rows sit below the {:.2} target because the\n  \
         embargo is still at the closed form's 17s — see the RD-1 and exact\n  \
         derivation tables for what the mean actually needs to be.",
        derived.mean_natural_fluff_ms,
        derived.p99_natural_fluff_ms,
        derived_secs,
        DandelionParams::INHERITED_EMBARGO_SECS,
        derived.full_travel_rate,
        memoryless_1s.full_travel_rate,
        faithful.full_travel_rate - memoryless_1s.full_travel_rate,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    );

    // Finding 1: the constant is 2.3x its derivation.
    assert_eq!(derived_secs, 17);
    assert_eq!(DandelionParams::INHERITED_EMBARGO_SECS, 39);
    assert!((2.2..2.4).contains(&params.inherited_embargo_ratio()));

    // Finding 2: correcting the constant changes nothing measurable, because
    // the distribution — not the mean — is what disabled the backstop.
    assert!(
        (inherited.full_travel_rate - derived.full_travel_rate).abs() < 0.001,
        "shipped {:.4} vs constant-fixed {:.4}: the 2.3x correction should be \
         invisible under Poisson",
        inherited.full_travel_rate,
        derived.full_travel_rate
    );
    assert!(
        inherited.preemption_rate < 0.001 && derived.preemption_rate < 0.001,
        "a Poisson embargo at these means should essentially never fire"
    );

    // The memoryless draw is the one that actually exercises the target.
    assert!(
        faithful.preemption_rate > derived.preemption_rate,
        "memoryless embargo must be able to fire early: {:.4} vs {:.4}",
        faithful.preemption_rate,
        derived.preemption_rate
    );

    // Finding 3: under the distribution the formula assumes, the formula's own
    // answer *misses* its own target. Substituting E[K] into an expression in
    // K(K-1) under-provisions, because the realized stem length is geometric
    // and E[K(K-1)] is twice E[K](E[K]-1).
    assert!(
        faithful.full_travel_rate < EMBARGO_FULL_TRAVEL_PROBABILITY,
        "expected the closed-form embargo to under-provision under a memoryless \
         draw; measured {:.4} against target {EMBARGO_FULL_TRAVEL_PROBABILITY:.2}",
        faithful.full_travel_rate
    );

    // The embargo is a backstop, not a router: none of the three moves the
    // stem-length distribution. Same seed, same walk.
    assert!(
        (inherited.mean_stem_hops - derived.mean_stem_hops).abs() < 0.05
            && (derived.mean_stem_hops - faithful.mean_stem_hops).abs() < 0.05,
        "embargo choice must not move the stem-length distribution"
    );
}

/// The analytic derivation and the Monte-Carlo simulator are two independent
/// implementations of the same quantity. Agreement is the strongest evidence
/// either is right; disagreement means one of them is lying and the design
/// round is being fed a number nobody checked.
///
/// This caught a real bug during development: the survival sum accumulates
/// `S(h) = S(h-1) + ceil(h*hop/tick)`, and a first draft *differenced* the
/// slack instead of accumulating it. That understated the exponent and
/// inflated the derived survival — invisible against the closed form it was
/// replacing, obvious against the simulator.
#[test]
fn analytic_derivation_agrees_with_the_simulator() {
    let params = DandelionParams::inherited();
    let tick = DEFAULT_EMBARGO_TICK_MILLIS;

    println!("\nAnalytic survival equation vs. simulator (q=20%, hop=175ms, tick=250ms)");
    println!(
        "{:<16} {:>14} {:>14} {:>12}",
        "mean @ tick", "analytic", "simulated", "delta"
    );
    println!("{}", "-".repeat(60));

    // RD-3: sweep the tick as well as the mean. The original cross-check only
    // asserted at 250ms, so a tick-dependent divergence — exactly where a
    // fire-vs-disarm boundary convention would surface — had nothing watching
    // it. Verified at 6M trials: agreement holds within +/-1 sigma at every
    // tick from 1000ms down to 50ms.
    for (mean_secs, tick) in [
        (10_u32, tick),
        (17, tick),
        (30, tick),
        (60, tick),
        (17, 1_000_u64),
        (17, 500),
        (17, 125),
        (17, 50),
    ] {
        let mean_ticks = u32::try_from(u64::from(mean_secs) * 1_000 / tick).expect("fits");
        let analytic = full_travel_probability(&params, mean_ticks, tick);

        let embargo = EmbargoTimer::geometric_with_tick(mean_secs, tick);
        let mut rng = SplitMix64::new(0xA11A_0000 + u64::from(mean_secs));
        let simulated = simulate_propagation(&params, &embargo, TRIALS, &mut rng).full_travel_rate;

        let delta = (analytic - simulated).abs();
        println!(
            "{:<16} {analytic:>14.4} {simulated:>14.4} {delta:>12.4}",
            format!("{mean_secs}s @ {tick}ms")
        );

        // Monte-Carlo standard error at this trial count is ~0.0008; 0.01 is a
        // generous band that still catches a structural disagreement.
        assert!(
            delta < 0.01,
            "analytic {analytic:.4} and simulated {simulated:.4} disagree at {mean_secs}s @ {tick}ms"
        );
    }
}

/// The number the design adopts: solved exactly from the survival equation
/// rather than taken from a closed form that does not describe the system.
#[test]
fn derived_embargo_replaces_the_closed_form() {
    let params = DandelionParams::inherited();

    println!("\nEmbargo: closed form vs. exact derivation vs. the inherited constant");
    println!("{}", "-".repeat(72));

    let closed_form = params.average_embargo_secs();
    let derived = derive_embargo(
        &params,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("target is reachable");

    let simulated = solve_embargo_secs_for_target(
        &params,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
        EmbargoDistribution::Geometric,
        40_000,
        0xC0FF_EE00,
    )
    .expect("target is reachable");

    println!("  closed form (paper, plug-in k)     : {closed_form:>5}s");
    println!(
        "  exact derivation (adopted)         : {:>5}s  ({} ticks @ {}ms, achieves {:.4})",
        derived.mean_secs(),
        derived.mean_ticks,
        derived.tick_millis,
        derived.achieved
    );
    println!("  simulator cross-check              : {simulated:>5}s");
    println!(
        "  inherited #define                  : {:>5}s",
        DandelionParams::INHERITED_EMBARGO_SECS
    );
    println!(
        "\n  The closed form under-provisions: it substitutes E[K] into an\n  \
         expression in K(K-1), and for a geometric stem length\n  \
         E[K(K-1)] = 2*E[K]*(E[K]-1) exactly — before Jensen is even reached,\n  \
         since the quantity wanted is E[exp(-c*K(K-1))], not exp(-c*E[K(K-1)]).\n  \
         No constant correction factor fixes that; the exact solve does.\n\n  \
         The inherited 39s lands near the right answer by way of a\n  \
         logarithm-base error rather than this correction, and is paired with a\n  \
         distribution under which the timer barely fires at all. Two wrongs\n  \
         approximately cancelling is not a derivation."
    );

    assert!(
        derived.achieved >= EMBARGO_FULL_TRAVEL_PROBABILITY,
        "derived embargo achieves only {:.4}",
        derived.achieved
    );
    assert!(
        derived.mean_secs() > closed_form,
        "exact derivation {}s did not exceed the closed form {closed_form}s",
        derived.mean_secs()
    );
    // Two independent solvers must agree proportionally. An absolute band
    // would be wrong at both ends: the simulator bisects on a Monte-Carlo
    // estimate, so its resolution scales with the answer.
    let gap = (f64::from(derived.mean_secs()) - f64::from(simulated)).abs();
    let tolerance = f64::from(derived.mean_secs()) * 0.05;
    assert!(
        gap <= tolerance,
        "exact derivation {}s and simulator {simulated}s disagree by {gap}s (>{tolerance:.1}s)",
        derived.mean_secs()
    );
}

/// The embargo's timer granularity, which the inherited code fixes at one
/// whole second without discussion.
#[test]
fn embargo_tick_granularity_matters() {
    let params = DandelionParams::inherited();
    let mean = params.average_embargo_secs();

    println!("\nEmbargo tick granularity (memoryless, mean={mean}s, q=20%, hop=175ms)");
    println!(
        "{:<28} {:>8} {:>9} {:>14} {:>14} {:>13} {:>12}",
        "tick", "embargo", "hops", "mean fluff", "p99 fluff", "full-travel", "preempted"
    );
    println!("{}", "-".repeat(104));

    let mut rates = Vec::new();
    for tick in [1_000_u64, 500, 250, 125, 50] {
        let embargo = EmbargoTimer::geometric_with_tick(mean, tick);
        assert!(
            !embargo.is_truncated(),
            "tick {tick}ms produced a clipped table — the measurement would be biased"
        );
        let mut rng = SplitMix64::new(0x71C4_0000 + tick);
        let s = simulate_propagation(&params, &embargo, TRIALS / 4, &mut rng);
        row(&format!("tick = {tick}ms"), mean, &s);
        rates.push((tick, s.full_travel_rate));
    }

    println!(
        "\n  A whole-second tick — what `crypto::random_poisson_seconds` gives —\n  \
         floors every sub-second embargo to zero, so a share of the measured\n  \
         preemption is rounding rather than mechanism. The stem it guards\n  \
         completes in ~700ms. Granularity is a parameter here, and the\n  \
         inherited code does not treat it as one."
    );

    // Finer ticks must be monotonically less preemptive: the coarse tick is
    // manufacturing early fires, not discovering them.
    for w in rates.windows(2) {
        assert!(
            w[1].1 >= w[0].1 - 0.002,
            "tick {}ms gave {:.4}, finer tick {}ms gave {:.4} — expected convergence upward",
            w[0].0,
            w[0].1,
            w[1].0,
            w[1].1
        );
    }
    assert!(
        rates.last().unwrap().1 - rates[0].1 > 0.02,
        "granularity should move the result materially: {:.4} -> {:.4}",
        rates[0].1,
        rates.last().unwrap().1
    );
}

/// What the fluff probability actually buys. This is the parameter the
/// inherited tree freezes at 20% with no recorded derivation, and it drives
/// both the anonymity set (stem length) and the broadcast latency.
#[test]
fn fluff_probability_trade_curve() {
    header("Fluff probability sweep (hop=175ms, embargo derived per row)");

    let mut rows = Vec::new();
    for pct in [5_u32, 10, 12, 20, 25, 33, 50] {
        let params = DandelionParams {
            fluff_probability_pct: pct,
            ..DandelionParams::inherited()
        };
        let poisson = EmbargoTimer::derived(&params);
        let secs = poisson.mean_secs();

        let mut rng = SplitMix64::new(0x5EED_0000 + u64::from(pct));
        let p = simulate_propagation(&params, &poisson, TRIALS / 4, &mut rng);
        row(&format!("q = {pct}%  Poisson"), secs, &p);

        let mut rng = SplitMix64::new(0x5EED_0000 + u64::from(pct));
        let g = simulate_propagation(
            &params,
            &EmbargoTimer::paper_faithful(&params),
            TRIALS / 4,
            &mut rng,
        );
        row(&format!("q = {pct}%  memoryless"), secs, &g);

        rows.push((pct, p, g));
    }

    println!(
        "\n  Longer stems (small q) mean a larger anonymity set and a longer\n  \
         embargo, because Tbase scales with k(k-1). The inherited q=20% sits at\n  \
         the permissive end of the paper's own <=0.2 recommendation.\n\n  \
         Two things to read off this table.\n\n  \
         The Poisson rows sit at 1.0000 almost everywhere. That is not the\n  \
         design working — it is the backstop failing to exist. A near-\n  \
         deterministic timer at 17s or 316s never fires against a stem that\n  \
         finishes in under four seconds.\n\n  \
         The memoryless rows sit near 0.85 at *every* q, never reaching the\n  \
         0.90 they were solved for. The shortfall is flat because the error is\n  \
         structural, not q-specific: E[K(K-1)] approaches 2*E[K]*(E[K]-1) for a\n  \
         geometric stem length regardless of q, so the closed form\n  \
         under-provisions by roughly the same factor across the whole sweep."
    );

    // Lowering the fluff probability must lengthen the stem — the basic
    // coupling, checked so the sweep is known to be exercising something.
    for w in rows.windows(2) {
        let (lo_pct, lo, _) = &w[0];
        let (hi_pct, hi, _) = &w[1];
        assert!(
            lo.mean_stem_hops > hi.mean_stem_hops,
            "q={lo_pct}% gave {:.2} hops, q={hi_pct}% gave {:.2} — expected monotone decrease",
            lo.mean_stem_hops,
            hi.mean_stem_hops
        );
    }

    // Finding 2, as a regression guard: a Poisson embargo essentially never
    // fires anywhere in the useful range of q.
    for (pct, p, _) in &rows {
        if *pct <= 20 {
            assert!(
                p.preemption_rate < 0.001,
                "q={pct}%: Poisson embargo fired at {:.4} — expected effectively never",
                p.preemption_rate
            );
        }
    }

    // Finding 3, as a regression guard: the closed form under-provisions at
    // every q. If someone later "fixes" this by loosening the target, this is
    // what tells them they deleted the evidence.
    let shortfalls: Vec<f64> = rows
        .iter()
        .map(|(_, _, g)| EMBARGO_FULL_TRAVEL_PROBABILITY - g.full_travel_rate)
        .collect();
    assert!(
        shortfalls.iter().all(|s| *s > 0.0),
        "expected the closed form to under-provision at every q; shortfalls {shortfalls:?}"
    );
    // Before RD-1 this shortfall was near-constant in q, because the F-3 error
    // is a fixed factor. Counting the fluff-return term breaks that: the
    // return trip is a *fixed time* added to every node's window, so it costs
    // proportionally more when stems are short. The direction is the invariant
    // worth pinning; the magnitude is reported rather than bounded tightly.
    let spread = shortfalls.iter().copied().fold(f64::MIN, f64::max)
        - shortfalls.iter().copied().fold(f64::MAX, f64::min);
    assert!(
        spread < 0.60,
        "shortfall spread {spread:.4} is implausibly wide — check the model"
    );
    println!("  (shortfall is now q-dependent, spread {spread:.4} — RD-1 effect)");
    println!(
        "\n  Memoryless shortfall below target across the sweep: {:.4} .. {:.4}",
        shortfalls.iter().copied().fold(f64::MAX, f64::min),
        shortfalls.iter().copied().fold(f64::MIN, f64::max),
    );
}

/// The hop-latency input the whole embargo derivation rests on, and which the
/// inherited tree carries only inside a code comment ("a recent Intel laptop
/// took ~80ms ... 175ms is the fudge factor"). If real hop latency is worse
/// than assumed, the embargo is too short and preemption rises.
#[test]
fn embargo_sensitivity_to_hop_latency_assumption() {
    header("Embargo derived at hop=175ms, exercised against real hop latencies");

    let assumed = DandelionParams::inherited();
    let embargo = EmbargoTimer::derived(&assumed);
    let embargo_secs = embargo.mean_secs();

    let mut degraded = Vec::new();
    for actual_hop_ms in [175_u32, 250, 350, 500, 750, 1_000] {
        let params = DandelionParams {
            time_between_hop_ms: actual_hop_ms,
            ..assumed
        };
        let mut rng = SplitMix64::new(0x0B0B_1234_u64.wrapping_add(u64::from(actual_hop_ms)));
        let s = simulate_propagation(&params, &embargo, TRIALS / 4, &mut rng);
        row(&format!("actual hop = {actual_hop_ms}ms"), embargo_secs, &s);
        degraded.push((actual_hop_ms, s));
    }

    println!(
        "\n  The embargo is fixed at derivation time but the network is not. A\n  \
         hop-latency assumption that is too optimistic silently converts into\n  \
         premature fluffing — transactions cut short of their stem. This is the\n  \
         sensitivity the design round needs a real measurement for; 175ms is a\n  \
         2019 comment about a laptop, not a Shekyl network observation."
    );

    // Preemption must rise monotonically as reality departs from the
    // assumption — if it does not, the instrument is not measuring what it
    // claims to.
    for w in degraded.windows(2) {
        assert!(
            w[1].1.preemption_rate >= w[0].1.preemption_rate,
            "preemption did not rise with hop latency: {:?} -> {:?}",
            w[0],
            w[1]
        );
    }
    // At the assumed latency the design target must hold.
    assert!(degraded[0].1.full_travel_rate >= EMBARGO_FULL_TRAVEL_PROBABILITY);
}

/// The fluff-delay defect, measured as the attack it enables.
///
/// The embargo is a rare backstop. *This* delay is applied by every node to
/// every transaction, and its whole job is to break the link between when a
/// node received a transaction and when it relayed it. The inherited draw is
/// `std::poisson_distribution`; the Bitcoin Core timer its comment cites
/// (`PoissonNextSend`) is an exponential inter-arrival. Same name, different
/// distribution, and the difference is the entire cover.
#[test]
fn fluff_delay_inference_resistance() {
    println!("\nFluff-delay inversion: P(adversary pins receipt time to within ±w)");
    println!(
        "{:<34} {:>7} {:>12} {:>12} {:>12}",
        "delay draw", "CV", "±0.25s", "±0.5s", "±1s"
    );
    println!("{}", "-".repeat(82));

    let lambda = shekyl_relay_privacy::params::inherited::FLUFF_AVERAGE_IN_QUARTER_SECS;
    let poisson = PoissonTable::new(lambda).masses();
    let geometric = GeometricTable::new(lambda).masses();

    // Windows in quarter-second ticks.
    let windows = [1_u64, 2, 4];
    let row = |label: &str, masses: &[u64]| {
        let cv = coefficient_of_variation(masses);
        let p: Vec<f64> = windows
            .iter()
            .map(|w| inference_precision(masses, *w))
            .collect();
        println!(
            "{label:<34} {cv:>7.3} {:>12.4} {:>12.4} {:>12.4}",
            p[0], p[1], p[2]
        );
        (cv, p)
    };

    let (poisson_cv, poisson_p) = row("inherited: Poisson lambda=20", &poisson);
    let (geometric_cv, geometric_p) = row("memoryless: geometric mean=20", &geometric);

    println!(
        "\n  Both draws have the same 5s mean. Under the inherited Poisson an\n  \
         adversary who subtracts a fixed offset lands within half a second of\n  \
         the true receipt time {:.0}% of the time; under a memoryless delay of\n  \
         the same mean, {:.0}%. The ratio is a near-constant ~{:.2}x across\n  \
         every tolerance an adversary might pick, which is what you expect when\n  \
         the difference is the width of the distribution rather than an artifact\n  \
         of one window.\n\n  \
         This is not a tuning preference. The mechanism is randomized delay; a\n  \
         distribution with CV {:.2} is not providing randomized delay.\n\n  \
         Honest counterweight for the design round: the memoryless draw has its\n  \
         mode at zero, so a real share of relays go out almost immediately —\n  \
         the adversary's best single guess against it is \"barely delayed at\n  \
         all\". That is inherent to an exponential and Bitcoin Core accepts it,\n  \
         but a shifted/floored variant is a live option and this instrument is\n  \
         what should decide it.",
        poisson_p[1] * 100.0,
        geometric_p[1] * 100.0,
        poisson_p[1] / geometric_p[1],
        poisson_cv,
    );

    // The inherited Poisson is near-deterministic: 1/sqrt(20) ~ 0.224.
    assert!(
        (0.20..0.25).contains(&poisson_cv),
        "Poisson CV at lambda=20 should be ~0.22, got {poisson_cv}"
    );
    // The memoryless delay is genuinely dispersed.
    assert!(
        geometric_cv > 0.9,
        "geometric CV should be ~1, got {geometric_cv}"
    );

    // The attack is materially harder under the memoryless draw at every
    // tolerance, by a ratio that barely moves with the window. Bands are set
    // from the measurement, not from a guess about it.
    for (i, w) in windows.iter().enumerate() {
        let ratio = poisson_p[i] / geometric_p[i];
        assert!(
            (1.8..2.2).contains(&ratio),
            "window +/-{w} ticks: Poisson {:.4} vs geometric {:.4} (ratio {ratio:.2}) \
             outside the measured band",
            poisson_p[i],
            geometric_p[i]
        );
    }
    // Concretely: under the inherited draw, a half-second inversion succeeds
    // more than 40% of the time.
    assert!(
        poisson_p[1] > 0.40,
        "inherited draw: +/-0.5s inversion only {:.4}",
        poisson_p[1]
    );
    assert!(
        geometric_p[1] < 0.25,
        "memoryless draw: +/-0.5s inversion still {:.4}",
        geometric_p[1]
    );
}

/// **RD-1.** The fluff flood's return trip, and what counting it does to the
/// embargo.
///
/// The survival equation originally ended a stem node's exposure when the
/// terminal node *emitted* the fluff. The mechanism ends it when that fluff
/// *reaches* the node: `tx_pool.cpp` clears the embargo via
/// `upgrade_relay_method` on receipt, not on remote emission. Every edge of
/// the return flood carries a fluff delay, so the correction is not a detail.
///
/// It also exposes an interaction worth stating plainly: the return time
/// depends on the *fluff* distribution, so fixing F-4 substantially repairs
/// the gap that counting the return trip opens. First passage is a minimum
/// over parallel paths, and a minimum only helps when the paths differ.
#[test]
fn fluff_return_dominates_the_embargo_derivation() {
    println!("\nFluff-flood first passage back to an arbitrary node (512 nodes)");
    println!(
        "{:<34} {:>8} {:>10} {:>10}",
        "fluff delay on each edge", "peers", "mean", "p90"
    );
    println!("{}", "-".repeat(66));

    let mut inherited_p90 = 0_u64;
    let mut memoryless_p90 = 0_u64;
    for (label, dist) in [
        ("inherited: Poisson lambda=20", EmbargoDistribution::Poisson),
        (
            "memoryless: geometric mean=20",
            EmbargoDistribution::Geometric,
        ),
    ] {
        for peers in [4_usize, 8] {
            let mut rng = SplitMix64::new(0xF100_D000 + peers as u64);
            let s =
                simulate_fluff_return(FloodParams { nodes: 512, peers }, 20, dist, 24, &mut rng);
            println!(
                "{label:<34} {peers:>8} {:>9.0}ms {:>9}ms",
                s.mean_ms, s.p90_ms
            );
            if peers == 8 {
                match dist {
                    EmbargoDistribution::Poisson => inherited_p90 = s.p90_ms,
                    EmbargoDistribution::Geometric => memoryless_p90 = s.p90_ms,
                }
            }
        }
    }

    println!(
        "\n  F-5: the inherited Poisson makes the whole network's diffusion ~{:.1}x\n  \
         slower. First passage is a minimum over parallel paths, and under a\n  \
         near-deterministic delay every path costs the same, so the minimum\n  \
         buys nothing. This is a throughput consequence of the same defect as\n  \
         F-4, and it feeds straight back into the embargo below.",
        inherited_p90 as f64 / memoryless_p90 as f64
    );
    assert!(
        inherited_p90 > memoryless_p90 * 3,
        "expected the inherited draw to flood far slower: {inherited_p90}ms vs {memoryless_p90}ms"
    );

    println!("\nEmbargo required at the 0.90 target, as a function of the return term");
    println!(
        "{:<32} {:>10} {:>26}",
        "fluff return F", "embargo", "what 31s actually achieves"
    );
    println!("{}", "-".repeat(70));

    let uncorrected = DandelionParams {
        fluff_return_ms: 0,
        ..DandelionParams::inherited()
    };
    let base = derive_embargo(
        &uncorrected,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("reachable");
    println!(
        "{:<32} {:>9}s {:>26}",
        "0ms (RD-1 uncorrected)",
        base.mean_secs(),
        "-"
    );

    let mut corrected = None;
    for f in [500_u32, 1_500, 2_250, 4_250, 13_750] {
        let p = DandelionParams {
            fluff_return_ms: f,
            ..DandelionParams::inherited()
        };
        let d = derive_embargo(
            &p,
            DEFAULT_EMBARGO_TICK_MILLIS,
            EMBARGO_FULL_TRAVEL_PROBABILITY,
        )
        .expect("reachable");
        let at_old = full_travel_probability(&p, base.mean_ticks, DEFAULT_EMBARGO_TICK_MILLIS);
        println!(
            "{:<32} {:>9}s {:>26.4}",
            format!("{f}ms"),
            d.mean_secs(),
            at_old
        );
        if f == 2_250 {
            corrected = Some((d, at_old));
        }
    }
    let (adopted, old_achieves) = corrected.expect("2250ms row was measured");

    println!(
        "\n  At the measured p90 return of 2250ms the requirement moves {}s -> {}s,\n  \
         and the previously-derived {}s delivers only {old_achieves:.4} rather than\n  \
         0.9002. The old figure was a lower bound, and a loose one.\n\n  \
         This is a large liveness cost -- a black-holed transaction now sits\n  \
         undiffused for ~{}s -- which makes the 0.90-on-ANY-preemption target\n  \
         the binding assumption to re-examine, not the derivation. A preemption\n  \
         by the last stem node leaks far less than one by the first, and the\n  \
         equation currently weights them equally.",
        base.mean_secs(),
        adopted.mean_secs(),
        base.mean_secs(),
        adopted.mean_secs()
    );

    // The correction must be large and in the conservative direction.
    assert!(
        adopted.mean_secs() > base.mean_secs() * 3,
        "expected the return term to lengthen the embargo substantially: {}s -> {}s",
        base.mean_secs(),
        adopted.mean_secs()
    );
    assert!(
        (0.61..0.85).contains(&old_achieves),
        "the uncorrected embargo should land in the sketched 0.61..0.85 band, got {old_achieves:.4}"
    );
}

/// **RD-2.** Which delay *shape* to use, decided by the metric that can
/// actually distinguish them.
///
/// Raw inversion precision cannot: it is a maximum over sliding windows, so it
/// is shift-invariant by construction, and every "add a floor" variant scores
/// identically to its unshifted twin. Conditioning on arrival phase can,
/// because the inherited fluff timer is a re-armed batching flush and a
/// transaction arriving mid-window experiences the *residual* of a draw that
/// already survived that long.
#[test]
fn residual_inversion_decides_the_distribution_shape() {
    fn uniform_masses(max_ticks: usize) -> Vec<u64> {
        vec![u64::MAX / (max_ticks as u64 + 1); max_ticks + 1]
    }
    fn with_floor(masses: &[u64], floor: usize) -> Vec<u64> {
        let mut v = vec![0_u64; floor];
        v.extend_from_slice(masses);
        v
    }

    let geometric = GeometricTable::new(20).masses();
    let poisson = PoissonTable::new(20).masses();
    let uniform = uniform_masses(40); // U[0,40] ticks, same mean 20
    let pure_shift = with_floor(&GeometricTable::new(20).masses(), 8); // mean 28
    let budgeted = with_floor(&GeometricTable::new(12).masses(), 8); // mean 20

    println!("\nInversion precision (+/-0.5s) vs. arrival phase into the flush window");
    println!(
        "{:<40} {:>9} {:>9} {:>9} {:>9}",
        "delay draw", "phase 0", "phase 10", "phase 20", "phase 30"
    );
    println!("{}", "-".repeat(80));
    let at = |m: &[u64], phase: u64| inference_precision(&residual_masses(m, phase), 2);
    let row = |label: &str, m: &[u64]| {
        println!(
            "{label:<40} {:>9.4} {:>9.4} {:>9.4} {:>9.4}",
            at(m, 0),
            at(m, 10),
            at(m, 20),
            at(m, 30)
        );
    };
    row("memoryless geometric (mean 20)", &geometric);
    row("inherited Poisson (lambda 20)", &poisson);
    row("uniform U[0,40] (mean 20)", &uniform);
    row("floor 8 + geo20, PURE SHIFT (mean 28)", &pure_shift);
    row("floor 8 + geo12, FIXED BUDGET (mean 20)", &budgeted);

    println!(
        "\n  Read three things off this table.\n\n  \
         (1) Only the memoryless row is flat. That is the actual argument for\n  \
         D-3, and it is not 'geometric inverts worst' -- uniform beats it at\n  \
         phase 0 ({:.4} vs {:.4}). It is that the flush is re-armed, so a\n  \
         transaction's delay is the residual of an in-flight draw, and only the\n  \
         memoryless family makes the residual identical to the full draw. The\n  \
         headline number then describes every transaction rather than only one\n  \
         that arrived exactly at window start.\n\n  \
         (2) The inherited Poisson degrades catastrophically with phase --\n  \
         {:.4} at phase 30. A transaction arriving late in a Poisson window is\n  \
         almost perfectly invertible. F-4 is worse than its phase-0 number said.\n\n  \
         (3) A floor is dominated in both framings. As a pure shift it scores\n  \
         identically ({:.4}) and costs 8 ticks of latency for nothing -- every\n  \
         inversion metric is shift-invariant, so no measurement can prefer it.\n  \
         Held to the same mean budget it is measurably worse ({:.4} vs {:.4}),\n  \
         because the floor buys its offset by narrowing the random part.",
        at(&uniform, 0),
        at(&geometric, 0),
        at(&poisson, 30),
        at(&pure_shift, 0),
        at(&budgeted, 0),
        at(&geometric, 0),
    );

    // (1) Memorylessness: flat across every phase.
    let g0 = at(&geometric, 0);
    for phase in [5_u64, 10, 20, 30, 50] {
        assert!(
            (at(&geometric, phase) - g0).abs() < 1e-9,
            "geometric residual moved at phase {phase}: {} vs {g0}",
            at(&geometric, phase)
        );
    }
    // Uniform wins at phase 0 and loses by phase 30 -- the adversarial reading
    // of D-3, and its refutation, both pinned.
    assert!(
        at(&uniform, 0) < g0,
        "uniform should invert better at phase 0"
    );
    assert!(
        at(&uniform, 30) > g0 * 2.0,
        "uniform should degrade past geometric by phase 30: {:.4} vs {g0:.4}",
        at(&uniform, 30)
    );

    // (2) Poisson collapses with phase.
    assert!(
        at(&poisson, 30) > 0.9,
        "inherited Poisson at phase 30 should be near-fully invertible, got {:.4}",
        at(&poisson, 30)
    );

    // (3) A floor is dominated either way.
    assert!(
        (at(&pure_shift, 0) - g0).abs() < 1e-9,
        "a pure shift must be invisible to this metric: {:.4} vs {g0:.4}",
        at(&pure_shift, 0)
    );
    assert!(
        at(&budgeted, 0) > g0,
        "a floor at fixed mean must score worse: {:.4} vs {g0:.4}",
        at(&budgeted, 0)
    );
}

/// **Q-8, made decidable.** The preemption profile — *who* fluffs early, not
/// just how often — plus the leakage dot-product it feeds. Round 1 (the review)
/// found the drafted Q-8 premise had the gradient backwards; this test pins the
/// corrected picture in code.
#[test]
fn preemption_profile_answers_who_preempts() {
    use shekyl_relay_privacy::conformance::simulate_preemption_profile;
    use shekyl_relay_privacy::marginal_preemption_profile;

    let params = DandelionParams::inherited();
    let d = derive_embargo(
        &params,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("reachable");
    // Measured at the exact derived tick count, not the seconds-rounded one.
    let embargo = EmbargoTimer::geometric_from_ticks(d.mean_ticks, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut rng = SplitMix64::new(0x9E8_2026);
    let profile = simulate_preemption_profile(&params, &embargo, 400_000, &mut rng);
    let analytic = marginal_preemption_profile(&params, d.mean_ticks, DEFAULT_EMBARGO_TICK_MILLIS);

    println!(
        "\nPreemption profile at the adopted embargo ({} ticks / {:.1}s, q=20%)",
        d.mean_ticks,
        f64::from(d.mean_ticks) * DEFAULT_EMBARGO_TICK_MILLIS as f64 / 1000.0
    );
    println!(
        "{:<12} {:>12} {:>16} {:>18}",
        "separation", "first (share)", "marginal (sim)", "marginal (analytic)"
    );
    println!("{}", "-".repeat(62));
    for i in 0..7 {
        println!(
            "{i:<12} {:>12.3} {:>16.4} {:>18.4}",
            profile.first[i],
            profile.marginal[i],
            analytic.get(i).copied().unwrap_or(0.0)
        );
    }

    // The headline: the origin is the MODAL preempter, which is what inverts
    // the drafted premise. A leakage-weighted target is more stringent, not
    // less, because the leakage-dominant event is the likely one.
    assert_eq!(
        profile.modal_separation(),
        0,
        "origin should be the modal preempter"
    );
    assert!(
        (0.19..0.24).contains(&profile.first[0]),
        "origin share {:.3} outside the reproduced band",
        profile.first[0]
    );
    // Monotone decay away from the origin (separations 0..3, before the tail).
    for w in profile.first[..4].windows(2) {
        assert!(
            w[0] > w[1],
            "first-preempter profile should decay from the origin"
        );
    }
    // P(preempt) is 1 - full-travel, the existing analytic quantity.
    let full = full_travel_probability(&params, d.mean_ticks, DEFAULT_EMBARGO_TICK_MILLIS);
    assert!(
        (profile.p_preempt - (1.0 - full)).abs() < 0.003,
        "P(preempt) {:.4} should match 1 - full-travel {:.4}",
        profile.p_preempt,
        1.0 - full
    );

    // The analytic marginal profile cross-checks the simulator marginal — the
    // same analytic-vs-simulator discipline F and the survival equation use,
    // now on a per-position quantity.
    for (i, (sim, ana)) in profile
        .marginal
        .iter()
        .zip(analytic.iter())
        .take(6)
        .enumerate()
    {
        assert!(
            (sim - ana).abs() < 0.001,
            "separation {i}: analytic marginal {ana:.4} disagrees with sim {sim:.4}"
        );
    }

    // The leakage dot-product Q-8 will use. Baseline (no Dandelion) = every tx
    // fluffs at its origin, so leakage is measured as a fraction of w[0].
    let flat = profile.weighted_leakage(&[1.0]); // origin-only weight
    let origin_share_of_all = profile.p_preempt * profile.first[0];
    assert!(
        (flat - origin_share_of_all).abs() < 1e-9,
        "origin-only leakage should equal P(preempt) x first[0]"
    );
    println!(
        "\n  ~{:.1}% of ALL transactions fluff from their own origin node under\n  \
         the adopted target. That is the number Q-8 is about. A leakage weight\n  \
         w(i) turns the whole profile into one dot product; the origin-only\n  \
         value ({:.4}) is its lower anchor, the flat P(preempt) ({:.4}) its\n  \
         upper. Which target is right depends on an a-priori epsilon stated in\n  \
         a chosen w(i) — Q-8's first deliverable, not a swept number.",
        origin_share_of_all * 100.0,
        flat,
        profile.p_preempt
    );

    // A decaying weight sits strictly between the origin-only and flat anchors.
    let decayed = profile.weighted_leakage(&[1.0, 0.5, 0.25, 0.125, 0.0625, 0.03, 0.015]);
    assert!(
        flat < decayed && decayed < profile.p_preempt,
        "decaying-weight leakage {decayed:.4} should sit between origin-only {flat:.4} \
         and flat {:.4}",
        profile.p_preempt
    );
}

/// **Q-8 liveness reframing.** Black-hole recovery is the minimum over all
/// holders' memoryless timers, so a black hole after hop `j` recovers with mean
/// `M/(j+1)`. The headline 112 s mean applies only to a first-hop black hole,
/// where the origin holds alone — and that worst case is exactly what a
/// profile-reshaping knob (Q-8a) would protect.
#[test]
fn black_hole_recovery_scales_with_holder_count() {
    let params = DandelionParams::inherited();
    let d = derive_embargo(
        &params,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("reachable");
    let table = GeometricTable::new(d.mean_ticks);
    let tick_ms = DEFAULT_EMBARGO_TICK_MILLIS;

    println!(
        "\nBlack-hole recovery = min over (j+1) memoryless timers (mean {:.1}s)",
        f64::from(d.mean_ticks) * tick_ms as f64 / 1000.0
    );
    println!(
        "{:<18} {:>12} {:>12}",
        "black hole after", "mean (s)", "M/(j+1) (s)"
    );
    println!("{}", "-".repeat(44));

    let base_mean = f64::from(d.mean_ticks);
    let mut rng = SplitMix64::new(0xB1AC_0000);
    let n = 100_000;
    for j in [0_usize, 1, 2, 4] {
        // j+1 independent timers held simultaneously; recovery = the min.
        let mut sum = 0.0;
        let mut p90_samples: Vec<u64> = Vec::with_capacity(n);
        for _ in 0..n {
            let recover = (0..=j)
                .map(|_| table.draw(&mut rng))
                .min()
                .expect("non-empty");
            sum += recover as f64;
            p90_samples.push(recover);
        }
        let mean_s = sum / n as f64 * tick_ms as f64 / 1000.0;
        let predicted = base_mean / (j as f64 + 1.0) * tick_ms as f64 / 1000.0;
        println!(
            "{:<18} {mean_s:>12.1} {predicted:>12.1}",
            format!("hop {j}")
        );
        // Mean-of-min tracks M/(j+1) for the geometric (memoryless).
        assert!(
            (mean_s - predicted).abs() < predicted * 0.05 + 1.0,
            "j={j}: recovery mean {mean_s:.1}s should track M/(j+1) = {predicted:.1}s"
        );
        if j == 0 {
            p90_samples.sort_unstable();
            let p90_ticks = p90_samples[n * 90 / 100];
            let p90_s = p90_ticks as f64 * tick_ms as f64 / 1000.0;
            println!("  origin-alone (j=0) recovery p90 = {p90_s:.1}s (MIN_RELAY_TIME = 300s)");
            assert!(
                (315.0..350.0).contains(&p90_s),
                "origin-alone p90 {p90_s:.1}s outside the reproduced band"
            );
            // RD-4 pushed the embargo to 144 s, so the worst-case recovery p90
            // now *exceeds* MIN_RELAY_TIME rather than approaching it.
            assert!(
                p90_s > 300.0,
                "under RD-4 the origin-alone p90 should exceed MIN_RELAY_TIME"
            );
        }
    }
    println!(
        "\n  Typical recovery is several-fold faster than the 144s headline —\n  \
         only a first-hop black hole leaves the origin holding alone. The p90\n  \
         of that worst case (~331s) now *exceeds* MIN_RELAY_TIME (300s) after\n  \
         RD-4 lengthened the embargo, so RP-4 must reconcile the two timers when\n  \
         the embargo cut lands — a black-holed origin's first re-relay and its\n  \
         embargo recovery can now cross."
    );
}

/// **Round 2 — the binding channel is the black-hole attack, and the embargo
/// mean does not defend it.**
///
/// Building the passive-spy Δ instrument surfaced a correction to the review's
/// composition table: absent an actual black hole, an embargo fire that becomes
/// the first fluff must be a *small* draw (it has to beat the sub-second natural
/// completion), so C3 preemptions are redundant races at seconds scale, not
/// 112 s-late leaks. The genuinely leaky C3 is the adversary-triggered
/// black-hole attack — and there the decisive result is that the source
/// attribution is *mean-invariant*: lengthening the embargo raises only the
/// adversary's wait, never how often the forced fluff reveals the origin.
#[test]
fn black_hole_attack_leak_is_mean_invariant() {
    use shekyl_relay_privacy::conformance::{
        simulate_blackhole_attack, simulate_sighting_separability,
    };

    let params = DandelionParams::inherited();

    println!("\nBlack-hole attack: forced-fluff source attribution vs embargo mean (f=0.10)");
    println!(
        "{:<14} {:>18} {:>16}",
        "embargo (s)", "P(source=origin)", "adversary wait (s)"
    );
    println!("{}", "-".repeat(50));

    let mut origin_shares = Vec::new();
    let mut waits = Vec::new();
    for secs in [50_u32, 144, 300, 500] {
        let ticks = u32::try_from(u64::from(secs) * 1000 / DEFAULT_EMBARGO_TICK_MILLIS).unwrap();
        let embargo = EmbargoTimer::geometric_from_ticks(ticks, DEFAULT_EMBARGO_TICK_MILLIS);
        let mut rng = SplitMix64::new(0xB1AC_0000 + u64::from(secs));
        let o = simulate_blackhole_attack(&params, &embargo, 0.10, 200_000, &mut rng);
        println!(
            "{secs:<14} {:>18.4} {:>16.1}",
            o.source_is_origin,
            o.mean_wait_ms / 1000.0
        );
        origin_shares.push(o.source_is_origin);
        waits.push(o.mean_wait_ms);
    }

    // The leak is flat across a 10x embargo range: lengthening the embargo does
    // not defend the binding channel.
    let leak_spread = origin_shares.iter().copied().fold(f64::MIN, f64::max)
        - origin_shares.iter().copied().fold(f64::MAX, f64::min);
    assert!(
        leak_spread < 0.02,
        "black-hole attribution should be mean-invariant; spread was {leak_spread:.4}"
    );
    assert!(
        origin_shares[0] > 0.4,
        "the forced fluff should reveal the origin ~half the time, got {:.3}",
        origin_shares[0]
    );
    // The adversary's wait, by contrast, scales with the mean — it is the only
    // thing lengthening the embargo buys against this attack.
    assert!(
        waits[3] > waits[0] * 3.0,
        "adversary wait should scale with the embargo mean: {waits:?}"
    );

    println!(
        "\n  The attribution leak is flat (spread {leak_spread:.4}) across a 10x\n  \
         embargo range while the adversary's wait scales ~linearly. Lengthening\n  \
         the embargo does not defend C1×C3 — only a mechanism that stops\n  \
         producing a forced fluff (re-stem-on-embargo, Q-8a) reshapes this."
    );

    // The correction to the review's C3 magnitude: absent a black hole, the
    // preemptions are non-leaky races, not 112 s-late fluffs.
    let d = derive_embargo(
        &params,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("reachable");
    let embargo = EmbargoTimer::geometric_from_ticks(d.mean_ticks, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut rng = SplitMix64::new(0xC1C3);
    let sep = simulate_sighting_separability(&params, &embargo, 0.10, 200_000, &mut rng);
    println!(
        "\n  Passive-spy Δ (no black hole): natural p50 {}ms / p99 {}ms, embargo\n  \
         p50 {}ms — the two bands OVERLAP (misclass {:.3}), because a first-fluff\n  \
         embargo fire is a small draw, not a 112s-late one. C3 is a leak only\n  \
         when black-holed.",
        sep.natural_p50_ms, sep.natural_p99_ms, sep.embargo_p50_ms, sep.misclassification_rate
    );
    assert!(
        sep.embargo_p50_ms < 10_000,
        "absent a black hole, embargo fluffs are seconds-scale races, not late leaks"
    );
}

/// **Round 2 — π₀, the first-spy diffusion precision** the stem phase exists to
/// defend against, and the baseline the ε argument's leakage weights reference.
#[test]
fn first_spy_precision_rises_with_spy_fraction() {
    use shekyl_relay_privacy::conformance::{simulate_diffusion_first_spy, FloodParams};

    println!("\nπ₀: first-spy source-attribution precision (memoryless flood, 512 nodes, 8 peers)");
    println!("{:>6} {:>12} {:>18}", "f", "precision", "mean hops to spy");
    println!("{}", "-".repeat(38));

    let mut precisions = Vec::new();
    for (seed, f) in [(1_u64, 0.05_f64), (2, 0.10), (3, 0.20)] {
        let mut rng = SplitMix64::new(0x9100_0000 + seed);
        let p = simulate_diffusion_first_spy(
            FloodParams {
                nodes: 512,
                peers: 8,
            },
            20,
            EmbargoDistribution::Geometric,
            f,
            40_000,
            &mut rng,
        );
        println!(
            "{f:>6.2} {:>12.4} {:>18.2}",
            p.precision, p.mean_first_spy_hops
        );
        precisions.push(p.precision);
    }
    // More spies ⇒ the first spy is closer to the source ⇒ higher precision.
    for w in precisions.windows(2) {
        assert!(
            w[1] > w[0],
            "π₀ should rise with the spy fraction: {precisions:?}"
        );
    }
    println!(
        "\n  π₀ traces to the paper's ~0.3 accuracy under 30%-spy attacks; it is\n  \
         the diffusion-phase leakage the STEM exists to reduce, and it prices\n  \
         the source attribution of any fluff — natural, q-role, or forced."
    );
}

/// **The quantified clearnet-vs-Tor security delta** for this mechanism — the
/// number that lets the Tor recommendation rest on a measurement rather than on
/// "Tor is more private." Clearnet is the weakest allowable configuration (the
/// floor we must defend); Tor is the likely recommended one, and this shows
/// *what* it buys, anchored to `levin_notify.cpp:448` (fluff is outbound-only on
/// I2P/Tor).
#[test]
fn tor_collapses_the_supernode_diffusion_observer() {
    use shekyl_relay_privacy::conformance::{simulate_transport_observation, Transport};

    println!("\nSupernode diffusion observer: clearnet vs Tor (256 nodes, 8 peers)");
    println!(
        "{:>7} {:>10} {:>18} {:>14}",
        "dial φ", "transport", "observed fraction", "first-spy π₀"
    );
    println!("{}", "-".repeat(54));

    for phi_pct in [5_u64, 10, 30] {
        let phi = phi_pct as f64 / 100.0;
        let mut clear = SplitMix64::new(0x707 + phi_pct);
        let c = simulate_transport_observation(
            FloodParams {
                nodes: 512,
                peers: 8,
            },
            20,
            EmbargoDistribution::Geometric,
            phi,
            Transport::Clearnet,
            12_000,
            &mut clear,
        );
        let mut tor = SplitMix64::new(0x707 + phi_pct + 9973);
        let t = simulate_transport_observation(
            FloodParams {
                nodes: 512,
                peers: 8,
            },
            20,
            EmbargoDistribution::Geometric,
            phi,
            Transport::Anonymity,
            12_000,
            &mut tor,
        );
        println!(
            "{phi:>7.2} {:>10} {:>18.4} {:>14.4}",
            "clearnet", c.observed_fraction, c.first_spy_precision
        );
        println!(
            "{phi:>7.2} {:>10} {:>18.4} {:>14.4}",
            "tor/i2p", t.observed_fraction, t.first_spy_precision
        );

        // Clearnet: an inbound supernode sees essentially every fluff.
        assert!(
            c.observed_fraction > 0.9,
            "clearnet supernode should observe almost all fluffs, got {:.4}",
            c.observed_fraction
        );
        // Tor: structurally blind — fluff never traverses its inbound edges.
        assert!(
            t.observed_fraction < 1e-12,
            "the Tor supernode must observe nothing (outbound-only fluff), got {:.6}",
            t.observed_fraction
        );
        assert!(t.first_spy_precision < 1e-12);
    }

    // The precision the clearnet supernode achieves rises with its reach — the
    // paper's first-spy estimator, and the thing Tor takes to zero.
    let mut a = SplitMix64::new(1);
    let mut b = SplitMix64::new(2);
    let lo = simulate_transport_observation(
        FloodParams {
            nodes: 512,
            peers: 8,
        },
        20,
        EmbargoDistribution::Geometric,
        0.05,
        Transport::Clearnet,
        40_000,
        &mut a,
    );
    let hi = simulate_transport_observation(
        FloodParams {
            nodes: 512,
            peers: 8,
        },
        20,
        EmbargoDistribution::Geometric,
        0.30,
        Transport::Clearnet,
        40_000,
        &mut b,
    );
    assert!(
        hi.first_spy_precision > lo.first_spy_precision,
        "clearnet first-spy precision should rise with reach: {:.3} -> {:.3}",
        lo.first_spy_precision,
        hi.first_spy_precision
    );

    println!(
        "\n  The delta is stark and structural: a clearnet supernode observes\n  \
         every fluff and attributes the source with the paper's first-spy\n  \
         precision (~0.45 at a 30% attack); the same supernode over Tor observes\n  \
         NOTHING, because fluff never traverses its inbound edges\n  \
         (levin_notify.cpp:448). This is the measured additional security of the\n  \
         Tor configuration.\n\n  \
         Honest scope: Tor collapses the PASSIVE supernode/diffusion observer.\n  \
         It does NOT change the ACTIVE black-hole attack, which needs an on-path\n  \
         stem-SUCCESSOR (outbound) position — required on both transports and\n  \
         modelled transport-independently by simulate_blackhole_attack. So the\n  \
         Tor benefit is specifically the elimination of the cheap-inbound\n  \
         supernode, not a blanket improvement; the black-hole channel (and its\n  \
         mean-invariant leak) is unchanged."
    );
}

/// **Round 3 — the clearnet passive channel is real, mean-dependent, and zero
/// on Tor.** This is why ε (correct embargo provisioning) is a live lever for
/// clearnet origins, and why it is built rather than deferred: the frozen
/// default supports clearnet, so the channel is in scope by policy.
#[test]
fn passive_clearnet_leak_is_mean_dependent_and_zero_on_tor() {
    use shekyl_relay_privacy::conformance::{simulate_passive_neighbor_leak, Transport};

    let params = DandelionParams::inherited();

    println!("\nPassive inbound-neighbour leak vs embargo mean (supernode reach φ=0.10)");
    println!(
        "{:>11} {:>10} {:>12} {:>14}",
        "embargo (s)", "transport", "leak rate", "origin share"
    );
    println!("{}", "-".repeat(50));

    let mut clearnet_rates = Vec::new();
    for secs in [31_u32, 50, 144, 300, 500] {
        let ticks = u32::try_from(u64::from(secs) * 1000 / DEFAULT_EMBARGO_TICK_MILLIS).unwrap();
        let e = EmbargoTimer::geometric_from_ticks(ticks, DEFAULT_EMBARGO_TICK_MILLIS);

        let mut cr = SplitMix64::new(0x9A5 + u64::from(secs));
        let c = simulate_passive_neighbor_leak(
            &params,
            &e,
            0.10,
            Transport::Clearnet,
            200_000,
            &mut cr,
        );
        let mut tr = SplitMix64::new(0x9A5 + u64::from(secs) + 7919);
        let t = simulate_passive_neighbor_leak(
            &params,
            &e,
            0.10,
            Transport::Anonymity,
            200_000,
            &mut tr,
        );

        println!(
            "{secs:>11} {:>10} {:>12.5} {:>14.4}",
            "clearnet", c.leak_rate, c.origin_share_of_leaks
        );
        println!(
            "{secs:>11} {:>10} {:>12.5} {:>14.4}",
            "tor/i2p", t.leak_rate, t.origin_share_of_leaks
        );
        // Tor is structurally zero at every mean.
        assert!(
            t.leak_rate < 1e-12,
            "Tor passive leak must be structurally zero, got {:.6}",
            t.leak_rate
        );
        clearnet_rates.push((secs, c.leak_rate));
    }

    // Mean-dependence: the clearnet leak falls monotonically as the embargo
    // lengthens — the property that makes ε a live lever there.
    for w in clearnet_rates.windows(2) {
        assert!(
            w[1].1 < w[0].1,
            "clearnet leak should fall with embargo mean: {}s={:.5} then {}s={:.5}",
            w[0].0,
            w[0].1,
            w[1].0,
            w[1].1
        );
    }
    // Non-negligible at the adopted 144 s embargo — a real channel, not noise.
    let at_144 = clearnet_rates.iter().find(|(s, _)| *s == 144).unwrap().1;
    assert!(
        at_144 > 0.005,
        "the clearnet passive channel should be non-negligible at the adopted \
         embargo, got {at_144:.5}"
    );
    // The RD-1/RD-4 corrections already helped here: the 31 s (pre-correction)
    // rate is several times the 144 s (adopted) rate.
    let at_31 = clearnet_rates.iter().find(|(s, _)| *s == 31).unwrap().1;
    assert!(
        at_31 > at_144 * 3.0,
        "correct provisioning should have cut the passive leak severalfold: \
         31s={at_31:.5} vs 144s={at_144:.5}"
    );

    println!(
        "\n  The clearnet passive channel is REAL and mean-DEPENDENT: the leak\n  \
         rate falls with the embargo mean, so correct provisioning (ε) reduces\n  \
         it — a live lever on clearnet. It is structurally ZERO on Tor (fluff\n  \
         never traverses the supernode's inbound edges, levin_notify.cpp:448).\n\n  \
         Both levers are therefore live and neither substitutes for the other:\n  \
         ε defends the clearnet origin against THIS (passive, mean-dependent)\n  \
         channel; Q-8a reshape defends every origin against the black-hole\n  \
         (active, mean-invariant, transport-independent) channel. Round 3\n  \
         derives ε from an a-priori adversary-advantage bound — the instrument\n  \
         turns (δ,f,β,π₀) into a number but cannot choose δ, and choosing δ is\n  \
         the privacy decision."
    );
}
