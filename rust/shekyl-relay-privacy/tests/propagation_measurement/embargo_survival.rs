// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Measurement instruments — embargo_survival family.
//!
//! Part of the `propagation_measurement` suite. Run with `--nocapture` for tables.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::{
    simulate_fluff_return, simulate_propagation, solve_embargo_secs_for_target, FloodParams,
};
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::{derive_embargo, full_travel_probability};
use shekyl_relay_privacy::{DelayFamily, EmbargoTimer, SplitMix64};

use crate::common::{header, row, row_ticked, TRIALS};

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
    let derived_secs = params.closed_form_embargo_secs();

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
    let derived = simulate_propagation(
        &params,
        &EmbargoTimer::closed_form_poisson(&params),
        TRIALS,
        &mut rng,
    );
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
    // Re-pinned when F-7 raised `fluff_return_ms` to 3250: the extra second of
    // return time clips ~0.13 % off the 17 s Poisson's lower tail (measured
    // 1.0000 vs 0.9987, gap 0.0013). The rail sits snug against that
    // measurement (0.0015, ~15 % headroom on a seeded, deterministic run) so a
    // model drift the size the pre-F-7 rail caught still goes red. The finding
    // stands — the constant correction moves ~0.001 where the distribution
    // correction moves ~0.1, two orders apart.
    assert!(
        (inherited.full_travel_rate - derived.full_travel_rate).abs() < 0.0015,
        "shipped {:.4} vs constant-fixed {:.4}: the 2.3x correction should be \
         invisible under Poisson",
        inherited.full_travel_rate,
        derived.full_travel_rate
    );
    // Same F-7 re-pin as the invisibility bound above: the 17 s Poisson's
    // lower tail now clips ~0.13 % against the longer return (rail snug at
    // 0.0015).
    assert!(
        inherited.preemption_rate < 0.0015 && derived.preemption_rate < 0.0015,
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

    let closed_form = params.closed_form_embargo_secs();
    let derived = derive_embargo(
        &params,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("target is reachable");

    let simulated = solve_embargo_secs_for_target(
        &params,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
        DelayFamily::Geometric,
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
    let mean = params.closed_form_embargo_secs();

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
        let poisson = EmbargoTimer::closed_form_poisson(&params);
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
            // Re-pinned at F-7's longer return (measured 0.0015 at q=20%; the
            // rail sits snug at 0.0018, ~20 % headroom on a seeded run): still
            // "effectively never" against the ~10 % a working backstop needs,
            // same two-orders separation as Finding 2.
            assert!(
                p.preemption_rate < 0.0018,
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
    // Rail re-pinned at F-7: the fixed return term grew ~44 %, and per the
    // note above a larger fixed term costs proportionally more at short stems
    // — the spread GROWING with F is the RD-1 mechanism working, not the model
    // degrading. Measured 0.6306 at F′ = 3250 on a seeded, deterministic run;
    // the rail sits snug at 0.66 (~5 % headroom) so drift the size the
    // pre-F-7 0.60 rail caught still goes red.
    assert!(
        spread < 0.66,
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
    let embargo = EmbargoTimer::closed_form_poisson(&assumed);
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
        ("inherited: Poisson lambda=20", DelayFamily::Poisson),
        ("memoryless: geometric mean=20", DelayFamily::Geometric),
    ] {
        for peers in [4_usize, 8] {
            let mut rng = SplitMix64::new(0xF100_D000 + peers as u64);
            let s = simulate_fluff_return(
                FloodParams {
                    peers,
                    ..FloodParams::default()
                },
                20,
                dist,
                24,
                &mut rng,
            );
            assert_eq!(
                s.unreached, 0,
                "undirected flood stranded {} of {} first passages — the p90 fed \
                 onward would be measured on collapsed coverage",
                s.unreached, s.samples
            );
            println!(
                "{label:<34} {peers:>8} {:>9.0}ms {:>9}ms",
                s.mean_ms, s.p90_ms
            );
            if peers == 8 {
                match dist {
                    DelayFamily::Poisson => inherited_p90 = s.p90_ms,
                    DelayFamily::Geometric => memoryless_p90 = s.p90_ms,
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
    for f in [500_u32, 1_500, 2_250, 3_250, 4_250, 13_750] {
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
        // 3250 is the shipped, F-7-corrected p90 return (OutboundOnly at
        // degree 12, §40.1); 2250 stays on the ladder as the pre-F-7
        // EveryPeer figure the original finding was written against.
        if f == 3_250 {
            corrected = Some((d, at_old));
        }
    }
    let (adopted, old_achieves) = corrected.expect("3250ms row was measured");

    println!(
        "\n  At the measured p90 return of 3250ms (F-7's directed re-measure; the\n  \
         2250ms row above is the pre-F-7 EveryPeer figure) the requirement moves\n  \
         {}s -> {}s, and the previously-derived {}s delivers only {old_achieves:.4} rather than\n  \
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
