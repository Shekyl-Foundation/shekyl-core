// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Measurement instruments — adversary family.
//!
//! Part of the `propagation_measurement` suite. Run with `--nocapture` for tables.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::{
    derive_embargo, full_travel_probability, DelayFamily, EmbargoTimer, GeometricTable, SplitMix64,
};

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
    use shekyl_relay_privacy::conformance::{
        simulate_diffusion_first_spy, FloodParams, FloodReach,
    };

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
                reach: FloodReach::EveryPeer,
            },
            20,
            DelayFamily::Geometric,
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
