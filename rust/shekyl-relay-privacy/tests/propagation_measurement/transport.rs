// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Measurement instruments — transport family.
//!
//! Part of the `propagation_measurement` suite. Run with `--nocapture` for tables.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::FloodParams;
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::{DelayFamily, EmbargoTimer, SplitMix64};

/// **The quantified clearnet-vs-Tor security delta** for this mechanism — the
/// number that lets the Tor recommendation rest on a measurement rather than on
/// "Tor is more private." Clearnet is the weakest allowable configuration (the
/// floor we must defend); Tor is the likely recommended one, and this shows
/// *what* it buys, anchored to `levin_notify.cpp:448` (fluff is outbound-only on
/// I2P/Tor).
#[test]
fn tor_collapses_the_supernode_diffusion_observer() {
    use shekyl_relay_privacy::conformance::{simulate_transport_observation, Transport};

    println!("\nSupernode diffusion observer: clearnet vs Tor (512 nodes, 8 peers)");
    println!(
        "{:>7} {:>10} {:>18} {:>14}",
        "dial φ", "transport", "observed fraction", "first-spy π₀"
    );
    println!("{}", "-".repeat(54));

    for phi_pct in [5_u64, 10, 30] {
        let phi = phi_pct as f64 / 100.0;
        let mut clear = SplitMix64::new(0x707 + phi_pct);
        let c = simulate_transport_observation(
            FloodParams::default(),
            20,
            DelayFamily::Geometric,
            phi,
            Transport::Clearnet,
            12_000,
            &mut clear,
        );
        let mut tor = SplitMix64::new(0x707 + phi_pct + 9973);
        let t = simulate_transport_observation(
            FloodParams::default(),
            20,
            DelayFamily::Geometric,
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
        FloodParams::default(),
        20,
        DelayFamily::Geometric,
        0.05,
        Transport::Clearnet,
        40_000,
        &mut a,
    );
    let hi = simulate_transport_observation(
        FloodParams::default(),
        20,
        DelayFamily::Geometric,
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
    for secs in [31_u32, 50, 144, 190, 300, 500] {
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
    // Non-negligible at the adopted 190 s embargo (the F-7-derived pair that
    // ships; 144 s stays on the printed ladder as the pre-F-7 point) — a real
    // channel, not noise.
    let at_190 = clearnet_rates.iter().find(|(s, _)| *s == 190).unwrap().1;
    assert!(
        at_190 > 0.005,
        "the clearnet passive channel should be non-negligible at the adopted \
         embargo, got {at_190:.5}"
    );
    // The RD-1/RD-4 corrections already helped here: the 31 s (pre-correction)
    // rate is several times the adopted 190 s rate.
    let at_31 = clearnet_rates.iter().find(|(s, _)| *s == 31).unwrap().1;
    assert!(
        at_31 > at_190 * 3.0,
        "correct provisioning should have cut the passive leak severalfold: \
         31s={at_31:.5} vs 190s={at_190:.5}"
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
