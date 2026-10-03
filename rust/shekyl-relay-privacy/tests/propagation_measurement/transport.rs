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

/// An inbound supernode sees a production fluff. Production reach is
/// [`FloodReach::EveryPeer`] on every connector, so the cheap inbound edge
/// receives the diffusion. The retired D7 graph (`OutboundOnly`) is the arm
/// that sees nothing; it is not a connector.
#[test]
fn an_inbound_supernode_observes_a_production_fluff() {
    use shekyl_relay_privacy::conformance::{simulate_transport_observation, FloodReach};
    use shekyl_relay_privacy::MeasuredConnector;

    let production = FloodParams {
        nodes: 512,
        peers: 12,
        reach: FloodReach::EveryPeer,
        transit_ms: shekyl_relay_privacy::conformance::transit_for(MeasuredConnector::Clearnet),
    };
    let retired = FloodParams {
        nodes: 512,
        peers: 12,
        reach: FloodReach::OutboundOnly,
        transit_ms: shekyl_relay_privacy::conformance::transit_for(MeasuredConnector::Tor),
    };
    println!(
        "\nSupernode diffusion observer: production EveryPeer ({} nodes, {} peers)",
        production.nodes, production.peers
    );
    println!(
        "{:>7} {:>18} {:>14}",
        "dial φ", "observed fraction", "first-spy π₀"
    );
    println!("{}", "-".repeat(42));

    for phi_pct in [5_u64, 10, 30] {
        let phi = phi_pct as f64 / 100.0;
        let mut rng = SplitMix64::new(0x707 + phi_pct);
        let observed = simulate_transport_observation(
            production,
            20,
            DelayFamily::Geometric,
            phi,
            12_000,
            &mut rng,
        );
        println!(
            "{phi:>7.2} {:>18.4} {:>14.4}",
            observed.observed_fraction, observed.first_spy_precision
        );
        assert!(
            observed.observed_fraction > 0.9,
            "an inbound supernode on a production fluff should observe almost \
             all of them, got {:.4}",
            observed.observed_fraction
        );
    }

    let mut retired_rng = SplitMix64::new(0x0D7);
    let blind = simulate_transport_observation(
        retired,
        20,
        DelayFamily::Geometric,
        0.30,
        1_000,
        &mut retired_rng,
    );
    assert!(
        blind.observed_fraction < 1e-12,
        "the retired OutboundOnly graph shows the inbound supernode nothing, got {:.6}",
        blind.observed_fraction
    );

    // First-spy precision on the production graph rises with the dial fraction.
    let mut a = SplitMix64::new(1);
    let mut b = SplitMix64::new(2);
    let lo = simulate_transport_observation(
        production,
        20,
        DelayFamily::Geometric,
        0.05,
        40_000,
        &mut a,
    );
    let hi = simulate_transport_observation(
        production,
        20,
        DelayFamily::Geometric,
        0.30,
        40_000,
        &mut b,
    );
    assert!(
        hi.first_spy_precision > lo.first_spy_precision,
        "first-spy precision should rise with the dial fraction: {:.3} -> {:.3}",
        lo.first_spy_precision,
        hi.first_spy_precision
    );
    println!(
        "\n  Production fluff is EveryPeer on every connector, so an inbound\n  \
         supernode observes it (first-spy {:.2} at a 30% dial). The retired D7\n  \
         graph, OutboundOnly, is the arm that sees nothing. Connector transit\n  \
         does not select that edge set.",
        hi.first_spy_precision
    );
}

/// The production passive channel is real and mean-dependent. ε (embargo
/// provisioning) is a live lever on [`FloodReach::EveryPeer`], which is the
/// fluff reach of every connector. The retired D7 graph leaks nothing on
/// this inbound edge.
#[test]
fn every_peer_passive_leak_falls_with_the_embargo() {
    use shekyl_relay_privacy::conformance::{simulate_passive_neighbor_leak, FloodReach};

    let params = DandelionParams::inherited();

    println!("\nPassive inbound-neighbour leak vs embargo mean (supernode reach φ=0.10)");
    println!(
        "{:>11} {:>14} {:>12} {:>14}",
        "embargo (s)", "reach", "leak rate", "origin share"
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
            FloodReach::EveryPeer,
            200_000,
            &mut cr,
        );
        let mut tr = SplitMix64::new(0x9A5 + u64::from(secs) + 7919);
        let t = simulate_passive_neighbor_leak(
            &params,
            &e,
            0.10,
            FloodReach::OutboundOnly,
            200_000,
            &mut tr,
        );

        println!(
            "{secs:>11} {:>14} {:>12.5} {:>14.4}",
            "EveryPeer", c.leak_rate, c.origin_share_of_leaks
        );
        println!(
            "{secs:>11} {:>14} {:>12.5} {:>14.4}",
            "OutboundOnly", t.leak_rate, t.origin_share_of_leaks
        );
        assert!(
            t.leak_rate < 1e-12,
            "the retired OutboundOnly graph must not leak on an inbound edge, got {:.6}",
            t.leak_rate
        );
        clearnet_rates.push((secs, c.leak_rate));
    }

    // Mean-dependence: the clearnet leak falls monotonically as the embargo
    // lengthens — the property that makes ε a live lever there.
    for w in clearnet_rates.windows(2) {
        assert!(
            w[1].1 < w[0].1,
            "production leak should fall with embargo mean: {}s={:.5} then {}s={:.5}",
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
        "the production passive channel should be non-negligible at the adopted \
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
        "\n  The production (EveryPeer) passive channel is real and mean-dependent:\n  \
         the leak falls with the embargo mean, on every connector. The retired\n  \
         D7 graph (OutboundOnly) leaks nothing on this inbound edge. ε defends\n  \
         the production channel; it is not a Tor-only zero."
    );
}
