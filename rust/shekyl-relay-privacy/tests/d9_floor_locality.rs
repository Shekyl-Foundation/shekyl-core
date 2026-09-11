// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
//! Q12-D9: is the outbound floor a **per-node** condition or a **network** one?
//!
//! §12.2 of the Q12-D6a run doc rules that the below-floor check must be
//! *live* — a node that falls below the floor stops stemming. That presumes a
//! per-node form of the condition exists: that being below the floor is a
//! property a node can evaluate about itself and act on.
//!
//! **The floor's own justification says what to measure.** §12.1: a node with
//! too few anonymity peers "is not running the topology the embargo was
//! derived for: its fluff return is slower, so `F` is under-provisioned in the
//! privacy-losing direction, and *its own* transactions carry an embargo too
//! short for the graph they traverse." The harm named there is **self-harm**,
//! about the degraded node's own fluff return — not about what it costs the
//! rest of the network.
//!
//! So the discriminating measurement is a pair, and which one you read decides
//! the answer:
//!
//! - **self axis** — the degraded node is the flood *source*, so the sample is
//!   its own fluff return;
//! - **network axis** — the degraded node is a peer, so the sample is everyone
//!   else's first passage.
//!
//! A measurement on the network axis cannot settle a rule justified on the
//! self axis. This file runs both against a common baseline so the two cannot
//! be conflated, and so the answer rests on running code rather than on a
//! remembered figure (Q12-D8: *does the thing this number describes currently
//! run?*).
//!
//! **This test reports; it does not assert a threshold.** The only assertions
//! are the ones that make the report trustworthy: that the instrument
//! discriminates at all (a whole-network degradation must move the number) and
//! that the arms are otherwise identical. Pinning a percentage here would pin
//! a seed-dependent draw, which is the defect Q12-R's `fluff_return_ms` sweep
//! already caught once.

#![allow(clippy::cast_precision_loss)]
// ^ Node counts and millisecond means widen to f64 for the ratios reported
//   below. Every value involved is far below 2^53.

use shekyl_relay_privacy::conformance::{
    simulate_fluff_return_mixed, FloodParams, FloodReach, FloodSummary,
};
use shekyl_relay_privacy::params::MIN_PROVISIONED_OUT_PEERS;
use shekyl_relay_privacy::schedule::DelayFamily;
use shekyl_relay_privacy::SplitMix64;

const NODES: usize = 60;
const TRIALS: usize = 400;
const MEAN_QUARTER_SECS: u32 = 20;

/// Seeds, not a seed. A single draw is one sample from a spread, and reading a
/// constant off one is the defect this crate has already shipped once
/// (`fluff_return_ms = 3250` was the minimum of its own seed spread).
const SEEDS: [u64; 8] = [
    0xD9_0001, 0xD9_0002, 0xD9_0003, 0xD9_0004, 0xD9_0005, 0xD9_0006, 0xD9_0007, 0xD9_0008,
];

fn floor() -> usize {
    MIN_PROVISIONED_OUT_PEERS as usize
}

/// Mean first passage over every seed, so a reported figure is a spread's
/// centre rather than one draw from it.
fn measure(degrees: &[usize]) -> f64 {
    let mut total = 0.0;
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        let s: FloodSummary = simulate_fluff_return_mixed(
            FloodParams {
                nodes: NODES,
                peers: floor(),
                reach: FloodReach::OutboundOnly,
                transit_ms: shekyl_relay_privacy::conformance::transit_for(
                    FloodReach::OutboundOnly,
                ),
            },
            degrees,
            MEAN_QUARTER_SECS,
            DelayFamily::Geometric,
            TRIALS,
            &mut rng,
        );
        assert!(
            s.unreached * 1000 <= s.samples,
            "flood coverage collapsed: {} of {} unreached",
            s.unreached,
            s.samples
        );
        total += s.mean_ms;
    }
    total / SEEDS.len() as f64
}

#[test]
fn the_floor_is_a_self_condition_not_a_network_one() {
    let below = floor() - 2; // 10 against a floor of 12

    // Baseline: every node at the floor, the topology the constants were
    // derived under.
    let uniform_at_floor = vec![floor(); NODES];
    let baseline = measure(&uniform_at_floor);

    // SELF axis: the degraded node is the source (node 0), so the sample is
    // its own fluff return.
    let mut self_axis = uniform_at_floor.clone();
    self_axis[0] = below;
    let self_ms = measure(&self_axis);

    // NETWORK axis: the degraded node is a peer, so the sample is the rest of
    // the network's first passage. Same graph size, same total degradation —
    // only the placement differs.
    let mut network_axis = uniform_at_floor.clone();
    network_axis[NODES / 2] = below;
    let network_ms = measure(&network_axis);

    // Control: the whole network below the floor. If this does not move, the
    // instrument is not measuring degree at all and every reading above is
    // vacuous.
    let all_below = vec![below; NODES];
    let all_ms = measure(&all_below);

    let pct = |x: f64| (x - baseline) / baseline * 100.0;
    println!("\n  Q12-D9 — first passage vs. baseline (every node at the floor)");
    println!(
        "  nodes={NODES} trials={TRIALS} seeds={} floor={} below={below}\n",
        SEEDS.len(),
        floor()
    );
    println!("  {:<44} {:>10} {:>9}", "arm", "mean_ms", "delta");
    println!("  {}", "-".repeat(66));
    println!(
        "  {:<44} {:>10.0} {:>8.2}%",
        "baseline: all at floor", baseline, 0.0
    );
    println!(
        "  {:<44} {:>10.0} {:>8.2}%",
        "SELF: source below floor",
        self_ms,
        pct(self_ms)
    );
    println!(
        "  {:<44} {:>10.0} {:>8.2}%",
        "NETWORK: one peer below floor",
        network_ms,
        pct(network_ms)
    );
    println!(
        "  {:<44} {:>10.0} {:>8.2}%",
        "control: all below floor",
        all_ms,
        pct(all_ms)
    );
    println!(
        "\n  The floor is justified on the SELF axis (§12.1: \"its own\n  \
         transactions carry an embargo too short for the graph they\n  \
         traverse\"). Read the SELF row against the NETWORK row: a rule that a\n  \
         node applies to itself is answerable only by the first.\n"
    );

    // The instrument must discriminate, or every number above is noise. This
    // is the negative control, and it is the only magnitude asserted.
    assert!(
        all_ms > baseline,
        "degrading every node did not slow first passage ({all_ms:.0} vs \
         {baseline:.0}) — the instrument is not measuring degree, so the \
         per-node arms above say nothing"
    );

    // The two axes must be distinguishable, or the placement is not the
    // variable it is claimed to be.
    assert!(
        (self_ms - network_ms).abs() > f64::EPSILON,
        "self and network axes produced identical means — the degraded node's \
         placement is not reaching the simulation"
    );
}

/// The uniform entry point must stay exactly the degrees-aware one at a
/// constant vector. If they drift, every comparison above is against a
/// baseline the rest of the crate does not share.
#[test]
fn uniform_is_the_mixed_form_at_a_constant_degree() {
    let params = FloodParams {
        nodes: 24,
        peers: floor(),
        reach: FloodReach::OutboundOnly,
        transit_ms: shekyl_relay_privacy::conformance::transit_for(FloodReach::OutboundOnly),
    };
    let degrees = vec![floor(); params.nodes];

    let mut a = SplitMix64::new(0xD9_1000);
    let uniform = shekyl_relay_privacy::conformance::simulate_fluff_return(
        params,
        MEAN_QUARTER_SECS,
        DelayFamily::Geometric,
        64,
        &mut a,
    );
    let mut b = SplitMix64::new(0xD9_1000);
    let mixed = simulate_fluff_return_mixed(
        params,
        &degrees,
        MEAN_QUARTER_SECS,
        DelayFamily::Geometric,
        64,
        &mut b,
    );

    // Bit-equality is the contract, and it is compared as bits. Both sides run
    // the same arithmetic on the same seed, so ANY difference means the paths
    // diverged and there is no tolerance to allow.
    //
    // This read `(a - b).abs() < f64::EPSILON` while claiming bit-equality in
    // this comment — written to satisfy `clippy::float_cmp` and describing
    // something the code did not do. `EPSILON` is the gap above 1.0, not an
    // exact-equality threshold: at larger magnitudes it accepts genuinely
    // different values, and it is not the contract in any case. `to_bits`
    // states the contract, needs no `allow`, and cannot drift from its comment.
    assert_eq!(
        uniform.mean_ms.to_bits(),
        mixed.mean_ms.to_bits(),
        "uniform and mixed diverged at the same degree and seed: {} vs {}",
        uniform.mean_ms,
        mixed.mean_ms
    );
    assert_eq!(uniform.p90_ms, mixed.p90_ms);
    assert_eq!(uniform.samples, mixed.samples);
}
