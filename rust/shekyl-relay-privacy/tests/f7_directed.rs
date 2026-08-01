// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
//! F-7's magnitude: `fluff_return_ms` is measured under `EveryPeer` and fed to
//! the embargo derivation for every transport (§26.2). This reports both
//! reaches side by side so the gap is a number rather than an argument.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::{simulate_fluff_return, FloodParams, FloodReach};
use shekyl_relay_privacy::schedule::DelayFamily;
use shekyl_relay_privacy::SplitMix64;

#[test]
fn f7_directed_first_passage_exceeds_the_shipped_input() {
    let dist = DelayFamily::Geometric;
    println!("\n  peers | reach         |  mean_ms |  p50_ms |  p90_ms");
    println!("  ------+---------------+----------+---------+--------");
    let mut p90 = std::collections::HashMap::new();
    for peers in [8_usize, 12, 16] {
        for (reach, label) in [
            (FloodReach::EveryPeer, "EveryPeer"),
            (FloodReach::OutboundOnly, "OutboundOnly"),
        ] {
            let mut rng = SplitMix64::new(0xF7_0000 + peers as u64);
            let s = simulate_fluff_return(
                FloodParams {
                    nodes: 512,
                    peers,
                    reach,
                },
                20,
                dist,
                24,
                &mut rng,
            );
            println!(
                "  {peers:5} | {label:13} | {:8.0} | {:7} | {:7}",
                s.mean_ms, s.p50_ms, s.p90_ms
            );
            p90.insert((peers, label), s.p90_ms);
        }
    }
    // The shipped input is 2250 ms, measured under EveryPeer at peers=8.
    let sym = p90[&(8, "EveryPeer")];
    let dir = p90[&(8, "OutboundOnly")];
    println!("\n  shipped fluff_return_ms = 2250 (EveryPeer, peers=8)");
    println!(
        "  directed p90 at peers=8  = {dir}  ({:+.1}%)",
        (dir as f64 / sym as f64 - 1.0) * 100.0
    );
    assert!(
        dir > sym,
        "directed first passage must exceed undirected: {dir} vs {sym} — if this \
         fails, the reach flag is not reaching the graph construction"
    );
}
