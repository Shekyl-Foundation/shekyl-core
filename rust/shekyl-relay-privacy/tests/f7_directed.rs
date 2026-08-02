// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
//! F-7's magnitude, kept as a comparative instrument: the pre-F-7
//! `fluff_return_ms` (2250 ms) was measured under `EveryPeer` — the rule the
//! instrument used to model *by construction* — and fed to the embargo
//! derivation for every transport, while anonymity-zone fluff is
//! outbound-only (§26.2). This reports both reaches side by side so the gap
//! stays a number rather than an argument. The shipped input is now the
//! directed measurement itself (`fluff_return_ms = 3250`, `OutboundOnly` at
//! degree 12, §40.1); what this test guards is the *direction* of the gap —
//! directed strictly slower — not the shipped value, whose pin lives with
//! `DandelionParams` and the derivation tests.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::{simulate_fluff_return, FloodParams, FloodReach};
use shekyl_relay_privacy::schedule::DelayFamily;
use shekyl_relay_privacy::SplitMix64;

#[test]
fn f7_directed_first_passage_exceeds_the_undirected_measurement() {
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
                    peers,
                    reach,
                    ..FloodParams::default()
                },
                20,
                dist,
                24,
                &mut rng,
            );
            assert!(
                s.unreached * 1000 <= s.samples,
                "flood coverage collapsed at peers={peers} ({label}): {} of {} \
                 first passages unreached",
                s.unreached,
                s.samples
            );
            println!(
                "  {peers:5} | {label:13} | {:8.0} | {:7} | {:7}",
                s.mean_ms, s.p50_ms, s.p90_ms
            );
            p90.insert((peers, label), s.p90_ms);
        }
    }
    // 2250 ms is the pre-F-7 input, measured under EveryPeer at peers=8; the
    // shipped input is 3250 ms (OutboundOnly, degree 12).
    let sym = p90[&(8, "EveryPeer")];
    let dir = p90[&(8, "OutboundOnly")];
    println!("\n  pre-F-7 fluff_return_ms = 2250 (EveryPeer, peers=8); shipped = 3250 (OutboundOnly, degree 12)");
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
