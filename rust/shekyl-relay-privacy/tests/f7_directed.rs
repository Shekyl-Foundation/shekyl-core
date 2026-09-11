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
//!
//! # Both arms run at ONE transit, and that is F-7's own lesson
//!
//! `transit_for(reach)` pairs the transit assumption to the link class, which
//! is right for an instrument simulating production and wrong for this one.
//! Using it here put `EveryPeer` at 50 ms against `OutboundOnly` at 1625 ms,
//! so the reported gap charged the reach rule for a 32× difference in link
//! latency — a rule change and a network change moving together, which is
//! **F-7's defect reproduced inside the file named for it**. The gap read
//! `+434 %` that way against `+46 %` at matched transit.
//!
//! Both arms therefore run at [`ANON_ZONE_TRANSIT_ASSUMPTION_MS`] via
//! `transit_for(OutboundOnly)`: the question is *"same network, different
//! fluff rule"*, and the anonymity zone is the network the rule applies to.
//! The comparison stays non-vacuous — at matched transit the directed arm is
//! still 1.3–1.5× slower at 1625 ms, and 2.3–3.0× at zero transit — so
//! `dir > sym` is carried by the reach mechanism, not by the latency.

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
                    nodes: 512,
                    reach,
                    // NOT `transit_for(reach)` — see the module note: pairing
                    // transit to reach makes this comparison measure two
                    // things at once. One link class, both arms.
                    transit_ms: shekyl_relay_privacy::conformance::transit_for(
                        FloodReach::OutboundOnly,
                    ),
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
    println!(
        "\n  both arms at ANON_ZONE_TRANSIT_ASSUMPTION_MS; the gap below is the REACH \
         rule alone\n  pre-F-7 fluff_return_ms = 2250 (EveryPeer, peers=8); shipped = \
         3250 (OutboundOnly, degree 12) — both transit-less readings (§91.6)"
    );
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
