// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
//! **The shipped `fluff_return_ms` is the transit-LESS reading, and any
//! admissible transit puts the true value above it.**
//!
//! §91.6 found the flood model had no transit term at all and made
//! `FloodParams::transit_ms` mandatory. §2.0 then recorded that the readings
//! already banked in this suite were transit-less numbers sitting beside a
//! transit-bearing instrument. **Nobody had run the comparison**, and the
//! reason nobody noticed is structural: every instrument in this suite asserts
//! *shape* — monotonicity, ordering, refusal at stranded degrees — and never
//! *level*. A 3.7× discrepancy is invisible to a shape assertion.
//!
//! # What the comparison says
//!
//! At `transit_ms = 0` the instrument reproduces **3250 ms** at OutboundOnly,
//! degree 12 — *exactly* the shipped `fluff_return_ms`, whose own doc calls it
//! "Tor-C (OutboundOnly, usable degree 12 exact) ~3250 ms <- binding". That is
//! not a coincidence to note; it is **proof of provenance**. The shipped
//! constant is the reading this instrument produces when transit is switched
//! off.
//!
//! And transit cannot be zero — it is a real network path:
//!
//! | `transit_ms` | 0 | 100 | 300 | 400 | 1000 | 1625 |
//! | --- | --- | --- | --- | --- | --- | --- |
//! | p90 | **3250** | 4050 | 5450 | 6000 | 9250 | 12125 |
//!
//! So the shipped value is under-provisioned under **any** admissible transit,
//! not merely under the 1625 assumption — and under-provisioning
//! `fluff_return_ms` shortens the embargo, which §65/§66 name the
//! privacy-losing direction.
//!
//! # What this test does NOT do, and why that is a ruling rather than caution
//!
//! **It does not re-baseline the constant.** 12125 is not a measurement: it is
//! [`ANON_ZONE_TRANSIT_ASSUMPTION_MS`] amplified through the flood arithmetic,
//! and that assumption is precisely what §94's round is measuring. Shipping it
//! would be an assumption wearing a derivation's clothes — §91.6's own failure,
//! one file over.
//!
//! §90 already ruled the disposition: `F′` and its dependents move **together**
//! in the re-derivation round, not piecemeal here. The named blocker is §94's
//! constant (rule 22 — a deferral with an owner, not an open end).
//!
//! So this file converts a **silent** staleness into an **asserted** one. The
//! assertion below is deliberately about the *relationship* and not about any
//! number, so it cannot rot when §94 lands: a level assertion pinned at 1625's
//! output would go stale the day the constant arrives and then be "fixed" by
//! whoever hits it — the `noise_stem` hazard, where a green test defends the
//! behaviour a ruling contradicts.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::{
    simulate_fluff_return, transit_for, FloodParams, FloodReach,
};
use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::DelayFamily;
use shekyl_relay_privacy::SplitMix64;

/// The topology the shipped constant names: OutboundOnly at usable degree 12.
const BINDING_PEERS: usize = 12;
const NODES: usize = 512;
const TRIALS: usize = 24;
const HOPS: u32 = 20;

fn p90_at(transit_ms: u64) -> u64 {
    let mut rng = SplitMix64::new(0xF7_000C);
    simulate_fluff_return(
        FloodParams {
            peers: BINDING_PEERS,
            nodes: NODES,
            reach: FloodReach::OutboundOnly,
            transit_ms,
        },
        HOPS,
        DelayFamily::Geometric,
        TRIALS,
        &mut rng,
    )
    .p90_ms
}

/// The provenance pin: the shipped constant IS the transit-less reading.
///
/// This is the load-bearing half. If it ever stops reproducing, the shipped
/// value's origin is no longer what its doc claims, and the discrepancy below
/// stops being interpretable.
#[test]
fn the_shipped_fluff_return_is_the_transit_less_reading() {
    let shipped = u64::from(
        DandelionParams::adopted_for(shekyl_relay_privacy::RelayZone::Tor).fluff_return_ms,
    );
    let transit_less = p90_at(0);
    assert_eq!(
        transit_less, shipped,
        "the shipped fluff_return_ms ({shipped}) should reproduce EXACTLY as this \
         instrument's p90 at transit_ms = 0 (got {transit_less}). If these have \
         diverged, either the instrument changed or the constant was edited, and \
         the transit discrepancy below can no longer be attributed."
    );
}

/// The discrepancy, stated so it cannot rot: **any** nonzero transit exceeds
/// the shipped value.
///
/// Asserted over a sweep rather than at one point, because the claim is
/// monotone in transit and a single point would invite the reading "true at
/// 1625, unknown elsewhere" — which is exactly the ambiguity that let this sit
/// unnoticed.
#[test]
fn any_admissible_transit_exceeds_the_shipped_fluff_return() {
    let shipped = u64::from(
        DandelionParams::adopted_for(shekyl_relay_privacy::RelayZone::Tor).fluff_return_ms,
    );
    println!("\n  transit_ms |  p90_ms | vs shipped {shipped}");
    println!("  -----------+---------+------------");
    let mut prev = 0_u64;
    // The low end brackets what §94's round is expected to find; the high end
    // is the standing assumption. The claim holds across the whole range.
    for t in [100_u64, 200, 300, 400, 600, 1000, 1625] {
        let p90 = p90_at(t);
        println!(
            "  {t:10} | {p90:7} | {:+.1}%",
            (p90 as f64 / shipped as f64 - 1.0) * 100.0
        );
        assert!(
            p90 > shipped,
            "at transit_ms={t} the instrument reads {p90} against a shipped \
             fluff_return_ms of {shipped}: the shipped value is the transit-LESS \
             reading, so it under-provisions at every real transit. Under-\
             provisioning fluff_return_ms shortens the embargo (§65, §66)."
        );
        assert!(
            p90 >= prev,
            "first passage must be monotone in transit: {p90} at {t} followed {prev}"
        );
        prev = p90;
    }

    // Production's own transit for this reach, so the row that ships is in the
    // record beside the sweep.
    let shipped_assumption = p90_at(transit_for(FloodReach::OutboundOnly));
    println!(
        "\n  at transit_for(OutboundOnly): p90 = {shipped_assumption} ms  ({:.1}x shipped)",
        shipped_assumption as f64 / shipped as f64
    );
    println!("  NOT a candidate value: it is the 1625 ms ASSUMPTION amplified through");
    println!("  the flood arithmetic, and §94 is measuring that assumption. §90 rules");
    println!("  that F' and its dependents re-derive together, in the successor round.");
}

/// The floor's argument is about **degree**, and survives the transit
/// correction — checked rather than assumed, because
/// `MIN_PROVISIONED_OUT_PEERS`' own doc says the floor "moves with
/// `fluff_return_ms`, not independently of it", which invites the reading that
/// a stale `fluff_return_ms` makes the floor stale too.
///
/// It does not: the floor rests on first passage being *worse below degree 12*,
/// and transit shifts every degree's level without reordering them. The levels
/// move; the argument does not.
#[test]
fn the_degree_floor_argument_survives_the_transit_correction() {
    for transit_ms in [0_u64, 400, 1625] {
        let mut worse_below = Vec::new();
        for peers in [8_usize, 10, 12] {
            let mut rng = SplitMix64::new(0xF7_0000 + peers as u64);
            let s = simulate_fluff_return(
                FloodParams {
                    peers,
                    nodes: NODES,
                    reach: FloodReach::OutboundOnly,
                    transit_ms,
                },
                HOPS,
                DelayFamily::Geometric,
                TRIALS,
                &mut rng,
            );
            worse_below.push((peers, s.p90_ms));
        }
        let at_twelve = worse_below.last().expect("degree 12 sampled").1;
        for (peers, p90) in &worse_below[..worse_below.len() - 1] {
            assert!(
                *p90 > at_twelve,
                "at transit_ms={transit_ms}, degree {peers} must be strictly worse \
                 than the degree-12 floor ({p90} vs {at_twelve}) — this is the \
                 argument MIN_PROVISIONED_OUT_PEERS rests on, and it must hold \
                 independently of the transit level"
            );
        }
    }
}
