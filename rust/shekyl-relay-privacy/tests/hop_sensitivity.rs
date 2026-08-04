// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
#![allow(clippy::cast_precision_loss)]
//! F-12: how far does the adopted embargo move with `time_between_hop_ms`,
//! and does a Tor-latency hop ever enter the term it spaces?
//!
//! `hop` is a **single global** applied to every transport, which is what
//! `fluff_return_ms` was before F-7. The first test measures the sensitivity.
//!
//! The second measures the premise, and **refutes it**. `hop` spaces the
//! nodes of a *Dandelion++ stem*, and the anonymity zone never runs one:
//! `levin_notify.cpp` dispatches `dandelionpp_notify` only when
//! `nzone == public_`, so `stem`/`forward`/`local` on i2p/tor fall through to
//! the fluff case — an outbound-only diffusion, marked `dandelionpp_fluff`
//! on the wire while the txpool is told `stem`. `levin.cpp`'s
//! `private_stem_without_padding` asserts exactly that, and names it: *"private
//! mode always uses fluff but marked as stem."*
//!
//! So from a Tor-configured origin the stem length is **1 with certainty** —
//! the production derivation's `fluff_probability_pct = 100` — and the shipped
//! embargo, derived at `q = 20`, over-provisions that path rather than
//! under-provisioning it. See §63.
use shekyl_relay_privacy::derive::derive_embargo;
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;

/// The adopted embargo, in whole seconds, for a given parameter set.
///
/// Reports through [`EmbargoDerivation::mean_secs`] rather than dividing by
/// 1000 here. The two disagree: ticks are 250 ms, so a floor undercounts by up
/// to 0.75 s, and the crate's reporting convention rounds *up*. Dividing here
/// put this file's shipped row at 189 s against the 190 s §44 adopted and the
/// whole arc quotes — **one number, two values, from a rounding choice made
/// in a test.**
fn embargo_secs(p: &DandelionParams) -> u64 {
    let d = derive_embargo(
        p,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("solves");
    u64::from(d.mean_secs())
}

#[test]
fn hop_sensitivity() {
    let mut seen: Vec<(u32, u64)> = Vec::new();
    println!("\n  hop_ms   embargo(s)   vs shipped");
    let base_s = embargo_secs(&DandelionParams::inherited());
    for hop in [175_u32, 300, 500, 875, 1050, 1750] {
        let mut p = DandelionParams::inherited();
        p.time_between_hop_ms = hop;
        let s = embargo_secs(&p);
        println!(
            "  {hop:>6}   {s:>8}   {:>+7.0}%{}",
            (s as f64 / base_s as f64 - 1.0) * 100.0,
            if hop == 175 {
                "   <- shipped (assumed, unmeasured)"
            } else {
                ""
            }
        );
        seen.push((hop, s));
    }

    // The shipped row must BE the arc's adopted embargo. §44 landed 190 s and
    // every section since quotes it; a table here reading 189 s would be the
    // same number with two values, which is how a rounding choice made in a
    // test leaks into a design document as a second fact.
    assert_eq!(
        base_s, 190,
        "shipped row must match §44's adopted 190 s embargo"
    );

    // Monotone in hop: a longer stem needs a longer embargo, so any
    // under-estimate of `hop` under-provisions in the privacy-losing
    // direction (`params.rs`'s own note on `fluff_return_ms`).
    for w in seen.windows(2) {
        assert!(
            w[1].1 > w[0].1,
            "embargo must grow with hop: {:?} -> {:?}",
            w[0],
            w[1]
        );
    }

    // The finding, pinned: at a Tor-plausible hop the derived embargo is far
    // above what ships. If this ever falls below +50 %, either the derivation
    // or the multiple changed and F-12's premise needs re-checking.
    let tor_6x = seen
        .iter()
        .find(|(h, _)| *h == 1050)
        .expect("row present")
        .1;
    assert!(
        tor_6x as f64 > base_s as f64 * 1.5,
        "6x-hop embargo {tor_6x}s should far exceed the shipped {base_s}s"
    );
}

/// F-12's premise, measured against the path it claims to describe.
///
/// The claim was that a Tor node arms a clearnet-derived embargo over
/// Tor-latency *stem hops*. There are none: the anonymity zone diffuses
/// instead of stemming, so its origin's stem length is 1 and the only
/// Tor-latency transmission is the terminal one — which lives in `F`, the
/// term F-7 already re-baselined, not in `hop`.
///
/// So the honest comparison is a **pair** sweep: fix the shipped embargo, and
/// against it evaluate the requirement of a path that takes one hop at a
/// Tor-plausible latency. If the shipped value dominates across the range,
/// F-12's sign is backwards and the finding retracts.
#[test]
fn anonymity_zone_origin_is_over_provisioned_not_under() {
    let shipped = embargo_secs(&DandelionParams::inherited());

    println!("\n  shipped embargo (q=20, hop=175): {shipped}s");
    println!("\n  tor_hop_ms   required(s)   headroom vs shipped");
    let mut required: Vec<(u32, u64)> = Vec::new();
    for hop in [175_u32, 300, 500, 875, 1050, 1750] {
        let mut p = DandelionParams::inherited();
        // The anonymity zone fluffs at the first node, always: stem length is
        // 1 with certainty, which is exactly `q = 100` in this derivation.
        p.fluff_probability_pct = 100;
        p.time_between_hop_ms = hop;
        let s = embargo_secs(&p);
        println!(
            "  {hop:>10}   {s:>11}   {:>+8.0}%",
            (s as f64 / shipped as f64 - 1.0) * 100.0
        );
        required.push((hop, s));
    }

    // The finding, inverted from what §62 asserted. Even at 10x clearnet
    // latency the single-hop requirement stays under the shipped embargo, so
    // the global constant provisions the anonymity path with room to spare.
    // A failure here means the anonymity zone started stemming, or `q` moved
    // far enough to change the comparison — either of which reopens §63.
    for (hop, s) in &required {
        assert!(
            *s < shipped,
            "single-hop requirement at hop={hop} is {s}s, which the shipped \
             {shipped}s no longer covers: the over-provisioning direction \
             established in §63 has flipped"
        );
    }
}
