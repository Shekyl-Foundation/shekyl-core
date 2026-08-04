// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//! F-12: how far does the adopted embargo move with `time_between_hop_ms`?
//!
//! `hop` is a **single global** applied to every transport — exactly what
//! `fluff_return_ms` was before F-7. An onion-service hop traverses six
//! relays where clearnet traverses one, and the embargo is derived from the
//! clearnet-ish figure, so a stem running over Tor is provisioned short.
//!
//! This is not introduced by R-1: **originated traffic has always stemmed on
//! the anonymity zone**, so the mismatch has been live for every Tor node
//! since the beginning. R-1 extends it to relayed traffic and exit (a) makes
//! it common.
use shekyl_relay_privacy::derive::derive_embargo;
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;

#[test]
fn hop_sensitivity() {
    let mut seen: Vec<(u32, u64)> = Vec::new();
    println!("\n  hop_ms   embargo(s)   vs shipped");
    let base = derive_embargo(
        &DandelionParams::inherited(),
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("solves");
    let base_s = u64::from(base.mean_ticks) * base.tick_millis / 1000;
    for hop in [175_u32, 300, 500, 875, 1050, 1750] {
        let mut p = DandelionParams::inherited();
        p.time_between_hop_ms = hop;
        let d = derive_embargo(
            &p,
            DEFAULT_EMBARGO_TICK_MILLIS,
            EMBARGO_FULL_TRAVEL_PROBABILITY,
        )
        .expect("solves");
        let s = u64::from(d.mean_ticks) * d.tick_millis / 1000;
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
