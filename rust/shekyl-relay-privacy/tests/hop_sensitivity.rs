// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
#![allow(clippy::cast_precision_loss)]
//! F-12: how far does the adopted embargo move with `time_between_hop_ms`,
//! and does a Tor-latency hop ever enter the term it spaces?
//!
//! The first test measures the sensitivity. The second used to answer the
//! second question **no** — and that answer is retired.
//!
//! # The retired reading, and the reason it is worth keeping visible
//!
//! §63 established that `dandelionpp_notify` dispatched only when
//! `nzone == public_`, so `stem`/`forward`/`local` on i2p/tor fell through to
//! an outbound-only diffusion. From a Tor-configured origin the stem length
//! was therefore **1 with certainty**, and the shipped embargo over-provisioned
//! that path by ≥75 %. F-12's sign was backwards and the finding retracted.
//!
//! **§89 reverses the premise: the anonymity zone stems.** `hop` is no longer
//! a single global — it is per-zone (§89.2), because it is transport-bound
//! while `fluff_return_ms` is not (§63.2's keeper). Tor-latency hops now exist
//! inside a stem, which is what F-12 originally claimed and could not then be
//! true.
//!
//! The comfortable margin went with the premise. Recomputed at the shipped
//! `q = 20`, the anonymity path needs **exactly** the clearnet embargo at
//! clearnet-parity hop and more above it — so a global would under-provision
//! it, the privacy-losing direction. That is why the second test below is now
//! about *separateness* rather than headroom.
use shekyl_relay_privacy::derive::derive_embargo;
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::RelayZone;

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

/// The anonymity zone's embargo is derived from its own `hop`, not clearnet's.
///
/// # What this replaces, and why the replacement is shaped differently
///
/// The case here was `anonymity_zone_origin_is_over_provisioned_not_under`,
/// written as a tripwire whose comment promised: *"a failure here means the
/// anonymity zone started stemming… either of which reopens §63."* **The zone
/// started stemming and it did not fail.** It set
/// `fluff_probability_pct = 100` as a *literal* — the diffusing posture's
/// stem-length-1-with-certainty — so it measured the retired posture by
/// construction and would have passed against any code whatsoever. Vacuous by
/// input, on the precise axis its comment advertised as guarded (§89.4).
///
/// **The posture cannot be pinned from this crate**, and pretending otherwise
/// is how the last one went wrong. The fact lives in C++ dispatch — whether
/// `dandelionpp_notify` runs for a non-public zone — and the oracle for it is
/// `tests/unit_tests/levin.cpp`'s six `private_*` cases, which assert a stem
/// send on i2p reaches one successor with `dandelionpp_fluff == false`. If the
/// transport gate came back, those fail. This test names them rather than
/// faking a local copy of what they check.
///
/// What *is* checkable here is that the two zones' embargoes are separately
/// derived and ordered — which is what §89.2 decided, and what a "simplifying"
/// edit collapsing them back to one global would break.
#[test]
fn the_anonymity_embargo_is_derived_from_its_own_hop() {
    let clearnet = DandelionParams::adopted_for(RelayZone::Public);
    let anon = DandelionParams::adopted_for(RelayZone::Tor);

    let clearnet_s = embargo_secs(&clearnet);
    let anon_s = embargo_secs(&anon);

    println!("\n  zone       hop_ms   embargo(s)");
    println!(
        "  clearnet   {:>6}   {clearnet_s:>10}",
        clearnet.time_between_hop_ms
    );
    println!(
        "  anon       {:>6}   {anon_s:>10}",
        anon.time_between_hop_ms
    );

    // Nothing here sets `fluff_probability_pct`. Both sides read the shipped
    // parameter set, so the derivation cannot be re-pointed at a posture the
    // code no longer runs — which is the specific failure being replaced.
    assert_eq!(
        clearnet.fluff_probability_pct, anon.fluff_probability_pct,
        "q is a network-wide constant; a per-zone q would be a different design \
         than §89.2 decided, and this test would be reading it silently"
    );

    assert!(
        anon.time_between_hop_ms > clearnet.time_between_hop_ms,
        "the anonymity hop must exceed clearnet's — a rendezvous path is six \
         relays where clearnet is one direct connection"
    );
    assert!(
        anon_s > clearnet_s,
        "anon embargo {anon_s}s must exceed clearnet's {clearnet_s}s: the two \
         are separately derived (§89.2), and equality means they were collapsed \
         back to one global — which under-provisions the rendezvous path, the \
         privacy-losing direction"
    );
}
