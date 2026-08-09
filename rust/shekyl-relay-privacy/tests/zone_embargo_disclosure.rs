// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
#![allow(clippy::cast_precision_loss)]
//! Does a per-zone embargo disclose which zone a transaction was stemming on?
//!
//! §64 rules the embargo **per-zone**: `time_between_hop_ms` is transport-bound
//! by nature (§63.2's keeper — the stem it spaces only ever runs on one
//! transport) and §59's coherence makes the quantity well-defined, because a
//! transaction that enters the anonymity zone's stem stays there until it
//! fluffs. Per-zone provisioning means the two zones draw their embargo from
//! **different means**, and a different mean is, in principle, an observable.
//!
//! This is the mirror of the `vin.size()` question D answered, so it gets the
//! same treatment: measured, not reasoned.
//!
//! # What the adversary must already hold
//!
//! The observable is a **self-fluff** — a node's own embargo firing — and it is
//! reachable only by an adversary who holds two things this test grants for
//! free:
//!
//! 1. **The arming time.** The timer measures from receipt; a bare wall-clock
//!    fluff timestamp is not a sample from the distribution. The observer needs
//!    the origin's send, which is the thing D++ exists to hide.
//! 2. **A black-hole.** In normal operation a transaction fluffs because its
//!    stem reached a fluff node, not because an embargo fired. Self-fluff is
//!    the *recovery* path.
//!
//! So the numbers below are an upper bound on an adversary already past both
//! gates. If discrimination is weak *there*, it is weaker everywhere real.
//!
//! # The instrument
//!
//! The embargo timer is geometric on ticks: `p = 1/(mean_ticks + 1)`, so
//! `P(fire at tick k) = (1-p)^(k-1) · p` (`derive.rs`). Total variation between
//! the two zones' distributions bounds **every** single-observation classifier
//! at once — the best achievable accuracy under equal priors is `1/2 + TV/2`,
//! with `1/2` being a coin flip. KL divergence gives the repeat-observation
//! cost: distinguishing at 95 % confidence needs about `ln(20)/KL` independent
//! self-fluffs of the *same* transaction population.
use shekyl_relay_privacy::derive::derive_embargo;
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;

/// Ticks below which the geometric tail cannot move either sum at `f64`
/// resolution. Both distributions are summed to the same horizon so the
/// comparison is not itself a truncation artifact.
const TAIL_HORIZON_TICKS: u32 = 2_000_000;

fn embargo_of(hop_ms: u32) -> (u32, u64) {
    let mut p = DandelionParams::inherited();
    p.time_between_hop_ms = hop_ms;
    let d = derive_embargo(
        &p,
        DEFAULT_EMBARGO_TICK_MILLIS,
        EMBARGO_FULL_TRAVEL_PROBABILITY,
    )
    .expect("solves");
    (d.mean_ticks, u64::from(d.mean_secs()))
}

/// `P(fire at tick k)` for a geometric embargo with the given mean, k >= 1.
fn pmf(mean_ticks: u32, k: u32) -> f64 {
    let p = 1.0 / (f64::from(mean_ticks) + 1.0);
    (1.0 - p).powi(i32::try_from(k - 1).expect("horizon fits i32")) * p
}

/// Total variation distance between two geometric embargo timers.
fn total_variation(mean_a: u32, mean_b: u32) -> f64 {
    let mut tv = 0.0_f64;
    for k in 1..=TAIL_HORIZON_TICKS {
        tv += (pmf(mean_a, k) - pmf(mean_b, k)).abs();
    }
    tv / 2.0
}

/// `KL(A || B)` in nats, for the repeat-observation cost.
fn kl_divergence(mean_a: u32, mean_b: u32) -> f64 {
    let mut kl = 0.0_f64;
    for k in 1..=TAIL_HORIZON_TICKS {
        let (pa, pb) = (pmf(mean_a, k), pmf(mean_b, k));
        if pa > 0.0 && pb > 0.0 {
            kl += pa * (pa / pb).ln();
        }
    }
    kl
}

/// Best single-observation classifier accuracy under equal priors.
fn best_accuracy(tv: f64) -> f64 {
    0.5 + tv / 2.0
}

/// Independent self-fluffs needed to reach ~95 % confidence.
fn observations_for_95(kl: f64) -> f64 {
    if kl <= 0.0 {
        return f64::INFINITY;
    }
    20.0_f64.ln() / kl
}

#[test]
fn zone_embargo_discrimination_rises_with_the_hop_gap() {
    let (clearnet_ticks, clearnet_secs) = embargo_of(175);
    println!("\n  clearnet embargo: {clearnet_secs}s ({clearnet_ticks} ticks)\n");

    // --- Negative control -------------------------------------------------
    // Identical zones must be indistinguishable. If this is ever non-zero the
    // instrument is measuring something other than the distributions.
    let tv_null = total_variation(clearnet_ticks, clearnet_ticks);
    println!(
        "  NEGATIVE CONTROL  identical zones:  TV={tv_null:.6}  acc={:.4}",
        best_accuracy(tv_null)
    );
    assert!(
        tv_null == 0.0,
        "identical distributions must have zero TV; got {tv_null}"
    );

    // --- Positive control -------------------------------------------------
    // A zone whose embargo is an order of magnitude longer MUST be visible, or
    // this test cannot detect disclosure at all and every pass below is
    // vacuous.
    let (far_ticks, far_secs) = embargo_of(20_000);
    let tv_far = total_variation(clearnet_ticks, far_ticks);
    println!(
        "  POSITIVE CONTROL  {far_secs}s zone:       TV={tv_far:.4}  acc={:.4}",
        best_accuracy(tv_far)
    );
    assert!(
        best_accuracy(tv_far) > 0.80,
        "instrument cannot see a {far_secs}s vs {clearnet_secs}s difference \
         (acc {:.4}) — it would not detect real disclosure either",
        best_accuracy(tv_far)
    );

    // --- The question ------------------------------------------------------
    println!("\n  anon hop   embargo   TV      single-obs acc   self-fluffs for 95%");
    let mut accuracies: Vec<(u32, f64)> = Vec::new();
    for hop in [500_u32, 1050, 1750, 3500] {
        let (ticks, secs) = embargo_of(hop);
        let tv = total_variation(clearnet_ticks, ticks);
        let kl = kl_divergence(ticks, clearnet_ticks);
        println!(
            "  {hop:>8}   {secs:>5}s   {tv:.4}  {:>13.4}   {:>18.0}",
            best_accuracy(tv),
            observations_for_95(kl)
        );
        accuracies.push((hop, best_accuracy(tv)));
    }

    // --- What this test is NOT allowed to be used to argue -----------------
    //
    // §64 closes the disclosure question on **vantage**: the self-fluff sample
    // is reachable only from a peer on the zone, and such a peer already knows
    // the transaction arrived over Tor. That leg is independent of the
    // rendezvous hop, which is still unmeasured.
    //
    // The tempting second leg — "the signal is weak anyway" — is NOT load
    // bearing, and these two assertions exist to stop it being cited as if it
    // were. Discrimination rises monotonically with the hop gap and is already
    // well clear of a coin flip at the top of the plausible range, so a closure
    // resting on signal strength would evaporate exactly when the measurement
    // lands high. If a future change makes the signal genuinely weak, this test
    // fails and the reasoning gets re-opened deliberately rather than inherited.
    for pair in accuracies.windows(2) {
        assert!(
            pair[1].1 > pair[0].1,
            "discrimination must rise with the hop gap: hop={} gives {:.4} but \
             hop={} gives {:.4}",
            pair[0].0,
            pair[0].1,
            pair[1].0,
            pair[1].1
        );
    }
    let (top_hop, top_acc) = *accuracies.last().expect("sweep is non-empty");
    assert!(
        top_acc > 0.65,
        "single-observation accuracy at hop={top_hop} fell to {top_acc:.4}, near \
         a coin flip. That would make the weak-signal argument look sound — it \
         is not the argument §64 closed on (vantage is), and the doc must not \
         be edited to lean on it without re-deriving why."
    );
}
