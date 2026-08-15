// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! §16.4's gate: the achieved full-travel probability `α` at below-floor degree.
//!
//! # What this decides
//!
//! D9(b) makes a below-floor node fluff at origin. §12.1's counter is that such
//! a node fluffs at origin *anyway* when its embargo expires — later, and after
//! the stem already leaked to its successor. Whether prompt-and-certain beats
//! late-and-probabilistic depends on **α**, the probability the stem completes
//! before any node's embargo fires, and D9(b) wins iff `α < α* = E/(L+E−R)`.
//!
//! `EMBARGO_FULL_TRAVEL_PROBABILITY = 0.90` is a *design input*: the shipped
//! embargo is solved for it **at degree 12**. A below-floor node runs a slower
//! graph, so its true `F′` exceeds the one the embargo was derived from and its
//! *achieved* α falls below 0.90. That shortfall is what this measures, by
//! feeding the degraded `F′` to the **unchanged** embargo.
//!
//! The decision rule is pre-registered in
//! `docs/design/Q12_D6A_PEER_DISCOVERY_RUN.md` §16.4 and was committed before
//! this file ran. The primary output is the **curve** `α(d)` and the degree at
//! which it crosses `α*` — not which band a single point lands in.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::{
    converged_fluff_return_mixed, ConvergenceBudget, FloodParams, FloodReach, FLOOD_TICK_MS,
};
use shekyl_relay_privacy::params::{DandelionParams, EMBARGO_FULL_TRAVEL_PROBABILITY};
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::{full_travel_probability, SplitMix64};

/// Seeds and topology as §13's arms ran them.
const SEEDS: [u64; 6] = [
    0xD9A1_0001,
    0xD9A1_0002,
    0xD9A1_0003,
    0xD9A1_0004,
    0xD9A1_0005,
    0xD9A1_0006,
];
const NODES: usize = 512;
const MEAN_QUARTER_SECS: u32 = 20;

/// The shipped embargo, in ticks: 190 s at the 250 ms tick.
const SHIPPED_EMBARGO_SECS: u32 = 190;
fn shipped_mean_ticks() -> u32 {
    let embargo_ms = u64::from(SHIPPED_EMBARGO_SECS) * 1000;
    // Exact divisibility asserted, not assumed: 190 000 ms / 250 ms = 760
    // today, but a tick that stops dividing the embargo would make `/`
    // truncate SILENTLY, shifting the embargo every alpha in the table is
    // measured against by an amount nothing else would flag. This value is
    // the measurement's denominator — it fails loudly or not at all.
    assert!(
        embargo_ms % DEFAULT_EMBARGO_TICK_MILLIS == 0,
        "shipped embargo ({embargo_ms} ms) is not a whole number of \
         {DEFAULT_EMBARGO_TICK_MILLIS} ms ticks — a constant moved; re-derive \
         the tick count explicitly instead of letting division round it"
    );
    let ticks = embargo_ms / DEFAULT_EMBARGO_TICK_MILLIS;
    u32::try_from(ticks).expect("shipped embargo in ticks must fit u32")
}

fn alpha_at(fluff_return_ms: u32) -> f64 {
    let params = DandelionParams {
        fluff_return_ms,
        ..DandelionParams::adopted()
    };
    full_travel_probability(&params, shipped_mean_ticks(), DEFAULT_EMBARGO_TICK_MILLIS)
}

/// **The non-vacuity control, and it runs first.**
///
/// If `fluff_return_ms` does not reach `full_travel_probability`, the sweep
/// below returns the same α at every degree — ≈ 0.90, which §16.4 pre-registers
/// as the *likely* outcome. It would then "confirm" the expected ruling on the
/// exact axis the measurement exists to vary.
///
/// That is `hop_sensitivity::anonymity_zone_origin_is_over_provisioned_not_under`
/// repeated: vacuous by input, hard-coded on the axis its own name advertised.
/// A sweep whose control has not run is not evidence.
#[test]
fn alpha_responds_to_fluff_return_at_all() {
    let base = alpha_at(3_250); // shipped, measured at degree 12
    let slow = alpha_at(4_750); // §90.3's measured value at a third-below-floor

    println!("\n  non-vacuity control");
    println!("  F' = 3250 ms -> alpha = {base:.6}");
    println!("  F' = 4750 ms -> alpha = {slow:.6}");

    assert!(
        (base - slow).abs() > f64::EPSILON,
        "alpha is INSENSITIVE to fluff_return_ms — the composition is vacuous on \
         the axis under test, and every number the sweep prints would be the same \
         value wearing different degree labels"
    );
    assert!(
        slow < base,
        "a slower fluff return must LOWER the achieved full-travel probability: a \
         longer return inflates the timer-survival exponent. Got {slow} >= {base}, \
         which is the sign inverted"
    );
}

/// α(d) across the degrees the arms actually observed below the floor, plus the
/// provisioning degree as the reference point.
#[test]
fn alpha_curve_across_below_floor_degrees() {
    let budget = ConvergenceBudget {
        start_trials: 32,
        max_trials: 1024,
        tolerance_ms: FLOOD_TICK_MS,
    };

    println!("\n  degree   F'(d) ms   alpha(d)   shortfall vs design 0.90");
    println!("  ------   --------   --------   ------------------------");

    // §16.4's pre-registered band boundary, and NOT a round number picked for
    // tidiness: D9(b) pays iff (1-a)·E > a·L, so a* = E/(E+L), and E <= L
    // makes a* <= 0.5 with equality only at E = L. 0.5 is therefore the
    // SUPREMUM of a* over the whole admissible pricing region — the weakest
    // assertion that discharges the rule without committing to values for E
    // and L, which is why it can be armed before either is measured. The one
    // premise this cannot see is E <= L itself (argued in §17.1, not
    // measured); if that fails, this stays green while the ruling stops
    // following. Asserting it here is what converts the frozen rule from a
    // document into something CI enforces — a rule that was frozen once,
    // versus a rule that stays frozen.
    const PREREGISTERED_ALPHA_BOUNDARY: f64 = 0.5;
    // Degrees where the OutboundOnly flood strands >10 % of nodes, so the
    // question is ill-posed and the instrument must REFUSE. Asserted, not
    // skipped: a refusal that silently became a reading (or spread to degree
    // 4) would change what the sweep claims without reddening anything.
    const MUST_REFUSE: [usize; 2] = [1, 2];

    let mut rows = Vec::new();
    for degree in [1_usize, 2, 4, 6, 8, 9, 10, 11, 12] {
        let flood = FloodParams {
            nodes: NODES,
            peers: degree,
            reach: FloodReach::OutboundOnly,
        };
        let degrees = vec![degree; NODES];
        let f_prime = match converged_fluff_return_mixed(
            flood,
            &degrees,
            MEAN_QUARTER_SECS,
            shekyl_relay_privacy::schedule::DelayFamily::Geometric,
            &SEEDS,
            budget,
            SplitMix64::new,
        ) {
            Ok(c) => c.p90_ms,
            Err(e) => {
                // A refusal is a reading: at very low degree the flood strands
                // nodes, and `Stranded` says the topology cannot support the
                // question rather than giving a number that looks finite.
                println!("  {degree:6}   REFUSED   {e}");
                assert!(
                    MUST_REFUSE.contains(&degree),
                    "degree {degree} REFUSED but is inside the answerable range — \
                     the sweep's coverage shrank and every claim about 'every \
                     measurable degree' is now over a smaller set than §17 records"
                );
                continue;
            }
        };
        // Fail loudly, never clamp: `unwrap_or(u32::MAX)` here would feed a
        // fabricated F' into alpha and report a number for a measurement that
        // did not happen. (The Ok arm already excludes u64::MAX — a stranded
        // p90 surfaces as a `Stranded` refusal, not a value.)
        let f_ms = u32::try_from(f_prime).unwrap_or_else(|_| {
            panic!(
                "converged p90 {f_prime} ms at degree {degree} exceeds u32 — \
                    not a value to clamp, a measurement to refuse"
            )
        });
        let a = alpha_at(f_ms);
        println!(
            "  {degree:6}   {f_ms:8}   {a:8.6}   {:+.6}",
            a - EMBARGO_FULL_TRAVEL_PROBABILITY
        );
        rows.push((degree, f_ms, a));
    }

    let at12 = rows.iter().find(|r| r.0 == 12).map(|r| r.2);
    if let Some(a12) = at12 {
        println!("\n  reference: alpha(12) = {a12:.6} against the design input 0.90");
    }

    // Monotonicity is the structural claim, and it is asserted rather than
    // eyeballed: a lower degree floods more slowly, so alpha must not rise.
    for w in rows.windows(2) {
        assert!(
            w[0].2 <= w[1].2 + 1e-12,
            "alpha FELL as degree ROSE ({} -> {}): {} then {}. Either the \
             flood measurement or the survival exponent has its sign inverted",
            w[0].0,
            w[1].0,
            w[0].2,
            w[1].2
        );
    }
    assert!(!rows.is_empty(), "no degree produced a reading");

    // The refusals must actually have refused. Without this, a future change
    // that lets degree 1-2 return a finite-looking number would silently
    // extend the curve into the region §17.2 records as ill-posed.
    for d in MUST_REFUSE {
        assert!(
            !rows.iter().any(|r| r.0 == d),
            "degree {d} produced a reading but the topology strands >10 % of \
             nodes there — a finite number in the ill-posed region"
        );
    }

    // THE PRE-REGISTERED RULE (§16.4, committed a5804d9c7 before this file
    // existed): alpha above 0.5 at every answering degree rules D9(b) off the
    // provisioning floor, robustly for any E <= L — and alpha never entering
    // the band anywhere measurable is the sharper mode: the MECHANISM is
    // wrong, not its threshold. This assertion is that ruling, armed. If a
    // change to the flood model or the survival derivation ever pushes alpha
    // into the band, this reddens and the D9(b) question REOPENS rather than
    // drifting.
    for (degree, f_ms, a) in &rows {
        assert!(
            *a > PREREGISTERED_ALPHA_BOUNDARY,
            "alpha({degree}) = {a:.6} (F' = {f_ms} ms) entered the pre-registered \
             band [0.1, 0.5] or below — §16.4's ruling no longer follows from \
             the measurement and §12.2's D9(b) question must be REOPENED, not \
             patched here"
        );
    }
}
