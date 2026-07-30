// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! TJ-4 and TJ-7 — the two inequalities the `(m, n)` re-pin needs and nobody
//! had derived (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §10.4, §11.6).
//!
//! Both were **asserted** in the design round and registered in `FOLLOWUPS.md`
//! as underived. They share a structure — a gain that saturates against a cost
//! that grows — so they share this module and one sweep.
//!
//! # TJ-4 — the slash/`Rebond` cycle
//!
//! The claim was: no minimum observation count means a fresh or reinstated pair
//! is unslashable for its first `m − 1` observations, so a free-rider's steady
//! state is *"zero service, 10 free epochs, slash, `Rebond`, 10 more"* — a
//! subscription fee if `free_epochs × reward` exceeds `BOND_FLOOR + friction`.
//!
//! **The left-hand side needed correcting before it could be derived, and the
//! correction comes from the reward path itself.** A zero-service `P` earns
//! **nothing**: [`shekyl_archival_retention::consensus_state::shard_work_micro`]
//! returns `0` without serve credit, `r_market_count` skips uncredited rows, and
//! `reward_share_floor` pays on credited work. So the `m − 1` epochs are free of
//! **slash**, not free **money**, and the inequality is only non-trivial when
//! the pair *is* being credited — i.e. when some fraction `f` of its epochs draw
//! a friendly (falsely attesting) witness.
//!
//! So the derived quantity is not a yes/no but a **break-even `f`**: the
//! attestation fraction at which the cycle's earnings cover the burned bond.
//!
//! **A second correction fell out of building it.** §9.6 read
//! `f ≈ (n − m + 1)/n` as the point above which the window never slashes. That
//! bounds an adversary who can **place** its passing epochs; §8.2's draw is
//! **unchooseable**, so friendly witnesses arrive at random and windows with
//! `m` misses still occur. Absorption is **deferred, not prevented** — the
//! unchooseable draw is doing more work than §9.6 credited, and the cycle
//! question stays live across the whole range.
//!
//! # TJ-7 — sybil-per-shard dilution
//!
//! `r_market_count` counts every credited row — no `(P, shard)` uniqueness, no
//! operator dedup — so sybil-per-shard is bounded only by capital. But per-shard
//! work is `C·g/r` across `r` credited bonds, so **the shard's pool is
//! conserved**: `N` sybils against `h` honest co-holders take `N/(N+h)·g`, not
//! `N·g`. The attack is **dilution**, its gain **saturates at `g`**, and its
//! cost is **linear in `N`** — so it has a finite optimum and is priceable.
//!
//! Rather than invent an opportunity-cost rate, this module reports the
//! **break-even rate**: the annual return on locked capital below which the
//! dilution attack pays. A reader supplies their own rate and reads off the
//! verdict.

use core::fmt;

use shekyl_archival_retention::{ARCHIVAL_BOND_FLOOR_ATOMIC, FAILURE_WINDOW_M, FAILURE_WINDOW_N};

use crate::burden::COIN;
use crate::proxy::{absorb_table, epochs_per_year, PRIOR_STATES};

/// Per-shard bonded collateral at risk on one sustained-failure slash, SKL.
#[must_use]
pub fn bond_floor_skl() -> f64 {
    ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN as f64
}

/// The **deterministic** no-slash threshold: `(n − m + 1)/n` — §9.6's
/// `f ≈ 0.23` at `m=11/n=13`.
///
/// **It is a bound on a PLACING adversary, not on a random one, and the
/// distinction is load-bearing** (finding from building this arm, 2026-07-29).
/// An adversary that can *choose which* epochs pass needs only `n − m + 1`
/// passes per window and never slashes. But §8.2's draw is **unchooseable** —
/// friendly witnesses arrive at the cartel's hashrate share, at random — so the
/// cartel faces a **stochastic** process, and a random pattern still hits
/// windows with `m` misses. Absorption therefore still occurs above this
/// fraction; it merely takes longer ([`expected_epochs_to_slash`] measures how
/// much longer).
///
/// So the unchooseable draw is doing **more** work than §9.6 credited: it
/// converts a hard threshold into a soft one, and the cartel needs not just a
/// share of draws but the ability to *place* them, which the derivation denies.
#[must_use]
pub fn no_slash_attestation_fraction() -> f64 {
    f64::from(FAILURE_WINDOW_N - FAILURE_WINDOW_M + 1) / f64::from(FAILURE_WINDOW_N)
}

/// Expected epochs until a slash absorbs, for a pair credited on fraction `f`
/// of its epochs (so miss rate `q = 1 − f`).
///
/// Reuses [`absorb_table`] — the absorption condition **is** the production
/// predicate `failure_window_slashable`, not a re-derivation of its rule
/// (dep-don't-mirror, the same discipline the A5 arm's DP uses).
///
/// Returns `None` when less than 99 % of the mass has absorbed within
/// `horizon_epochs` — the honest report that the horizon is truncating the
/// tail, so any "expectation" would be a horizon artifact rather than a
/// property of `f`. Note this happens at `f` well **above**
/// [`no_slash_attestation_fraction`], not at it: random friendly draws do not
/// prevent absorption, they defer it.
#[must_use]
pub fn expected_epochs_to_slash(f: f64, horizon_epochs: u64) -> Option<f64> {
    let q = (1.0 - f).clamp(0.0, 1.0);
    let absorb = absorb_table();
    let mask = PRIOR_STATES - 1;
    let mut dist = vec![0.0_f64; PRIOR_STATES];
    dist[0] = 1.0;
    let mut next = vec![0.0_f64; PRIOR_STATES];
    let mut expected = 0.0_f64;
    let mut absorbed = 0.0_f64;
    for epoch in 1..=horizon_epochs {
        next.iter_mut().for_each(|v| *v = 0.0);
        for (state, &p) in dist.iter().enumerate() {
            if p < 1e-18 {
                continue;
            }
            let miss = p * q;
            if absorb[state] {
                expected += miss * epoch as f64;
                absorbed += miss;
            } else {
                next[((state << 1) | 1) & mask] += miss;
            }
            next[(state << 1) & mask] += p * (1.0 - q);
        }
        core::mem::swap(&mut dist, &mut next);
    }
    // Require most of the mass to have absorbed before quoting a mean; below
    // that the horizon is truncating the tail and the "expectation" would be a
    // horizon artifact rather than a property of `f`.
    if absorbed < 0.99 {
        return None;
    }
    Some(expected / absorbed)
}

/// One slash/`Rebond` cycle's net, SKL, for a pair credited on fraction `f`.
///
/// `earnings = E[epochs to slash] · f · reward_per_epoch_skl`;
/// `cost = bond_floor + friction`. Positive net means the cycle pays — the
/// "subscription fee" TJ-4 warned about.
#[must_use]
pub fn rebond_cycle_net_skl(
    f: f64,
    reward_per_epoch_skl: f64,
    friction_skl: f64,
    horizon_epochs: u64,
) -> Option<f64> {
    let epochs = expected_epochs_to_slash(f, horizon_epochs)?;
    let earnings = epochs * f * reward_per_epoch_skl;
    Some(earnings - (bond_floor_skl() + friction_skl))
}

/// The attestation fraction at which the cycle first breaks even.
///
/// Searched across the whole regime where absorption is measurable, **not**
/// capped at [`no_slash_attestation_fraction`] — see this module's second
/// correction: a randomly-drawn cartel still absorbs above that fraction.
///
/// `None` means the burned bond is never covered where the cycle completes —
/// the window is **not** a subscription fee at this reward level.
#[must_use]
pub fn rebond_breakeven_f(
    reward_per_epoch_skl: f64,
    friction_skl: f64,
    horizon_epochs: u64,
) -> Option<f64> {
    // Upper bound: the highest f at which absorption is still measurable within
    // the horizon; beyond it `expected_epochs_to_slash` reports None rather
    // than a truncation artifact.
    let mut hi_bound = 0.0_f64;
    for i in 1..=95 {
        let f = f64::from(i) / 100.0;
        if expected_epochs_to_slash(f, horizon_epochs).is_some() {
            hi_bound = f;
        }
    }
    let (mut lo, mut hi) = (0.0_f64, hi_bound);
    let net = |x: f64| rebond_cycle_net_skl(x, reward_per_epoch_skl, friction_skl, horizon_epochs);
    if net(hi).is_none_or(|v| v < 0.0) {
        return None;
    }
    if net(lo).is_some_and(|v| v >= 0.0) {
        return Some(0.0);
    }
    for _ in 0..60 {
        let mid = 0.5 * (lo + hi);
        match net(mid) {
            Some(v) if v >= 0.0 => hi = mid,
            _ => lo = mid,
        }
    }
    Some(hi)
}

/// TJ-7 gain: the share of shard `s`'s conserved pool `g` that `n_sybil` bonds
/// take from `h_honest` co-holders, above what a single honest bond would take.
///
/// `[ N/(N+h) − 1/(1+h) ] · g`, saturating at `g` as `N → ∞`.
#[must_use]
pub fn sybil_dilution_gain(n_sybil: u64, h_honest: u64, pool_g_skl: f64) -> f64 {
    if n_sybil == 0 {
        return 0.0;
    }
    let n = n_sybil as f64;
    let h = h_honest as f64;
    (n / (n + h) - 1.0 / (1.0 + h)) * pool_g_skl
}

/// The **annual** return on locked capital below which sybil-per-shard pays.
///
/// The cartel locks `(N − 1)` extra bond floors for a year to gain
/// `epochs_per_year · gain_per_epoch`. Reporting the break-even rate rather
/// than assuming one keeps the modeling parameter out of the verdict.
#[must_use]
pub fn sybil_breakeven_opportunity_rate(
    n_sybil: u64,
    h_honest: u64,
    pool_g_per_epoch_skl: f64,
) -> Option<f64> {
    if n_sybil <= 1 {
        return None;
    }
    let locked = (n_sybil - 1) as f64 * bond_floor_skl();
    if locked <= 0.0 {
        return None;
    }
    let annual_gain =
        sybil_dilution_gain(n_sybil, h_honest, pool_g_per_epoch_skl) * epochs_per_year();
    Some(annual_gain / locked)
}

/// TJ-4 + TJ-7 report — the two underived inequalities, derived.
pub fn tj_inequalities_report(
    out: &mut impl fmt::Write,
    reward_per_epoch_skl: f64,
    pool_g_per_epoch_skl: f64,
) -> fmt::Result {
    let ceiling = no_slash_attestation_fraction();
    writeln!(
        out,
        "\nTJ-4/TJ-7 — the two inequalities the (m,n) re-pin needs (m={M}/n={N}).\n\
         BOND_FLOOR = {BF:.3} SKL per shard. Deterministic no-slash fraction {C:.4}\n\
         bounds a PLACING adversary only; under an unchooseable draw absorption is\n\
         deferred, not prevented, so the cycle question stays live across the range.\n\
         !! OPERAND DIRECTION (label at the number): reward_per_epoch here is the\n\
         SCENARIO-FAMILY MAXIMUM per-shard pool. A5 uses that operand because a\n\
         larger forfeit is a STRONGER deterrent there, so max is conservative. For\n\
         TJ-4 it runs the OTHER WAY -- a larger reward makes the cycle MORE\n\
         profitable -- so every net below is the ALARM-RAISING end and the\n\
         break-even f is a LOWER bound. A representative-reward run is the honest\n\
         complement and is NOT yet done.",
        M = FAILURE_WINDOW_M,
        N = FAILURE_WINDOW_N,
        BF = bond_floor_skl(),
        C = ceiling,
    )?;
    writeln!(
        out,
        "  TJ-4 CORRECTION (reward path, verified): a ZERO-service P earns NOTHING\n\
         (shard_work_micro returns 0 without serve credit; reward pays on credited\n\
         work), so the m-1 unslashable epochs are free of SLASH, not free MONEY.\n\
         The inequality is only non-trivial when the pair is being credited, i.e.\n\
         at attestation fraction f > 0 — so the derived quantity is a break-even f."
    )?;
    writeln!(
        out,
        "{:<10} {:>14} {:>16} {:>16}",
        "f", "E[epochs]", "earnings SKL", "cycle net SKL"
    )?;
    for &f in &[0.0_f64, 0.02, 0.05, 0.10, 0.15, 0.20] {
        match (
            expected_epochs_to_slash(f, 4_000),
            rebond_cycle_net_skl(f, reward_per_epoch_skl, 0.0, 4_000),
        ) {
            (Some(e), Some(net)) => writeln!(
                out,
                "{:<10.3} {:>14.2} {:>16.4} {:>16.4}",
                f,
                e,
                e * f * reward_per_epoch_skl,
                net
            )?,
            _ => writeln!(out, "{f:<10.3} {:>14} {:>16} {:>16}", "no slash", "—", "—")?,
        }
    }
    match rebond_breakeven_f(reward_per_epoch_skl, 0.0, 4_000) {
        Some(f) => writeln!(
            out,
            "  -> TJ-4 break-even f = {f:.4} (friction 0 — the attacker-favourable end;\n\
             friction only raises it). Below it the burned bond is not covered and\n\
             the window is NOT a subscription fee; above it the cycle pays and\n\
             attestation-resistance is what must carry the deterrent.\n\
             NOTE: {ceiling:.4} is the DETERMINISTIC no-slash fraction, which bounds an\n\
             adversary that can PLACE its passing epochs. Under SS 8.2's unchooseable\n\
             draw the cartel cannot place them, so absorption still occurs above it\n\
             — deferred, not prevented."
        )?,
        None => writeln!(
            out,
            "  -> TJ-4: NO break-even f where the cycle completes — the burned bond is\n\
             never covered at this reward level, so the 'subscription fee' shape\n\
             does not arise and the binding constraint is entirely\n\
             attestation-resistance (the draw)."
        )?,
    }
    writeln!(
        out,
        "\n  TJ-7 sybil-per-shard: pool is CONSERVED (C*g/r over r credited bonds),\n\
         so N sybils vs h honest take N/(N+h)*g, NOT N*g — dilution, not\n\
         multiplication. Gain saturates at g = {G:.4} SKL/epoch; cost is linear in N.\n\
         Break-even = the ANNUAL return on locked capital below which it pays:",
        G = pool_g_per_epoch_skl,
    )?;
    writeln!(
        out,
        "{:<8} {:>8} {:>16} {:>22}",
        "N", "h", "gain SKL/epoch", "break-even rate/yr"
    )?;
    for &(n, h) in &[(2u64, 1u64), (5, 1), (5, 5), (20, 5), (100, 5), (100, 50)] {
        let gain = sybil_dilution_gain(n, h, pool_g_per_epoch_skl);
        let rate = sybil_breakeven_opportunity_rate(n, h, pool_g_per_epoch_skl);
        writeln!(
            out,
            "{:<8} {:>8} {:>16.5} {:>22}",
            n,
            h,
            gain,
            rate.map_or("—".to_string(), |r| format!("{:.1}%", r * 100.0))
        )?;
    }
    writeln!(
        out,
        "  -> the attack pays iff the cartel's real cost of locked capital is BELOW\n\
         the listed rate. Gain saturating at g while cost grows linearly gives a\n\
         finite optimal N — priceable, not unbounded. NOTE (§11.4): a single\n\
         operator behind N personas is NOT a mechanism concern — service is the\n\
         product, the linkage is unobservable by design (G-1), and participation\n\
         distribution is a tacit-vote outcome. This table prices DILUTION OF\n\
         HONEST CO-HOLDERS, which is a reward-fairness question, not a storage-\n\
         accounting one."
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_attestation_earns_nothing_so_the_cycle_cannot_pay() {
        // The TJ-4 correction, as a test: at f = 0 the pair is credited on no
        // epoch, so earnings are 0 and the cycle is a pure loss of the bond at
        // ANY reward level. The "10 free epochs" are free of slash, not money.
        for &reward in &[0.0_f64, 1.0, 100.0, 10_000.0] {
            let net = rebond_cycle_net_skl(0.0, reward, 0.0, 4_000).expect("absorbs at f=0");
            assert!(
                net < 0.0,
                "f=0 must lose the bond at reward {reward}, got net {net}"
            );
            assert!(
                (net + bond_floor_skl()).abs() < 1e-9,
                "f=0 earnings must be exactly zero"
            );
        }
    }

    #[test]
    fn the_deterministic_ceiling_does_not_stop_a_randomly_drawn_cartel() {
        // The finding this arm produced. §9.6's f ≈ 0.23 bounds an adversary
        // that CHOOSES which epochs pass. Under §8.2's unchooseable draw the
        // friendly witnesses arrive at random, so windows with m misses still
        // occur and absorption still happens ABOVE the deterministic ceiling —
        // it is deferred, not prevented. If this ever starts returning None at
        // the ceiling, the draw has become placeable and §9.6's hard reading
        // would be the correct one again.
        let ceiling = no_slash_attestation_fraction();
        let at = expected_epochs_to_slash(ceiling, 4_000);
        let above = expected_epochs_to_slash(ceiling + 0.05, 4_000);
        assert!(at.is_some(), "random draws at the ceiling still absorb");
        assert!(above.is_some(), "and above it");
        // Deferred, though: the wait grows with f.
        assert!(above.unwrap() > at.unwrap());
        // Far above, the horizon truncates and we report None rather than a
        // horizon artifact.
        assert!(expected_epochs_to_slash(0.95, 4_000).is_none());
    }

    #[test]
    fn expected_epochs_to_slash_is_monotone_in_attestation() {
        // More friendly draws => later slash. Monotonicity is what makes the
        // break-even bisection well-defined.
        let mut prev = 0.0;
        for i in 0..=8 {
            let f = f64::from(i) * 0.02;
            let e = expected_epochs_to_slash(f, 4_000).expect("absorbs below ceiling");
            assert!(e >= prev, "E[epochs] fell at f={f}: {e} < {prev}");
            prev = e;
        }
    }

    #[test]
    fn sybil_gain_is_dilution_and_saturates_at_the_pool() {
        // The conservation property: N sybils take N/(N+h)*g, never N*g, and the
        // gain is bounded by g however large N grows.
        let g = 10.0;
        let h = 5;
        let one = sybil_dilution_gain(1, h, g);
        assert!(one.abs() < 1e-12, "a single bond gains nothing over itself");
        let mut prev = 0.0;
        for &n in &[2u64, 10, 100, 10_000, 1_000_000] {
            let gain = sybil_dilution_gain(n, h, g);
            assert!(gain > prev, "gain must rise in N");
            assert!(
                gain < g,
                "gain must saturate below the pool g={g}, got {gain}"
            );
            prev = gain;
        }
        // Explicitly NOT multiplication: 100 sybils do not take 100x a single bond.
        assert!(sybil_dilution_gain(100, h, g) < 100.0 * (g / (1.0 + h as f64)));
    }

    #[test]
    fn sybil_breakeven_rate_falls_as_the_cartel_grows() {
        // Cost linear in N against a saturating gain => the break-even rate
        // falls, which is what gives the attack a finite optimum.
        let g = 1.0;
        let r2 = sybil_breakeven_opportunity_rate(2, 5, g).expect("N=2");
        let r100 = sybil_breakeven_opportunity_rate(100, 5, g).expect("N=100");
        assert!(
            r100 < r2,
            "break-even rate must fall with N: {r100} !< {r2}"
        );
        assert!(sybil_breakeven_opportunity_rate(1, 5, g).is_none());
    }
}
