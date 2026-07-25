// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DQ-2H archiver **population** model — the served-work distribution the A4 (W9)
//! ROI gate weighs the stuffer against, and the substrate the A2/A3 distribution
//! / stranding arms will reuse.
//!
//! **Why served work, not stake (the A4 channel correction).** The D2
//! `staker_pool` is the *archival* reward pool: `epoch_close_compute` distributes
//! it by **served work per bond** (`sigma_work_milli(work_by_bond, curve)` →
//! `reward_share_floor(pool, my_capped_work, Σwork)`), scarcity-weighted, *not* by
//! stake fraction. So an attacker captures the raised pool only by **archiving**
//! the shards they stuff — bonding `ARCHIVAL_BOND_FLOOR` per shard and storing
//! them forever. That coupling is §6.2's "stuffing it funds it", and it is the
//! defense; a stake-fraction model would delete it.
//!
//! **The replica-count invariant (why the tail shape mostly cancels).** At age 0,
//! a shard served by `r` replicas scores `scarcity_micro = WORK_MICRO_SCALE / r`
//! per replica, so its **total** pre-curve work across all `r` servers is
//! `WORK_MICRO_SCALE` — *independent of `r`*. The heavy tail therefore moves
//! `Σwork` **only** through the per-bond `curve_milli` plateau cap: a big bond
//! (many shards → work far past the knee) is capped and earns almost nothing per
//! shard; small bonds stay in the linear region. That concentration lever — not
//! the tail — is what A4 probes, so `holdings_per_bond` is an explicit swept axis
//! rather than a guessed constant.
//!
//! **DQ-2G — every work value flows through the production reward chain**
//! (`scarcity_micro` → `work_milli_from_micro` → `curve_milli` /
//! `reward_share_floor`), never a re-expression; only the honest holdings size and
//! the replica tail are model parameters, and both are swept.

use shekyl_archival_retention::{
    curve_milli, scarcity_micro, work_milli_from_micro, BandedCurveParams,
};

/// Provisional consensus reward curve — the same `from_sim_cap_milli(8_000)`
/// (`plateau_work = 16_000`, `plateau_value = 8_000`) `epoch_close_compute`'s
/// tests and `EpochCloseInputs` default pin.
#[must_use]
pub fn reward_curve() -> BandedCurveParams {
    BandedCurveParams::from_sim_cap_milli(8_000)
}

/// Shard age in the scarcity term. Pinned to **0** — the attacker-favouring
/// floor: `g(age)` only *boosts* older (incumbent) shards' scarcity, enlarging
/// honest `Σwork` and shrinking the stuffer's capture fraction. Age 0 for both
/// honest and attacker shards removes that incumbency advantage — the strongest
/// case for the stuffer (so a passing gate is robust to it).
pub const AGE_MILLI: u64 = 0;

/// Age-weight `age_weight_milli`. Irrelevant at [`AGE_MILLI`] `= 0` (`g` collapses
/// to the base regardless), carried explicitly so the age-0 choice — not a hidden
/// default — is what zeroes the incumbency term.
pub const AGE_WEIGHT_MILLI: u64 = 1_000;

/// DQ-2H replica-count tail: `(per-mille of shards, r_market)` bands — a common
/// core at the target replica count plus a stranded (under-replicated) head and a
/// popular/hot (over-replicated) tail. Deterministic; the per-shard `1/r`
/// scarcity cancels `r` in the pre-curve total (see the module note), so these
/// weights move `Σwork` only through the per-bond cap.
pub const DQ2H_TAIL: &[(u32, u64)] = &[
    (100, 2),  // 10% stranded  (under-replicated — high scarcity per replica)
    (700, 6),  // 70% common    (= R_target)
    (150, 12), // 15% popular
    (50, 30),  // 5% hot        (over-replicated — low scarcity per replica)
];

/// `r_market` for shard `i` of `n` under `tail`, spread across the index by
/// `i % 1000` so consecutive holdings chunks get a representative band mix (no
/// RNG — deterministic and resume-safe).
#[must_use]
pub fn shard_r_market(i: u64, tail: &[(u32, u64)]) -> u64 {
    let bucket = (i % 1000) as u32;
    let mut acc = 0u32;
    for &(per_mille, r) in tail {
        acc += per_mille;
        if bucket < acc {
            return r;
        }
    }
    // Bands should sum to 1000; fall back to the last band if they under-fill.
    tail.last().map_or(1, |&(_, r)| r)
}

/// Honest `Σwork(E)` in milli over `n` shards with replica tail `tail`, when each
/// honest bond holds `holdings_per_bond` shard-slots. Builds each bond's work
/// through the production chain (`scarcity_micro` summed in micro →
/// `work_milli_from_micro` → `curve_milli`) so the per-bond plateau cap is real.
///
/// A shard with `r` replicas occupies `r` bond-slots (each scoring
/// `scarcity_micro(r)`); slots are laid out shard-major and chunked into bonds, so
/// the concentration a large `holdings_per_bond` causes — work past the knee,
/// capped — is modelled exactly, not approximated.
#[must_use]
pub fn honest_sigma_work_milli(n: u64, tail: &[(u32, u64)], holdings_per_bond: u64) -> u64 {
    let holdings = holdings_per_bond.max(1);
    let curve = reward_curve();
    let mut sigma = 0u64;
    let mut bond_micro = 0u64;
    let mut in_bond = 0u64;
    let flush = |bond_micro: &mut u64, sigma: &mut u64| {
        let milli = work_milli_from_micro(*bond_micro);
        *sigma = sigma.saturating_add(curve_milli(milli, &curve));
        *bond_micro = 0;
    };
    for i in 0..n {
        let r = shard_r_market(i, tail);
        let s = scarcity_micro(r, AGE_MILLI, AGE_WEIGHT_MILLI);
        // One slot per replica of this shard.
        for _ in 0..r {
            bond_micro = bond_micro.saturating_add(s);
            in_bond += 1;
            if in_bond == holdings {
                flush(&mut bond_micro, &mut sigma);
                in_bond = 0;
            }
        }
    }
    if in_bond > 0 {
        flush(&mut bond_micro, &mut sigma);
    }
    sigma
}

/// The stuffer's first-mover capped work (milli): `delta` fresh shards served at
/// `r = 1` (sole server, age 0 → maximal scarcity), grouped into bonds of
/// `holdings_per_bond`. The attacker picks a *small* grouping to stay under the
/// plateau knee (full credit) — attacker-favouring; the same production chain.
#[must_use]
pub fn attacker_capped_work_milli(delta: u64, holdings_per_bond: u64) -> u64 {
    let holdings = holdings_per_bond.max(1);
    let curve = reward_curve();
    let s = scarcity_micro(1, AGE_MILLI, AGE_WEIGHT_MILLI); // r = 1, sole first-mover
    let mut sigma = 0u64;
    let mut remaining = delta;
    while remaining > 0 {
        let this = remaining.min(holdings);
        let milli = work_milli_from_micro(s.saturating_mul(this));
        sigma = sigma.saturating_add(curve_milli(milli, &curve));
        remaining -= this;
    }
    sigma
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_bands_sum_to_full() {
        let total: u32 = DQ2H_TAIL.iter().map(|&(p, _)| p).sum();
        assert_eq!(
            total, 1000,
            "DQ-2H tail must partition the shard population"
        );
    }

    #[test]
    fn replica_invariant_uncapped_sigma_is_near_n_times_base() {
        // A shard's total pre-curve work across its r replicas is r-independent —
        // but EXACTLY so only in micro (r · WORK_MICRO_SCALE/r = WORK_MICRO_SCALE);
        // the per-bond milli floor (`work_milli_from_micro`) drops each slot's
        // sub-milli remainder, so at holdings=1 (max split, no capping) Σwork sits
        // just BELOW n · 1000 by that flooring loss (< 1 milli per slot). The
        // r-independence still holds up to the loss, so a wildly different tail
        // lands within a milli-per-shard of the same value.
        let n = 5_000u64;
        let sigma = honest_sigma_work_milli(n, DQ2H_TAIL, 1);
        assert!(
            sigma <= n * 1_000 && sigma >= n * 990,
            "uncapped Σwork must be ~n·1000 (below by the per-slot floor): {sigma}"
        );
        // Flat all-r=6 tail: each slot floors 1e6/6 = 166_666 µ → 166 m, ×6 = 996.
        let flat_tail: &[(u32, u64)] = &[(1000, 6)];
        assert_eq!(honest_sigma_work_milli(n, flat_tail, 1), n * 996);
        // The two tails agree to within the per-shard flooring slack (< 1000/shard).
        assert!(sigma.abs_diff(n * 996) < n);
    }

    #[test]
    fn large_bonds_are_capped_below_uncapped() {
        // Big holdings push each bond far past the plateau → capped, so Σwork is
        // strictly below the uncapped n × base. This is the concentration lever.
        let n = 5_000u64;
        let uncapped = honest_sigma_work_milli(n, DQ2H_TAIL, 1);
        let capped = honest_sigma_work_milli(n, DQ2H_TAIL, 512);
        assert!(
            capped < uncapped,
            "large bonds must be curve-capped: capped={capped} uncapped={uncapped}"
        );
    }

    #[test]
    fn attacker_work_scales_and_small_grouping_beats_large() {
        // Small (uncapped) grouping yields more credited work than one big capped
        // bond for the same Δn — why the attacker splits (and we model them doing
        // so, attacker-favouring).
        let delta = 1_000u64;
        let small = attacker_capped_work_milli(delta, 4);
        let big = attacker_capped_work_milli(delta, delta);
        assert!(
            small > big,
            "small grouping must dodge the cap: {small} !> {big}"
        );
    }
}
