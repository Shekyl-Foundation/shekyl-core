// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **OQ-2** — sizing the R3 **minimum-holding admission floor** (D3 round, §12.8).
//!
//! **What R3 buys.** Today a small bond at deep replication locks real capital into
//! a **guaranteed-zero** position: the quantization boundary (§12.7 Finding 3) is
//! invisible at bonding time and discovered at claim time. An admission floor makes
//! the unviable bond **unrepresentable** rather than merely unprofitable — *do not
//! admit positions the frozen scale cannot pay*. That is consumer protection and
//! legibility in one consensus rule, and it **protects reach** rather than taxing
//! it: the positions it refuses were already zeros (G-4's eviction concern is about
//! evicting *viable* archivers, which this does not do).
//!
//! **The boundary, in closed form.** At age 0 a shard scores
//! `scarcity_micro(r) = floor(WORK_MICRO_SCALE / r)` micro, and a bond of `h`
//! shards credits `floor(h · scarcity_micro(r) / WORK_MICRO_PER_MILLI)` milli. So a
//! holding is viable exactly when that reaches 1 milli, i.e.
//!
//! ```text
//! min_holding(r) ≈ ceil(r / 1000)      (exactly: the least h with h·⌊1e6/r⌋ ≥ 1000)
//! ```
//!
//! — the mirror image of the `r > ~1000 × shards_held` cliff.
//!
//! **Why this is a genesis-provisional *number* under a frozen *shape*.** `r` is
//! dynamic (`archivers × holdings / n`), so the floor is forecast-dependent: it
//! follows the `bond_duration` freeze posture — **shape frozen, number re-pinned at
//! testnet** against measured replication, with a named reopen.

use shekyl_archival_retention::{
    scarcity_micro, work_milli_from_micro, MAX_HOLDINGS_SHARDS, WORK_MICRO_PER_MILLI,
};

use crate::population::{AGE_MILLI, AGE_WEIGHT_MILLI};
use crate::stranding::mean_replication;

/// Safety multiple applied to the forecast-`r` floor. `r` is a forecast, and
/// under-sizing is the costly direction — an under-sized floor admits bonds that
/// then score zero, which is exactly the harm R3 exists to prevent. Over-sizing
/// costs reach, so this is deliberately small.
pub const MIN_HOLDING_SAFETY_MULTIPLE: u64 = 2;

/// Least holding size (shards) that credits ≥ 1 milli at replication `r` — the
/// viability boundary. Computed through the **production** scarcity/floor chain,
/// not the closed form, so it cannot drift from consensus arithmetic.
#[must_use]
pub fn min_viable_holding(r_market: u64) -> u64 {
    let s = scarcity_micro(r_market, AGE_MILLI, AGE_WEIGHT_MILLI);
    if s == 0 {
        // Beyond even one-milli-per-whole-corpus; the closed form is unbounded.
        return MAX_HOLDINGS_SHARDS as u64;
    }
    // Least h with floor(h·s / WORK_MICRO_PER_MILLI) ≥ 1  ⇔  h ≥ ceil(PER_MILLI / s).
    WORK_MICRO_PER_MILLI.div_ceil(s).max(1)
}

/// Sanity: does `holding` actually credit non-zero work at `r`? Runs the exact
/// production path the consensus reward uses.
#[must_use]
pub fn credits_nonzero(holding: u64, r_market: u64) -> bool {
    let s = scarcity_micro(r_market, AGE_MILLI, AGE_WEIGHT_MILLI);
    work_milli_from_micro(s.saturating_mul(holding)) > 0
}

/// Recommended `min_holding` covering every replication in `r_samples`, with the
/// safety multiple applied. Clamped to `MAX_HOLDINGS_SHARDS` (a floor above the
/// wire cap would admit nothing — see [`composes_with_wire_cap`]).
#[must_use]
pub fn recommend_min_holding(r_samples: &[u64]) -> u64 {
    let worst = r_samples
        .iter()
        .map(|&r| min_viable_holding(r))
        .max()
        .unwrap_or(1);
    worst
        .saturating_mul(MIN_HOLDING_SAFETY_MULTIPLE)
        .min(MAX_HOLDINGS_SHARDS as u64)
}

/// **Composition check (OQ-2, second half).** A floor is only coherent if it sits
/// strictly below the wire cap — otherwise the admissible band is empty and the
/// rule admits nothing.
#[must_use]
pub fn composes_with_wire_cap(min_holding: u64) -> bool {
    min_holding >= 1 && min_holding < MAX_HOLDINGS_SHARDS as u64
}

/// **Clustering check (OQ-2, second half).** Would actors bunch at *exactly*
/// `min_holding`?
///
/// Under **R2 (plateau deleted)** credited work is **linear** in holdings, so bond
/// *count* does not change an actor's total credit — the splitting incentive that
/// motivated D3 is gone. What remains is a mild pressure the other way: each bond
/// floors independently, so splitting `h` into `k` bonds discards up to `k − 1`
/// sub-milli remainders. Hence **consolidation is weakly preferred and clustering
/// at the floor is not incentivised**. Returns the milli lost by splitting `holding`
/// into `min_holding`-sized bonds — the size of that anti-splitting pressure.
#[must_use]
pub fn splitting_loss_milli(holding: u64, min_holding: u64, r_market: u64) -> u64 {
    whole_credit_milli(holding, r_market).saturating_sub(split_credit_milli(
        holding,
        min_holding,
        r_market,
    ))
}

/// Credited milli holding `holding` shards as ONE bond at `r_market`.
#[must_use]
pub fn whole_credit_milli(holding: u64, r_market: u64) -> u64 {
    let s = scarcity_micro(r_market, AGE_MILLI, AGE_WEIGHT_MILLI);
    work_milli_from_micro(s.saturating_mul(holding))
}

/// Credited milli holding `holding` shards split into `min_holding`-sized bonds,
/// each floored independently — the split an actor would make under a floor.
#[must_use]
pub fn split_credit_milli(holding: u64, min_holding: u64, r_market: u64) -> u64 {
    let s = scarcity_micro(r_market, AGE_MILLI, AGE_WEIGHT_MILLI);
    let m = min_holding.max(1);
    let mut total = 0u64;
    let mut left = holding;
    while left > 0 {
        let take = left.min(m);
        total = total.saturating_add(work_milli_from_micro(s.saturating_mul(take)));
        left -= take;
    }
    total
}

/// OQ-2 report: the viability boundary across the A3 replication regimes, the
/// recommended provisional floor, and the composition/clustering checks.
pub fn oq2_report(archiver_band: &[u64], n_samples: &[u64]) {
    eprintln!(
        "\nOQ-2 (D3 round §12.8) — sizing the R3 minimum-holding admission floor.\n\
         Boundary (production chain, not a closed form): min_holding(r) = least h whose\n\
         h x scarcity_micro(r) reaches one milli ≈ ceil(r/1000) — the mirror of the\n\
         r > ~1000 x shards_held cliff. Purpose: make guaranteed-zero bonds\n\
         UNREPRESENTABLE rather than merely unprofitable (they lock capital into a\n\
         position the frozen scale cannot pay). Safety multiple = {SM}x.",
        SM = MIN_HOLDING_SAFETY_MULTIPLE
    );
    eprintln!(
        "{:<10} {:>9} {:>9} {:>14} {:>14}",
        "archivers", "n", "mean_r", "min_viable_h", "split-loss@4096"
    );
    let mut r_samples: Vec<u64> = Vec::new();
    for &n in n_samples {
        for &a in archiver_band {
            let r = mean_replication(a, n);
            r_samples.push(r);
            let mv = min_viable_holding(r);
            eprintln!(
                "{:<10} {:>9} {:>9} {:>14} {:>14}",
                a,
                n,
                r,
                mv,
                splitting_loss_milli(4_096, mv, r),
            );
        }
    }
    let rec = recommend_min_holding(&r_samples);
    eprintln!(
        "  -> RECOMMENDED provisional min_holding = {REC} shards ({SM}x the worst swept\n\
         boundary). Composes with the wire cap: {OK} (must sit strictly below\n\
         MAX_HOLDINGS_SHARDS = {CAP}). Genesis-provisional NUMBER under a frozen SHAPE\n\
         (bond_duration posture): re-pin at testnet against MEASURED replication, with a\n\
         named reopen — r is a forecast, and under-sizing is the costly direction\n\
         (an under-sized floor admits the very zero-scoring bonds R3 exists to refuse).\n\
         CLUSTERING: none expected. Under R2 (plateau deleted) credited work is LINEAR,\n\
         so bond count does not change total credit — the splitting incentive that\n\
         motivated D3 is gone. The residual pressure runs the other way: each bond\n\
         floors independently, so splitting discards sub-milli remainders (the\n\
         split-loss column). Consolidation is weakly preferred; nobody is pushed to sit\n\
         at exactly the floor.",
        REC = rec,
        SM = MIN_HOLDING_SAFETY_MULTIPLE,
        OK = composes_with_wire_cap(rec)
            && credits_nonzero(rec, *r_samples.iter().max().unwrap_or(&1)),
        CAP = MAX_HOLDINGS_SHARDS,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_matches_the_quantization_cliff() {
        // min_holding(r) ≈ ceil(r/1000) — the mirror of r > ~1000 × shards_held.
        for (r, expect) in [(6u64, 1u64), (1_000, 1), (5_000, 5), (100_000, 100)] {
            assert_eq!(min_viable_holding(r), expect, "min_viable_holding({r})");
        }
    }

    #[test]
    fn the_boundary_is_exact_in_both_directions() {
        // At the boundary the holding credits; one shard below it does not. This is
        // what makes the floor a *correct* admission rule rather than a guess.
        for r in [500u64, 5_000, 20_000, 100_000] {
            let h = min_viable_holding(r);
            assert!(credits_nonzero(h, r), "h={h} must credit at r={r}");
            if h > 1 {
                assert!(!credits_nonzero(h - 1, r), "h-1 must NOT credit at r={r}");
            }
        }
    }

    #[test]
    fn recommendation_composes_with_the_wire_cap() {
        let rec = recommend_min_holding(&[6, 100, 5_000, 20_000]);
        assert!(
            composes_with_wire_cap(rec),
            "floor {rec} must sit strictly below the wire cap"
        );
        // And it must actually cover the worst case it was sized against.
        assert!(credits_nonzero(rec, 20_000));
    }

    #[test]
    fn splitting_is_weakly_penalised_so_no_floor_clustering() {
        // Under R2 work is linear, so splitting cannot INCREASE credit; independent
        // per-bond flooring means it can only lose. That is the absence of the
        // clustering pressure OQ-2 asks about.
        // The property that matters: splitting NEVER pays. (At a `min_holding` that
        // divides the boundary exactly, each bond credits exactly 1 milli with no
        // remainder, so the loss is legitimately ZERO — the ideal case, not a
        // counterexample. What must never happen is split > whole.)
        for r in [500u64, 5_000, 20_000] {
            let m = min_viable_holding(r);
            for h in [64u64, 512, 4_096] {
                assert!(
                    split_credit_milli(h, m, r) <= whole_credit_milli(h, r),
                    "splitting must never pay: h={h} m={m} r={r}"
                );
            }
        }
        // A split that does NOT divide the boundary strictly discards remainders.
        let r = 5_000;
        assert!(splitting_loss_milli(4_096, min_viable_holding(r) + 2, r) > 0);
    }
}
