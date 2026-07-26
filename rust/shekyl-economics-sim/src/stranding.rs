// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A3 **budget stranding** (§12.2), with the pre-/post-**D1** comparison that is
//! the executable evidence for the Stage-0 coupling claim (§1).
//!
//! **What strands, and why it is real money.** `budget(E)` is a **minting
//! entitlement, not held coin**: budget unclaimed when the epoch leaves the claim
//! window (`MAX_CLAIM_AGE_W = 26`) is *"supply never created"* — no roll-forward,
//! no expiry sweep (`ARCHIVAL_BUDGET_SCHEDULE.md` §4, ratified; the R1.B
//! under-mint-never-over-mint posture extended from intra-epoch remainders to
//! whole epochs). *"`Σwork(E)` bounds the **shares**; `budget(E)` bounds the
//! **coins**"* — so a share that is never claimed is a coin that never exists.
//!
//! **The Stage-0 claim this arm tests (§1).** *"A zero-work archiver (D1) has
//! nothing claimable → their slice of any diverted budget goes unclaimed → never
//! mints. Raising the staker share (D2) while a cohort sits at structural zero
//! (D1) would enlarge a pool that partly evaporates."* This arm measures the
//! stranded fraction under **both** work scorings so the claim is evidence, not
//! assertion.
//!
//! **The two scorings.** Post-fix (production, `scarcity_micro` accumulated in
//! micro and floored **once** at the aggregate) is **called**, never mirrored
//! (DQ-2G). Pre-fix (`scarcity_milli`: floor `g/r` **per shard**) no longer exists
//! in production — D1 deleted it — so the counterfactual is re-expressed here and
//! labelled as such; re-expressing a *deleted* function for a historical
//! comparison is not a live mirror.
//!
//! **The cliff is a high-replication phenomenon.** Pre-fix scoring zeroes a shard
//! only past the **co-holder cliff** `r_market > g_milli` (≈ 1,000 co-holders at
//! age 0), so the pre/post gap appears only where replication is deep. Replication
//! is therefore derived from network size (`archivers · holdings / n`) rather than
//! pinned, so the model reaches the cliff only when the network actually would.

use shekyl_archival_retention::{
    curve_milli, g_age_milli, reward_share_floor, scarcity_micro, work_milli_from_micro,
    MAX_CLAIM_AGE_W, MAX_HOLDINGS_SHARDS,
};

use crate::population::{reward_curve, AGE_MILLI, AGE_WEIGHT_MILLI};

/// DQ-2H archiver size classes: `(share of archivers per-mille, shards held)` —
/// binary + heavy-tailed (many small, few at the `MAX_HOLDINGS_SHARDS` cap). The
/// **size spread is the stranding driver**: a small holder's reward can fall below
/// the cost of the claim transaction, so it is rationally never claimed.
pub const ARCHIVER_CLASSES: &[(u32, u64)] = &[
    (700, 16),                        // 70% hobbyist
    (250, 256),                       // 25% mid
    (50, MAX_HOLDINGS_SHARDS as u64), // 5% at the per-bond cap
];

/// Which work scoring to score the population under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scoring {
    /// **Pre-D1** counterfactual: per-shard `floor(g_milli / r_market)` — zero for
    /// every shard past the co-holder cliff (`r_market > g_milli`). Re-expressed
    /// here because D1 deleted it from production (see module note).
    PreD1,
    /// **Post-D1** production: `scarcity_micro` per shard, summed in micro, floored
    /// **once** at the aggregate via `work_milli_from_micro`. Called, not mirrored.
    PostD1,
}

impl Scoring {
    /// One bond's work (milli) holding `shards` shards each replicated `r_market`.
    #[must_use]
    pub fn work_milli(self, shards: u64, r_market: u64) -> u64 {
        match self {
            Scoring::PreD1 => {
                // Per-shard floor at MILLI — the D1 defect: `g/r` floors to 0 past
                // the cliff, so a bulk holder of common shards scores nothing.
                let g = g_age_milli(AGE_MILLI, AGE_WEIGHT_MILLI);
                let per_shard = if r_market == 0 { 0 } else { g / r_market };
                per_shard.saturating_mul(shards)
            }
            Scoring::PostD1 => {
                // Production path: accumulate micro, floor once at the aggregate.
                let per_shard_micro = scarcity_micro(r_market, AGE_MILLI, AGE_WEIGHT_MILLI);
                work_milli_from_micro(per_shard_micro.saturating_mul(shards))
            }
        }
    }
}

/// Mean replication implied by network size: `archivers · holdings / n`, floored
/// at 1. Deep replication is what pushes shards past the pre-fix cliff.
#[must_use]
pub fn mean_replication(archivers: u64, n_shards: u64) -> u64 {
    if n_shards == 0 {
        return 1;
    }
    let held: u128 = ARCHIVER_CLASSES
        .iter()
        .map(|&(per_mille, shards)| {
            u128::from(archivers) * u128::from(per_mille) / 1000 * u128::from(shards)
        })
        .sum();
    u64::try_from(held / u128::from(n_shards))
        .unwrap_or(u64::MAX)
        .max(1)
}

/// One class's stranding contribution.
#[derive(Debug, Clone, Copy)]
pub struct ClassOutcome {
    pub archivers: u64,
    pub reward_atomic_each: u64,
    pub claims: bool,
}

/// A3 result for one `(scenario-year, scoring)` point.
#[derive(Debug, Clone, Copy)]
pub struct StrandingOutcome {
    /// Fraction of `budget(E)` that never mints (unclaimed + floor remainder).
    pub stranded_fraction: f64,
    /// Fraction of archivers whose reward is below the claim cost.
    pub non_claiming_fraction: f64,
    /// Mean replication in this configuration (drives the pre-fix cliff).
    pub mean_r: u64,
    /// Bonds scoring **structurally zero** work (the D1 cohort), as a fraction.
    pub zero_work_fraction: f64,
}

/// Rational claim **cadence**, in settlement epochs. Rewards batch: an archiver
/// may claim once per `MAX_CLAIM_AGE_W` window, amortising **one** claim
/// transaction across that many epochs of accrued reward, which lowers the
/// claim-cost viability floor by the same factor. `1` is the naive per-epoch
/// claimer; [`MAX_CLAIM_AGE_W`] is the rational batcher and the **bound** on the
/// amortisation (claim later than that and the epoch expires — *supply never
/// created*, `ARCHIVAL_BUDGET_SCHEDULE.md` §4). Purely archiver-side behaviour:
/// **no consensus change**, which is what makes it the cheapest of the levers.
pub const RATIONAL_CLAIM_CADENCE_EPOCHS: u64 = MAX_CLAIM_AGE_W;

/// Measure stranding for one epoch's `budget_atomic` over the DQ-2H population,
/// under `scoring`. A class claims iff its accrued reward over
/// `claim_cadence_epochs` covers `claim_cost_atomic` (one claim transaction at
/// the fee floor) — the rational non-claim rule that turns small shares into
/// *supply never created*.
///
/// **Cadence is load-bearing** (do not leave it implicit): the per-epoch reward is
/// weighed against `claim_cost / cadence`, so a batching archiver's viability
/// floor is up to `MAX_CLAIM_AGE_W` (26×) below a naive per-epoch claimer's. An
/// earlier revision of this arm priced cadence `1` implicitly and therefore
/// *overstated* the floor — and with it the claim-cost force in the D3 triangle
/// (§12.8) — by that factor.
#[must_use]
pub fn measure(
    budget_atomic: u64,
    n_shards: u64,
    archivers: u64,
    claim_cost_atomic: u64,
    claim_cadence_epochs: u64,
    scoring: Scoring,
) -> StrandingOutcome {
    // Amortise one claim tx across the batching window.
    let claim_cost_atomic = claim_cost_atomic / claim_cadence_epochs.max(1);
    let mean_r = mean_replication(archivers, n_shards);
    let curve = reward_curve();

    // Per class: population count, capped work, and the Σwork contribution.
    let mut classes: Vec<ClassOutcome> = Vec::new();
    let mut sigma_milli: u128 = 0;
    let mut capped_by_class: Vec<u64> = Vec::new();
    for &(per_mille, shards) in ARCHIVER_CLASSES {
        let count = archivers * u64::from(per_mille) / 1000;
        let work = scoring.work_milli(shards, mean_r);
        let capped = if work > 0 {
            curve_milli(work, &curve)
        } else {
            0
        };
        sigma_milli += u128::from(capped) * u128::from(count);
        capped_by_class.push(capped);
        classes.push(ClassOutcome {
            archivers: count,
            reward_atomic_each: 0,
            claims: false,
        });
    }
    let sigma = u64::try_from(sigma_milli).unwrap_or(u64::MAX);

    // Per-archiver reward through the PRODUCTION distribution, then the rational
    // claim decision. Unclaimed shares — and the floor remainder — never mint.
    let mut minted: u128 = 0;
    let mut non_claiming = 0u64;
    let mut zero_work = 0u64;
    let total_archivers: u64 = classes.iter().map(|c| c.archivers).sum();
    for (i, c) in classes.iter_mut().enumerate() {
        let capped = capped_by_class[i];
        if capped == 0 {
            zero_work += c.archivers;
            non_claiming += c.archivers; // nothing claimable at all
            continue;
        }
        let reward = reward_share_floor(budget_atomic, capped, sigma);
        c.reward_atomic_each = reward;
        c.claims = reward >= claim_cost_atomic;
        if c.claims {
            minted += u128::from(reward) * u128::from(c.archivers);
        } else {
            non_claiming += c.archivers;
        }
    }

    let stranded = u128::from(budget_atomic).saturating_sub(minted);
    StrandingOutcome {
        stranded_fraction: if budget_atomic == 0 {
            0.0
        } else {
            stranded as f64 / budget_atomic as f64
        },
        non_claiming_fraction: if total_archivers == 0 {
            0.0
        } else {
            non_claiming as f64 / total_archivers as f64
        },
        mean_r,
        zero_work_fraction: if total_archivers == 0 {
            0.0
        } else {
            zero_work as f64 / total_archivers as f64
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_d1_zeroes_bulk_holders_past_the_cliff() {
        // The D1 defect, made executable: past the co-holder cliff (r > g_milli
        // ≈ 1000 at age 0) the pre-fix per-shard floor returns 0 for EVERY shard,
        // so a bulk holder scores nothing; the post-fix micro path still pays.
        let deep_r = 2_000; // past the cliff
        assert_eq!(Scoring::PreD1.work_milli(4_096, deep_r), 0);
        assert!(Scoring::PostD1.work_milli(4_096, deep_r) > 0);
        // Below the cliff both score, and pre-fix is never ABOVE post-fix
        // (per-shard flooring only discards).
        let shallow_r = 6;
        let pre = Scoring::PreD1.work_milli(4_096, shallow_r);
        let post = Scoring::PostD1.work_milli(4_096, shallow_r);
        assert!(pre > 0 && post > 0);
        assert!(
            pre <= post,
            "per-shard flooring cannot exceed the micro path"
        );
    }

    #[test]
    fn deep_replication_strands_more_under_pre_d1() {
        // The Stage-0 claim's testable core, at the regime where it actually
        // bites: an EARLY chain — few frozen shards, many archivers holding them ⇒
        // very deep replication ⇒ past the co-holder cliff. Pre-D1 puts the cohort
        // at structural zero and its budget share never mints; post-D1 must strand
        // no more. (As `n` grows, `r` falls below the cliff and the gap closes —
        // which is why the report sweeps the corpus trajectory, not a single `n`.)
        let budget = 1_000_000_000_000u64; // 1000 SKL/epoch
        let n = 1_000u64; // early corpus
        let archivers = 40_000u64;
        let claim_cost = 10_000_000u64; // 0.01 SKL
        let pre = measure(budget, n, archivers, claim_cost, 1, Scoring::PreD1);
        let post = measure(budget, n, archivers, claim_cost, 1, Scoring::PostD1);
        assert!(
            pre.mean_r > 1_000,
            "test must reach the cliff: r={}",
            pre.mean_r
        );
        assert!(
            pre.zero_work_fraction > 0.0,
            "pre-D1 must produce a structural-zero cohort"
        );
        assert_eq!(
            post.zero_work_fraction, 0.0,
            "D1 removes the structural zeros"
        );
        assert!(
            post.stranded_fraction <= pre.stranded_fraction,
            "D1 must not increase stranding at deep replication: pre={} post={}",
            pre.stranded_fraction,
            post.stranded_fraction
        );
    }

    #[test]
    fn stranded_fraction_is_bounded() {
        let out = measure(
            1_000_000_000_000,
            10_000,
            5_000,
            10_000_000,
            1,
            Scoring::PostD1,
        );
        assert!((0.0..=1.0).contains(&out.stranded_fraction));
        assert!((0.0..=1.0).contains(&out.non_claiming_fraction));
    }

    #[test]
    fn batching_lowers_the_claim_viability_floor() {
        // G-3: cadence is load-bearing. Batching to the MAX_CLAIM_AGE_W window
        // amortises one claim tx across 26 epochs, so a holder who cannot justify
        // claiming every epoch may still clear the floor when batching — the
        // claim-cost force in D3's triangle is cadence-dependent, bounded by 26x.
        let budget = 1_000_000_000u64; // small pool ⇒ small per-epoch rewards
        let (n, archivers) = (10_000u64, 3_000u64);
        let claim_cost = 5_000_000u64; // 0.005 SKL
        let naive = measure(budget, n, archivers, claim_cost, 1, Scoring::PostD1);
        let batched = measure(
            budget,
            n,
            archivers,
            claim_cost,
            RATIONAL_CLAIM_CADENCE_EPOCHS,
            Scoring::PostD1,
        );
        assert!(
            batched.non_claiming_fraction <= naive.non_claiming_fraction,
            "batching must not raise the non-claim fraction: naive={} batched={}",
            naive.non_claiming_fraction,
            batched.non_claiming_fraction
        );
        assert!(batched.stranded_fraction <= naive.stranded_fraction);
    }
}
