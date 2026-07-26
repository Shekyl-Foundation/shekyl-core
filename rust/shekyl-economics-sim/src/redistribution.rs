// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **A2 — distributional shift (wargame W6)**, §12.2.
//!
//! **The concern, precisely.** The D1 fix moves **ex-zero bulk holders** into
//! `Σwork`. Under pre-D1 scoring a shard past the co-holder cliff
//! (`r_market > g_milli ≈ 1000`) scored **zero**, so its holders were absent from
//! the denominator entirely and **scarce-holders** — holders of *low*-`r`,
//! high-scarcity shards — divided the whole budget among themselves. Post-D1 the
//! ex-zeros enter, `Σwork` grows, and every incumbent's share **dilutes**. W6 asks:
//! by how much, and does it strand scarce holders **below their marginal cost**?
//!
//! **"Scarce-holder" is about *what* you hold, not *how much*.** So the population
//! crosses the DQ-2H **size** classes with a **holding-scarcity** dimension (which
//! replication band the archiver's shards sit in). Size alone cannot express W6 —
//! the diluting cohort is defined by holding *common* (high-`r`) shards.
//!
//! **Deletion collapses the regime axis (D3/R2).** With the plateau gone there is
//! no naive/rational split to sweep: credited work **is** work, so
//! `PlateauDeleted` is the sole live regime and each class's credit is exactly its
//! `Scoring::{PreD1,PostD1}::work_milli`. That is why this arm is simpler than its
//! §12.2 spec anticipated — the cap that would have needed a behavioural axis no
//! longer exists.
//!
//! **Disposition (§12.2):** *descriptive* — quantify the redistribution; **flag**
//! if it strands scarce holders below marginal cost.

use shekyl_archival_retention::{reward_share_floor, ARCHIVAL_BOND_FLOOR_ATOMIC};

use crate::burden::{COIN, OPP_COST_RATE_BAND, SHARD_BYTES};
use crate::proxy::{epochs_per_year, STORAGE_FIAT_PER_BYTE_YEAR};
use crate::stranding::{Scoring, ARCHIVER_CLASSES};

/// Holding-scarcity bands: `(per-mille of archivers, r_market of their shards)`.
/// Spans **both sides of the co-holder cliff** — the last band is the cohort that
/// scored a structural **zero** pre-D1 and enters `Σwork` post-D1, which is the
/// whole mechanism W6 is about.
pub const SCARCITY_BANDS: &[(u32, u64)] = &[
    (100, 2),     // scarce      — few co-holders, highest per-shard scarcity
    (600, 6),     // target      — R_target
    (200, 50),    // popular
    (100, 3_000), // common/hot  — PAST the cliff: pre-D1 zero, post-D1 pays
];

/// One `(size × scarcity)` cell of the population.
#[derive(Debug, Clone, Copy)]
pub struct Cell {
    pub shards: u64,
    pub r_market: u64,
    /// Fraction of all archivers in this cell.
    pub frac: f64,
}

/// The crossed population. Size and holding-scarcity are treated as independent,
/// so a cell's weight is the product of its two marginals.
#[must_use]
pub fn population() -> Vec<Cell> {
    let mut cells = Vec::new();
    for &(size_pm, shards) in ARCHIVER_CLASSES {
        for &(scar_pm, r) in SCARCITY_BANDS {
            cells.push(Cell {
                shards,
                r_market: r,
                frac: (f64::from(size_pm) / 1000.0) * (f64::from(scar_pm) / 1000.0),
            });
        }
    }
    cells
}

/// Per-cell outcome under one scoring.
#[derive(Debug, Clone, Copy)]
pub struct CellOutcome {
    pub cell: Cell,
    /// Credited work (milli) for **one** archiver in this cell. Under R2 there is
    /// no curve, so credited work *is* work.
    pub work_milli: u64,
    /// This cell's share of the whole pool (all archivers in it, summed).
    pub pool_share: f64,
    /// One archiver's reward, atomic units per epoch.
    pub reward_atomic: u64,
    /// One archiver's marginal cost, SKL per epoch (bond opportunity cost +
    /// storage). The comparison the "stranded below marginal cost" flag needs.
    pub cost_skl: f64,
    /// `reward − cost`, SKL per epoch. Negative ⇒ this cell is under water.
    pub margin_skl: f64,
}

/// One archiver's marginal cost per epoch, SKL: locked-bond opportunity cost
/// (`ARCHIVAL_BOND_FLOOR` per shard) plus storage, both prorated to one settlement
/// epoch. `fiat_per_skl` converts the fiat storage leg; the bond leg is
/// SKL-denominated and price-independent (F-G).
#[must_use]
pub fn marginal_cost_skl_per_epoch(shards: u64, opp_rate: f64, fiat_per_skl: f64) -> f64 {
    let epy = epochs_per_year();
    let bond_skl =
        (u128::from(ARCHIVAL_BOND_FLOOR_ATOMIC) * u128::from(shards)) as f64 / COIN as f64;
    let bond_leg = bond_skl * opp_rate / epy;
    let storage_fiat = shards as f64 * SHARD_BYTES * STORAGE_FIAT_PER_BYTE_YEAR / epy;
    bond_leg + storage_fiat / fiat_per_skl
}

/// Score the population under `scoring`, distributing `budget_atomic` (one epoch's
/// pool) through the **production** `reward_share_floor`. `archivers` scales the
/// cell fractions into counts for the `Σwork` denominator.
#[must_use]
pub fn score(
    budget_atomic: u64,
    archivers: u64,
    scoring: Scoring,
    opp_rate: f64,
    fiat_per_skl: f64,
) -> Vec<CellOutcome> {
    let cells = population();
    // Σwork over the whole population — the denominator D1 changes.
    let mut sigma: u128 = 0;
    let mut work: Vec<u64> = Vec::with_capacity(cells.len());
    for c in &cells {
        let w = scoring.work_milli(c.shards, c.r_market);
        work.push(w);
        let count = (c.frac * archivers as f64) as u128;
        sigma += u128::from(w) * count;
    }
    let sigma_u64 = u64::try_from(sigma).unwrap_or(u64::MAX);

    cells
        .iter()
        .zip(work.iter())
        .map(|(&cell, &w)| {
            let reward = reward_share_floor(budget_atomic, w, sigma_u64);
            let count = cell.frac * archivers as f64;
            let pool_share = if budget_atomic == 0 {
                0.0
            } else {
                (reward as f64 * count) / budget_atomic as f64
            };
            let cost_skl = marginal_cost_skl_per_epoch(cell.shards, opp_rate, fiat_per_skl);
            CellOutcome {
                cell,
                work_milli: w,
                pool_share,
                reward_atomic: reward,
                cost_skl,
                margin_skl: reward as f64 / COIN as f64 - cost_skl,
            }
        })
        .collect()
}

/// Total pool share of every cell whose holdings sit at or below `r_at_most` — the
/// **scarce-holder** aggregate, which is the quantity W6 says D1 dilutes.
#[must_use]
pub fn scarce_share(outcomes: &[CellOutcome], r_at_most: u64) -> f64 {
    outcomes
        .iter()
        .filter(|o| o.cell.r_market <= r_at_most)
        .map(|o| o.pool_share)
        .sum()
}

/// A2 report: the W6 redistribution, per-class margins, and the stranding flag.
/// `budget_per_epoch` comes from the A1-conditional envelope (the surviving
/// candidate's pool at the scenario's `n`), so the margins are measured against
/// the funding a survivor actually delivers.
pub fn a2_report(budget_per_epoch: u64, archivers: u64, label: &str) {
    // Binding case for the flag: highest opportunity-cost rate (F-G), mid price.
    let opp = OPP_COST_RATE_BAND[OPP_COST_RATE_BAND.len() - 1];
    let price = 0.10;
    let pre = score(budget_per_epoch, archivers, Scoring::PreD1, opp, price);
    let post = score(budget_per_epoch, archivers, Scoring::PostD1, opp, price);

    eprintln!(
        "\nA2 — distributional shift (W6, §12.2): does D1 bringing ex-zero bulk holders\n\
         into Σwork dilute SCARCE holders below their marginal cost? Population =\n\
         DQ-2H size classes x holding-scarcity bands {BANDS:?} (per-mille, r). The last\n\
         band sits PAST the co-holder cliff — a structural zero pre-D1, paid post-D1,\n\
         which is the whole mechanism. Regime = PLATEAU DELETED (D3/R2), the sole live\n\
         regime: no curve, so credited work IS work and there is no naive/rational axis.\n\
         Margin = reward - (bond opp cost @ {OPP:.0}% + storage), SKL/epoch, at {L}.",
        BANDS = SCARCITY_BANDS,
        OPP = opp * 100.0,
        L = label,
    );
    eprintln!(
        "{:>7} {:>8} {:>9} {:>12} {:>12} {:>13} {:>13} {:>9}",
        "shards", "r", "work_mil", "share PRE", "share POST", "reward SKL", "cost SKL", "margin"
    );
    for (a, b) in pre.iter().zip(post.iter()) {
        eprintln!(
            "{:>7} {:>8} {:>9} {:>12.5} {:>12.5} {:>13.6} {:>13.6} {:>9}",
            b.cell.shards,
            b.cell.r_market,
            b.work_milli,
            a.pool_share,
            b.pool_share,
            b.reward_atomic as f64 / COIN as f64,
            b.cost_skl,
            if b.margin_skl >= 0.0 { "ok" } else { "UNDER" },
        );
    }
    let s_pre = scarce_share(&pre, 50);
    let s_post = scarce_share(&post, 50);
    let stranded: Vec<&CellOutcome> = post.iter().filter(|o| o.margin_skl < 0.0).collect();
    let scarce_stranded = stranded.iter().filter(|o| o.cell.r_market <= 50).count();
    eprintln!(
        "  -> Scarce-holder (r<=50) aggregate share: PRE-D1 {SP:.4} -> POST-D1 {SO:.4}\n\
         (dilution {D:.2}% of their former share — the W6 quantum, DESCRIPTIVE).\n\
         Cells under water post-D1: {N} of {T} ({SS} of them scarce-holders).\n\
         FLAG: {FLAG}",
        SP = s_pre,
        SO = s_post,
        D = if s_pre > 0.0 {
            (s_pre - s_post) / s_pre * 100.0
        } else {
            0.0
        },
        N = stranded.len(),
        T = post.len(),
        SS = scarce_stranded,
        FLAG = if scarce_stranded > 0 {
            "SCARCE HOLDERS STRANDED BELOW MARGINAL COST — escalate per §12.2"
        } else {
            "no scarce holder stranded below marginal cost"
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: u64 = 500_000_000_000; // 500 SKL/epoch
    const ARCHIVERS: u64 = 20_000;

    #[test]
    fn population_weights_sum_to_one() {
        let total: f64 = population().iter().map(|c| c.frac).sum();
        assert!(
            (total - 1.0).abs() < 1e-9,
            "cell weights must partition: {total}"
        );
    }

    #[test]
    fn pre_d1_zeroes_the_past_cliff_cohort_and_post_d1_pays_it() {
        // The W6 mechanism, made executable: the r=3000 band is a structural zero
        // pre-D1 (floor(1000/3000) = 0 per shard) and earns post-D1.
        let pre = score(BUDGET, ARCHIVERS, Scoring::PreD1, 0.05, 0.10);
        let post = score(BUDGET, ARCHIVERS, Scoring::PostD1, 0.05, 0.10);
        let past_cliff_pre: u64 = pre
            .iter()
            .filter(|o| o.cell.r_market == 3_000)
            .map(|o| o.work_milli)
            .sum();
        let past_cliff_post: u64 = post
            .iter()
            .filter(|o| o.cell.r_market == 3_000)
            .map(|o| o.work_milli)
            .sum();
        assert_eq!(past_cliff_pre, 0, "pre-D1 must zero the past-cliff cohort");
        assert!(past_cliff_post > 0, "post-D1 must pay it");
    }

    #[test]
    fn d1_dilutes_scarce_holders_which_is_exactly_w6() {
        // W6's claim: bringing ex-zeros into Σwork shrinks incumbents' shares. The
        // arm is DESCRIPTIVE, so this pins the direction, not a threshold.
        let pre = score(BUDGET, ARCHIVERS, Scoring::PreD1, 0.05, 0.10);
        let post = score(BUDGET, ARCHIVERS, Scoring::PostD1, 0.05, 0.10);
        let s_pre = scarce_share(&pre, 50);
        let s_post = scarce_share(&post, 50);
        assert!(
            s_post < s_pre,
            "D1 must dilute scarce holders: pre={s_pre} post={s_post}"
        );
    }

    #[test]
    fn margins_respond_to_the_opportunity_cost_band() {
        // The margin's dominant term is the bond opportunity cost (F-G), so a
        // higher rate must not raise any cell's margin.
        let lo = score(
            BUDGET,
            ARCHIVERS,
            Scoring::PostD1,
            OPP_COST_RATE_BAND[0],
            0.10,
        );
        let hi = score(
            BUDGET,
            ARCHIVERS,
            Scoring::PostD1,
            OPP_COST_RATE_BAND[2],
            0.10,
        );
        for (a, b) in lo.iter().zip(hi.iter()) {
            assert!(b.margin_skl <= a.margin_skl + 1e-12);
        }
    }
}
