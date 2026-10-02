// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Physical archival-**burden** model for the Stage-2 sim
//! (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §12, DQ-2A / DQ-2B).
//!
//! The funding side (`budget.rs`) already exists; this is the burden side the
//! §12.2 arms weigh it against. It is deliberately a set of **pure functions
//! over explicit, swept model parameters** — the two least-knowable inputs are
//! carried as parameters, never embedded:
//!
//! - **Kryder rate** ([`KryderRate`], DQ-2B) — the annual fiat `$/byte`
//!   storage-cost decline. `0%` is the binding clearance case.
//! - **`SKL/fiat` price** (DQ-2A / N-1) — `reward_P` is atomic SKL but
//!   `burden_cost` is fiat, so the two are not commensurable without an
//!   exchange rate. It is exogenous, constant per run, and swept; it lands with
//!   the A1 clearance arm (the first arm that compares a SKL reward to a fiat
//!   burden). The report states the **trend-vs-absolute** corollary (trends are
//!   robust, absolute clearance is conditional on the price band — the Filecoin
//!   provider-exodus face as a swept parameter).
//!
//! Everything here is `f64` per DQ-2G (measurement precision; the *escalation*
//! candidates are the only integer-`curve_milli` surface). The shard-count
//! mapping is **not** re-derived — it calls the consensus
//! [`shard_of`] on a fold of production-predicted archival bytes
//! ([`normal_tx_archival_bytes`]), so the sim cannot drift from the partition
//! (`SHT-Q2`; `ARCHIVAL_SHARD_COUNT_CUTOVER.md` §F step 3).

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_tx_weight::{predict_archival_len, InputCount, OutputCount};
use shekyl_types::{shard_of, ArchivalLength, SHARD_LENGTH};

use crate::calibration::tree_depth_for_leaves;

/// Atomic units per SKL — the SKL/atomic conversion factor.
pub const COIN: u64 = 1_000_000_000;

/// Bytes an archiver stores per closed shard: **`W`**, the archival length of a
/// shard (`shekyl_types::SHARD_LENGTH`, sourced from
/// `config/consensus_constants.json` `archival_shard_length_bytes`; `SHT-Q2`).
/// A shard is *defined* as `W` bytes of archival good — `|pqc_auths| +
/// |prunable|` over its transactions — so this is the unit, not a modelling
/// mean. The partition assigns a transaction to the shard its **starting**
/// offset falls in (`rules/tx.rs`, SHT-Q2), so shard `k` actually holds
/// `W + (overshoot_k − overshoot_{k−1})`: it begins where the previous
/// shard's last transaction ended and ends where its own does. Summed over
/// any run of consecutive shards that **telescopes** — `n` shards hold
/// `n · W` plus under one transaction in total, and a capped holding of
/// `MAX_HOLDINGS_SHARDS` consecutive shards is off from `n · W` by at most
/// two transactions (one at each end). `n · SHARD_BYTES` is therefore exact
/// to within a transaction for the whole-corpus and the capped-holding
/// burdens alike; the per-shard `± one transaction` (≤ 5 % by the §9
/// selection rule) is not an occupancy this omits, it is where one shard's
/// bytes end and the next's begin. The unprunable skeleton every node keeps
/// is not the archiver's burden and is not counted. As `f64` because the fiat
/// arithmetic below is `f64` (DQ-2G); the integer authority is the typed
/// constant.
pub const SHARD_BYTES: f64 = SHARD_LENGTH.to_raw() as f64;

/// Outputs per ordinary transaction (1-in / 2-out typical traffic). Drives the
/// honest **curve-tree depth** (`leaves = tx_volume · this`), which sets the
/// FCMP proof size in every transaction's archival length. The **stuffer**
/// uses the archival-per-fee shape instead (`calibration.rs`, DQ-2C directive
/// 2), not this value.
pub const OUTPUTS_PER_TX_NORMAL: f64 = 2.0;

/// The ordinary transaction's shape: 1-in / 2-out, the pair
/// [`OUTPUTS_PER_TX_NORMAL`] states as a mean.
#[must_use]
pub fn normal_tx_shape() -> (InputCount, OutputCount) {
    (InputCount::clamped(1), OutputCount::clamped(2))
}

/// Archival bytes one ordinary (1-in / 2-out) transaction adds to the fold
/// when the curve tree holds `chain_leaves` outputs — the production
/// predictor's archival length at the production depth, never a byte model of
/// the sim's own (DQ-2G dep-don't-mirror). Fee-independent: the fee varint is
/// in the unprunable prefix.
#[must_use]
pub fn normal_tx_archival_bytes(chain_leaves: u64) -> u64 {
    let (n_in, n_out) = normal_tx_shape();
    predict_archival_len(n_in, n_out, tree_depth_for_leaves(chain_leaves)) as u64
}

/// Leaves (outputs) an honest 1-in / 2-out chain holds once it has closed
/// `closed_shards` shards — the inverse of the honest fold, for arms that
/// sample the operand `n` directly and need the curve-tree depth at that
/// chain size. `n · W` archival bytes at `normal_tx_archival_bytes` per tx,
/// `OUTPUTS_PER_TX_NORMAL` leaves per tx; the per-tx length depends on the
/// depth it is solving for, so two iterations settle it (the same converge
/// the fee path runs). A **modelling** map (honest composition), not a
/// consensus derivation: the chain does not record leaves-per-shard.
#[must_use]
pub fn honest_leaves_at_closed_shards(closed_shards: u64) -> u64 {
    let bytes = closed_shards.saturating_mul(SHARD_LENGTH.to_raw());
    let mut leaves: u64 = 0;
    for _ in 0..2 {
        let per_tx = normal_tx_archival_bytes(leaves).max(1);
        leaves = ((bytes / per_tx) as f64 * OUTPUTS_PER_TX_NORMAL) as u64;
    }
    leaves
}

/// Base annual storage cost at year 0, fiat `$/byte`. Amortized commodity HDD:
/// ~`$0.02/GB` capital over a ~5-year service life plus power/redundancy
/// overhead ≈ `$0.01/GB/yr` ⇒ `1.0e-2 / 1e9 B` = `1.0e-11 $/B/yr`. A swept
/// baseline (the Kryder rate declines it over time); order-of-magnitude, not a
/// point claim (N-1 corollary).
pub const BASE_STORAGE_FIAT_PER_BYTE_YEAR: f64 = 1.0e-11;

/// Exogenous `SKL/fiat` price band (DQ-2A / N-1): fiat per 1 SKL. The
/// **least-knowable** input — swept, never embedded (A1 consumes it). A wide
/// spread on purpose: `$0.01` (bear / token-price collapse — the Filecoin
/// exodus face), `$0.10` (mid), `$1.00` (bull). Absolute clearance is reported
/// *conditional* on which member holds; the robust outputs are the trend
/// comparisons.
pub const SKL_FIAT_PRICE_BAND: [f64; 3] = [0.01, 0.10, 1.00];

/// Seated replicas per deep shard (`R_target`; L15 lean ≈ 6). The **network**
/// stores this many copies of every frozen shard, so the whole-network storage
/// burden is `n · R · SHARD_BYTES`. (`engine.rs`'s `ArchivalLockModel` uses the
/// same 6.)
pub const REPLICAS_PER_SHARD: u64 = 6;

/// Exogenous opportunity-cost-rate band (F-G, ratified): annual yield foregone
/// on locked bond capital. `2%` risk-free / `5%` moderate-alt / `10%` high;
/// **10% is the binding case** (highest bar for staking to clear). Another
/// least-knowable exogenous, swept like Kryder/price. Float: it lives in the
/// scenario/boundary layer (DQ-2G), applied at the single conversion below.
pub const OPP_COST_RATE_BAND: [f64; 3] = [0.02, 0.05, 0.10];

/// Whole-network locked bond capital at `n` frozen shards, in **atomic units**
/// — the binding staker burden's principal (F-G). Integer, single-sourced from
/// the consensus `ARCHIVAL_BOND_FLOOR_ATOMIC` (`750_000_000` = 0.75 SKL) ·
/// `R` · `n`, so the algorithm zone stays integer (DQ-2G seam rule). The
/// exogenous opportunity-cost rate is the *only* float, applied once in
/// [`bond_opp_cost_skl`].
#[must_use]
pub fn locked_bond_atomic(n: u64) -> u128 {
    u128::from(ARCHIVAL_BOND_FLOOR_ATOMIC) * u128::from(REPLICAS_PER_SHARD) * u128::from(n)
}

/// Annual opportunity cost of the locked bond capital, SKL (F-G). The locked
/// principal is integer atomic; the **single float boundary** is the exogenous
/// rate multiply — the SKL result is a reporting/comparison quantity, not an
/// algorithm-zone intermediate (DQ-2G).
#[must_use]
pub fn bond_opp_cost_skl(n: u64, opp_cost_rate: f64) -> f64 {
    (locked_bond_atomic(n) as f64 / COIN as f64) * opp_cost_rate
}

/// The DQ-2B storage-cost-decline band. Annual fractional decline in fiat
/// `$/byte`; the report states the provenance, never bare numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KryderRate {
    /// `0%/yr` — the Kryder-stall / Arweave failure face. **Binding** clearance
    /// case (§12.2 A1): a shape "clears" only if it holds here.
    Stall,
    /// `~10%/yr` — the post-2010s `$/GB` slowdown.
    Slowdown,
    /// `~25%/yr` — the long-run historical `$/GB` decline.
    Historical,
}

impl KryderRate {
    /// The full DQ-2B band, in report order (binding case first).
    pub const BAND: [KryderRate; 3] = [
        KryderRate::Stall,
        KryderRate::Slowdown,
        KryderRate::Historical,
    ];

    /// Annual fractional decline in `$/byte`.
    #[must_use]
    pub fn annual_decline(self) -> f64 {
        match self {
            KryderRate::Stall => 0.0,
            KryderRate::Slowdown => 0.10,
            KryderRate::Historical => 0.25,
        }
    }

    /// Report label carrying the provenance (DQ-2B).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            KryderRate::Stall => "0%/yr (Kryder-stall / Arweave failure face; BINDING)",
            KryderRate::Slowdown => "10%/yr (post-2010s $/GB slowdown)",
            KryderRate::Historical => "25%/yr (long-run historical $/GB decline)",
        }
    }
}

/// Closed shards (the D2 operand `n`) at a cumulative archival length — the
/// consensus partition [`shard_of`], **not** re-derived (single source). This
/// is what the validator reads at parent state
/// (`shekyl_chain_rules::closed_shards_before` is `shard_of` of the recorded
/// fold), so the sim's `n` and the chain's `n` are one function of one
/// quantity.
#[must_use]
pub fn closed_shards(cumulative_archival_bytes: u64) -> u64 {
    shard_of(ArchivalLength::from_raw(cumulative_archival_bytes)).to_raw()
}

/// Fiat `$/byte` for storage in year `year`, under a Kryder decline off
/// `base_fiat_per_byte_year`. Floors at 0 years (no pre-genesis discount).
#[must_use]
pub fn storage_fiat_per_byte_year(
    year: f64,
    base_fiat_per_byte_year: f64,
    kryder: KryderRate,
) -> f64 {
    let y = year.max(0.0);
    base_fiat_per_byte_year * (1.0 - kryder.annual_decline()).powf(y)
}

/// Annual fiat cost to hold `shards` closed shards in year `year`. This is the
/// **whole-corpus** burden — pass the D2 operand `n` (total closed shards),
/// which grows unbounded.
///
/// **The per-archiver cost is capped**, and the A1/A2 arms apply that cap over
/// the DQ-2H population: a single bond holds at most `MAX_HOLDINGS_SHARDS`
/// (4,096) shards, so one archiver's storage burden tops out at `4096 · W`
/// ≈ **12.3 GB** — the figure §7.4 uses for W10's honest cost. The
/// whole-corpus `n` drives the *escalation*; the capped per-archiver holdings
/// drive the *cost* side of clearance.
#[must_use]
pub fn burden_cost_fiat_per_year(
    shards: u64,
    year: f64,
    base_fiat_per_byte_year: f64,
    kryder: KryderRate,
) -> f64 {
    (shards as f64)
        * SHARD_BYTES
        * storage_fiat_per_byte_year(year, base_fiat_per_byte_year, kryder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_shards_is_the_partition() {
        // One shard closes at exactly W archival bytes, not before — the
        // consensus `shard_of`, read through the sim's one call site.
        let w = SHARD_LENGTH.to_raw();
        assert_eq!(closed_shards(w - 1), 0);
        assert_eq!(closed_shards(w), 1);
        assert_eq!(closed_shards(2 * w + 5), 2);
        assert!((SHARD_BYTES - w as f64).abs() < f64::EPSILON);
    }

    #[test]
    fn honest_leaves_inverts_the_fold_to_within_a_shard() {
        // Fold the honest composition forward from the leaves the inverse
        // reports and land back on the same closed-shard count: the two
        // directions share one per-tx length, so they must agree.
        for n in [1u64, 100, 10_000, 1_000_000] {
            let leaves = honest_leaves_at_closed_shards(n);
            let txs = leaves as f64 / OUTPUTS_PER_TX_NORMAL;
            let bytes = txs * normal_tx_archival_bytes(leaves) as f64;
            let back = closed_shards(bytes as u64);
            assert!(
                back.abs_diff(n) <= 1,
                "n={n}: inverse gave {leaves} leaves, folding back gives n={back}"
            );
        }
        // A 1-in/2-out tx is a few KB of archival good, so W buys hundreds of
        // them: the per-shard leaf count is in the hundreds, not the tens of
        // thousands the retired J-segment held.
        let per_tx = normal_tx_archival_bytes(1_000_000);
        assert!(
            (1_000..20_000).contains(&per_tx),
            "per-tx archival {per_tx}"
        );
    }

    #[test]
    fn kryder_stall_is_flat_others_decline() {
        let base = BASE_STORAGE_FIAT_PER_BYTE_YEAR;
        // 0%/yr: price is identical at year 0 and year 10 (the binding case).
        assert_eq!(
            storage_fiat_per_byte_year(0.0, base, KryderRate::Stall),
            storage_fiat_per_byte_year(10.0, base, KryderRate::Stall),
        );
        // 25%/yr: year-10 price is strictly below year-0.
        assert!(
            storage_fiat_per_byte_year(10.0, base, KryderRate::Historical)
                < storage_fiat_per_byte_year(0.0, base, KryderRate::Historical)
        );
        // All three coincide at year 0 (decline hasn't applied yet).
        for k in KryderRate::BAND {
            assert!((storage_fiat_per_byte_year(0.0, base, k) - base).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn burden_grows_with_shards_and_stalls_worst() {
        let base = BASE_STORAGE_FIAT_PER_BYTE_YEAR;
        // Monotone in shard count at a fixed year/rate.
        let c1 = burden_cost_fiat_per_year(100, 5.0, base, KryderRate::Stall);
        let c2 = burden_cost_fiat_per_year(200, 5.0, base, KryderRate::Stall);
        assert!(c2 > c1 && (c2 - 2.0 * c1).abs() < 1e-6 * c1);
        // At a fixed shard count/year, Stall is the most expensive band member
        // (no decline) — the binding case.
        let year = 8.0;
        let stall = burden_cost_fiat_per_year(500, year, base, KryderRate::Stall);
        for k in [KryderRate::Slowdown, KryderRate::Historical] {
            assert!(burden_cost_fiat_per_year(500, year, base, k) <= stall);
        }
    }
}
