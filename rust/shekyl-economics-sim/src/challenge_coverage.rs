// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Challenge-coverage urn simulation — the executable derivation behind the
//! fork-1 ruling in `docs/design/ARCHIVAL_CHALLENGE_MECHANISM.md` (§7.1):
//! **exact-min urn**, tail accepted.
//!
//! One settlement epoch of the issuance urn is simulated: each block draws
//! from the pairs at the minimum issued-challenge count (`exact-min`), or
//! from the pairs at `{min, min+1}` (`band`, the rejected alternative kept
//! here so the ruling's evidence base stays reproducible). Three quantities
//! ground the ruling:
//!
//! - **Wave-tail exposure**: the fraction of draws made while the candidate
//!   set is small enough that a pair's draw is predictable within `τ` blocks
//!   (`m ≤ k_avg·τ`). Exact-min has the closed form `exposure(τ) = 3τ/SEB`
//!   (scale-invariant in `D`, because `k_avg = 3D/SEB`); the ruling's
//!   arithmetic prices this against the outer window and accepts it.
//! - **Issued-count histogram** at epoch close: exact-min converges to
//!   exactly 3 per pair at exact budget; the band pays a heavy variance
//!   (~23 % of pairs at issued-2) — the cost side of its rejection. The
//!   histogram is an `(m, n)` derivation input.
//! - **The capped regime** (`k_cap`-bound budget): the figure that justifies
//!   the tx-carrier prunable-residence work — at maturity with permanent
//!   3.43 KB records, 72 % of pairs are unobservable per epoch.
//!
//! The RNG is a local SplitMix64: deterministic across platforms, no new
//! dependency (rule 17), and randomness here only breaks ties inside the
//! candidate set — every reported aggregate is insensitive to seed at the
//! tolerances asserted (the genesis tests run three seeds to show it).

use serde::Serialize;

use shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;

/// Advance-notice thresholds, in blocks, at which exposure is reported.
/// `W₂` is underived (doc §9), so the exposure curve is parameterized
/// rather than evaluated at a point.
pub const NOTICE_TAUS: [u64; 4] = [25, 50, 100, 200];

/// Deterministic SplitMix64 — tie-breaking only (see module doc).
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform draw in `[0, n)` by rejection (no modulo bias).
    /// `n` must be nonzero — an empty range has no uniform draw.
    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "uniform draw from an empty range");
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next();
            if v < zone {
                return v % n;
            }
        }
    }
}

/// Pairs grouped by issued count with O(1) uniform pick + move: the draw
/// selects by index inside the candidate buckets, so a swap-remove keeps
/// every operation constant-time without a position map.
struct Buckets {
    count: Vec<u32>,
    /// `lists[c]` = pair ids at issued count `c`.
    lists: Vec<Vec<u32>>,
    min_count: usize,
}

impl Buckets {
    fn new(d: u32) -> Self {
        Buckets {
            count: vec![0; d as usize],
            lists: vec![(0..d).collect()],
            min_count: 0,
        }
    }

    fn bucket_len(&self, c: usize) -> usize {
        self.lists.get(c).map_or(0, Vec::len)
    }

    /// Draw one pair uniformly from the candidate set and bump its count.
    /// Returns `(pair, candidate_set_size_at_draw)`.
    fn draw(&mut self, band: bool, rng: &mut SplitMix64) -> (u32, usize) {
        let lo = self.bucket_len(self.min_count);
        let hi = if band {
            self.bucket_len(self.min_count + 1)
        } else {
            0
        };
        let m = lo + hi;
        let r = rng.below(m as u64) as usize;
        let c = if r < lo {
            self.min_count
        } else {
            self.min_count + 1
        };
        let idx = if r < lo { r } else { r - lo };
        let p = self.lists[c][idx];

        self.lists[c].swap_remove(idx);

        self.count[p as usize] += 1;
        if self.lists.len() <= c + 1 {
            self.lists.push(Vec::new());
        }
        self.lists[c + 1].push(p);

        while self.min_count < self.lists.len() && self.lists[self.min_count].is_empty() {
            self.min_count += 1;
        }
        (p, m)
    }
}

/// One epoch's simulation output.
#[derive(Debug, Serialize)]
pub struct CoverageRun {
    pub variant: &'static str,
    pub pairs: u32,
    pub total_draws: u64,
    pub seed: u64,
    /// `exposure[i]` = fraction of draws with advance notice ≤ `NOTICE_TAUS[i]`
    /// blocks (candidate set `m ≤ k_avg·τ` at draw time).
    pub exposure: [f64; 4],
    /// Issued-count histogram at epoch close: `(count, pairs_at_count)`.
    pub issued_hist: Vec<(u32, u32)>,
    /// 1st→2nd issuance gap percentiles in blocks (redraw-floor context);
    /// `None` when no pair received two draws.
    pub gap_p50: Option<u64>,
    pub gap_p99: Option<u64>,
}

/// Simulate one settlement epoch: `total_draws` spread evenly (Bresenham)
/// over `SETTLEMENT_EPOCH_BLOCKS` blocks, drawn from the exact-min urn or
/// the `(min, min+1)` band.
pub fn run_epoch(pairs: u32, total_draws: u64, band: bool, seed: u64) -> CoverageRun {
    assert!(
        pairs > 0,
        "a settlement epoch needs at least one bonded pair to draw from"
    );
    let seb = SETTLEMENT_EPOCH_BLOCKS;
    let mut rng = SplitMix64(seed.wrapping_mul(0x9e37_79b9).wrapping_add(1));
    let mut buckets = Buckets::new(pairs);
    let k_avg = total_draws as f64 / seb as f64;
    let mut exposed = [0u64; 4];
    let mut first_block = vec![u64::MAX; pairs as usize];
    let mut gaps: Vec<u64> = Vec::new();

    let mut done: u64 = 0;
    for h in 0..seb {
        // Even spread: draws completed through block h total ⌊(h+1)·total/SEB⌋.
        let due = ((h + 1) as u128 * total_draws as u128 / seb as u128) as u64;
        while done < due {
            let (p, m) = buckets.draw(band, &mut rng);
            done += 1;
            for (i, tau) in NOTICE_TAUS.iter().enumerate() {
                if (m as f64) <= k_avg * (*tau as f64) {
                    exposed[i] += 1;
                }
            }
            let n = buckets.count[p as usize];
            if n == 1 {
                first_block[p as usize] = h;
            } else if n == 2 {
                gaps.push(h - first_block[p as usize]);
            }
        }
    }

    let mut hist_map = std::collections::BTreeMap::new();
    for &c in &buckets.count {
        *hist_map.entry(c).or_insert(0u32) += 1;
    }
    gaps.sort_unstable();
    let pct = |q: f64| {
        if gaps.is_empty() {
            None
        } else {
            Some(gaps[((gaps.len() - 1) as f64 * q) as usize])
        }
    };

    CoverageRun {
        variant: if band { "band" } else { "exact-min" },
        pairs,
        total_draws,
        seed,
        exposure: std::array::from_fn(|i| exposed[i] as f64 / done as f64),
        issued_hist: hist_map.into_iter().collect(),
        gap_p50: pct(0.5),
        gap_p99: pct(0.99),
    }
}

/// The closed form the exact-min exposure matches:
/// `exposure(τ) = λ_target·τ/SEB` with `λ_target = total_draws/D` — for the
/// ruling's `λ = 3`, `3τ/SEB`, independent of `D`.
#[must_use]
pub fn exact_min_exposure_closed_form(total_draws: u64, pairs: u32, tau: u64) -> f64 {
    // Assert rather than return a silent `inf`: this is a derivation
    // function whose output feeds arithmetic, and a quiet NaN/inf is worse
    // than a loud stop in a sim.
    assert!(pairs > 0, "the closed form is undefined for zero pairs");
    (total_draws as f64 / pairs as f64) * tau as f64 / SETTLEMENT_EPOCH_BLOCKS as f64
}

/// The fork-1 evidence set: genesis + maturity at exact budget for both
/// variants, plus the `k_cap`-capped maturity regime (the §8 tx-carrier
/// justification figure). Deterministic; used by `--challenge-coverage`.
#[must_use]
pub fn evidence_runs() -> Vec<CoverageRun> {
    const GENESIS_D: u32 = 4_096;
    const MATURITY_D: u32 = 324_000;
    const K_CAP: u64 = 30;
    vec![
        run_epoch(GENESIS_D, 3 * GENESIS_D as u64, false, 1),
        run_epoch(GENESIS_D, 3 * GENESIS_D as u64, true, 1),
        run_epoch(MATURITY_D, 3 * MATURITY_D as u64, false, 1),
        run_epoch(MATURITY_D, 3 * MATURITY_D as u64, true, 1),
        run_epoch(MATURITY_D, K_CAP * SETTLEMENT_EPOCH_BLOCKS, true, 1),
    ]
}

/// `--challenge-coverage` entry: JSON to stdout, summary to stderr
/// (the crate's output convention).
pub fn run_and_print() {
    let runs = evidence_runs();
    for r in &runs {
        // Print the closed form next to the measurement for the ruled
        // variant, so the derivation self-checks in its own output.
        let closed_form = if r.variant == "exact-min" {
            format!(
                " closed_form(tau100)={:.3}%",
                exact_min_exposure_closed_form(r.total_draws, r.pairs, NOTICE_TAUS[2]) * 100.0
            )
        } else {
            String::new()
        };
        eprintln!(
            "{} D={} draws={}: exposure(tau100)={:.3}%{closed_form} hist={:?}",
            r.variant,
            r.pairs,
            r.total_draws,
            r.exposure[2] * 100.0,
            r.issued_hist
        );
    }
    let json = serde_json::to_string_pretty(&runs).expect("serializable");
    println!("{json}");
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS_D: u32 = 4_096;

    #[test]
    #[should_panic(expected = "at least one bonded pair")]
    fn zero_pairs_is_rejected_at_the_boundary() {
        // The empty candidate set fails loudly at the entry point with the
        // domain reason, not deep in the RNG with a divide-by-zero.
        let _ = run_epoch(0, 1, false, 1);
    }

    #[test]
    fn exact_min_converges_to_exactly_three_per_pair() {
        // The ruled variant's defining property at exact budget — and the
        // redraw floor with it (every pair reaches 3 ≥ 2 before close).
        for seed in [1, 2, 3] {
            let r = run_epoch(GENESIS_D, 3 * GENESIS_D as u64, false, seed);
            assert_eq!(r.issued_hist, vec![(3, GENESIS_D)], "seed {seed}");
        }
    }

    #[test]
    fn exact_min_exposure_matches_the_closed_form_and_is_scale_invariant() {
        // exposure(τ) = 3τ/SEB, independent of D. Tolerance is generous
        // (±20 % relative) because the tail is a small count; the point is
        // the shape and the scale-invariance, both of which a shape change
        // in the urn would break loudly.
        for d in [GENESIS_D, 4 * GENESIS_D] {
            let r = run_epoch(d, 3 * d as u64, false, 1);
            for (i, tau) in NOTICE_TAUS.iter().enumerate() {
                let expect = exact_min_exposure_closed_form(3 * d as u64, d, *tau);
                let got = r.exposure[i];
                assert!(
                    (got - expect).abs() <= 0.2 * expect,
                    "D={d} tau={tau}: exposure {got:.5} vs closed form {expect:.5}"
                );
            }
        }
    }

    #[test]
    fn band_cuts_exposure_but_pays_issued_count_variance() {
        // The rejected alternative's two sides, kept reproducible: exposure
        // strictly below exact-min's, paid for by pairs finishing at
        // issued-2 (symmetric with issued-4 by draw conservation).
        let exact = run_epoch(GENESIS_D, 3 * GENESIS_D as u64, false, 1);
        let band = run_epoch(GENESIS_D, 3 * GENESIS_D as u64, true, 1);
        assert!(band.exposure[2] < exact.exposure[2]);
        let at = |r: &CoverageRun, c: u32| {
            r.issued_hist
                .iter()
                .find(|(k, _)| *k == c)
                .map_or(0, |(_, n)| *n)
        };
        assert!(at(&band, 2) > 0, "band pays with under-issued pairs");
        assert_eq!(
            at(&band, 2),
            at(&band, 4),
            "draw conservation makes the spread symmetric"
        );
    }

    #[test]
    fn capped_budget_regime_reproduces_the_unobservable_fractions() {
        // The §8 justification figure at 1/100 scale (fractions are what
        // matter; the urn keeps counts within ±1 of the mean, so the split
        // is determined by the budget ratio 30·SEB/(3·324k) ≈ 0.309):
        // ~35 % at 0, ~37 % at 1, ~28 % at 2 — 72 % of pairs below the
        // absolute-2 observation floor.
        let d: u32 = 3_240;
        let draws = 3 * SETTLEMENT_EPOCH_BLOCKS / 10; // k_cap=30 at 1/100 D
        let r = run_epoch(d, draws, true, 1);
        let frac = |c: u32| {
            r.issued_hist
                .iter()
                .find(|(k, _)| *k == c)
                .map_or(0.0, |(_, n)| f64::from(*n) / f64::from(d))
        };
        assert!((frac(0) - 0.35).abs() < 0.03, "issued-0 {:.3}", frac(0));
        assert!((frac(1) - 0.37).abs() < 0.03, "issued-1 {:.3}", frac(1));
        assert!((frac(2) - 0.28).abs() < 0.03, "issued-2 {:.3}", frac(2));
        let unobservable = frac(0) + frac(1);
        assert!(
            unobservable > 0.69 && unobservable < 0.75,
            "under-issued (<2) fraction {unobservable:.3} strays from the ~72 % figure"
        );
    }

    /// Full-scale reproduction of the figures cited in
    /// `ARCHIVAL_CHALLENGE_MECHANISM.md` §7.1/§8 (run with `--ignored`;
    /// ~1M draws, a few seconds in release).
    ///
    /// The band's issued-2 fraction is **realization-dependent even at
    /// maturity scale** — the wave dynamics leave the straggler fraction
    /// high-variance (observed 23.3 % under one sampler and 30.0 % under
    /// this one, same D and budget) — so the assertion is the honest range
    /// plus the exact symmetry draw-conservation forces, not a point.
    #[test]
    #[ignore]
    fn full_scale_maturity_reproduces_doc_figures() {
        let d: u32 = 324_000;
        let band = run_epoch(d, 3 * d as u64, true, 1);
        let at = |c: u32| {
            band.issued_hist
                .iter()
                .find(|(k, _)| *k == c)
                .map_or(0, |(_, n)| *n)
        };
        let at2 = f64::from(at(2)) / f64::from(d);
        assert!(
            (0.10..=0.35).contains(&at2),
            "band issued-2 {at2:.3} outside the observed realization range"
        );
        assert_eq!(at(2), at(4), "draw conservation makes the spread symmetric");

        let capped = run_epoch(d, 30 * SETTLEMENT_EPOCH_BLOCKS, true, 1);
        let below2: u32 = capped
            .issued_hist
            .iter()
            .filter(|(k, _)| *k < 2)
            .map(|(_, n)| n)
            .sum();
        let unobservable = f64::from(below2) / f64::from(d);
        assert!(
            (unobservable - 0.72).abs() < 0.02,
            "capped under-issued fraction {unobservable:.3} vs 72 %"
        );
    }
}
