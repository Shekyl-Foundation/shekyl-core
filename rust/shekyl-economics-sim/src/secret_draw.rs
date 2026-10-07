// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The secret per-block draw (ESR-11): one settlement epoch of the
//! serve-credit design in which each block's producer draws pairs from a
//! seed only it knows, and a draw is *issued* only when that seed is
//! revealed.
//!
//! The model, its scale, its one bar and its predictions were fixed before
//! this file existed (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`
//! §5.13). What is simulated:
//!
//! - **Dropout.** Each block is unrevealed with a fixed probability. An
//!   unrevealed block issues nothing: no passes and no misses.
//! - **Reveal lag.** A revealed block's seed lands a uniform `0..=W₂`
//!   blocks after it. Its draws are visible to every later block.
//! - **Weighting.** A draw picks a pair with replacement, weight 1 if the
//!   pair is visibly short of [`COUNTED_DRAWS`] issued draws and
//!   `1 / FULL_WEIGHT_DIVISOR` otherwise.
//! - **Count per block.** A base rate of one draw per pair per epoch plus a
//!   top-up that spreads the visible shortfall over a horizon, capped at
//!   [`CAP_MULTIPLE`] times nominal. Every input is an issued count; no
//!   outcome is read.
//!
//! The draw, the weighting and the count rule have no production owner yet,
//! so this module is a declared divergence (§4 of the same document): the
//! sim leads the code. The epoch length, `W₂`, the shard length and the
//! failure window are production's.
//!
//! The read itself is not modelled. Every revealed draw is issued whether or
//! not it passed, which is the design's own rule; pass and miss enter only
//! through the `(m, n)` re-check, analytically.

use serde::Serialize;

use shekyl_archival_retention::{
    CHALLENGE_RESPONSE_BLOCKS, FAILURE_WINDOW_M, FAILURE_WINDOW_N, SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_types::SHARD_LENGTH;

use crate::challenge_coverage::SplitMix64;
use crate::mn_feasibility::{default_sources, false_slash_bound, BOND_LIFE_EPOCHS};

/// Draws counted per pair at settlement, and the count a pair must reach to
/// be observed at all.
pub const COUNTED_DRAWS: u8 = 3;

/// A pair that is not visibly short is drawn at `1 / FULL_WEIGHT_DIVISOR`
/// the weight of one that is. PROVISIONAL (the brief's §2 item 3).
pub const FULL_WEIGHT_DIVISOR: u64 = 16;

/// The per-block count is capped at this multiple of nominal
/// (`COUNTED_DRAWS · D / SEB`). PROVISIONAL (§2 item 4).
pub const CAP_MULTIPLE: f64 = 3.0;

/// The top-up horizon never falls below this many blocks.
pub const MIN_HORIZON_BLOCKS: u64 = 200;

/// The top-up aims to finish by this share of the epoch, in per-mille.
pub const CATCH_UP_BY_PERMILLE: u64 = 700;

/// The bar, in per-mille of pairs short of [`COUNTED_DRAWS`] at 10 %
/// dropout. PROVISIONAL (the brief's ruling 6); graded on the maximum over
/// seeds.
pub const SHORT_BAR_PERMILLE: f64 = 30.0;

/// The dropout the bar is stated at, in per-mille of blocks.
pub const BAR_DROPOUT_PERMILLE: u32 = 100;

/// How "draws issued in the last `W₂` blocks" is read (§5.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InFlight {
    /// Draws of blocks in the last `W₂` whose seed is not yet revealed.
    Unrevealed,
    /// Every draw of the last `W₂` blocks, revealed or not.
    AllRecent,
}

impl InFlight {
    const fn label(self) -> &'static str {
        match self {
            Self::Unrevealed => "A (unrevealed only)",
            Self::AllRecent => "B (all recent)",
        }
    }
}

/// One simulated epoch.
#[derive(Debug, Clone, Serialize)]
pub struct DrawRun {
    pub pairs: u32,
    pub dropout_permille: u32,
    pub in_flight: InFlight,
    pub seed: u64,
    /// Draws made by every block, revealed or not.
    pub drawn: u64,
    /// Draws whose seed was revealed: the issued draws.
    pub issued: u64,
    /// Pairs by final issued count: `[0, 1, 2, ≥ 3]`.
    pub issued_hist: [u32; 4],
    /// Largest per-block draw count in the epoch.
    pub max_per_block: u64,
    /// Blocks whose count was held down by the cap.
    pub capped_blocks: u64,
    /// Issued draws answered by pairs that ended short: reads served in an
    /// epoch that settles NonObservation.
    pub unpaid_reads: u64,
}

impl DrawRun {
    /// Pairs that end short of [`COUNTED_DRAWS`] issued draws.
    #[must_use]
    pub fn short_pairs(&self) -> u32 {
        self.issued_hist[0] + self.issued_hist[1] + self.issued_hist[2]
    }

    /// Share of pairs that end short, in per-mille.
    #[must_use]
    pub fn short_permille(&self) -> f64 {
        f64::from(self.short_pairs()) * 1000.0 / f64::from(self.pairs)
    }

    /// Mean draws per block over the epoch, revealed or not.
    #[must_use]
    pub fn mean_per_block(&self) -> f64 {
        self.drawn as f64 / SETTLEMENT_EPOCH_BLOCKS as f64
    }

    /// Issued draws per pair.
    #[must_use]
    pub fn issued_per_pair(&self) -> f64 {
        self.issued as f64 / f64::from(self.pairs)
    }
}

/// The pairs, split by whether each is visibly short, with O(1) uniform
/// pick from either side and O(1) move from short to full.
struct Pairs {
    visible: Vec<u8>,
    short: Vec<u32>,
    full: Vec<u32>,
    /// Index of each pair in whichever list holds it.
    slot: Vec<u32>,
    /// `Σ max(0, COUNTED_DRAWS − visible)`.
    shortfall: u64,
}

impl Pairs {
    fn new(pairs: u32) -> Self {
        Self {
            visible: vec![0; pairs as usize],
            short: (0..pairs).collect(),
            full: Vec::new(),
            slot: (0..pairs).collect(),
            shortfall: u64::from(pairs) * u64::from(COUNTED_DRAWS),
        }
    }

    /// One weighted draw with replacement.
    fn draw(&self, rng: &mut SplitMix64) -> u32 {
        let short = self.short.len() as u64;
        let full = self.full.len() as u64;
        // Integer weights: a short pair weighs FULL_WEIGHT_DIVISOR, a full
        // pair weighs 1.
        let r = rng.below(short * FULL_WEIGHT_DIVISOR + full);
        if r < short * FULL_WEIGHT_DIVISOR {
            self.short[(r / FULL_WEIGHT_DIVISOR) as usize]
        } else {
            self.full[(r - short * FULL_WEIGHT_DIVISOR) as usize]
        }
    }

    /// A draw of `pair` becomes visible.
    fn reveal(&mut self, pair: u32) {
        let p = pair as usize;
        if self.visible[p] < COUNTED_DRAWS {
            self.shortfall -= 1;
        }
        self.visible[p] = self.visible[p].saturating_add(1);
        if self.visible[p] == COUNTED_DRAWS {
            let at = self.slot[p] as usize;
            let last = *self.short.last().expect("the pair is in the short list");
            self.short.swap_remove(at);
            if last != pair {
                self.slot[last as usize] = at as u32;
            }
            self.slot[p] = self.full.len() as u32;
            self.full.push(pair);
        }
    }
}

/// The top-up horizon at epoch-relative block `h`, in blocks.
#[must_use]
pub fn horizon(h: u64) -> u64 {
    let seb = SETTLEMENT_EPOCH_BLOCKS;
    let catch_up = seb * CATCH_UP_BY_PERMILLE / 1000;
    let end = if h < catch_up {
        catch_up
    } else {
        seb - CHALLENGE_RESPONSE_BLOCKS
    };
    end.saturating_sub(h).max(MIN_HORIZON_BLOCKS)
}

/// The per-block draw target before the fractional carry: base plus top-up,
/// capped. Returns the target and whether the cap held it down.
#[must_use]
pub fn block_target(pairs: u32, shortfall: u64, in_flight: u64, h: u64) -> (f64, bool) {
    let seb = SETTLEMENT_EPOCH_BLOCKS as f64;
    let base = f64::from(pairs) / seb;
    let top_up = shortfall.saturating_sub(in_flight) as f64 / horizon(h) as f64;
    let cap = CAP_MULTIPLE * f64::from(COUNTED_DRAWS) * f64::from(pairs) / seb;
    let wanted = base + top_up;
    (wanted.min(cap), wanted > cap)
}

/// Simulate one epoch.
///
/// # Panics
///
/// If `pairs` is zero or `dropout_permille` exceeds 1000: neither is an
/// epoch.
#[must_use]
pub fn run_epoch(pairs: u32, dropout_permille: u32, in_flight: InFlight, seed: u64) -> DrawRun {
    assert!(pairs > 0, "a settlement epoch needs at least one pair");
    assert!(dropout_permille <= 1000, "dropout is a share of blocks");
    let seb = SETTLEMENT_EPOCH_BLOCKS;
    let w2 = CHALLENGE_RESPONSE_BLOCKS;
    let mut rng = SplitMix64::seeded(seed);
    let mut state = Pairs::new(pairs);

    // Per block: its draws, and the block at which they become visible
    // (`None` for a block that never reveals).
    let mut draws: Vec<Vec<u32>> = Vec::with_capacity(seb as usize);
    let mut reveal_at: Vec<Option<u64>> = Vec::with_capacity(seb as usize);
    // Blocks whose seed lands in block `i`.
    let mut landing: Vec<Vec<u32>> = vec![Vec::new(); (seb + w2 + 1) as usize];

    let mut unrevealed_recent: u64 = 0;
    let mut all_recent: u64 = 0;
    let mut carry = 0.0f64;
    let (mut drawn, mut issued, mut max_per_block, mut capped_blocks) = (0u64, 0u64, 0u64, 0u64);

    for h in 0..seb + w2 + 1 {
        // Seeds that landed in block `h − 1` are visible from `h`.
        if h > 0 {
            for &block in &std::mem::take(&mut landing[(h - 1) as usize]) {
                let count = draws[block as usize].len() as u64;
                for &pair in &draws[block as usize] {
                    state.reveal(pair);
                }
                issued += count;
                // Still inside the recent window when it landed, by
                // construction: the lag is at most `W₂`.
                unrevealed_recent -= count;
            }
        }
        // The block `W₂ + 1` back leaves the window. If its seed never
        // landed, its draws stop counting as in flight.
        if h > w2 {
            let old = (h - w2 - 1) as usize;
            if old < draws.len() {
                let count = draws[old].len() as u64;
                all_recent -= count;
                let landed = reveal_at[old].is_some_and(|at| at < h);
                if !landed {
                    unrevealed_recent -= count;
                }
            }
        }
        if h >= seb {
            continue;
        }

        let pending = match in_flight {
            InFlight::Unrevealed => unrevealed_recent,
            InFlight::AllRecent => all_recent,
        };
        let (target, capped) = block_target(pairs, state.shortfall, pending, h);
        capped_blocks += u64::from(capped);
        carry += target;
        let count = carry.floor();
        carry -= count;
        let count = count as u64;

        let block_draws: Vec<u32> = (0..count).map(|_| state.draw(&mut rng)).collect();
        drawn += count;
        max_per_block = max_per_block.max(count);
        unrevealed_recent += count;
        all_recent += count;

        let revealed = rng.below(1000) >= u64::from(dropout_permille);
        let at = revealed.then(|| h + rng.below(w2 + 1));
        if let Some(at) = at {
            landing[at as usize].push(h as u32);
        }
        draws.push(block_draws);
        reveal_at.push(at);
    }

    let mut issued_hist = [0u32; 4];
    let mut unpaid_reads = 0u64;
    for &v in &state.visible {
        issued_hist[usize::from(v.min(COUNTED_DRAWS))] += 1;
        if v < COUNTED_DRAWS {
            unpaid_reads += u64::from(v);
        }
    }
    DrawRun {
        pairs,
        dropout_permille,
        in_flight,
        seed,
        drawn,
        issued,
        issued_hist,
        max_per_block,
        capped_blocks,
        unpaid_reads,
    }
}

/// One cell of the evidence table: a `(D, dropout, reading)` over seeds.
#[derive(Debug, Clone, Serialize)]
pub struct Cell {
    pub pairs: u32,
    pub dropout_permille: u32,
    pub in_flight: InFlight,
    pub seeds: u32,
    /// Pairs short of [`COUNTED_DRAWS`], per-mille: mean, min, max.
    pub short_permille: [f64; 3],
    /// Seeds whose short share exceeds [`SHORT_BAR_PERMILLE`].
    pub seeds_over_bar: u32,
    /// Issued draws per pair: mean over seeds.
    pub issued_per_pair: f64,
    /// Draws per block, revealed or not: mean over seeds, and the largest
    /// single block in any seed.
    pub mean_per_block: f64,
    pub max_per_block: u64,
    /// Blocks held down by the cap, summed over seeds.
    pub capped_blocks: u64,
    /// Bytes a producer fetches for one won block at the mean count.
    pub fetch_bytes_per_block: f64,
    /// Reads answered in pair-epochs that settle NonObservation, per pair:
    /// mean over seeds.
    pub unpaid_reads_per_pair: f64,
    /// The per-seed runs the cell summarises.
    pub runs: Vec<DrawRun>,
}

/// Seeds per cell (§5.13).
pub const SEEDS: u64 = 8;

/// Run one cell.
#[must_use]
pub fn cell(pairs: u32, dropout_permille: u32, in_flight: InFlight) -> Cell {
    let runs: Vec<DrawRun> = (1..=SEEDS)
        .map(|seed| run_epoch(pairs, dropout_permille, in_flight, seed))
        .collect();
    let n = runs.len() as f64;
    let shorts: Vec<f64> = runs.iter().map(DrawRun::short_permille).collect();
    let mean = |f: &dyn Fn(&DrawRun) -> f64| runs.iter().map(f).sum::<f64>() / n;
    let mean_per_block = mean(&DrawRun::mean_per_block);
    Cell {
        pairs,
        dropout_permille,
        in_flight,
        seeds: runs.len() as u32,
        short_permille: [
            shorts.iter().sum::<f64>() / n,
            shorts.iter().copied().fold(f64::INFINITY, f64::min),
            shorts.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        ],
        seeds_over_bar: shorts.iter().filter(|s| **s > SHORT_BAR_PERMILLE).count() as u32,
        issued_per_pair: mean(&DrawRun::issued_per_pair),
        mean_per_block,
        max_per_block: runs.iter().map(|r| r.max_per_block).max().unwrap_or(0),
        capped_blocks: runs.iter().map(|r| r.capped_blocks).sum(),
        fetch_bytes_per_block: mean_per_block * SHARD_LENGTH.to_raw() as f64,
        unpaid_reads_per_pair: mean(&|r| r.unpaid_reads as f64 / f64::from(r.pairs)),
        runs,
    }
}

/// The `(m, n)` re-check at one observation rate (§5.13).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct WindowCheck {
    /// Per-read failure probability, from the feasibility module's sources.
    pub read_failure: f64,
    /// Probability an observed epoch settles Missed for an honest pair:
    /// fewer than 2 of the 3 counted reads passed.
    pub miss_given_observation: f64,
    /// Union bound on a false slash over the bond's life at production
    /// `(m, n)`.
    pub false_slash_bound: f64,
    /// Share of epochs that are observations: `1 − short`.
    pub observation_rate: f64,
    /// Epochs a pair that never serves takes to reach `m` misses.
    pub epochs_to_m_misses: f64,
}

/// Probability that fewer than 2 of 3 independent reads pass, at per-read
/// failure `x`.
#[must_use]
pub fn missed_two_of_three(x: f64) -> f64 {
    let x = x.clamp(0.0, 1.0);
    3.0 * x * x * (1.0 - x) + x * x * x
}

/// Re-check the production window at a short share, in per-mille.
#[must_use]
pub fn window_check(short_permille: f64) -> WindowCheck {
    let sources = default_sources();
    let read_failure = sources
        .p_attempt
        .clamp(0.0, 1.0)
        .powi(sources.attempts as i32);
    let q = missed_two_of_three(read_failure);
    let observation_rate = 1.0 - short_permille / 1000.0;
    WindowCheck {
        read_failure,
        miss_given_observation: q,
        false_slash_bound: false_slash_bound(
            FAILURE_WINDOW_M,
            FAILURE_WINDOW_N,
            q,
            BOND_LIFE_EPOCHS,
        ),
        observation_rate,
        epochs_to_m_misses: f64::from(FAILURE_WINDOW_M) / observation_rate,
    }
}

/// The pair counts the evidence set runs at: the genesis set
/// `--challenge-coverage` uses, and maturity.
pub const EVIDENCE_PAIRS: [u32; 2] = [4_096, 324_000];

/// The dropouts the evidence set runs at, in per-mille.
pub const EVIDENCE_DROPOUT_PERMILLE: [u32; 3] = [0, 100, 300];

/// The evidence set: every `(D, dropout, reading)` cell.
#[must_use]
pub fn evidence_cells() -> Vec<Cell> {
    let mut cells = Vec::new();
    for pairs in EVIDENCE_PAIRS {
        for in_flight in [InFlight::Unrevealed, InFlight::AllRecent] {
            for dropout in EVIDENCE_DROPOUT_PERMILLE {
                cells.push(cell(pairs, dropout, in_flight));
            }
        }
    }
    cells
}

/// Whether the bar holds: the largest short share over seeds, in the
/// maturity cell at the bar's dropout under reading `in_flight`, is at most
/// [`SHORT_BAR_PERMILLE`]. `None` if the cell is not in `cells`.
#[must_use]
pub fn bar_holds(cells: &[Cell], in_flight: InFlight) -> Option<bool> {
    let maturity = EVIDENCE_PAIRS[EVIDENCE_PAIRS.len() - 1];
    cells
        .iter()
        .find(|c| {
            c.pairs == maturity
                && c.dropout_permille == BAR_DROPOUT_PERMILLE
                && c.in_flight == in_flight
        })
        .map(|c| c.short_permille[2] <= SHORT_BAR_PERMILLE)
}

/// Render the human-readable table into `out`. `main` performs the write.
///
/// # Errors
///
/// The sink's.
pub fn render_summary(out: &mut impl std::fmt::Write, cells: &[Cell]) -> std::fmt::Result {
    writeln!(
        out,
        "secret draw (ESR-11): SEB={SETTLEMENT_EPOCH_BLOCKS} W2={CHALLENGE_RESPONSE_BLOCKS} \
         counted={COUNTED_DRAWS} full-weight=1/{FULL_WEIGHT_DIVISOR} cap={CAP_MULTIPLE}x nominal \
         seeds={SEEDS} shard={} B",
        SHARD_LENGTH.to_raw()
    )?;
    writeln!(
        out,
        "{:>7} {:<20} {:>5} | {:>22} {:>4} | {:>7} {:>9} {:>6} {:>7} | {:>9} {:>8} | {:>6} {:>10} {:>7}",
        "D",
        "in-flight reading",
        "drop",
        "short % mean/min/max",
        ">bar",
        "iss/pr",
        "draws/blk",
        "max",
        "capped",
        "fetch MB",
        "unpd/pr",
        "obs",
        "false-slash",
        "epochs"
    )?;
    for c in cells {
        let w = window_check(c.short_permille[0]);
        writeln!(
            out,
            "{:>7} {:<20} {:>4}% | {:>6.2} {:>6.2} {:>6.2}    {:>4} | {:>7.3} {:>9.2} {:>6} {:>7} | {:>9.1} {:>8.4} | {:>6.3} {:>10.2e} {:>7.2}",
            c.pairs,
            c.in_flight.label(),
            c.dropout_permille / 10,
            c.short_permille[0] / 10.0,
            c.short_permille[1] / 10.0,
            c.short_permille[2] / 10.0,
            c.seeds_over_bar,
            c.issued_per_pair,
            c.mean_per_block,
            c.max_per_block,
            c.capped_blocks,
            c.fetch_bytes_per_block / 1.0e6,
            c.unpaid_reads_per_pair,
            w.observation_rate,
            w.false_slash_bound,
            w.epochs_to_m_misses,
        )?;
    }
    let w = window_check(0.0);
    writeln!(
        out,
        "(m, n) = ({FAILURE_WINDOW_M}, {FAILURE_WINDOW_N}): read failure x = {:.2}, \
         missed-observation q = 3x^2(1-x) + x^3 = {:.4}; the false-slash bound does not depend \
         on the observation rate",
        w.read_failure, w.miss_given_observation
    )?;
    for in_flight in [InFlight::Unrevealed, InFlight::AllRecent] {
        let verdict = match bar_holds(cells, in_flight) {
            Some(true) => "HOLDS",
            Some(false) => "FAILS",
            None => "not run",
        };
        writeln!(
            out,
            "bar (max over seeds <= {:.1} % short at {} % dropout, D = {}), reading {}: {verdict}",
            SHORT_BAR_PERMILLE / 10.0,
            BAR_DROPOUT_PERMILLE / 10,
            EVIDENCE_PAIRS[EVIDENCE_PAIRS.len() - 1],
            in_flight.label(),
        )?;
    }
    Ok(())
}

/// The machine-readable evidence set (`main` writes it).
#[must_use]
pub fn evidence_json(cells: &[Cell]) -> String {
    serde_json::to_string_pretty(cells).expect("Cell is serializable")
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: u32 = 4_096;

    #[test]
    #[should_panic(expected = "at least one pair")]
    fn zero_pairs_is_refused() {
        let _ = run_epoch(0, 0, InFlight::Unrevealed, 1);
    }

    #[test]
    fn a_run_is_a_function_of_its_seed() {
        let a = run_epoch(D, 100, InFlight::Unrevealed, 3);
        let b = run_epoch(D, 100, InFlight::Unrevealed, 3);
        assert_eq!(a.issued_hist, b.issued_hist);
        assert_eq!((a.drawn, a.issued), (b.drawn, b.issued));
        let c = run_epoch(D, 100, InFlight::Unrevealed, 4);
        assert_ne!(
            (a.issued_hist, a.drawn),
            (c.issued_hist, c.drawn),
            "a different seed is a different epoch"
        );
    }

    #[test]
    fn every_draw_of_a_revealed_block_is_issued_and_none_of_an_unrevealed_one() {
        // No dropout: every draw is issued, and the pairs' issued counts sum
        // to the draws. This is the conservation the short share rests on.
        let all = run_epoch(D, 0, InFlight::Unrevealed, 1);
        assert_eq!(all.issued, all.drawn);
        // Total dropout: draws are still made (the count is public and
        // nobody knows the block will not reveal), and nothing is issued.
        let none = run_epoch(D, 1000, InFlight::Unrevealed, 1);
        assert!(none.drawn > 0);
        assert_eq!(none.issued, 0);
        assert_eq!(none.issued_hist, [D, 0, 0, 0]);
        assert_eq!(none.unpaid_reads, 0);
    }

    #[test]
    fn issued_counts_account_for_every_issued_draw() {
        // Rebuild the issued total from the histogram's low buckets and the
        // unpaid reads: pairs at 1 and 2 issued hold exactly those reads.
        let r = run_epoch(D, 300, InFlight::Unrevealed, 2);
        assert_eq!(
            r.unpaid_reads,
            u64::from(r.issued_hist[1]) + 2 * u64::from(r.issued_hist[2])
        );
        assert_eq!(r.issued_hist.iter().sum::<u32>(), D);
        assert!(r.issued <= r.drawn);
        assert!(r.issued >= r.unpaid_reads + 3 * u64::from(r.issued_hist[3]));
    }

    #[test]
    fn the_count_is_base_plus_top_up_under_the_cap() {
        // Nothing short and nothing in flight: the base rate alone, one
        // draw per pair per epoch.
        let (t, capped) = block_target(10_000, 0, 0, 0);
        assert!((t - 1.0).abs() < 1e-12 && !capped);
        // A shortfall spreads over the horizon to 70 % of the epoch.
        let (t, _) = block_target(10_000, 7_000, 0, 0);
        assert!((t - 2.0).abs() < 1e-12, "base 1 + 7000/7000");
        // In-flight draws are not asked for twice.
        let (t, _) = block_target(10_000, 7_000, 7_000, 0);
        assert!((t - 1.0).abs() < 1e-12);
        // The cap is 3 x nominal = 9 draws per block at 10,000 pairs.
        let (t, capped) = block_target(10_000, 30_000, 0, 6_900);
        assert!((t - 9.0).abs() < 1e-12 && capped);
    }

    #[test]
    fn the_horizon_runs_to_seventy_percent_then_to_the_close_less_w2() {
        let seb = SETTLEMENT_EPOCH_BLOCKS;
        let w2 = CHALLENGE_RESPONSE_BLOCKS;
        assert_eq!(horizon(0), seb * 7 / 10);
        assert_eq!(horizon(seb * 7 / 10 - 1), MIN_HORIZON_BLOCKS, "the floor");
        assert_eq!(horizon(seb * 7 / 10), seb - w2 - seb * 7 / 10);
        assert_eq!(horizon(seb - 1), MIN_HORIZON_BLOCKS);
    }

    #[test]
    fn no_block_draws_more_than_the_cap_allows() {
        // The carry can add at most one draw to a block's capped target.
        for dropout in [0, 300, 1000] {
            let r = run_epoch(D, dropout, InFlight::Unrevealed, 5);
            let cap = CAP_MULTIPLE * f64::from(COUNTED_DRAWS) * f64::from(D)
                / SETTLEMENT_EPOCH_BLOCKS as f64;
            assert!(
                (r.max_per_block as f64) <= cap + 1.0,
                "dropout {dropout}: {} over a cap of {cap}",
                r.max_per_block
            );
        }
    }

    #[test]
    fn a_short_pair_is_drawn_sixteen_times_as_often_as_a_full_one() {
        // Half the pairs made full by hand; count where 200,000 draws land.
        let mut state = Pairs::new(1_000);
        for pair in 0..500 {
            for _ in 0..COUNTED_DRAWS {
                state.reveal(pair);
            }
        }
        assert_eq!((state.short.len(), state.full.len()), (500, 500));
        assert_eq!(state.shortfall, 1_500);
        let mut rng = SplitMix64::seeded(9);
        let n = 200_000u32;
        let full_hits = (0..n).filter(|_| state.draw(&mut rng) < 500).count();
        let share = full_hits as f64 / f64::from(n);
        let expected = 1.0 / 17.0;
        assert!(
            (share - expected).abs() < 0.004,
            "full pairs took {share:.4} of draws, expected {expected:.4}"
        );
    }

    #[test]
    fn more_dropout_leaves_more_pairs_short() {
        let short = |d| cell(D, d, InFlight::Unrevealed).short_permille[0];
        let (none, some, many) = (short(0), short(100), short(300));
        assert!(none < some && some < many, "{none} {some} {many}");
    }

    #[test]
    fn the_missed_observation_rate_is_the_two_of_three_tail() {
        assert!((missed_two_of_three(0.30) - 0.216).abs() < 1e-12);
        assert!(missed_two_of_three(0.0).abs() < 1e-12);
        assert!((missed_two_of_three(1.0) - 1.0).abs() < 1e-12);
        let w = window_check(25.0);
        assert!((w.observation_rate - 0.975).abs() < 1e-12);
        assert!(
            (w.epochs_to_m_misses - f64::from(FAILURE_WINDOW_M) / 0.975).abs() < 1e-9,
            "a non-serving pair needs m observed epochs"
        );
        // The bound is priced at one observation per epoch, so it is the
        // same at every observation rate.
        assert!((w.false_slash_bound - window_check(0.0).false_slash_bound).abs() < f64::EPSILON);
    }

    #[test]
    #[ignore = "the full evidence set: 12 cells x 8 seeds, ~1.3M draws per maturity run; run with --release --ignored"]
    fn the_evidence_set_runs_and_the_table_renders() {
        let cells = evidence_cells();
        assert_eq!(cells.len(), 12);
        let mut out = String::new();
        render_summary(&mut out, &cells).expect("String sink is infallible");
        assert!(out.contains("bar (max over seeds"));
    }
}
