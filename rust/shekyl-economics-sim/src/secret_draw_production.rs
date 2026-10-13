// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The secret per-block draw on production's count and selection (ESR-13).
//!
//! [`crate::secret_draw`] (ESR-11) ran when the draw had no production
//! owner: it carries its own count rule in `f64` and its own weighted pick.
//! This module runs the same one-epoch experiment and calls the owners in
//! `shekyl-archival-retention` instead: [`draw_count`] and [`draw_horizon`]
//! for the count and its 32-bit carry, [`select_draw`] for every draw.
//! ESR-11 is not changed and is printed beside this arm as the `f64`
//! reference.
//!
//! The model, its cells, its bar and its predictions were fixed before this
//! file existed (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.17).
//!
//! What this arm adds is the **bundle**. A block's reveal and all of its
//! pass records travel as one object, and the block's draws are issued only
//! when that object is admitted in a block `h_incl` with
//! `h < h_incl ≤ h + W₂`. A bundle that is never filed, filed too late, or
//! lost to a reorg issues nothing.
//!
//! There is no partial state, and the code has none to hold: a draw has no
//! outcome field here, issuance is one step that takes a whole block's
//! draws ([`Visible::issue`]), and only a block whose [`Fate`] is
//! [`Fate::Admitted`] is ever handed to it. So a lost bundle cannot leave a
//! draw issued, and with no draw issued there is nothing to settle as a
//! miss. As in ESR-11 the read itself is not modelled; pass and miss enter
//! only through the `(m, n)` figures, which are ESR-11's own functions.
//!
//! Dropout, the filing lag, the inclusion latency, the reorg loss and each
//! block's seed and hash have no production owner: a declared divergence
//! (§4 of the same document).
//!
//! Three limits of the model, stated where the numbers are made (§5.19):
//!
//! - **The reorg term is independent per bundle.** Each bundle included in
//!   the last `R` blocks of its window is lost with probability `p_reorg`,
//!   on its own roll. A real reorg removes a run of consecutive blocks and
//!   loses every bundle in that run together. That correlated loss is not
//!   modelled. And `p_reorg` having no effect at `M = 30` follows from the
//!   parameters: with `R = 3` and a latency of `1..=3`, the latest honest
//!   inclusion is `h + 473` and the zone starts at `h + 498`. A deeper
//!   reorg or a longer latency reaches it.
//! - **The section budget is not modelled.** A filed bundle is included
//!   after its latency whatever else is waiting. Inclusion is never refused
//!   for lack of room, so a backlog near the budget is unexamined.
//! - **Common random numbers.** The same seeds drive dropout, lag, latency
//!   and the loss roll in every cell. That makes differences between cells
//!   sharp. The cells are therefore not independent samples, and they all
//!   share one realised dropout.

use core::convert::Infallible;

use serde::Serialize;

use shekyl_archival_retention::{
    draw_count, draw_horizon, draw_target, select_draw, CHALLENGE_RESPONSE_BLOCKS, DRAW_ATTEMPTS,
    SETTLEMENT_EPOCH_BLOCKS,
};

use crate::challenge_coverage::SplitMix64;
use crate::secret_draw::{
    self, InFlight, BAR_DROPOUT_PERMILLE, COUNTED_DRAWS, EVIDENCE_DROPOUT_PERMILLE, EVIDENCE_PAIRS,
    SEEDS, SHORT_BAR_PERMILLE,
};

/// The challenger's margin `M`: an honest producer files by
/// `h + W₂ − M`. PROVISIONAL, and policy, not consensus.
pub const HONEST_MARGIN_BLOCKS: u64 = 30;

/// The smallest margin at which a lazy bundle is always in time under
/// [`DEFAULT_LATENCY`]: its upper end.
pub const MINIMAL_MARGIN_BLOCKS: u64 = 3;

/// Blocks from filing to inclusion, uniform on this closed range.
pub const DEFAULT_LATENCY: (u64, u64) = (1, 3);

/// A bundle included in one of the last `R` blocks of its window is exposed
/// to loss by reorg.
pub const DEFAULT_REORG_DEPTH: u64 = 3;

/// The reorg-loss probabilities the evidence set runs at, in per-mille.
pub const EVIDENCE_REORG_PERMILLE: [u32; 3] = [0, 10, 100];

/// When a producer that files does so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Lag {
    /// Uniform on `0..=(W₂ − M)` blocks after its block.
    Honest,
    /// At `W₂ − M` exactly: the last block its policy allows.
    Lazy,
}

/// How a block's bundle travels from its producer to the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Timing {
    /// `M`, in blocks.
    pub margin: u64,
    pub lag: Lag,
    /// Inclusion latency, uniform on `latency.0..=latency.1`.
    pub latency: (u64, u64),
    /// `R`, in blocks.
    pub reorg_depth: u64,
    /// `p_reorg`, in per-mille.
    pub reorg_permille: u32,
}

impl Timing {
    /// The bundle's timing at the default latency and reorg depth.
    #[must_use]
    pub const fn bundle(margin: u64, lag: Lag, reorg_permille: u32) -> Self {
        Self {
            margin,
            lag,
            latency: DEFAULT_LATENCY,
            reorg_depth: DEFAULT_REORG_DEPTH,
            reorg_permille,
        }
    }

    /// ESR-11's reveal lag: uniform on `0..=W₂`, no latency, no loss. The
    /// one difference is that a lag of 0 lands in the next block, since a
    /// bundle is never included in its own.
    #[must_use]
    pub const fn esr11() -> Self {
        Self {
            margin: 0,
            lag: Lag::Honest,
            latency: (0, 0),
            reorg_depth: DEFAULT_REORG_DEPTH,
            reorg_permille: 0,
        }
    }

    fn label(&self) -> &'static str {
        if *self == Self::esr11() {
            "ESR-11 timing"
        } else {
            match self.lag {
                Lag::Honest => "bundle, honest lag",
                Lag::Lazy => "bundle, lazy",
            }
        }
    }
}

/// What became of one block's bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Admitted in block `at`, with `h < at ≤ h + W₂`. Its draws are
    /// visible to every block above `at`.
    Admitted { at: u64 },
    /// The producer dropped out.
    NeverFiled,
    /// Included after `h + W₂`: refused.
    Late,
    /// Included in the last `R` blocks of the window and reorganised away.
    Lost,
}

impl Fate {
    /// Index into the per-fate tallies.
    const fn slot(self) -> usize {
        match self {
            Self::Admitted { .. } => 0,
            Self::NeverFiled => 1,
            Self::Late => 2,
            Self::Lost => 3,
        }
    }

    /// Whether the bundle is in the chain below `h`.
    const fn admitted_below(self, h: u64) -> bool {
        matches!(self, Self::Admitted { at } if at < h)
    }
}

/// One block's rolls. All four are taken for every block, used or not, so
/// every cell runs on common random numbers: two cells that differ in one
/// parameter read the same rolls, and differ by that parameter alone. The
/// price is that cells are not independent samples.
#[derive(Debug, Clone, Copy)]
pub struct Rolls {
    /// Uniform on `0..1000`. The producer drops out below the dropout.
    pub dropout: u32,
    /// Uniform on `0..=(W₂ − M)`. Unused by a lazy producer.
    pub lag: u64,
    /// Uniform on the latency range.
    pub latency: u64,
    /// Uniform on `0..1000`. An exposed bundle is lost below `p_reorg`.
    pub loss: u32,
}

/// The fate of block `h`'s bundle.
///
/// `h_incl = h + max(lag + latency, 1)`. Late if that is past `h + W₂`;
/// exposed to loss if it is one of the last `R` blocks at or below it.
#[must_use]
pub fn fate(h: u64, dropout_permille: u32, timing: &Timing, rolls: Rolls) -> Fate {
    if rolls.dropout < dropout_permille {
        return Fate::NeverFiled;
    }
    let deadline = h + CHALLENGE_RESPONSE_BLOCKS;
    let lag = match timing.lag {
        Lag::Honest => rolls.lag,
        Lag::Lazy => CHALLENGE_RESPONSE_BLOCKS - timing.margin,
    };
    let at = h + (lag + rolls.latency).max(1);
    if at > deadline {
        return Fate::Late;
    }
    if at + timing.reorg_depth > deadline && rolls.loss < timing.reorg_permille {
        return Fate::Lost;
    }
    Fate::Admitted { at }
}

/// The count rule's two inputs that the run derives: `u`, the visible
/// shortfall less what is in flight and never below zero, and the horizon.
/// Production's functions take `u`, not the raw shortfall.
fn rule_inputs(shortfall: u64, in_flight: u64, h: u64) -> (u64, u64) {
    (
        shortfall.saturating_sub(in_flight),
        draw_horizon(h, SETTLEMENT_EPOCH_BLOCKS, CHALLENGE_RESPONSE_BLOCKS),
    )
}

/// `count(h)` and the carry it leaves, from production's rule.
#[must_use]
pub fn count_at(pairs: u32, shortfall: u64, in_flight: u64, h: u64, carry: u32) -> (u64, u32) {
    let (u, horizon) = rule_inputs(shortfall, in_flight, h);
    draw_count(u64::from(pairs), u, horizon, SETTLEMENT_EPOCH_BLOCKS, carry)
        .expect("the epoch length and the horizon are both nonzero")
}

/// Whether the cap bound at these inputs: production's answer
/// ([`draw_target`]), which is `D·H + SEB·u > 9·D·H`. A target that lands
/// exactly on the cap is not capped. The sim keeps no copy of the cap.
#[must_use]
pub fn capped_at(pairs: u32, shortfall: u64, in_flight: u64, h: u64) -> bool {
    let (u, horizon) = rule_inputs(shortfall, in_flight, h);
    draw_target(u64::from(pairs), u, horizon, SETTLEMENT_EPOCH_BLOCKS)
        .expect("the epoch length and the horizon are both nonzero")
        .capped
}

/// The issued counts every block can see.
struct Visible {
    count: Vec<u16>,
    /// `Σ max(0, COUNTED_DRAWS − count)`.
    shortfall: u64,
    /// Draws issued so far.
    issued: u64,
}

impl Visible {
    fn new(pairs: u32) -> Self {
        Self {
            count: vec![0; pairs as usize],
            shortfall: u64::from(pairs) * u64::from(COUNTED_DRAWS),
            issued: 0,
        }
    }

    /// Whether pair `index` is visibly short.
    fn short(&self, index: u64) -> bool {
        self.count[index as usize] < u16::from(COUNTED_DRAWS)
    }

    /// Issue an admitted bundle: every draw of its block, at once. This is
    /// the only way a draw becomes visible, and it takes the block whole.
    fn issue(&mut self, block_draws: &[u32]) {
        for &pair in block_draws {
            let seen = &mut self.count[pair as usize];
            if *seen < u16::from(COUNTED_DRAWS) {
                self.shortfall -= 1;
            }
            *seen = seen
                .checked_add(1)
                .expect("a pair is not drawn 65,536 times in an epoch");
        }
        self.issued += block_draws.len() as u64;
    }
}

/// What one block did, as the run saw it. For tests that recompute the
/// run from outside.
// CLIPPY: the run fills every field and only the tests read them; the
// non-test binary hands each block to an observer that ignores it, so
// rustc reports the fields as never read. They are read by
// `the_run_is_production_s_count_and_selection_block_by_block`.
#[cfg_attr(not(test), allow(dead_code))]
pub struct BlockTrace<'a> {
    pub h: u64,
    pub seed: &'a [u8; 32],
    pub block_hash: &'a [u8; 32],
    /// The visible issued counts at `h`, before this block's draws.
    pub visible: &'a [u16],
    pub shortfall: u64,
    pub in_flight: u64,
    pub carry_in: u32,
    pub carry_out: u32,
    /// The pairs drawn, in draw order; its length is `count(h)`.
    pub draws: &'a [u32],
    pub fate: Fate,
}

/// One simulated epoch.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProductionRun {
    pub pairs: u32,
    pub dropout_permille: u32,
    pub timing: Timing,
    pub seed: u64,
    /// Draws made by every block, whatever became of its bundle.
    pub drawn: u64,
    /// Draws of blocks whose bundle was admitted: the issued draws.
    pub issued: u64,
    /// Pairs by final issued count: `[0, 1, 2, ≥ 3]`.
    pub issued_hist: [u32; 4],
    /// Largest per-block draw count in the epoch.
    pub max_per_block: u64,
    /// Blocks where the cap bound, by production's [`draw_target`].
    pub blocks_at_cap: u64,
    /// Issued draws answered by pairs that ended short.
    pub unpaid_reads: u64,
    /// Blocks by fate: `[admitted, never filed, late, lost]`.
    pub blocks_by_fate: [u64; 4],
    /// Draws by their block's fate, same order.
    pub drawn_by_fate: [u64; 4],
    /// `select_draw` attempts, summed over every draw.
    pub attempts: u64,
    /// The most attempts any one draw took.
    pub max_attempts: u32,
    /// Draws that reached the last attempt, which selects whatever its
    /// weight.
    pub last_attempt_draws: u64,
    /// Total draws ESR-11's `f64` rule gives on this run's own inputs.
    pub f64_drawn: u64,
    /// Blocks where the `f64` rule's count is not production's.
    pub f64_differing_blocks: u64,
}

impl ProductionRun {
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

    /// Mean draws per block over the epoch.
    #[must_use]
    pub fn mean_per_block(&self) -> f64 {
        self.drawn as f64 / SETTLEMENT_EPOCH_BLOCKS as f64
    }

    /// Draws made per pair.
    #[must_use]
    pub fn drawn_per_pair(&self) -> f64 {
        self.drawn as f64 / f64::from(self.pairs)
    }

    /// Issued draws per pair.
    #[must_use]
    pub fn issued_per_pair(&self) -> f64 {
        self.issued as f64 / f64::from(self.pairs)
    }
}

fn bytes32(rng: &mut SplitMix64) -> [u8; 32] {
    let mut out = [0u8; 32];
    for byte in &mut out {
        *byte = rng.below(256) as u8;
    }
    out
}

/// Simulate one epoch.
///
/// # Panics
///
/// If `pairs` is zero, a share exceeds 1000 per-mille, the margin exceeds
/// `W₂`, or the latency range is empty.
#[must_use]
pub fn run_epoch(pairs: u32, dropout_permille: u32, timing: Timing, seed: u64) -> ProductionRun {
    run_epoch_observed(pairs, dropout_permille, timing, seed, &mut |_| {})
}

/// [`run_epoch`], handing each block to `observe` as it is made.
///
/// # Panics
///
/// As [`run_epoch`].
#[must_use]
pub fn run_epoch_observed(
    pairs: u32,
    dropout_permille: u32,
    timing: Timing,
    seed: u64,
    observe: &mut dyn FnMut(&BlockTrace<'_>),
) -> ProductionRun {
    let seb = SETTLEMENT_EPOCH_BLOCKS;
    let w2 = CHALLENGE_RESPONSE_BLOCKS;
    assert!(pairs > 0, "a settlement epoch needs at least one pair");
    assert!(dropout_permille <= 1000, "dropout is a share of blocks");
    assert!(
        timing.reorg_permille <= 1000,
        "reorg loss is a share of bundles"
    );
    assert!(timing.margin <= w2, "the margin is inside the window");
    assert!(
        timing.latency.0 <= timing.latency.1,
        "the latency range is not empty"
    );

    let mut rng = SplitMix64::seeded(seed);
    let mut visible = Visible::new(pairs);
    let mut draws: Vec<Vec<u32>> = Vec::with_capacity(seb as usize);
    let mut fates: Vec<Fate> = Vec::with_capacity(seb as usize);
    // Blocks whose bundle is admitted in block `i`.
    let mut landing: Vec<Vec<u32>> = vec![Vec::new(); (seb + w2 + 1) as usize];

    let mut in_flight: u64 = 0;
    let mut carry: u32 = 0;
    let mut f64_carry = 0.0f64;
    let mut run = ProductionRun {
        pairs,
        dropout_permille,
        timing,
        seed,
        drawn: 0,
        issued: 0,
        issued_hist: [0; 4],
        max_per_block: 0,
        blocks_at_cap: 0,
        unpaid_reads: 0,
        blocks_by_fate: [0; 4],
        drawn_by_fate: [0; 4],
        attempts: 0,
        max_attempts: 0,
        last_attempt_draws: 0,
        f64_drawn: 0,
        f64_differing_blocks: 0,
    };

    for h in 0..=seb + w2 {
        // Bundles admitted in block `h − 1` are visible from `h`.
        if h > 0 {
            for &block in &std::mem::take(&mut landing[(h - 1) as usize]) {
                let block_draws = &draws[block as usize];
                visible.issue(block_draws);
                // Still inside the recent range when it landed: a bundle is
                // admitted at most `W₂` above its block.
                in_flight -= block_draws.len() as u64;
            }
        }
        // The block `W₂ + 1` back leaves the range. If no bundle of it is
        // in the chain, its draws stop counting as in flight.
        if h > w2 {
            let old = (h - w2 - 1) as usize;
            if old < draws.len() && !fates[old].admitted_below(h) {
                in_flight -= draws[old].len() as u64;
            }
        }
        if h >= seb {
            continue;
        }

        let shortfall = visible.shortfall;
        let (count, carry_out) = count_at(pairs, shortfall, in_flight, h, carry);
        run.blocks_at_cap += u64::from(capped_at(pairs, shortfall, in_flight, h));

        // ESR-11's rule on the same inputs, with its own carry.
        let (target, _) = secret_draw::block_target(pairs, shortfall, in_flight, h);
        f64_carry += target;
        let f64_count = f64_carry.floor();
        f64_carry -= f64_count;
        run.f64_drawn += f64_count as u64;
        run.f64_differing_blocks += u64::from(f64_count as u64 != count);

        let block_seed = bytes32(&mut rng);
        let block_hash = bytes32(&mut rng);
        let rolls = Rolls {
            dropout: rng.below(1000) as u32,
            lag: rng.below(w2 - timing.margin + 1),
            latency: timing.latency.0 + rng.below(timing.latency.1 - timing.latency.0 + 1),
            loss: rng.below(1000) as u32,
        };

        let mut block_draws: Vec<u32> = Vec::with_capacity(count as usize);
        for j in 0..count {
            let j = u32::try_from(j).expect("a block's draw count fits the record's index");
            // The short read is this process's own count and cannot fail;
            // `Infallible` says so, and the `let` is irrefutable.
            let Ok(selected) = select_draw(&block_seed, &block_hash, j, u64::from(pairs), |i| {
                Ok::<_, Infallible>(visible.short(i))
            });
            let selected = selected.expect("the set is not empty");
            block_draws.push(selected.index as u32);
            run.attempts += u64::from(selected.attempts);
            run.max_attempts = run.max_attempts.max(selected.attempts);
            run.last_attempt_draws += u64::from(selected.attempts == DRAW_ATTEMPTS);
        }

        let block_fate = fate(h, dropout_permille, &timing, rolls);
        if let Fate::Admitted { at } = block_fate {
            assert!(
                h < at && at <= h + w2,
                "a bundle is admitted above its block and inside the window"
            );
            landing[at as usize].push(h as u32);
        }
        run.blocks_by_fate[block_fate.slot()] += 1;
        run.drawn_by_fate[block_fate.slot()] += count;
        run.drawn += count;
        run.max_per_block = run.max_per_block.max(count);
        in_flight += count;

        observe(&BlockTrace {
            h,
            seed: &block_seed,
            block_hash: &block_hash,
            visible: &visible.count,
            shortfall,
            in_flight: in_flight - count,
            carry_in: carry,
            carry_out,
            draws: &block_draws,
            fate: block_fate,
        });

        carry = carry_out;
        draws.push(block_draws);
        fates.push(block_fate);
    }

    run.issued = visible.issued;
    // The bundle is whole: what is issued is exactly the draws of the
    // admitted blocks, and every issued draw is on some pair's count.
    assert_eq!(
        run.issued,
        run.drawn_by_fate[Fate::Admitted { at: 0 }.slot()],
        "issued draws are the admitted blocks' draws and no others"
    );
    assert_eq!(
        visible.count.iter().map(|c| u64::from(*c)).sum::<u64>(),
        run.issued,
        "every issued draw is counted on its pair"
    );
    assert_eq!(
        in_flight, 0,
        "nothing is in flight once the last window ends"
    );

    for &seen in &visible.count {
        run.issued_hist[usize::from(seen.min(u16::from(COUNTED_DRAWS)))] += 1;
        if seen < u16::from(COUNTED_DRAWS) {
            run.unpaid_reads += u64::from(seen);
        }
    }
    run
}

/// Which part of the evidence set a cell belongs to (§5.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Group {
    /// ESR-11's timing: isolates the two production functions.
    Esr11Timing,
    /// Dropout × `M` × `p_reorg`, honest lag.
    Grid,
    /// Every producer files at the last block its margin allows.
    Lazy,
}

/// One cell's parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CellSpec {
    pub group: Group,
    pub pairs: u32,
    pub dropout_permille: u32,
    pub timing: Timing,
}

/// One cell of the evidence table, over seeds.
#[derive(Debug, Clone, Serialize)]
pub struct Cell {
    pub spec: CellSpec,
    pub seeds: u32,
    /// Pairs short of [`COUNTED_DRAWS`], per-mille: mean, min, max.
    pub short_permille: [f64; 3],
    /// Seeds whose short share exceeds [`SHORT_BAR_PERMILLE`].
    pub seeds_over_bar: u32,
    /// Draws per pair, made and issued: means over seeds.
    pub drawn_per_pair: f64,
    pub issued_per_pair: f64,
    /// Draws per block: mean over seeds, and the largest single block.
    pub mean_per_block: f64,
    pub max_per_block: u64,
    /// Blocks where the cap bound, summed over seeds.
    pub blocks_at_cap: u64,
    /// Share of blocks by fate, per-mille, over all seeds:
    /// `[admitted, never filed, late, lost]`.
    pub fate_permille: [f64; 4],
    /// `select_draw` attempts per draw, over all seeds, and the most any
    /// draw took.
    pub attempts_per_draw: f64,
    pub max_attempts: u32,
    /// Draws that reached the last attempt, summed over seeds.
    pub last_attempt_draws: u64,
    /// Blocks where ESR-11's `f64` rule gives another count on the run's
    /// own inputs, summed over seeds.
    pub f64_differing_blocks: u64,
    /// The largest difference in an epoch's total draws between the two
    /// rules, over seeds.
    pub f64_max_total_difference: u64,
    /// The per-seed runs the cell summarises.
    pub runs: Vec<ProductionRun>,
}

/// Run one cell: [`SEEDS`] epochs, one thread each. A run is a function of
/// its seed alone, so the threads change nothing but the wall time.
#[must_use]
pub fn cell(spec: CellSpec) -> Cell {
    let runs: Vec<ProductionRun> = std::thread::scope(|scope| {
        let handles: Vec<_> = (1..=SEEDS)
            .map(|seed| {
                scope.spawn(move || run_epoch(spec.pairs, spec.dropout_permille, spec.timing, seed))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("an epoch run does not panic"))
            .collect()
    });
    let n = runs.len() as f64;
    let shorts: Vec<f64> = runs.iter().map(ProductionRun::short_permille).collect();
    let mean = |f: &dyn Fn(&ProductionRun) -> f64| runs.iter().map(f).sum::<f64>() / n;
    let blocks = n * SETTLEMENT_EPOCH_BLOCKS as f64;
    let mut fate_permille = [0.0; 4];
    for (slot, share) in fate_permille.iter_mut().enumerate() {
        let total: u64 = runs.iter().map(|r| r.blocks_by_fate[slot]).sum();
        *share = total as f64 * 1000.0 / blocks;
    }
    let drawn: u64 = runs.iter().map(|r| r.drawn).sum();
    let attempts: u64 = runs.iter().map(|r| r.attempts).sum();
    Cell {
        spec,
        seeds: runs.len() as u32,
        short_permille: [
            shorts.iter().sum::<f64>() / n,
            shorts.iter().copied().fold(f64::INFINITY, f64::min),
            shorts.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        ],
        seeds_over_bar: shorts.iter().filter(|s| **s > SHORT_BAR_PERMILLE).count() as u32,
        drawn_per_pair: mean(&ProductionRun::drawn_per_pair),
        issued_per_pair: mean(&ProductionRun::issued_per_pair),
        mean_per_block: mean(&ProductionRun::mean_per_block),
        max_per_block: runs.iter().map(|r| r.max_per_block).max().unwrap_or(0),
        blocks_at_cap: runs.iter().map(|r| r.blocks_at_cap).sum(),
        fate_permille,
        attempts_per_draw: if drawn == 0 {
            0.0
        } else {
            attempts as f64 / drawn as f64
        },
        max_attempts: runs.iter().map(|r| r.max_attempts).max().unwrap_or(0),
        last_attempt_draws: runs.iter().map(|r| r.last_attempt_draws).sum(),
        f64_differing_blocks: runs.iter().map(|r| r.f64_differing_blocks).sum(),
        f64_max_total_difference: runs
            .iter()
            .map(|r| r.drawn.abs_diff(r.f64_drawn))
            .max()
            .unwrap_or(0),
        runs,
    }
}

/// The cells of the evidence set at one pair count, in table order (§5.17).
#[must_use]
pub fn evidence_specs(pairs: u32) -> Vec<CellSpec> {
    let mut specs = Vec::new();
    for dropout_permille in EVIDENCE_DROPOUT_PERMILLE {
        specs.push(CellSpec {
            group: Group::Esr11Timing,
            pairs,
            dropout_permille,
            timing: Timing::esr11(),
        });
    }
    for dropout_permille in EVIDENCE_DROPOUT_PERMILLE {
        for margin in [0, HONEST_MARGIN_BLOCKS] {
            for reorg_permille in EVIDENCE_REORG_PERMILLE {
                specs.push(CellSpec {
                    group: Group::Grid,
                    pairs,
                    dropout_permille,
                    timing: Timing::bundle(margin, Lag::Honest, reorg_permille),
                });
            }
        }
    }
    for margin in [0, MINIMAL_MARGIN_BLOCKS, HONEST_MARGIN_BLOCKS] {
        for reorg_permille in EVIDENCE_REORG_PERMILLE {
            specs.push(CellSpec {
                group: Group::Lazy,
                pairs,
                dropout_permille: BAR_DROPOUT_PERMILLE,
                timing: Timing::bundle(margin, Lag::Lazy, reorg_permille),
            });
        }
    }
    specs
}

/// ESR-11's own cells at one pair count, under the reading the
/// specification states: the `f64` reference. Called, not copied.
#[must_use]
pub fn f64_reference(pairs: u32) -> Vec<secret_draw::Cell> {
    EVIDENCE_DROPOUT_PERMILLE
        .into_iter()
        .map(|dropout| secret_draw::cell(pairs, dropout, InFlight::Unrevealed))
        .collect()
}

/// The evidence set: ESR-11's reference cells and this arm's.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub reference: Vec<secret_draw::Cell>,
    pub cells: Vec<Cell>,
}

/// The timing the bar is graded at.
#[must_use]
pub const fn bar_timing() -> Timing {
    Timing::bundle(HONEST_MARGIN_BLOCKS, Lag::Honest, 0)
}

/// Whether the bar holds: the largest short share over seeds, at maturity,
/// at the bar's dropout and [`bar_timing`], is at most
/// [`SHORT_BAR_PERMILLE`]. `None` if that cell is not in `cells`.
#[must_use]
pub fn bar_holds(cells: &[Cell]) -> Option<bool> {
    let maturity = EVIDENCE_PAIRS[EVIDENCE_PAIRS.len() - 1];
    cells
        .iter()
        .find(|c| {
            c.spec.pairs == maturity
                && c.spec.dropout_permille == BAR_DROPOUT_PERMILLE
                && c.spec.timing == bar_timing()
        })
        .map(|c| c.short_permille[2] <= SHORT_BAR_PERMILLE)
}

/// The `(m, n)` figures, as ESR-11 prints them.
///
/// These are ESR-11's own lines, taken from its renderer run on no cells:
/// the function takes no run, so nothing a cell measures can reach them.
#[must_use]
pub fn window_lines() -> String {
    let mut all = String::new();
    secret_draw::render_summary(&mut all, &[]).expect("String sink is infallible");
    let mut lines = String::new();
    for line in all
        .lines()
        .skip_while(|line| !line.starts_with("(m, n) = "))
        .take_while(|line| !line.starts_with("bar ("))
    {
        lines.push_str(line);
        lines.push('\n');
    }
    lines
}

fn render_header(out: &mut impl std::fmt::Write) -> std::fmt::Result {
    writeln!(
        out,
        "secret draw on production's count and selection (ESR-13): \
         SEB={SETTLEMENT_EPOCH_BLOCKS} W2={CHALLENGE_RESPONSE_BLOCKS} counted={COUNTED_DRAWS} \
         attempts<={DRAW_ATTEMPTS} seeds={SEEDS}; each row carries its own M, latency, R and \
         p_reorg"
    )?;
    writeln!(
        out,
        "{:>7} {:<19} {:>4} {:>3} {:>6} {:>2} {:>5} | {:>22} {:>4} | {:>6} {:>6} {:>9} {:>5} {:>7} | {:>6} {:>6} | \
         {:>6} {:>6} {:>5} {:>5} | {:>6} {:>4} {:>5} | {:>6} {:>5}",
        "D",
        "arm",
        "drop",
        "M",
        "lat",
        "R",
        "p_re",
        "short % mean/min/max",
        ">bar",
        "drn/pr",
        "iss/pr",
        "draws/blk",
        "max",
        "cap sum",
        "obs",
        "epochs",
        "adm %",
        "never%",
        "late%",
        "lost%",
        "att/dr",
        "max",
        "last",
        "f64blk",
        "f64dr"
    )
}

/// One of ESR-11's cells, in this table's columns.
fn render_reference_row(out: &mut impl std::fmt::Write, c: &secret_draw::Cell) -> std::fmt::Result {
    let w = secret_draw::window_check(c.short_permille[0]);
    let drawn_per_pair = c.runs.iter().map(|r| r.drawn as f64).sum::<f64>()
        / (c.runs.len() as f64 * f64::from(c.pairs));
    writeln!(
        out,
        "{:>7} {:<19} {:>3}% {:>3} {:>6} {:>2} {:>5} | {:>6.2} {:>6.2} {:>6.2}    {:>4} | {:>6.3} {:>6.3} {:>9.2} {:>5} {:>7} | {:>6.4} {:>6.2} | \
         {:>6} {:>6} {:>5} {:>5} | {:>6} {:>4} {:>5} | {:>6} {:>5}",
        c.pairs,
        "ESR-11 f64",
        c.dropout_permille / 10,
        "-",
        "-",
        "-",
        "-",
        c.short_permille[0] / 10.0,
        c.short_permille[1] / 10.0,
        c.short_permille[2] / 10.0,
        c.seeds_over_bar,
        drawn_per_pair,
        c.issued_per_pair,
        c.mean_per_block,
        c.max_per_block,
        c.capped_blocks,
        w.observation_rate,
        w.epochs_to_m_misses,
        "-",
        "-",
        "-",
        "-",
        "-",
        "-",
        "-",
        "-",
        "-"
    )
}

fn render_row(out: &mut impl std::fmt::Write, c: &Cell) -> std::fmt::Result {
    let w = secret_draw::window_check(c.short_permille[0]);
    writeln!(
        out,
        "{:>7} {:<19} {:>3}% {:>3} {:>6} {:>2} {:>5.2} | {:>6.2} {:>6.2} {:>6.2}    {:>4} | {:>6.3} {:>6.3} {:>9.2} {:>5} {:>7} | {:>6.4} {:>6.2} | \
         {:>6.2} {:>6.2} {:>5.2} {:>5.2} | {:>6.2} {:>4} {:>5} | {:>6} {:>5}",
        c.spec.pairs,
        c.spec.timing.label(),
        c.spec.dropout_permille / 10,
        c.spec.timing.margin,
        format!("{}..={}", c.spec.timing.latency.0, c.spec.timing.latency.1),
        c.spec.timing.reorg_depth,
        f64::from(c.spec.timing.reorg_permille) / 1000.0,
        c.short_permille[0] / 10.0,
        c.short_permille[1] / 10.0,
        c.short_permille[2] / 10.0,
        c.seeds_over_bar,
        c.drawn_per_pair,
        c.issued_per_pair,
        c.mean_per_block,
        c.max_per_block,
        c.blocks_at_cap,
        w.observation_rate,
        w.epochs_to_m_misses,
        c.fate_permille[0] / 10.0,
        c.fate_permille[1] / 10.0,
        c.fate_permille[2] / 10.0,
        c.fate_permille[3] / 10.0,
        c.attempts_per_draw,
        c.max_attempts,
        c.last_attempt_draws,
        c.f64_differing_blocks,
        c.f64_max_total_difference,
    )
}

/// Render one cell's row alone, for progress while the set runs.
///
/// # Errors
///
/// The sink's.
pub fn render_cell(out: &mut impl std::fmt::Write, c: &Cell) -> std::fmt::Result {
    render_row(out, c)
}

/// Render the human-readable table into `out`. `main` performs the write.
///
/// # Errors
///
/// The sink's.
pub fn render_summary(out: &mut impl std::fmt::Write, report: &Report) -> std::fmt::Result {
    render_header(out)?;
    // One section per pair count, ascending, whatever order the cells are
    // in. A reference cell with no cell of this arm at its pair count gets
    // a section too.
    let pair_counts: std::collections::BTreeSet<u32> = report
        .cells
        .iter()
        .map(|c| c.spec.pairs)
        .chain(report.reference.iter().map(|c| c.pairs))
        .collect();
    for pairs in pair_counts {
        for c in report.reference.iter().filter(|c| c.pairs == pairs) {
            render_reference_row(out, c)?;
        }
        for c in report.cells.iter().filter(|c| c.spec.pairs == pairs) {
            render_row(out, c)?;
        }
    }
    writeln!(
        out,
        "columns: M = margin in blocks; lat = inclusion latency, uniform on the range; R = reorg \
         depth; p_re = p_reorg; drn/pr, iss/pr = draws per pair made, issued; cap sum = blocks \
         where the cap bound (D*H + SEB*u > 9*D*H, production's draw_target), summed over the \
         cell's {SEEDS} seeds: divide by {SEEDS} for blocks per epoch; obs = 1 - short; epochs = epochs to m misses for a pair \
         that never serves; adm/never/late/lost = where the blocks' bundles went; att/dr, max, \
         last = select_draw attempts per draw, the most, and draws that reached attempt \
         {DRAW_ATTEMPTS}; f64blk, f64dr = blocks where ESR-11's f64 rule gives another count on \
         the same inputs (all seeds), and the largest difference in an epoch's total draws"
    )?;
    writeln!(
        out,
        "model: the cells run on common random numbers (the same {SEEDS} seeds drive dropout, \
         lag, latency and loss in every cell), so they are not independent samples and share one \
         realised dropout; p_reorg loses each bundle on its own roll, where a real reorg loses \
         every bundle in a run of blocks together; p_reorg cannot act at M = {HONEST_MARGIN_BLOCKS} \
         only because R = {DEFAULT_REORG_DEPTH} and the latency is at most {} blocks; the section \
         budget is not modelled",
        DEFAULT_LATENCY.1
    )?;
    out.write_str(&window_lines())?;
    let verdict = match bar_holds(&report.cells) {
        Some(true) => "HOLDS",
        Some(false) => "FAILS",
        None => "not run",
    };
    writeln!(
        out,
        "bar (max over seeds <= {:.1} % short at {} % dropout, D = {}, M = {}, p_reorg = 0, honest \
         lag): {verdict}",
        SHORT_BAR_PERMILLE / 10.0,
        BAR_DROPOUT_PERMILLE / 10,
        EVIDENCE_PAIRS[EVIDENCE_PAIRS.len() - 1],
        HONEST_MARGIN_BLOCKS,
    )
}

/// The machine-readable evidence set (`main` writes it).
#[must_use]
pub fn evidence_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).expect("Report is serializable")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::secret_draw::clearing_read_failure;

    const D: u32 = 512;
    const SEB: u64 = SETTLEMENT_EPOCH_BLOCKS;
    const W2: u64 = CHALLENGE_RESPONSE_BLOCKS;

    /// One block of a run, kept.
    struct Kept {
        seed: [u8; 32],
        block_hash: [u8; 32],
        visible: Vec<u16>,
        shortfall: u64,
        in_flight: u64,
        carry_in: u32,
        carry_out: u32,
        draws: Vec<u32>,
        fate: Fate,
    }

    fn traced(
        pairs: u32,
        dropout_permille: u32,
        timing: Timing,
        seed: u64,
    ) -> (ProductionRun, Vec<Kept>) {
        let mut kept = Vec::new();
        let run = run_epoch_observed(pairs, dropout_permille, timing, seed, &mut |b| {
            assert_eq!(b.h, kept.len() as u64, "blocks arrive in order");
            kept.push(Kept {
                seed: *b.seed,
                block_hash: *b.block_hash,
                visible: b.visible.to_vec(),
                shortfall: b.shortfall,
                in_flight: b.in_flight,
                carry_in: b.carry_in,
                carry_out: b.carry_out,
                draws: b.draws.to_vec(),
                fate: b.fate,
            });
        });
        (run, kept)
    }

    fn rolls(lag: u64, latency: u64, loss: u32) -> Rolls {
        Rolls {
            dropout: 999,
            lag,
            latency,
            loss,
        }
    }

    /// Bites against: passing the raw shortfall to `draw_count` (the third
    /// step would carry 2^31), dropping the carry (the second step would
    /// give 0), a horizon that is not production's, a missing cap.
    /// Does NOT cover: whether the run feeds this function the right
    /// shortfall and in-flight; `the_run_is_production_s_count_and_selection_block_by_block`
    /// does.
    #[test]
    fn the_count_is_production_s_on_a_hand_checked_sequence() {
        // The arithmetic below is done by hand at these two values.
        assert_eq!((SEB, W2), (10_000, 500));
        let half = 1u32 << 31;
        // 5,000 pairs, nothing short, h = 6,900: H = max(200, 100) = 200,
        // t = 5000/10000 = 1/2. Half a draw carries.
        assert_eq!(count_at(5_000, 0, 0, 6_900, 0), (0, half));
        // The carried half and another half are one draw.
        assert_eq!(count_at(5_000, 0, 0, 6_900, half), (1, 0));
        // h = 0: H = 7,000. Shortfall 7,000 with 3,500 in flight is
        // u = 3,500: t = 1/2 + 3500/7000 = 1.
        assert_eq!(count_at(5_000, 7_000, 3_500, 0, 0), (1, 0));
        // More in flight than short: u = 0, the base alone.
        assert_eq!(count_at(5_000, 3_500, 7_000, 0, 0), (0, half));
        // 10,000 pairs, u = 1,750, H = 7,000: t = 1 + 1/4.
        assert_eq!(count_at(10_000, 1_750, 0, 0, 0), (1, 1 << 30));
        // u = 30,000 over H = 200 is 150 a block: capped at 9 x D/SEB.
        assert_eq!(count_at(10_000, 30_000, 0, 6_900, 0), (9, 0));
        assert!(capped_at(10_000, 30_000, 0, 6_900));
        assert!(!capped_at(10_000, 1_750, 0, 0));
        // At H = 200 the two sides of the cap meet at u = 1,600
        // (2,000,000 + 10,000 u against 18,000,000). The count is nine on
        // both sides of it; only above it was anything held down. In flight
        // comes off first: 2,000 short with 400 in flight is u = 1,600.
        assert_eq!(count_at(10_000, 1_600, 0, 6_900, 0), (9, 0));
        assert_eq!(count_at(10_000, 1_601, 0, 6_900, 0), (9, 0));
        assert!(!capped_at(10_000, 1_600, 0, 6_900));
        assert!(capped_at(10_000, 1_601, 0, 6_900));
        assert!(!capped_at(10_000, 2_000, 400, 6_900));
        assert!(capped_at(10_000, 2_001, 400, 6_900));
        // The function is production's, argument for argument.
        assert_eq!(
            count_at(4_096, 9_000, 1_234, 4_321, 77),
            draw_count(4_096, 9_000 - 1_234, draw_horizon(4_321, SEB, W2), SEB, 77)
                .expect("H and SEB")
        );
    }

    /// Recomputes a whole epoch from outside the run: the visible counts,
    /// the shortfall and the in-flight total by their definitions, the
    /// count by `draw_count`, and every draw by `select_draw`.
    ///
    /// Bites against: a selection that is not `select_draw` (any other
    /// pick, a wrong `j`, a `short` that reads counts newer than `h`), a
    /// count that is not `draw_count`'s, a carry not threaded block to
    /// block, an in-flight range that is not `[h − W₂, h − 1]` or that
    /// forgets a block whose bundle never lands, and a draw made visible
    /// from a bundle that was not admitted, or before the block after its
    /// admission.
    /// Does NOT cover: `select_draw` and `draw_count` themselves; their
    /// vectors are in `shekyl-archival-retention`.
    #[test]
    fn the_run_is_production_s_count_and_selection_block_by_block() {
        // M = 0 at 30 % dropout with a certain loss in the last three
        // blocks: all four fates occur.
        let timing = Timing::bundle(0, Lag::Honest, 1000);
        let (run, kept) = traced(D, 300, timing, 7);
        assert!(run.blocks_by_fate.iter().all(|n| *n > 0), "{run:?}");
        assert_eq!(kept.len() as u64, SEB);

        let mut carry = 0u32;
        let mut selected = 0u64;
        for (h, block) in kept.iter().enumerate() {
            let h64 = h as u64;
            // Visible at h: the draws of every earlier block whose bundle
            // was admitted below h. Recomputed from scratch on a sample of
            // blocks; the full scan is quadratic.
            if h % 97 == 0 || h + 1 == kept.len() {
                let mut expected = vec![0u16; D as usize];
                for earlier in &kept[..h] {
                    if earlier.fate.admitted_below(h64) {
                        for &pair in &earlier.draws {
                            expected[pair as usize] += 1;
                        }
                    }
                }
                assert_eq!(block.visible, expected, "visible counts at {h}");
            }
            let shortfall: u64 = block
                .visible
                .iter()
                .map(|c| u64::from(u16::from(COUNTED_DRAWS).saturating_sub(*c)))
                .sum();
            assert_eq!(block.shortfall, shortfall, "shortfall at {h}");
            let from = h.saturating_sub(W2 as usize);
            let in_flight: u64 = kept[from..h]
                .iter()
                .filter(|earlier| !earlier.fate.admitted_below(h64))
                .map(|earlier| earlier.draws.len() as u64)
                .sum();
            assert_eq!(block.in_flight, in_flight, "in flight at {h}");

            assert_eq!(block.carry_in, carry, "carry into {h}");
            let (count, next) = draw_count(
                u64::from(D),
                shortfall.saturating_sub(in_flight),
                draw_horizon(h64, SEB, W2),
                SEB,
                carry,
            )
            .expect("H and SEB");
            assert_eq!(
                (block.draws.len() as u64, block.carry_out),
                (count, next),
                "count at {h}"
            );
            carry = next;

            for (j, &pair) in block.draws.iter().enumerate() {
                let Ok(direct) = select_draw(
                    &block.seed,
                    &block.block_hash,
                    j as u32,
                    u64::from(D),
                    |i| Ok::<_, Infallible>(block.visible[i as usize] < u16::from(COUNTED_DRAWS)),
                );
                let direct = direct.expect("the set is not empty");
                assert_eq!(u64::from(pair), direct.index, "draw {j} at {h}");
                selected += 1;
            }
        }
        assert_eq!(selected, run.drawn);
        assert!(selected > u64::from(D), "the epoch drew");
    }

    /// Bites against: admitting a bundle the reorg took (push a `Lost`
    /// block to `landing`, or return `Admitted` from the loss arm of
    /// `fate`), and any path that makes one of its draws visible.
    /// Does NOT cover: a bundle that is visible for a while and then
    /// reorganised away; the model has no such state.
    #[test]
    fn a_lost_bundle_issues_nothing_and_leaves_no_draw_to_miss() {
        // Lazy at the minimal margin: every bundle lands in the last three
        // blocks of its window. A certain reorg loses all of them.
        let all_lost = Timing::bundle(MINIMAL_MARGIN_BLOCKS, Lag::Lazy, 1000);
        let run = run_epoch(D, 0, all_lost, 1);
        assert_eq!(run.blocks_by_fate, [0, 0, 0, SEB]);
        assert!(run.drawn > 0, "the count is public; the blocks still draw");
        assert_eq!(run.drawn_by_fate, [0, 0, 0, run.drawn]);
        assert_eq!(run.issued, 0);
        assert_eq!(run.issued_hist, [D, 0, 0, 0]);
        assert_eq!(run.unpaid_reads, 0, "no pair answered an issued draw");

        // The same producers with no reorg: every bundle is admitted and
        // the same blocks issue everything.
        let none_lost = Timing::bundle(MINIMAL_MARGIN_BLOCKS, Lag::Lazy, 0);
        let run = run_epoch(D, 0, none_lost, 1);
        assert_eq!(run.blocks_by_fate, [SEB, 0, 0, 0]);
        assert_eq!(run.issued, run.drawn);

        // Mixed: what is issued is the admitted blocks' draws exactly, and
        // the pairs' counts hold no draw of a lost block.
        let some_lost = Timing::bundle(MINIMAL_MARGIN_BLOCKS, Lag::Lazy, 400);
        let (run, kept) = traced(D, 0, some_lost, 1);
        assert!(run.blocks_by_fate[0] > 0 && run.blocks_by_fate[3] > 0);
        let mut counts = vec![0u32; D as usize];
        let mut lost_draws = 0u64;
        for block in &kept {
            match block.fate {
                Fate::Admitted { .. } => {
                    for &pair in &block.draws {
                        counts[pair as usize] += 1;
                    }
                }
                _ => lost_draws += block.draws.len() as u64,
            }
        }
        assert_eq!(run.issued + lost_draws, run.drawn);
        let mut hist = [0u32; 4];
        for seen in counts {
            hist[seen.min(u32::from(COUNTED_DRAWS)) as usize] += 1;
        }
        assert_eq!(run.issued_hist, hist);
    }

    /// Bites against: a filing rule that lets a bundle be late or exposed
    /// at `M = 30`, a latency-0 bundle included in its own block (the
    /// run's own assert), an issuance that skips a filed block.
    /// Does NOT cover: `M = 0` or a nonzero latency; the fate arithmetic
    /// test does.
    #[test]
    fn with_the_margin_and_no_reorg_every_filed_block_s_draws_are_issued() {
        let timing = Timing {
            latency: (0, 0),
            ..Timing::bundle(HONEST_MARGIN_BLOCKS, Lag::Honest, 0)
        };
        for dropout in [0, 100, 300] {
            let run = run_epoch(D, dropout, timing, 2);
            assert_eq!(run.blocks_by_fate[2], 0, "none late at dropout {dropout}");
            assert_eq!(run.blocks_by_fate[3], 0, "none lost at dropout {dropout}");
            let never_filed = run.drawn_by_fate[1];
            assert_eq!(run.issued + never_filed, run.drawn, "dropout {dropout}");
            assert_eq!(
                run.blocks_by_fate[0] + run.blocks_by_fate[1],
                SEB,
                "dropout {dropout}"
            );
            if dropout == 0 {
                assert_eq!(run.issued, run.drawn);
            } else {
                assert!(never_filed > 0 && run.issued > 0);
            }
            // The pairs' counts hold every issued draw.
            assert!(run.issued >= run.unpaid_reads + 3 * u64::from(run.issued_hist[3]));
            assert_eq!(run.issued_hist.iter().sum::<u32>(), D);
        }
    }

    /// Bites against: any state that outlives a run or any input besides
    /// the seed (a thread-order dependence in `cell`, a clock).
    #[test]
    fn a_run_is_a_function_of_its_seed() {
        let timing = bar_timing();
        let a = run_epoch(D, 100, timing, 3);
        assert_eq!(a, run_epoch(D, 100, timing, 3));
        let c = run_epoch(D, 100, timing, 4);
        assert_ne!(
            (a.issued_hist, a.drawn),
            (c.issued_hist, c.drawn),
            "a different seed is a different epoch"
        );
        // A cell runs its seeds on threads and reports them in seed order.
        let spec = CellSpec {
            group: Group::Grid,
            pairs: D,
            dropout_permille: 100,
            timing,
        };
        let cell = cell(spec);
        assert_eq!(cell.runs.len() as u64, SEEDS);
        assert_eq!(cell.runs[2], a);
        assert_eq!(cell.runs[3], c);
    }

    /// Bites against: a reorg zone that is not the last `R` blocks at or
    /// below `h + W₂`, a window bound off by one, a lazy lag that is not
    /// `W₂ − M`, and a bundle included in its own block.
    #[test]
    fn a_bundle_s_fate_is_its_inclusion_height_against_the_window() {
        let h = 4_000;
        let honest = |margin, p| Timing::bundle(margin, Lag::Honest, p);
        let lazy = |margin, p| Timing::bundle(margin, Lag::Lazy, p);
        // A producer that drops out never files, whatever else it rolled.
        let dropped = Rolls {
            dropout: 99,
            ..rolls(0, 1, 0)
        };
        assert_eq!(fate(h, 100, &honest(30, 0), dropped), Fate::NeverFiled);
        assert_ne!(
            fate(
                h,
                100,
                &honest(30, 0),
                Rolls {
                    dropout: 100,
                    ..dropped
                }
            ),
            Fate::NeverFiled
        );
        // Inclusion at h + lag + latency.
        assert_eq!(
            fate(h, 0, &honest(30, 0), rolls(0, 1, 0)),
            Fate::Admitted { at: h + 1 }
        );
        assert_eq!(
            fate(h, 0, &honest(30, 0), rolls(470, 3, 0)),
            Fate::Admitted { at: h + 473 }
        );
        // The last block of the window is in time; the next is late.
        assert_eq!(
            fate(h, 0, &honest(0, 0), rolls(499, 1, 0)),
            Fate::Admitted { at: h + W2 }
        );
        assert_eq!(fate(h, 0, &honest(0, 0), rolls(500, 1, 0)), Fate::Late);
        // The last R = 3 blocks are exposed: 498, 499, 500 above h, and
        // not 497. A loss roll below p_reorg loses the bundle.
        for offset in [498, 499, 500] {
            assert_eq!(
                fate(h, 0, &honest(0, 100), rolls(offset - 1, 1, 99)),
                Fate::Lost,
                "offset {offset}"
            );
            assert_eq!(
                fate(h, 0, &honest(0, 100), rolls(offset - 1, 1, 100)),
                Fate::Admitted { at: h + offset },
                "offset {offset}"
            );
        }
        assert_eq!(
            fate(h, 0, &honest(0, 1000), rolls(496, 1, 0)),
            Fate::Admitted { at: h + 497 }
        );
        // Late is late before it is lost.
        assert_eq!(fate(h, 0, &honest(0, 1000), rolls(500, 1, 0)), Fate::Late);
        // A lazy producer files at W₂ − M whatever its lag roll.
        assert_eq!(
            fate(h, 0, &lazy(30, 1000), rolls(0, 3, 0)),
            Fate::Admitted { at: h + 473 }
        );
        assert_eq!(
            fate(h, 0, &lazy(3, 0), rolls(0, 1, 0)),
            Fate::Admitted { at: h + 498 }
        );
        assert_eq!(fate(h, 0, &lazy(3, 1000), rolls(0, 1, 0)), Fate::Lost);
        assert_eq!(fate(h, 0, &lazy(0, 0), rolls(0, 1, 0)), Fate::Late);
        // No latency and no lag is the next block, never the block itself.
        assert_eq!(
            fate(h, 0, &Timing::esr11(), rolls(0, 0, 0)),
            Fate::Admitted { at: h + 1 }
        );
        assert_eq!(
            fate(h, 0, &Timing::esr11(), rolls(500, 0, 0)),
            Fate::Admitted { at: h + W2 }
        );
    }

    /// Bites against: a reorg term that reaches a bundle outside the last
    /// `R` blocks, and rolls that are taken only when used (the cells
    /// would then read different streams).
    #[test]
    fn the_reorg_term_cannot_reach_a_bundle_filed_with_the_margin() {
        let at = |p| {
            run_epoch(
                D,
                100,
                Timing::bundle(HONEST_MARGIN_BLOCKS, Lag::Honest, p),
                5,
            )
        };
        let base = at(0);
        for p in [10, 100, 1000] {
            let run = at(p);
            assert_eq!(run.timing.reorg_permille, p);
            let same = ProductionRun {
                timing: base.timing,
                ..run
            };
            assert_eq!(same, base, "p_reorg = {p} per-mille");
        }
        // Without the margin the same rolls lose bundles.
        let exposed = run_epoch(D, 100, Timing::bundle(0, Lag::Honest, 1000), 5);
        assert!(exposed.blocks_by_fate[3] > 0);
        assert!(exposed.blocks_by_fate[2] > 0, "and some are late");
    }

    /// Bites against: a lazy producer with no margin being admitted.
    #[test]
    fn a_lazy_producer_with_no_margin_is_always_late() {
        let run = run_epoch(D, 0, Timing::bundle(0, Lag::Lazy, 0), 1);
        assert_eq!(run.blocks_by_fate, [0, 0, SEB, 0]);
        assert_eq!(run.issued_hist, [D, 0, 0, 0]);
        assert!((run.short_permille() - 1000.0).abs() < f64::EPSILON);
        // Nothing is ever visible, so every pair is short and every draw
        // is taken on its first candidate.
        assert_eq!(run.max_attempts, 1);
        assert!(run.blocks_at_cap > 0);
    }

    /// The premise of the `f64` comparison: the two rules are fed the same
    /// horizon.
    ///
    /// Bites against: either horizon moving without the other.
    #[test]
    fn the_two_arms_read_one_horizon() {
        for h in 0..SEB {
            assert_eq!(secret_draw::horizon(h), draw_horizon(h, SEB, W2), "h = {h}");
        }
    }

    /// Bites against: a shadow fed inputs other than the run's own (the
    /// totals would part by far more than one), or an integer rule that
    /// loses more than its last bit.
    /// Does NOT cover: how the two arms compare between runs with
    /// different selections; that is the evidence table.
    #[test]
    fn the_f64_rule_on_the_same_inputs_stays_within_one_draw() {
        for (dropout, timing) in [
            (0, Timing::esr11()),
            (100, bar_timing()),
            (300, Timing::bundle(0, Lag::Lazy, 0)),
        ] {
            let run = run_epoch(1_024, dropout, timing, 6);
            assert!(run.drawn > 1_024);
            assert!(
                run.drawn.abs_diff(run.f64_drawn) <= 1,
                "{} integer, {} f64",
                run.drawn,
                run.f64_drawn
            );
            assert!(run.f64_differing_blocks <= 20, "{run:?}");
        }
    }

    /// Bites against: restating any `(m, n)` line here, with any number in
    /// it, and against a figure that reads a cell.
    /// Does NOT cover: the figures' values; ESR-11's tests do.
    #[test]
    fn the_window_figures_are_esr11_s_lines_and_read_no_run() {
        let lines = window_lines();
        assert!(lines.starts_with("(m, n) = ("), "{lines}");
        assert!(lines.contains("false slash over the bond's life"));
        assert!(lines.contains(&format!("<= {:.4}", clearing_read_failure())));
        assert!(!lines.contains("bar ("));
        // ESR-11 prints the same lines over cells of its own.
        let cells = [secret_draw::cell(64, 300, InFlight::Unrevealed)];
        let mut theirs = String::new();
        secret_draw::render_summary(&mut theirs, &cells).expect("String sink is infallible");
        for line in lines.lines() {
            assert!(theirs.contains(line), "ESR-11 does not print: {line}");
        }
        assert!(lines.lines().count() >= 10, "the retry table is included");
    }

    /// Bites against: a cell missing from the set, or the bar read from a
    /// cell other than `(maturity, 10 %, M = 30, p_reorg = 0, honest)`.
    #[test]
    fn the_evidence_set_is_thirty_cells_and_the_bar_reads_its_own() {
        let specs = evidence_specs(D);
        assert_eq!(specs.len(), 30);
        let count = |g| specs.iter().filter(|s| s.group == g).count();
        assert_eq!(
            (
                count(Group::Esr11Timing),
                count(Group::Grid),
                count(Group::Lazy)
            ),
            (3, 18, 9)
        );
        let mut seen = Vec::new();
        for spec in &specs {
            assert!(!seen.contains(spec), "a cell is listed twice: {spec:?}");
            seen.push(*spec);
        }

        let maturity = EVIDENCE_PAIRS[EVIDENCE_PAIRS.len() - 1];
        // The verdict reads a cell's parameters and its largest short
        // share, so one small cell is relabelled rather than five run.
        let template = cell(CellSpec {
            group: Group::Grid,
            pairs: 16,
            dropout_permille: 0,
            timing: bar_timing(),
        });
        let with_max = |pairs, dropout_permille, timing, max| Cell {
            spec: CellSpec {
                group: Group::Grid,
                pairs,
                dropout_permille,
                timing,
            },
            short_permille: [0.0, 0.0, max],
            ..template.clone()
        };
        let over = SHORT_BAR_PERMILLE + 1.0;
        let under = SHORT_BAR_PERMILLE;
        let bar = BAR_DROPOUT_PERMILLE;
        assert_eq!(bar_holds(&[]), None);
        // Other cells over the bar do not fail it.
        let others = [
            with_max(D, bar, bar_timing(), over),
            with_max(maturity, 300, bar_timing(), over),
            with_max(maturity, bar, Timing::bundle(0, Lag::Honest, 0), over),
            with_max(maturity, bar, Timing::esr11(), over),
        ];
        assert_eq!(bar_holds(&others), None);
        let mut cells = others.to_vec();
        cells.push(with_max(maturity, bar, bar_timing(), under));
        assert_eq!(bar_holds(&cells), Some(true));
        cells.pop();
        cells.push(with_max(maturity, bar, bar_timing(), over));
        assert_eq!(bar_holds(&cells), Some(false));
    }

    /// Bites against: a row or the reference dropped from the table, a
    /// row printed without its own latency and reorg depth, and a header
    /// that states a timing some row does not have.
    /// Does NOT cover: any figure in it.
    #[test]
    fn the_table_prints_the_reference_beside_each_arm_and_each_row_s_own_timing() {
        let unusual = Timing {
            latency: (2, 5),
            reorg_depth: 7,
            ..Timing::bundle(HONEST_MARGIN_BLOCKS, Lag::Honest, 100)
        };
        let specs = [
            CellSpec {
                group: Group::Esr11Timing,
                pairs: D,
                dropout_permille: 100,
                timing: Timing::esr11(),
            },
            CellSpec {
                group: Group::Lazy,
                pairs: D,
                dropout_permille: 100,
                timing: Timing::bundle(HONEST_MARGIN_BLOCKS, Lag::Lazy, 100),
            },
            CellSpec {
                group: Group::Grid,
                pairs: D,
                dropout_permille: 100,
                timing: unusual,
            },
        ];
        let report = Report {
            reference: vec![secret_draw::cell(D, 100, InFlight::Unrevealed)],
            cells: specs.into_iter().map(cell).collect(),
        };
        let mut out = String::new();
        render_summary(&mut out, &report).expect("String sink is infallible");
        for needle in [
            "ESR-13",
            "ESR-11 f64",
            "ESR-11 timing",
            "bundle, lazy",
            "(m, n) = (",
            "): not run",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
        }
        let row_of = |c: &Cell| {
            let mut row = String::new();
            render_cell(&mut row, c).expect("String sink is infallible");
            row
        };
        // Columns after the dropout: M, latency, R, p_reorg.
        let rows: Vec<String> = report.cells.iter().map(row_of).collect();
        assert!(rows[0].contains("10%   0  0..=0  3  0.00 |"), "{}", rows[0]);
        assert!(rows[1].contains("10%  30  1..=3  3  0.10 |"), "{}", rows[1]);
        assert!(rows[2].contains("10%  30  2..=5  7  0.10 |"), "{}", rows[2]);
        for row in &rows {
            assert_eq!(out.matches(row.as_str()).count(), 1, "{row}");
        }
        // The cap column names its unit, in the label and in the legend.
        let labels = out.lines().nth(1).expect("the column labels");
        assert!(labels.contains(" cap sum |"), "{labels}");
        assert!(!labels.contains("capped"), "{labels}");
        assert!(out.contains(&format!(
            "summed over the cell's {SEEDS} seeds: divide by {SEEDS} for blocks per epoch"
        )));
        // The cell's figure is the sum of its runs', and that is what the
        // row prints.
        let summed: u64 = report.cells[1].runs.iter().map(|r| r.blocks_at_cap).sum();
        assert_eq!(report.cells[1].blocks_at_cap, summed);
        // The model's limits are on the output, not only in the document.
        for needle in [
            "common random numbers",
            "every bundle in a run of blocks together",
            "the section budget is not modelled",
        ] {
            assert!(out.contains(needle), "missing {needle:?}");
        }
        // The first line says only what holds for every row.
        let first = out.lines().next().expect("a header");
        assert!(
            !first.contains("latency=") && !first.contains("R="),
            "{first}"
        );
        assert!(!first.contains("1..=3"), "{first}");
        assert!(evidence_json(&report).contains("\"f64_differing_blocks\""));
    }

    /// Bites against: sections found by `dedup` on the cells' order (the
    /// interleaved report below would print each pair count's section
    /// twice, with its reference rows twice), and a pair count dropped.
    /// Does NOT cover: any figure in a row.
    #[test]
    fn each_pair_count_is_one_section_whatever_order_the_cells_are_in() {
        let spec = |pairs, dropout_permille| CellSpec {
            group: Group::Grid,
            pairs,
            dropout_permille,
            timing: bar_timing(),
        };
        // 64, 16, 64, 16: no two neighbours share a pair count.
        let report = Report {
            reference: vec![
                secret_draw::cell(64, 100, InFlight::Unrevealed),
                secret_draw::cell(16, 100, InFlight::Unrevealed),
            ],
            cells: [spec(64, 0), spec(16, 0), spec(64, 300), spec(16, 300)]
                .into_iter()
                .map(cell)
                .collect(),
        };
        let mut out = String::new();
        render_summary(&mut out, &report).expect("String sink is infallible");
        // The table's rows: after the two header lines, up to the legend.
        let pairs_column: Vec<u32> = out
            .lines()
            .skip(2)
            .take_while(|line| !line.starts_with("columns:"))
            .map(|line| {
                line.split_whitespace()
                    .next()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or_else(|| panic!("a row starts with its pair count: {line}"))
            })
            .collect();
        // One section each, ascending: the reference row, then the cells.
        assert_eq!(pairs_column, [16, 16, 16, 64, 64, 64], "{out}");
        let rows: Vec<&str> = out.lines().skip(2).take(6).collect();
        for (at, row) in rows.iter().enumerate() {
            assert_eq!(
                row.contains("ESR-11 f64"),
                at % 3 == 0,
                "the reference opens each section: {row}"
            );
            assert_eq!(out.matches(row).count(), 1, "printed once: {row}");
        }
        // Within a section the cells keep the order they were given in.
        assert!(
            rows[1].contains("  0%") && rows[2].contains(" 30%"),
            "{out}"
        );
        assert!(
            rows[4].contains("  0%") && rows[5].contains(" 30%"),
            "{out}"
        );
    }
}
