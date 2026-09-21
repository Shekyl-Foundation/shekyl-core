// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The corpus the measurements scale by — every operand read from its owner.
//!
//! `WALLET_SIDE_STORE.md` §6.3.4 pins the rig and the budgets; this module pins
//! the *corpus*, and does it by **calling** the landed constants and functions
//! rather than restating their values. That is not style. The round's own
//! `WSS-Q8` finding was a horizon assembled from documents that named an
//! operand with no value; the first draft of this bench repeated it, deriving a
//! worst-case leaf rate from "the block-weight constants in
//! `config/consensus_constants.json`" — which carries no block-weight ceiling
//! at all, only the surge factor `S`. See [`worst_case_leaves_per_block`] for
//! what it carries instead.
//!
//! ## The three block counts, which are three different numbers
//!
//! | Name | Value | What it is |
//! | --- | --- | --- |
//! | [`W`] | 730 | Finalization depth. `F = tip − W` |
//! | [`REPLAY_WINDOW_BLOCKS`] | 725 | `[F, ref]` — what a spend replays |
//! | [`HELD_BUFFER_BLOCKS`] | 790 | `W + 60` — what the wallet holds and refetches |
//!
//! They were conflated in this harness's opening brief. `W` is not the buffer:
//! §6.3.2 row 2's amendment extends the buffer 60 blocks *below* `F`, because
//! replaying drains over `[F, ref]` needs outputs **created** from `F − 60`
//! (coinbase maturity). And the replay window is shorter than `W`, because the
//! reference block is itself at least [`REFERENCE_BLOCK_MIN_AGE`] below the tip.

use shekyl_consensus::COINBASE_LOCK_WINDOW;
use shekyl_curve_tree::reference::REFERENCE_BLOCK_MIN_AGE;
use shekyl_curve_tree::segment::{SEGMENT_FREEZE_REORG_MARGIN_BLOCKS, SPENDABLE_AGE_BLOCKS};
use shekyl_economics::block_weight::BLOCK_WEIGHT_SURGE_FACTOR;
use shekyl_economics::emission::block_weight_limit;
use shekyl_economics::EconomicParams;
use shekyl_fcmp::tree::outputs_per_node;
use shekyl_tx_weight::{predict_weight, InputCount, OutputCount, MAX_OUTPUTS};
use shekyl_wire::transaction::{MIN_BLOCK_WEIGHT, TX_WEIGHT_LIMIT};

/// Finalization depth `W`, in blocks: the age at which the wallet's frontier is
/// taken to be beyond reorg.
///
/// Summed from its two owners rather than written as `730`, which is the form
/// [`shekyl_curve_tree::segment::segment_freeze_eligible`] uses for the same
/// quantity. A reorg shallower than `W` never touches persisted state, which is
/// why §6.3 needs no undo log.
pub const W: u64 = SPENDABLE_AGE_BLOCKS + SEGMENT_FREEZE_REORG_MARGIN_BLOCKS;

/// The blocks a spend replays: `[F, ref]`, where `ref` is at most
/// `tip − REFERENCE_BLOCK_MIN_AGE`.
///
/// This is the **upper** bound of the window (a reference block chosen deeper
/// than the minimum age replays fewer blocks), so it is the one a worst-case
/// measurement uses.
pub const REPLAY_WINDOW_BLOCKS: u64 = W - REFERENCE_BLOCK_MIN_AGE;

/// The blocks the wallet holds, and refetches at open: `W + 60`.
///
/// §6.3.2 row 2's amendment. The 60 is [`COINBASE_LOCK_WINDOW`] — to replay
/// drains over `[F, ref]` the wallet needs the outputs those drains spend, and
/// a coinbase output created at `F − 60` matures exactly at `F`.
pub const HELD_BUFFER_BLOCKS: u64 = W + COINBASE_LOCK_WINDOW as u64;

const _: () = assert!(W == 730);
const _: () = assert!(REPLAY_WINDOW_BLOCKS == 725);
const _: () = assert!(HELD_BUFFER_BLOCKS == 790);

/// The canonical transaction shape, by citation: **2-in/2-out**.
///
/// `FCMP_PLUS_PLUS.md` §13 already fixes this as the project's budget shape and
/// `PDM` §9 and the firewall round both cite it. **Reused, never minted** —
/// a second canonical shape beside §13's would be the duplicate-source error
/// this project has corrected twice.
pub const CANONICAL_INPUTS: usize = 2;
/// See [`CANONICAL_INPUTS`].
pub const CANONICAL_OUTPUTS: usize = 2;

/// The sustained per-block weight ceiling reachable in the early chain.
///
/// **This is the operand the opening brief could not find**, and it is a
/// function call, not a constant:
///
/// 1. The long-term effective median is floored at the full-reward zone
///    [`MIN_BLOCK_WEIGHT`] (300 000).
/// 2. The short-term governor may run it up to `S ×` that floor
///    ([`BLOCK_WEIGHT_SURGE_FACTOR`], ratified `S = 4`);
///    `shekyl_economics::block_weight` records in its own words that for the
///    first ~100 000 blocks this clamp is *the only* protection against
///    early-chain weight growth.
/// 3. A block's admissible weight is then
///    [`block_weight_limit`]`(median, zone)` = `2 × max(median, zone)`.
///
/// `config/consensus_constants.json` carries step 2's `S` and, since E6
/// slice 4, the zone (`block_weight_full_reward_zone_bytes`, read here through
/// `EconomicParams::full_reward_zone`) — and nothing else of this chain: there
/// is no maximum block weight in it, and `shekyl_wire::block::MAX_BLOCK_BLOB_SIZE`
/// is a parse-DoS guard rather than a consensus bound. Deriving a ceiling
/// from that file would have named a value that does not exist.
#[must_use]
pub fn sustained_block_weight_ceiling() -> u64 {
    let params = EconomicParams::default();
    let surged_median = params.full_reward_zone * BLOCK_WEIGHT_SURGE_FACTOR;
    block_weight_limit(surged_median, &params)
}

/// The transaction shape that produces the most leaves per unit of block
/// weight, and that shape's weight.
///
/// Searched over the type-bounded `(n_in, n_out)` grid through
/// [`predict_weight`] — the single-sourced structural predictor the wallet's
/// own fee path uses — rather than counting bytes here. Shapes whose weight
/// exceeds [`TX_WEIGHT_LIMIT`] are excluded: the mempool refuses them, so they
/// cannot appear in the block a worst case is built from.
///
/// `fee` is passed as `0`; it enters the prediction only through `varint_len`,
/// and a zero fee is the shortest varint, which is the direction a worst case
/// wants.
#[must_use]
pub fn densest_leaf_shape(tree_depth: u8) -> LeafShape {
    let mut best: Option<LeafShape> = None;
    for n_out in 1..=MAX_OUTPUTS {
        // One input is the cheapest membership leg per transaction, but the
        // grid is searched rather than assumed: `fcmp_proof_size` is not linear
        // in `n_in`, so "fewest inputs wins" is a prediction, not a fact.
        for n_in in 1..=CANONICAL_INPUTS.max(1) {
            let inputs = InputCount::clamped(n_in);
            let outputs = OutputCount::clamped(n_out);
            let weight = predict_weight(inputs, outputs, tree_depth, 0);
            if weight > TX_WEIGHT_LIMIT {
                continue;
            }
            let candidate = LeafShape {
                inputs: n_in,
                outputs: n_out,
                weight,
            };
            let better = match &best {
                None => true,
                // Compare outputs-per-weight as a cross-product, so the
                // ordering is exact integer arithmetic rather than a float.
                Some(b) => candidate.outputs * b.weight > b.outputs * candidate.weight,
            };
            if better {
                best = Some(candidate);
            }
        }
    }
    best.expect("a 1-in/1-out transaction is always within TX_WEIGHT_LIMIT")
}

/// A transaction shape and the weight [`predict_weight`] gives it.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct LeafShape {
    /// Input count.
    pub inputs: usize,
    /// Output count — every one of which becomes a leaf.
    pub outputs: usize,
    /// Predicted weight, in the same units as [`TX_WEIGHT_LIMIT`].
    pub weight: usize,
}

/// The tree depth a **graded** spend-edge run is owed at.
///
/// §6.3.2 row 4 puts the production target at ~6 layers (~100 M leaves), and
/// `WSS_Q1B_BENCH_SPEC.md` §3.5 registers the corpus and protocol against that
/// depth. A run at another *licensed* depth is a perfectly good measurement and
/// a different one: its leaf rate and its denominator both move, so its verdict
/// is not the verdict §6.3.4 waits for — and it would otherwise satisfy the
/// `FOLLOWUPS` discharge condition while answering another question.
///
/// **A stated judgment with a reopening criterion (rule 21)**, not a
/// derivation: the chain is depth 6 only while its leaf count sits between
/// [`min_leaves_for_depth`]`(6)` and `min_leaves_for_depth(7)`. When it leaves
/// that band the graded depth moves with it, and this constant is where.
pub const GRADED_TREE_DEPTH: u8 = 6;

/// The **nominal** per-block weight the open edge grades at.
///
/// The full-reward zone, [`MIN_BLOCK_WEIGHT`] — a block that fills the space
/// every block gets regardless of the dynamic median.
///
/// **This is a stated judgment, not a derivation**, in the same class as
/// §6.3.4's 2 s and 15 % budgets. There is no chain history to take a typical
/// fill from, and the zone is an *upper bound on the un-penalized region*
/// rather than a measured average — so grading here is conservative in the
/// right direction without being the adversarial ceiling.
///
/// **Why this value and not another:** it is the density at which the
/// measurement can still surprise you. The adversarial ceiling
/// ([`sustained_block_weight_ceiling`]) is a foregone *fail* — 790 blocks at
/// 2.4 MB is ~1.9 GB decoded, which no hardware refetches in 5 s, so grading
/// there writes the miss response before measuring it. An empty chain is a
/// foregone *pass*. The zone is neither: 790 × 300 kB ≈ 237 MB in 5 s is
/// ~47 MB/s decoded (about twice that on the wire, which is hex), and whether
/// a Pi 4 does that over JSON-RPC is a genuinely open question.
///
/// **Reopening criterion (rule 21):** a measured distribution of real block
/// weights, once a chain exists, or a crossover measurement showing the 5 s
/// budget breaks below this density.
#[must_use]
pub fn nominal_block_weight() -> u64 {
    MIN_BLOCK_WEIGHT as u64
}

/// Worst-case leaves per block at a stated tree depth.
///
/// Every output becomes a leaf: §6.3.2 row 1 verified that maturity is the
/// *only* drain gate (`unlock_time` appears nowhere in `shekyl-curve-tree`), so
/// there is no second filter to discount by.
///
/// **The rate is monotonically decreasing in `tree_depth`**, because a deeper
/// tree means a larger `fcmp_proof_size` and therefore a heavier transaction.
/// That is not a reason to grade at the shallowest depth: depth is *determined*
/// by the leaf count, so a high rate sustained at depth 2 is a tree that stops
/// being depth 2. The honest pairing is to compute the rate at the depth being
/// graded, which is what the caller passes.
///
/// The coinbase is charged at [`MAX_OUTPUTS`] — an upper bound rather than the
/// real count, which is at most 16 against tens of thousands and so cannot move
/// the result.
#[must_use]
pub fn worst_case_leaves_per_block(tree_depth: u8) -> LeafRate {
    leaves_per_block_at(tree_depth, sustained_block_weight_ceiling())
}

/// Leaves per block at a stated per-block weight.
///
/// The density is a parameter because the two edges grade at different ones,
/// and that asymmetry is a ruling rather than an oversight — see
/// [`nominal_block_weight`] and `WSS_Q1B_BENCH_SPEC.md` §4.4.
#[must_use]
pub fn leaves_per_block_at(tree_depth: u8, ceiling: u64) -> LeafRate {
    let shape = densest_leaf_shape(tree_depth);
    let txs = ceiling / shape.weight as u64;
    LeafRate {
        tree_depth,
        block_weight_ceiling: ceiling,
        shape,
        transactions_per_block: txs,
        leaves_per_block: txs * shape.outputs as u64 + MAX_OUTPUTS as u64,
    }
}

/// The worst-case leaf rate, with every term that produced it.
///
/// Serialized into the run record whole: a grading run that reports only the
/// final number cannot be re-derived by a reader who disagrees with one step.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct LeafRate {
    /// The depth the rate was computed at.
    pub tree_depth: u8,
    /// [`sustained_block_weight_ceiling`].
    pub block_weight_ceiling: u64,
    /// [`densest_leaf_shape`].
    pub shape: LeafShape,
    /// `ceiling / shape.weight`.
    pub transactions_per_block: u64,
    /// The scale factor of the whole spend-edge measurement.
    pub leaves_per_block: u64,
}

/// Leaves a worst-case replay window contains, at a stated depth.
#[must_use]
pub fn worst_case_window_leaves(tree_depth: u8) -> u64 {
    worst_case_leaves_per_block(tree_depth).leaves_per_block * REPLAY_WINDOW_BLOCKS
}

/// The fewest leaves whose tree reaches `depth`.
///
/// Derived from [`outputs_per_node`] — the production capacity function — so
/// the ladder cannot drift from the widths it is built on. `outputs_per_node(j)`
/// is the leaf capacity of one node at layer `j`, so a tree rooted at layer `j`
/// holds at most that many leaves and one more leaf forces layer `j + 1`.
/// A tree rooted at layer `j` has depth `j + 1`.
///
/// Returns `None` for `depth < 2`: the Selene leaf layer is never itself the
/// root (`shekyl_fcmp::tree`'s topology note), so depth 1 is not a tree shape.
#[must_use]
pub fn min_leaves_for_depth(depth: u8) -> Option<u64> {
    if depth < 2 {
        return None;
    }
    if depth == 2 {
        return Some(1);
    }
    // Root layer of the next-shallower tree, plus one leaf.
    Some(outputs_per_node(depth - 2) as u64 + 1)
}

/// Reject a control set that cannot license what it is asked to license.
///
/// The sparse-path argument is *flatness of the sparse/dense ratio across
/// **adjacent** rungs*. A repeated depth supplies no second rung, and a gap
/// (4 and 6) establishes no adjacency — either would have been accepted and
/// then used as licensing evidence.
///
/// # Errors
/// A human-readable reason the set cannot license a sparse path.
pub fn validate_control_depths(depths: &[u8]) -> Result<(), String> {
    if depths.is_empty() {
        return Err("at least one --control-depth is required".to_string());
    }
    let mut sorted = depths.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(format!(
            "--control-depth values must be distinct; got {depths:?}. A repeated rung is \
             one rung, and one rung licenses nothing above itself."
        ));
    }
    // The Selene leaf layer is never itself the root, so depth 2 is the floor
    // of the ladder (`corpus::min_leaves_for_depth`).
    if let Some(&low) = sorted.first() {
        if low < 2 {
            return Err(format!(
                "--control-depth {low} is below the ladder floor of 2: a tree rooted at the \
                 leaf layer is not a tree shape"
            ));
        }
    }
    if sorted.len() > 1 && sorted.windows(2).any(|w| w[1] != w[0] + 1) {
        return Err(format!(
            "--control-depth values must be adjacent rungs; got {depths:?}. A gap shows no \
             flatness across the rungs it skips."
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "corpus_tests.rs"]
mod tests;
