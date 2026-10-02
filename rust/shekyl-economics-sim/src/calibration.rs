// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! W9 **stuffer** cost model (A4, §12.2 / DQ-2C).
//!
//! **Shape, stated so no future reader imports the wrong threat model.** The D2
//! operand `n` counts the shards **closed** by cumulative archival length —
//! `|pqc_auths| + |prunable|` per transaction, `W` bytes per shard (`SHT-Q2`,
//! `shekyl_types::shard_of`). A stuffer therefore buys **archival bytes per
//! fee**, and the fee is `weight × FEE_PER_BYTE`, so the lever is the ratio
//! `archival_len / weight` over the shapes the builder accepts
//! (`1..=MAX_INPUTS` × `1..=MAX_OUTPUTS`). That ratio is **maximised by
//! inputs, not outputs**: each input carries a hybrid PQC authorisation
//! (prunable) and a share of the FCMP proof (prunable), while each output's
//! bytes are mostly the unprunable prefix the fee pays for and the shard does
//! not count. So the shape is **`MAX_INPUTS`-in / 1-out** — the reverse of the
//! J-segment era's 1-in / 16-out *leaf* stuffer, which inflated a count of
//! outputs that the operand no longer measures. It is **not** a
//! black-marble/decoy construct: FCMP++ has no rings; nothing here poisons a
//! decoy pool (the ring-side half of the Rucknium report that FCMP++ deletes).
//!
//! The shape is **searched, not asserted** ([`stuffer_shape`]): the argmax is
//! computed over every shape at the chain's depth, so if a wire change moved
//! the balance the model would follow it. The one-shot (binding, attacker-
//! favouring) cost uses that shape alone; a *sustained* campaign cannot — it
//! consumes `MAX_INPUTS − 1` outputs per transaction, and outputs are
//! conserved — so [`sustained_stuffer_cost_per_shard_atomic`] prices the
//! cheapest producer/consumer **cycle** whose net output balance is zero, and
//! the reports carry both.
//!
//! **DQ-2G / DQ-2C — cost is single-sourced through the production predictor.**
//! Weight comes from `shekyl_tx_weight::predict_weight` (the byte-mirror of
//! `Transaction::write`, hoisted D-1) and archival length from its sibling
//! `predict_archival_len`, pinned to `Transaction::archival_len()` over the
//! whole shape space; `tree_depth` rides the chain's leaf count via the
//! production [`shekyl_curve_tree::segment::outputs_per_node`]. The Monero
//! March-2024 figures are an order-of-magnitude anchor + proof-of-willingness
//! (§12.3 DQ-2C), re-expressed in Shekyl's unit below — never hard-coded.

use shekyl_curve_tree::segment::outputs_per_node;
use shekyl_tx_weight::{
    predict_archival_len, predict_weight, InputCount, OutputCount, MAX_OUTPUTS, MAX_TREE_DEPTH,
};
use shekyl_types::SHARD_LENGTH;

use crate::burden::SHARD_BYTES;

/// Minimum weight-fee, atomic units per byte (`cryptonote_config.h:66`
/// `FEE_PER_BYTE = 300`). Genesis-provisional; the stuffer pays this floor
/// (DQ-2C directive 1). A boundary constant (scenario layer, DQ-2G).
pub const FEE_PER_BYTE_ATOMIC: u64 = 300;

// ── Rucknium March-2024 anchor (DQ-2C; report/calibration only) ──────────────
/// Sustained duration of the incident, days (report §6). Weeks, not a burst.
pub const RUCKNIUM_DURATION_DAYS: u64 = 23;
/// Total spam fees paid, XMR (report §6). ~a quarter-cent per output at the time.
pub const RUCKNIUM_SPAM_FEES_XMR: f64 = 61.5;
/// Total spam bytes, GB (report §6). `20 nanonero/byte × 3.08 GB ≈ 61.6 XMR`.
pub const RUCKNIUM_SPAM_BYTES_GB: f64 = 3.08;
/// The spam's byte volume as Shekyl shards' worth of archival good (`W` per
/// shard) — the replication row. Monero's transaction bytes are
/// prunable-heavy, so this is the volume's order of magnitude in the unit the
/// operand counts, not a claim that every byte would have been archival.
#[must_use]
pub fn rucknium_shards_equivalent() -> u64 {
    (RUCKNIUM_SPAM_BYTES_GB * 1.0e9 / SHARD_BYTES) as u64
}

/// Leaves a tree of depth `j` holds — the production [`outputs_per_node`] —
/// or `None` once that product no longer fits the machine word.
/// `outputs_per_node` is a `const fn` product that overflows `usize` around
/// layer 12 (its own doc) — a panic, not a wrap — so the layer below is
/// checked against the widest per-layer multiplier (the leaf chunk,
/// `outputs_per_node(0)`) before the product is asked for. A capacity that
/// does not fit the word is one no chain can fill.
fn layer_capacity(j: u8) -> Option<u64> {
    let mut cap = outputs_per_node(0);
    for layer in 1..=j {
        if cap > usize::MAX / outputs_per_node(0) {
            return None;
        }
        cap = outputs_per_node(layer);
    }
    Some(cap as u64)
}

/// Curve-tree depth needed to hold `n` leaves — the smallest layer whose
/// [`layer_capacity`] covers `n`, clamped to the proof system's max. Deps the
/// real width logic (DQ-2G dep-don't-mirror), so every transaction's FCMP
/// proof cost rides real chain depth: shallow early, deeper late.
#[must_use]
pub fn tree_depth_for_leaves(n: u64) -> u8 {
    let n = n.max(1);
    for j in 0..=MAX_TREE_DEPTH {
        match layer_capacity(j) {
            Some(cap) if cap >= n => return j.max(1),
            Some(_) => {}
            // Deeper than any chain can be; report the layer rather than
            // ask for a capacity that does not fit.
            None => return j.min(MAX_TREE_DEPTH),
        }
    }
    MAX_TREE_DEPTH
}

/// A transaction shape the builder accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub n_in: InputCount,
    pub n_out: OutputCount,
}

impl Shape {
    /// Block weight of one transaction of this shape at `tree_depth`, at its
    /// min-fee, via the **converge fixpoint** the build path runs (fee feeds
    /// `varint(fee)` into the weight, so it is circular by a few bytes; two
    /// iterations from zero settle it). Integer throughout (DQ-2G).
    #[must_use]
    pub fn tx_weight(self, tree_depth: u8) -> u64 {
        let mut fee = 0u64;
        let mut weight = 0u64;
        for _ in 0..2 {
            weight = predict_weight(self.n_in, self.n_out, tree_depth, fee) as u64;
            fee = weight * FEE_PER_BYTE_ATOMIC;
        }
        weight
    }

    /// Weight-fee (atomic) of one transaction of this shape at `tree_depth`:
    /// `tx_weight × FEE_PER_BYTE`.
    #[must_use]
    pub fn tx_fee_atomic(self, tree_depth: u8) -> u64 {
        self.tx_weight(tree_depth) * FEE_PER_BYTE_ATOMIC
    }

    /// Archival bytes one transaction of this shape adds to the fold at
    /// `tree_depth` — what the operand counts.
    #[must_use]
    pub fn archival_bytes(self, tree_depth: u8) -> u64 {
        predict_archival_len(self.n_in, self.n_out, tree_depth) as u64
    }

    /// Outputs created minus outputs consumed: positive for a producer,
    /// negative for a consumer. A sustained campaign's shapes must net to zero.
    #[must_use]
    pub fn net_outputs(self) -> i64 {
        self.n_out.get() as i64 - self.n_in.get() as i64
    }

    /// `"8-in/1-out"`, for the reports.
    #[must_use]
    pub fn label(self) -> String {
        format!("{}-in/{}-out", self.n_in.get(), self.n_out.get())
    }
}

/// Every shape the builder accepts, `1..=MAX_INPUTS` × `1..=MAX_OUTPUTS`. The
/// input cap is read off the bounded type (it is crate-internal to the
/// predictor by design); clamping `usize::MAX` lands on it.
fn all_shapes() -> impl Iterator<Item = Shape> {
    let max_in = InputCount::clamped(usize::MAX).get();
    (1..=max_in).flat_map(move |i| {
        (1..=MAX_OUTPUTS).map(move |o| Shape {
            n_in: InputCount::clamped(i),
            n_out: OutputCount::clamped(o),
        })
    })
}

/// Fee per archival byte of `shape` at `tree_depth`, as a rational
/// `(fee, bytes)`; compared cross-multiplied so the argmax is exact.
fn fee_per_archival(shape: Shape, tree_depth: u8) -> (u128, u128) {
    (
        u128::from(shape.tx_fee_atomic(tree_depth)),
        u128::from(shape.archival_bytes(tree_depth).max(1)),
    )
}

fn cheaper(a: (u128, u128), b: (u128, u128)) -> bool {
    // a.fee / a.bytes < b.fee / b.bytes
    a.0 * b.1 < b.0 * a.1
}

/// The **max-archival-per-fee** shape at `tree_depth` — the one-shot
/// stuffer's transaction, searched over every shape the builder accepts.
#[must_use]
pub fn stuffer_shape(tree_depth: u8) -> Shape {
    all_shapes()
        .map(|s| (s, fee_per_archival(s, tree_depth)))
        .fold(
            None,
            |best: Option<(Shape, (u128, u128))>, cand| match best {
                Some(b) if !cheaper(cand.1, b.1) => Some(b),
                _ => Some(cand),
            },
        )
        .expect("the shape space is non-empty")
        .0
}

/// The **max-archival-per-block** figure at `tree_depth`: the most archival
/// bytes any single shape the builder accepts can land in one block of
/// `block_weight`, `max over shapes of ⌊block_weight / weight⌋ · archival_len`.
/// This is **not** [`stuffer_shape`]'s packing: the fee-per-byte argmin is the
/// cheapest shape, but only whole transactions fit a finite block, so a
/// shape with a slightly worse ratio and a smaller remainder can land more
/// bytes (at the surge ceiling, 6-in/1-out beats 8-in/1-out by ≈ 3 %). The
/// physical ceiling on the fold's slew is this search, not the cost search.
#[must_use]
pub fn max_archival_bytes_per_block(block_weight: u64, tree_depth: u8) -> u64 {
    all_shapes()
        .map(|s| {
            let weight = s.tx_weight(tree_depth);
            if weight == 0 {
                0
            } else {
                (block_weight / weight).saturating_mul(s.archival_bytes(tree_depth))
            }
        })
        .max()
        .unwrap_or(0)
}

impl Shape {
    /// Transactions of this shape at `tree_depth` that land `bytes` of
    /// archival good: `⌈bytes / archival_bytes⌉`.
    fn txs_for_archival_bytes(self, tree_depth: u8, bytes: u128) -> u128 {
        bytes.div_ceil(u128::from(self.archival_bytes(tree_depth).max(1)))
    }
}

/// Transactions of [`stuffer_shape`] that close one shard — `W` archival
/// bytes — at `tree_depth`. The per-depth rate the reports print; a campaign
/// is priced by [`stuffer_campaign`], not by multiplying this.
#[must_use]
pub fn stuffer_txs_per_shard(tree_depth: u8) -> u64 {
    let txs = stuffer_shape(tree_depth)
        .txs_for_archival_bytes(tree_depth, u128::from(SHARD_LENGTH.to_raw()));
    u64::try_from(txs).unwrap_or(u64::MAX)
}

/// Transactions of a shape minting `n_out` outputs each that a tree of
/// `leaves` outputs absorbs **before it deepens past `depth`**. A transaction
/// is built — and its FCMP proof priced — against the tree as it stands, so
/// the `k`-th (from 0) sees `leaves + k · n_out` outputs and is at `depth`
/// while that is within the layer's capacity. Unbounded at the deepest layer
/// and past the representable capacities (no chain gets there).
fn stuffer_txs_before_deepening(depth: u8, leaves: u64, n_out: u64) -> u128 {
    if depth >= MAX_TREE_DEPTH {
        return u128::MAX;
    }
    match layer_capacity(depth) {
        None => u128::MAX,
        Some(cap) => u128::from(cap.saturating_sub(leaves) / n_out.max(1)) + 1,
    }
}

/// One **one-shot** stuffer campaign: every transaction is the
/// max-archival-per-fee shape, outputs assumed on hand. The binding
/// (attacker-favouring) figure. Integer (DQ-2G).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StufferCampaign {
    /// Transactions sent.
    pub txs: u64,
    /// Weight-fees paid, atomic.
    pub cost_atomic: u128,
}

/// The campaign that closes `delta` more shards — `delta · W` archival bytes —
/// against a curve tree of `honest_leaves` outputs, **integrated across the
/// tree-layer boundaries its own outputs cross**: each transaction is priced
/// at the depth the tree has when it is built, so a campaign that deepens
/// the tree pays the shallower fee up to the crossing and the deeper one
/// after it, with the deeper shape's bytes counted from there. Pricing the
/// whole campaign at the final depth would charge every transaction before
/// the crossing the wrong proof size.
///
/// The transaction count is **rounded once**, at the end: within a layer
/// whole transactions land exact bytes, and only the last segment carries
/// the ceiling. Rounding per shard and multiplying would reset the fold
/// remainder at every boundary and overstate the count by up to `delta − 1`
/// transactions. The fold's position inside the current shard when the
/// campaign starts is not modelled (the operand is a shard count): it can
/// only lower the count, by under one shard's worth of transactions.
#[must_use]
pub fn stuffer_campaign(honest_leaves: u64, delta: u64) -> StufferCampaign {
    let mut remaining = u128::from(SHARD_LENGTH.to_raw()) * u128::from(delta);
    let mut leaves = honest_leaves;
    let mut txs = 0u64;
    let mut cost_atomic = 0u128;
    while remaining > 0 {
        let depth = tree_depth_for_leaves(leaves);
        let shape = stuffer_shape(depth);
        let n_out = shape.n_out.get() as u64;
        let to_finish = shape.txs_for_archival_bytes(depth, remaining);
        let take = to_finish.min(stuffer_txs_before_deepening(depth, leaves, n_out));
        // `take ≥ 1` (both operands are), so every pass retires bytes and the
        // loop terminates; `take < to_finish` leaves `remaining > 0`.
        remaining = remaining.saturating_sub(take * u128::from(shape.archival_bytes(depth).max(1)));
        cost_atomic += take * u128::from(shape.tx_fee_atomic(depth));
        let take = u64::try_from(take).unwrap_or(u64::MAX);
        txs = txs.saturating_add(take);
        leaves = leaves.saturating_add(take.saturating_mul(n_out));
    }
    StufferCampaign { txs, cost_atomic }
}

/// Attacker cost (atomic) to close one more shard — `W` archival bytes —
/// against a tree of `honest_leaves`: [`stuffer_campaign`] at `delta = 1`.
/// The per-shard rate the reports print; a campaign of `delta` shards is
/// priced by the campaign function, not by multiplying this.
#[must_use]
pub fn stuffer_cost_per_shard_atomic(honest_leaves: u64) -> u128 {
    stuffer_campaign(honest_leaves, 1).cost_atomic
}

/// Attacker cost (atomic) to close one more shard under **output
/// conservation**: the cheapest producer/consumer cycle whose net output
/// balance is zero. For a consumer `C` (`net < 0`) and producer `P`
/// (`net > 0`), a cycle of `net_P` copies of `C` and `−net_C` copies of `P`
/// nets to zero; a shape with `net ≥ 0` is a cycle on its own. Cost per shard
/// is `⌈W · fee_cycle / bytes_cycle⌉`. The sustained figure a campaign that
/// has to mint its own inputs actually pays; reported beside the one-shot
/// cost, which stays the gate's input.
///
/// **Pairs are complete, not a shortcut.** Minimising `Σλ·fee / Σλ·bytes`
/// over shape weights `λ ≥ 0` under `Σλ·net = 0` is a linear-fractional
/// program; after the Charnes–Cooper transform it is a linear program with
/// two equality constraints (the balance and the normalisation), so a basic
/// optimum has at most two shapes with non-zero weight. Searching triples
/// would find nothing cheaper.
#[must_use]
pub fn sustained_stuffer_cost_per_shard_atomic(chain_leaves: u64) -> u128 {
    let depth = tree_depth_for_leaves(chain_leaves);
    let shapes: Vec<(Shape, (u128, u128))> = all_shapes()
        .map(|s| (s, fee_per_archival(s, depth)))
        .collect();
    let mut best: Option<(u128, u128)> = None;
    let mut consider = |cycle: (u128, u128)| {
        if best.is_none_or(|b| cheaper(cycle, b)) {
            best = Some(cycle);
        }
    };
    for &(c, (fee_c, bytes_c)) in &shapes {
        let net_c = c.net_outputs();
        if net_c >= 0 {
            consider((fee_c, bytes_c));
            continue;
        }
        let need = u128::from(net_c.unsigned_abs());
        for &(p, (fee_p, bytes_p)) in &shapes {
            let net_p = p.net_outputs();
            if net_p <= 0 {
                continue;
            }
            let copies_c = u128::from(net_p.unsigned_abs());
            consider((
                copies_c * fee_c + need * fee_p,
                copies_c * bytes_c + need * bytes_p,
            ));
        }
    }
    let (fee, bytes) = best.expect("the shape space is non-empty");
    (u128::from(SHARD_LENGTH.to_raw()) * fee).div_ceil(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_depth_monotone_and_bounded() {
        // Deeper chains need deeper trees; always in [1, MAX].
        let d_small = tree_depth_for_leaves(1_000);
        let d_big = tree_depth_for_leaves(5_000_000_000);
        assert!((1..=MAX_TREE_DEPTH).contains(&d_small));
        assert!(d_big >= d_small);
        // A chain holding exactly one layer-2 node's capacity sits at depth 2.
        assert_eq!(tree_depth_for_leaves(outputs_per_node(2) as u64), 2);
    }

    #[test]
    fn stuffer_shape_is_max_inputs_min_outputs() {
        // Inputs carry the archival bytes (PQC auth + FCMP share, both
        // prunable); outputs carry unprunable prefix the fee pays for and the
        // operand does not count. So the argmax is MAX_INPUTS-in / 1-out at
        // every depth — and the J-segment era's 1-in/16-out leaf stuffer is
        // now among the DEAREST shapes per archival byte.
        //
        // TRIPWIRE, not a regression check: `stuffer_shape` SEARCHES, so a
        // wire-format change that moved the archival/weight balance would be
        // followed by the model and fail only here. On failure the model is
        // right and this expectation is stale — re-read the prose that quotes
        // the shape (ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md §12.13) and
        // update both.
        let max_in = InputCount::clamped(usize::MAX).get();
        for depth in 2..=MAX_TREE_DEPTH {
            let s = stuffer_shape(depth);
            assert_eq!(
                (s.n_in.get(), s.n_out.get()),
                (max_in, 1),
                "depth {depth}: the archival/weight balance moved — the searched \
                 shape is now {}-in/{}-out; update the model's prose and §12.13, \
                 this is not a regression",
                s.n_in.get(),
                s.n_out.get()
            );
            let leafy = Shape {
                n_in: InputCount::clamped(1),
                n_out: OutputCount::clamped(MAX_OUTPUTS),
            };
            assert!(cheaper(
                fee_per_archival(s, depth),
                fee_per_archival(leafy, depth)
            ));
        }
    }

    #[test]
    fn layer_capacity_is_the_depth_boundary() {
        // `tree_depth_for_leaves` and the campaign integrator read the same
        // boundary: a tree filled exactly to a layer's capacity is at that
        // depth; one more leaf deepens it.
        for j in 2..=6u8 {
            let cap = layer_capacity(j).expect("single-digit layers fit the word");
            assert_eq!(tree_depth_for_leaves(cap), j);
            assert_eq!(tree_depth_for_leaves(cap + 1), j + 1);
        }
        assert!(layer_capacity(MAX_TREE_DEPTH).is_none());
    }

    #[test]
    fn campaign_rounds_once_and_is_never_dearer_than_per_shard_times_delta() {
        // Inside one layer the only difference between the campaign and
        // `delta` per-shard campaigns is the rounding, so start the tree at
        // the bottom of a layer wide enough that no sweep delta here deepens it.
        let leaves = layer_capacity(4).unwrap() + 1_000;
        let depth = tree_depth_for_leaves(leaves);
        let shape = stuffer_shape(depth);
        let fee = u128::from(shape.tx_fee_atomic(depth));
        let per_shard = stuffer_cost_per_shard_atomic(leaves);
        for delta in [1u64, 2, 7, 250, 4_096] {
            let campaign = stuffer_campaign(leaves, delta);
            assert_eq!(
                tree_depth_for_leaves(leaves + campaign.txs * shape.n_out.get() as u64),
                depth,
                "delta {delta} deepened the tree; this test's premise is one layer"
            );
            let naive = per_shard * u128::from(delta);
            // Rounding once can only drop whole transactions the per-shard
            // ceiling counted twice: at most `delta − 1` of them.
            assert!(
                campaign.cost_atomic <= naive,
                "delta {delta}: {} > {naive}",
                campaign.cost_atomic
            );
            assert!(
                campaign.cost_atomic + fee * u128::from(delta - 1) >= naive,
                "delta {delta}: campaign dropped more than delta − 1 transactions"
            );
            assert_eq!(campaign.cost_atomic, u128::from(campaign.txs) * fee);
        }
        assert_eq!(stuffer_campaign(leaves, 1).cost_atomic, per_shard);
    }

    #[test]
    fn campaign_crossing_a_layer_boundary_is_priced_per_segment() {
        // Start just under the layer-4 capacity so a 100-shard campaign
        // deepens the tree part-way: the transactions before the crossing
        // are priced at depth 4, the rest at depth 5 with depth-5 bytes.
        let cap = layer_capacity(4).unwrap();
        let leaves = cap - 1_000;
        let delta = 100u64;
        let shallow = tree_depth_for_leaves(leaves);
        assert_eq!(shallow, 4);
        let s4 = stuffer_shape(shallow);
        let n_out = s4.n_out.get() as u64;
        // The k-th transaction (from 0) sees `leaves + k·n_out`; it is at
        // depth 4 while that is ≤ cap.
        let first = (cap - leaves) / n_out + 1;
        let bytes_total = u128::from(SHARD_LENGTH.to_raw()) * u128::from(delta);
        let bytes_after = bytes_total - u128::from(first) * u128::from(s4.archival_bytes(shallow));
        let deep = tree_depth_for_leaves(leaves + first * n_out);
        assert_eq!(deep, 5, "the campaign must actually cross");
        let s5 = stuffer_shape(deep);
        let rest = bytes_after.div_ceil(u128::from(s5.archival_bytes(deep)));
        assert!(rest > 0, "the campaign must continue past the crossing");

        let campaign = stuffer_campaign(leaves, delta);
        assert_eq!(u128::from(campaign.txs), u128::from(first) + rest);
        assert_eq!(
            campaign.cost_atomic,
            u128::from(first) * u128::from(s4.tx_fee_atomic(shallow))
                + rest * u128::from(s5.tx_fee_atomic(deep))
        );
        // And it is neither flat pricing: the crossing is visible in the figure.
        let flat = |d: u8| {
            stuffer_shape(d).txs_for_archival_bytes(d, bytes_total)
                * u128::from(stuffer_shape(d).tx_fee_atomic(d))
        };
        assert_ne!(campaign.cost_atomic, flat(shallow));
        assert_ne!(campaign.cost_atomic, flat(deep));
    }

    #[test]
    fn max_archival_per_block_is_a_search_not_the_cost_shape() {
        // The physical ceiling is argmax ⌊B/w⌋·archival over every shape; the
        // fee-per-byte argmin is a candidate, never above the max. At the
        // surge ceiling the two differ: whole transactions, finite block.
        let block_weight =
            shekyl_economics::FULL_REWARD_ZONE * shekyl_economics::BLOCK_WEIGHT_SURGE_FACTOR;
        let mut differs_somewhere = false;
        for depth in 2..=MAX_TREE_DEPTH {
            let best = max_archival_bytes_per_block(block_weight, depth);
            let s = stuffer_shape(depth);
            let cost_shape = (block_weight / s.tx_weight(depth)) * s.archival_bytes(depth);
            assert!(best >= cost_shape, "depth {depth}: {best} < {cost_shape}");
            assert!(
                best <= block_weight,
                "archival bytes cannot exceed the block"
            );
            differs_somewhere |= best > cost_shape;
        }
        assert!(
            differs_somewhere,
            "the search never beat the cost shape — if the wire format moved so the \
             two coincide at every depth, this expectation is stale, not the model"
        );
    }

    #[test]
    fn cost_per_shard_is_txs_times_fee_and_sustained_is_dearer() {
        let leaves = 100_000;
        let depth = tree_depth_for_leaves(leaves);
        let expected = u128::from(stuffer_txs_per_shard(depth))
            * u128::from(stuffer_shape(depth).tx_fee_atomic(depth));
        assert_eq!(stuffer_cost_per_shard_atomic(leaves), expected);
        assert!(expected > 0);
        // Conserving outputs can only add producer transactions to the mix.
        let sustained = sustained_stuffer_cost_per_shard_atomic(leaves);
        assert!(sustained >= expected, "{sustained} < {expected}");
        // …and never by more than the dearest single producer would cost.
        let leafy = Shape {
            n_in: InputCount::clamped(1),
            n_out: OutputCount::clamped(MAX_OUTPUTS),
        };
        let all_leafy = (u128::from(SHARD_LENGTH.to_raw())
            * u128::from(leafy.tx_fee_atomic(depth)))
        .div_ceil(u128::from(leafy.archival_bytes(depth)));
        assert!(sustained <= all_leafy);
    }

    #[test]
    fn a_shard_costs_about_one_skl_and_depth_barely_moves_it() {
        // W = 3 MB of archival good at 300 atomic/byte of WEIGHT: weight ≳
        // archival, so a shard is on the order of W × 300 ≈ 0.9 SKL. Deeper
        // trees grow the FCMP proof — which is archival good the stuffer is
        // buying — so depth moves the archival/weight RATIO, not the price,
        // and only by a few percent (measured 2026-10-01: +1.3 % one-shot,
        // −2.6 % sustained, depth 1 → 6). The leaf era's "cheapest early" was
        // a lever; byte-keyed it is noise. Pinned as a bound, not a direction,
        // because integer tx-per-shard rounding makes the sign depth-local.
        let early = stuffer_cost_per_shard_atomic(30_000);
        let late = stuffer_cost_per_shard_atomic(5_000_000_000);
        let one_skl = u128::from(crate::burden::COIN);
        assert!(
            (one_skl / 2..=2 * one_skl).contains(&early),
            "early {early}"
        );
        let (lo, hi) = (early.min(late), early.max(late));
        assert!(
            hi * 100 <= lo * 105,
            "depth moves the cost by >5%: {early} vs {late}"
        );
    }
}
