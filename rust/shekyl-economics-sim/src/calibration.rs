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

/// Curve-tree depth needed to hold `n` leaves — the smallest layer whose
/// production capacity ([`outputs_per_node`]) covers `n`, clamped to the proof
/// system's max. Deps the real width logic (DQ-2G dep-don't-mirror), so every
/// transaction's FCMP proof cost rides real chain depth: shallow early, deeper
/// late.
#[must_use]
pub fn tree_depth_for_leaves(n: u64) -> u8 {
    let n = n.max(1);
    for j in 0..=MAX_TREE_DEPTH {
        let cap = outputs_per_node(j);
        if cap as u64 >= n {
            return j.max(1);
        }
        // `outputs_per_node` is a `const fn` product that overflows `usize`
        // around layer 12 (its own doc) — a panic, not a wrap. A leaf count
        // the next layer could not represent is deeper than any chain can be;
        // report that layer rather than ask for a capacity that does not fit.
        // The widest per-layer multiplier is the leaf chunk, `outputs_per_node(0)`.
        if cap > usize::MAX / outputs_per_node(0) {
            return (j + 1).min(MAX_TREE_DEPTH);
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

/// Transactions of [`stuffer_shape`] that close `delta` more shards —
/// `delta · W` archival bytes — at `tree_depth`: `⌈delta · W / archival_bytes⌉`,
/// **rounded once** for the whole campaign. Rounding per shard and
/// multiplying would reset the fold remainder at every boundary and
/// overstate the count by up to `delta − 1` transactions. The fold's
/// position inside the current shard when the campaign starts is not
/// modelled (the operand is a shard count): it can only lower the count,
/// by under one shard's worth of transactions.
#[must_use]
pub fn stuffer_campaign_txs(tree_depth: u8, delta: u64) -> u64 {
    let bytes = stuffer_shape(tree_depth).archival_bytes(tree_depth).max(1);
    SHARD_LENGTH.to_raw().saturating_mul(delta).div_ceil(bytes)
}

/// Transactions of [`stuffer_shape`] that close one shard at `tree_depth`:
/// [`stuffer_campaign_txs`] at `delta = 1`.
#[must_use]
pub fn stuffer_txs_per_shard(tree_depth: u8) -> u64 {
    stuffer_campaign_txs(tree_depth, 1)
}

/// Leaves (outputs) a campaign closing `delta` shards adds to the curve tree
/// at `tree_depth` — the tree-depth bookkeeping for a campaign, small: the
/// shape minimises outputs.
#[must_use]
pub fn stuffer_campaign_leaves(tree_depth: u8, delta: u64) -> u64 {
    stuffer_campaign_txs(tree_depth, delta) * stuffer_shape(tree_depth).n_out.get() as u64
}

/// Attacker cost (atomic) to close `delta` more shards when the curve tree
/// holds `chain_leaves` outputs, **one-shot**: every transaction is the
/// max-archival-per-fee shape, outputs assumed on hand, the transaction count
/// rounded once for the campaign ([`stuffer_campaign_txs`]). The binding
/// (attacker-favouring) figure. Integer (DQ-2G).
#[must_use]
pub fn stuffer_campaign_cost_atomic(chain_leaves: u64, delta: u64) -> u128 {
    let depth = tree_depth_for_leaves(chain_leaves);
    u128::from(stuffer_campaign_txs(depth, delta))
        * u128::from(stuffer_shape(depth).tx_fee_atomic(depth))
}

/// Attacker cost (atomic) to close one more shard — `W` archival bytes:
/// [`stuffer_campaign_cost_atomic`] at `delta = 1`. The per-shard rate the
/// reports print; a campaign of `delta` shards is priced by the campaign
/// function, not by multiplying this.
#[must_use]
pub fn stuffer_cost_per_shard_atomic(chain_leaves: u64) -> u128 {
    stuffer_campaign_cost_atomic(chain_leaves, 1)
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
    fn campaign_rounds_once_and_is_never_dearer_than_per_shard_times_delta() {
        let leaves = 100_000;
        let depth = tree_depth_for_leaves(leaves);
        let fee = u128::from(stuffer_shape(depth).tx_fee_atomic(depth));
        let per_shard = stuffer_cost_per_shard_atomic(leaves);
        for delta in [1u64, 2, 7, 250, 4_096] {
            let campaign = stuffer_campaign_cost_atomic(leaves, delta);
            let naive = per_shard * u128::from(delta);
            // Rounding once can only drop whole transactions the per-shard
            // ceiling counted twice: at most `delta − 1` of them.
            assert!(campaign <= naive, "delta {delta}: {campaign} > {naive}");
            assert!(
                campaign + fee * u128::from(delta - 1) >= naive,
                "delta {delta}: campaign dropped more than delta − 1 transactions"
            );
            assert_eq!(
                stuffer_campaign_leaves(depth, delta),
                stuffer_campaign_txs(depth, delta) * stuffer_shape(depth).n_out.get() as u64
            );
        }
        assert_eq!(stuffer_campaign_cost_atomic(leaves, 1), per_shard);
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
