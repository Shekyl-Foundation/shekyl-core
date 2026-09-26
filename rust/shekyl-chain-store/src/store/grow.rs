// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connect's phase 3 — the curve-tree writer (DRS-E3,
//! `DRS_E3_CURVE_WRITER.md` §3.1–§3.5; `CTW-Q1` RULED). The body of the
//! `[E3 hook]` in `connect`'s phase list: it appends what the verdict
//! drained and records the tree's state after the block.
//!
//! **The store persists; it does not compute** (C2-R8 principle 3). Every
//! byte written here came off the [`ChainValid`] — the leaves, the layer
//! chunks their growth changed, the root, the depth, the leaf count, and
//! the drained outputs' indices in drain order. What the store adds is the
//! belts: that the growth continues the tree it holds (SI-11), that the
//! position maps stay a bijection (SI-17), and that the per-height count
//! advances by exactly what drained (SI-18). A verdict that does not fit
//! the tree is not adjusted; the writer halts.
//!
//! ```text
//!  3a. leaves   curve_tree_leaves[p] = leaf, p = leaf_count_before + i
//!               output_to_leaf[g] = p, leaf_to_output[p] = g      (SI-17)
//!  3b. layers   curve_tree_layers[(layer, chunk)] = hash — the last chunk
//!               of each layer, overwritten; new chunks inserted  (CTW-8)
//!  3c. summary  curve_tree_meta = {root, depth, leaf_count}       (SI-12)
//!               curve_tree_leaf_counts[h + 1] = leaf count after (SI-18)
//! ```
//!
//! 3a and 3b run only when something drained; 3c's second row is written
//! on **every** connect, grown or not, exactly as `curve_tree_roots[h + 1]`
//! is (SI-4) — the count going into `h + 1` is a fact whether or not it
//! moved, and `leaf_count_at` reads it without a fallback (SCW-19's rule
//! for the roots, applied to the count it is keyed like).
//!
//! No pending table, no checkpoint, no segment freeze (§3.5, §3.7,
//! `CTW-Q3`): the C++'s `locked_outputs` was a stored view of the drain
//! function `validate` now computes, and its checkpoints and
//! intermediate-layer pruning served a re-derivation this design does not
//! do. The frontier — each layer's last chunk — is the whole of what a
//! grow reads back (CTW-8), and it is read from `curve_tree_layers` by
//! `leaf_reads::frontier`.

use shekyl_chain_rules::{ChainValid, ChainView, Drain};
use shekyl_types::TreePosition;

use crate::codec::{Canonical, CurveTreeState, LayerHash, LeafCount, TreeDepth};
use crate::ids::{ChunkIndex, LayerChunk, TreeLayer};
use crate::schema::{
    CURVE_TREE_LAYERS, CURVE_TREE_LEAF_COUNTS, CURVE_TREE_LEAVES, CURVE_TREE_META, LEAF_TO_OUTPUT,
    OUTPUT_TO_LEAF,
};

use super::curve_reads;
use super::error::{LeafDensity, StoreError, StoreInvariant};
use super::write::WriteBatch;

impl<'id> WriteBatch<'_, 'id> {
    /// Phase 3: append the verdict's drain and record the tree's state
    /// going into `height + 1`. Returns nothing the caller needs — the root
    /// row is phase 4's, written from the same verdict.
    pub(super) fn record_drain<V: ChainView<'id>>(
        &self,
        height: u64,
        valid: &ChainValid<'id, V>,
    ) -> Result<(), StoreError> {
        // The tree as the store holds it, before this block. The summary
        // is the count's owner (SCU-Q1); the leaf table's length is SI-11's
        // other side and the summary read has already held them equal.
        let before = curve_reads::summary(self.txn()).map_err(|f| self.arm_read_fault(f))?;
        let after = match valid.block().drain() {
            None => before.leaf_count,
            Some(drain) => self.append(before, drain)?,
        };
        self.open_insert_table(CURVE_TREE_LEAF_COUNTS, StoreInvariant::LeafCountRewritten)?
            .insert(height + 1, after.encoded().as_encoded())?;
        Ok(())
    }

    /// 3a + 3b + 3c's summary: the writes a non-empty drain makes.
    fn append(&self, before: CurveTreeState, drain: &Drain) -> Result<LeafCount, StoreError> {
        let growth = &drain.growth;
        // SI-11: the growth continues the tree the store holds. The
        // verdict was derived over this batch's own view, so a
        // disagreement here is the store's record changing under the
        // derivation — a corrupt tree, not a stale claim.
        if growth.leaf_count_before != before.leaf_count.to_raw() {
            return Err(self.poison().arm(StoreInvariant::LeavesNotDense {
                observed: LeafDensity::Length {
                    count: growth.leaf_count_before,
                    rows: before.leaf_count.to_raw(),
                },
            }));
        }
        // SI-17's precondition: one index per leaf, in the order the
        // derivation assigned positions.
        if drain.outputs.len() != growth.leaves.len() {
            return Err(self.poison().arm(StoreInvariant::PositionMapsNotBijective));
        }

        // ---- 3a. leaves and the position maps --------------------------
        {
            let mut leaves = self.open_insert_table(
                CURVE_TREE_LEAVES,
                StoreInvariant::LeavesNotDense {
                    observed: LeafDensity::Length {
                        count: growth.leaf_count_before,
                        rows: before.leaf_count.to_raw(),
                    },
                },
            )?;
            let mut to_leaf =
                self.open_insert_table(OUTPUT_TO_LEAF, StoreInvariant::PositionMapsNotBijective)?;
            let mut to_output =
                self.open_insert_table(LEAF_TO_OUTPUT, StoreInvariant::PositionMapsNotBijective)?;
            for (i, (leaf, output)) in growth.leaves.iter().zip(&drain.outputs).enumerate() {
                let position =
                    growth.leaf_count_before + u64::try_from(i).expect("leaf count fits u64");
                leaves.insert(position, leaf.encoded().as_encoded())?;
                to_leaf.insert(
                    output.to_raw(),
                    TreePosition::from_raw(position).encoded().as_encoded(),
                )?;
                to_output.insert(position, output.encoded().as_encoded())?;
            }
        }

        // ---- 3b. the layer chunks the growth changed --------------------
        // Each layer's last chunk is overwritten (its pre-image journaled
        // for `pop`); a chunk beyond the old frontier is new. One verb for
        // both: the upsert's journal entry carries whether a prior existed.
        {
            let mut layers = self.open_upsert_table(CURVE_TREE_LAYERS)?;
            for write in &growth.layer_writes {
                let key = LayerChunk::new(
                    TreeLayer::from_raw(write.layer),
                    ChunkIndex::from_raw(write.chunk),
                )
                .key();
                layers.upsert(
                    key,
                    LayerHash::from_bytes(write.hash).encoded().as_encoded(),
                )?;
            }
        }

        // ---- 3c. the summary --------------------------------------------
        let after = LeafCount::from_raw(growth.leaf_count_after());
        let state = CurveTreeState {
            root: growth.root,
            depth: TreeDepth::from_raw(growth.depth),
            leaf_count: after,
        };
        self.open_upsert_table(CURVE_TREE_META)?
            .upsert((), state.encoded().as_encoded())?;
        Ok(after)
    }
}
