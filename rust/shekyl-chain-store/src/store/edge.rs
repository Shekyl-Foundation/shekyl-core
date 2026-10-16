// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SI-5 — the tree's right edge after a pop (`DRS_E5_POOL_ALT_PRUNE.md`
//! §2.3, ruled 2026-10-15; `STORE_INVARIANT_REGISTER.md` SI-5).
//!
//! A pop replays the tip's undo row, and the curve-tree rows come back from
//! their journaled pre-images like every other row. SI-12 then holds the
//! summary's root to `curve_tree_roots[tip + 1]`, but both come back from
//! the same journal: a pre-image recorded wrong restores a wrong layer chunk
//! that SI-12 cannot see. This belt reads the tree itself.
//!
//! A pop only trims leaves at the end, so the chunks a pop can change are
//! exactly each layer's last chunk. The belt rebuilds every one of them
//! from its stored children — the leaves under layer 0's last chunk, then,
//! layer by layer, the stored full chunks under the next last chunk plus the
//! chunk just rebuilt — with the rules crate's arithmetic
//! ([`rebuild_right_edge`]; the store hosts storage and computes no hash of
//! its own, DRS-D3b). Every rebuilt chunk must equal the stored one, and the
//! top must equal the live root. Cost: chunk width × depth reads.
//!
//! [`WriteBatch::pop_many`] is the one entry that runs it: the connector's
//! `Rewind` and the switch both pop through it, so a caller cannot pop a
//! run and skip the belt.

use shekyl_chain_rules::{rebuild_right_edge, FrontierFault, RightEdgeSpan};
use shekyl_types::{CurveTreeRoot, TreePosition};

use crate::codec::CodecError;

use super::at_index::AtIndex;
use super::curve_reads;
use super::error::{CellFault, EdgeFault, StoreError, StoreInvariant};
use super::leaf_reads;
use super::pop::Popped;
use super::write::WriteBatch;

impl WriteBatch<'_, '_> {
    /// Pop `count` blocks off the tip, then hold the tree the pops left to
    /// its own children (SI-5). Returns what each pop removed, tip first.
    /// Popping nothing reads nothing.
    ///
    /// # Errors
    ///
    /// Whatever [`pop`](Self::pop) returns, at the pop that returned it;
    /// [`StoreInvariant::RightEdgeDiverged`] (SI-5, poisons and halts) when a
    /// rebuilt chunk is not the stored one or the rebuilt root is not the
    /// live root; SI-7 for a layer row or leaf that is absent, undecodable
    /// or off its curve; engine errors.
    pub fn pop_many(&self, count: u64) -> Result<Vec<Popped>, StoreError> {
        let mut popped = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
        for _ in 0..count {
            popped.push(self.pop()?);
        }
        if count > 0 {
            self.check_right_edge()?;
        }
        Ok(popped)
    }

    /// SI-5 over the tree as this batch holds it (module docs).
    pub(super) fn check_right_edge(&self) -> Result<(), StoreError> {
        let txn = self.txn();
        // The summary read holds SI-11 (count = rows) and SI-12 (its root is
        // the live root), so `state.root` below is `curve_tree_roots[tip + 1]`.
        let state = curve_reads::summary(txn).map_err(|f| self.arm_read_fault(f))?;
        let Some(span) = RightEdgeSpan::of(state.leaf_count.to_raw()) else {
            // No leaves, no edge: SI-12 has held the empty summary to the
            // live root.
            return Ok(());
        };
        let range =
            TreePosition::from_raw(span.leaves.start)..TreePosition::from_raw(span.leaves.end);
        let leaves = match curve_reads::leaves(txn, range).map_err(|f| self.arm_read_fault(f))? {
            AtIndex::Recorded(leaves) => leaves,
            // The span ends at the summary's own count, so the bound cannot
            // refuse it; reaching here is the bound disagreeing with itself.
            AtIndex::BeyondCount => unreachable!("the edge span ends at the summary's count"),
        };
        let mut full = Vec::with_capacity(span.children.len());
        for (below, children) in span.children.iter().enumerate() {
            let below = u8::try_from(below).expect("a tree has fewer than 256 layers");
            full.push(
                leaf_reads::layer_chunks(txn, below, children.start..children.end - 1)
                    .map_err(|f| self.arm_read_fault(f))?,
            );
        }
        let stored = leaf_reads::frontier(txn).map_err(|f| self.arm_read_fault(f))?;
        let edge = rebuild_right_edge(&span, &leaves, &full)
            .map_err(|fault| self.poison().arm(unservable(fault)))?;
        for (layer, (rebuilt, held)) in edge.iter().zip(&stored.last_chunks).enumerate() {
            if rebuilt != held {
                let layer = u8::try_from(layer).expect("a tree has fewer than 256 layers");
                return Err(self.poison().arm(StoreInvariant::RightEdgeDiverged {
                    observed: EdgeFault::Chunk { layer },
                }));
            }
        }
        let rebuilt_root = CurveTreeRoot::from_bytes(*edge.last().expect("a non-empty edge"));
        if rebuilt_root != state.root {
            return Err(self.poison().arm(StoreInvariant::RightEdgeDiverged {
                observed: EdgeFault::Root,
            }));
        }
        Ok(())
    }
}

/// A rebuild input that is not a tree: the stored bytes are off their
/// curve, or the span read is not the span's size. SI-7 on the table the
/// bytes were read from. A leaf scalar is layer 0 (`curve_tree_leaves`,
/// codec `tree_leaf`); a chunk hash is every layer above it
/// (`curve_tree_layers`, codec `layer_hash`). The grow path (`write.rs`)
/// maps `NotOnCurve` only for a frontier last-chunk hash, already known
/// to be a layer hash — a leaf fails earlier as `LeafNotConstructible`.
fn unservable(fault: FrontierFault) -> StoreInvariant {
    match fault {
        FrontierFault::NotOnCurve { layer: 0 } => StoreInvariant::CellCorrupt {
            key: "curve_tree_leaves",
            fault: CellFault::Undecodable(CodecError::Invalid {
                codec: "tree_leaf",
                reason: "a leaf scalar on the tree's right edge is not on its curve",
            }),
        },
        FrontierFault::NotOnCurve { .. } => StoreInvariant::CellCorrupt {
            key: "curve_tree_layers",
            fault: CellFault::Undecodable(CodecError::Invalid {
                codec: "layer_hash",
                reason: "a chunk hash on the tree's right edge is not on its curve",
            }),
        },
        FrontierFault::Shape { .. } => StoreInvariant::CellCorrupt {
            key: "curve_tree_layers",
            fault: CellFault::Undecodable(CodecError::Invalid {
                codec: "layer_hash",
                reason: "the right edge's reads are not the span its leaf count implies",
            }),
        },
    }
}
