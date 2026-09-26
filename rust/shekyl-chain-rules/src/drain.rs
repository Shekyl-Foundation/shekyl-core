// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The drain — which recorded outputs mature at a connecting height, and
//! what the curve tree becomes once they are appended. DRS-E3
//! (`DRS_E3_CURVE_WRITER.md` §3.2, §3.3, §3.6).
//!
//! Maturity in Shekyl is a function of height and origin, nothing else
//! (`blockchain_db.cpp:554–567`; `unlock_time` plays no part — CEN-H14's
//! family): a coinbase output matures `mined_money_unlock_window` blocks
//! after its block, every other output `tx_spendable_age` blocks after.
//! So the set of outputs that join the tree when the block at `h` connects
//! is a **function of the chain below `h`** — block `h − window`'s coinbase
//! outputs, then block `h − age`'s listed outputs, in that order — and is
//! computed here from the view, never read from a pending table (CTW-10:
//! the C++'s `locked_outputs` was a stored view of this function, and a
//! stored view of facts the store already holds is a query).
//!
//! **Drain order is not output order** (§3.3). The two source blocks are
//! `window − age` heights apart, so the coinbase half is the *older*
//! block's; its outputs carry smaller global indices but are appended
//! **first**, at the lower leaf positions, before the younger block's listed
//! outputs. Any reader that assumes leaf position is monotone in global
//! index is wrong; `output_to_leaf` exists because it is not (SOK-10).
//!
//! This module is not a rule. It refuses nothing about the candidate block
//! — a drain is decided by the chain, not by the block being connected —
//! and it has no census row, because growth is an operand that F17, I12,
//! I13 and I15 read, not a rule (E3 Round 1: `Provenance::passed_through`
//! is its instrument). What it can raise is `Corrupt`: a recorded output
//! whose points do not decompress, or a tree the view describes
//! inconsistently, is a store that no longer conforms, and the verdict
//! halts rather than mint a root over it (C2-R8 principle 3: the root is a
//! consensus fact and this is the consensus-owned function that computes
//! it; the store persists what it is handed).

use shekyl_fcmp::tree::construct_leaf;
use shekyl_types::{BlockHeight, CurveTreeRoot, GlobalOutputIndex, TreeLeaf};

use crate::fault::{Corrupt, PerHeightRecord, ViewRead};
use crate::rule_set::RuleSet;
use crate::tree_growth::{grow, TreeGrowth};
use crate::view::{AtHeight, BlockOutputs, ChainView, LeafSource};

/// What a block's connect appends to the tree: the matured outputs **in
/// drain order** and the growth their leaves produce. `outputs[i]` is the
/// output whose leaf sits at position `growth.leaf_count_before + i` —
/// the pair the position maps record (`output_to_leaf`, `leaf_to_output`;
/// SI-17), carried on the verdict so the writer records the order the
/// derivation used rather than re-deriving it (§3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drain {
    /// The drained outputs' chain-wide indices, in drain order. Same
    /// length as `growth.leaves`.
    pub outputs: Vec<GlobalOutputIndex>,
    /// The leaves, the layer chunks they change, and the root.
    pub growth: TreeGrowth,
}

/// The tree after the block at `connecting` drains: the growth its matured
/// outputs produce, or `None` when none matured — in which case the root
/// is unchanged and the caller carries `root_at(connecting)` forward.
///
/// Reads the two source heights ([`sources`]) — each present on a
/// conforming view because both are below `connecting`, so `AboveTip` from
/// either is [`Corrupt::HoleBelowTip`] — constructs each output's leaf, and
/// grows the frontier. A view whose frontier is `EMPTY` and whose drain is
/// empty (the first `age` heights of every chain) returns `None` without
/// touching the frontier.
pub(crate) fn drain<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
    rule_set: &RuleSet,
) -> Result<Option<Drain>, ViewRead<V::Fault>> {
    let sources = sources(connecting, rule_set);
    let mut outputs: Vec<GlobalOutputIndex> = Vec::new();
    let mut leaves: Vec<TreeLeaf> = Vec::new();
    if let Some(height) = sources.coinbase_of {
        let recorded = recorded_outputs(view, height)?;
        extend(&mut outputs, &mut leaves, &recorded.coinbase)?;
    }
    if let Some(height) = sources.listed_of {
        let recorded = recorded_outputs(view, height)?;
        extend(&mut outputs, &mut leaves, &recorded.listed)?;
    }
    if leaves.is_empty() {
        return Ok(None);
    }
    let frontier = view.tree_frontier().map_err(ViewRead::View)?;
    let growth = grow(&frontier, &leaves)
        .map_err(|fault| ViewRead::Corrupt(Corrupt::TreeUnservable { fault }))?;
    Ok(Some(Drain { outputs, growth }))
}

/// The two heights whose outputs mature at `connecting`: the block whose
/// coinbase does, and the block whose listed outputs do. `None` where the
/// subtraction would reach below genesis — nothing matured yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DrainSources {
    /// `connecting − mined_money_unlock_window`.
    pub coinbase_of: Option<BlockHeight>,
    /// `connecting − tx_spendable_age`.
    pub listed_of: Option<BlockHeight>,
}

/// The source heights of the drain at `connecting` under `rule_set`.
pub(crate) fn sources(connecting: BlockHeight, rule_set: &RuleSet) -> DrainSources {
    DrainSources {
        coinbase_of: connecting.checked_sub_count(rule_set.mined_money_unlock_window()),
        listed_of: connecting.checked_sub_count(rule_set.tx_spendable_age()),
    }
}

/// The tree after the block at `connecting` connects: its root, and the
/// drain that produced it when anything matured. What `validate` derives
/// for the verdict (`ValidatedBlock::{root_after, drain}`), exposed so a
/// fixture that builds a chain can carry the root the next header must
/// (CEN-B5) without a second definition of the drain — one derivation,
/// driven over whatever [`ChainView`] holds the blocks.
pub fn tree_after<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
    rule_set: &RuleSet,
) -> Result<(CurveTreeRoot, Option<Drain>), ViewRead<V::Fault>> {
    let drained = drain(view, connecting, rule_set)?;
    let root = match &drained {
        Some(drain) => drain.growth.root,
        None => unchanged_root(view, connecting)?,
    };
    Ok((root, drained))
}

/// The root the verdict carries when the drain appended nothing: the tree
/// at `connecting`, which a conforming view has recorded (`root_at(0)` is
/// [`CurveTreeRoot::EMPTY`] by definition, SCW-19).
fn unchanged_root<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
) -> Result<CurveTreeRoot, ViewRead<V::Fault>> {
    match view.root_at(connecting).map_err(ViewRead::View)? {
        AtHeight::Recorded(root) => Ok(root),
        AtHeight::AboveTip => Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
            at: connecting,
            record: PerHeightRecord::CurveTreeRoot,
        })),
    }
}

fn recorded_outputs<'id, V: ChainView<'id>>(
    view: &V,
    height: BlockHeight,
) -> Result<BlockOutputs, ViewRead<V::Fault>> {
    match view.outputs_at(height).map_err(ViewRead::View)? {
        AtHeight::Recorded(outputs) => Ok(outputs),
        AtHeight::AboveTip => Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
            at: height,
            record: PerHeightRecord::Outputs,
        })),
    }
}

fn extend<VF>(
    outputs: &mut Vec<GlobalOutputIndex>,
    leaves: &mut Vec<TreeLeaf>,
    sources: &[LeafSource],
) -> Result<(), ViewRead<VF>> {
    for source in sources {
        let leaf = construct_leaf(&source.key, &source.commitment, &source.pqc_leaf_commitment)
            .ok_or(ViewRead::Corrupt(Corrupt::LeafNotConstructible {
                output: source.output,
            }))?;
        outputs.push(source.output);
        leaves.push(TreeLeaf::from_bytes(leaf));
    }
    Ok(())
}

#[cfg(test)]
#[path = "drain_tests.rs"]
mod tests;
