// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One read body for the curve-tree tables (DRS-E1 S-CURVE,
//! `DRS_E1_SCURVE.md` §3), the fourth sibling of `chain_reads`,
//! `output_reads` and `tx_reads`. Five C++ reads become three
//! (`DRS_E1_SCURVE.md` §3.2):
//!
//! - **C1** [`summary`] — `curve_tree_meta`'s one row, the tree's
//!   `{root, depth, leaf_count}` as one value (`SCU-Q1`).
//! - **C2** [`root_at`] — `curve_tree_roots[h]`, the tree state *going
//!   into* block `h`. The body `ChainView::root_at` had on the batch view,
//!   generic over [`ReadTables`] so the committed snapshot and the batch
//!   read the same table under the same absence rule — one read, no
//!   private twin.
//! - **C3** [`leaves`] — a bounded walk over `curve_tree_leaves` in the
//!   table's own key order, dense by invariant.
//!
//! # Absence, stated once (`DRS_E1_SCURVE.md` §3.3)
//!
//! - **An empty tree is a written row**, [`CurveTreeState::EMPTY`], put by
//!   the seal. An absent `curve_tree_meta` row is therefore **SI-7**
//!   ([`StoreInvariant::CellCorrupt`] `{ Absent }`), never a default: the
//!   C++ defaulted three cells three ways and documented the resulting
//!   root ambiguity for callers to disentangle with a second read (SCU-1).
//!   No caller compares a root against `hash_init` here.
//! - **A root above `tip + 1`** is [`AtHeight::AboveTip`]; a missing row at
//!   or below it is SI-7. Row 0 is the empty tree by definition and is not
//!   stored.
//! - **A leaf range past the count** is [`AtIndex::BeyondCount`] and no row
//!   is read; a position *inside* the count with no row is **SI-11**
//!   ([`StoreInvariant::LeavesNotDense`]). The C++ collapsed both into one
//!   `false`.
//!
//! # SI-11 is armed here, not at a writer
//!
//! The grow path is DRS-E3's and not yet built, so the reads carry the
//! belt: C1 compares the summary's count with the leaf table's length, C3
//! names the first position in range with no row. When E3 lands, its batch
//! moves the count and the rows together and this belt becomes the
//! second check, as SI-9's read-side belt is for `output_txs`.

use core::ops::Range;

use redb::{ReadableTable, ReadableTableMetadata};
use shekyl_chain_rules::AtHeight;
use shekyl_types::{BlockHeight, CurveTreeRoot, TreeLeaf, TreePosition};

use crate::codec::CurveTreeState;
use crate::schema::{CURVE_TREE_LEAVES, CURVE_TREE_META, CURVE_TREE_ROOTS};

use super::at_index::AtIndex;
use super::chain_reads::{self, absent, undecodable, ReadFault, ReadTables};
use super::error::StoreInvariant;

/// The `curve_tree_meta` cell as faults name it.
const META: &str = "curve_tree_meta";
/// The `curve_tree_leaves` cell as faults name it.
const LEAVES: &str = "curve_tree_leaves";
/// The `curve_tree_roots` cell as faults name it.
const ROOTS: &str = "curve_tree_roots";

/// SI-11 for a read: the summary's count and the leaf rows disagree at
/// `position` (module docs).
const fn not_dense(position: TreePosition) -> ReadFault {
    ReadFault::Invariant(StoreInvariant::LeavesNotDense {
        position: position.to_raw(),
    })
}

/// **C1.** The tree's summary — `curve_tree_meta`'s one row, decoded.
/// Absent is SI-7 (the seal wrote `EMPTY`); a count that is not the leaf
/// table's length is SI-11 (module docs).
pub(super) fn summary<T: ReadTables>(txn: &T) -> Result<CurveTreeState, ReadFault> {
    let state = summary_row(txn)?;
    let rows = txn.table(CURVE_TREE_LEAVES)?.len()?;
    if rows != state.leaf_count.to_raw() {
        return Err(not_dense(state.leaf_count.next_position()));
    }
    Ok(state)
}

/// The summary row alone, without the density belt — C3's bound, which
/// walks the rows itself and would report the same disagreement at the
/// position it finds it.
fn summary_row<T: ReadTables>(txn: &T) -> Result<CurveTreeState, ReadFault> {
    let table = txn.table(CURVE_TREE_META)?;
    let Some(guard) = table.get(())? else {
        return Err(absent(META));
    };
    guard
        .value()
        .decode()
        .map_err(|cause| undecodable(META, cause))
}

/// **C2.** `curve_tree_roots[height]` — the tree state **at** `height`,
/// written by the connect of `height − 1`. Height 0 is the empty tree,
/// [`CurveTreeRoot::EMPTY`], and is not a row; `1..=tip + 1` must be
/// present (SI-7 otherwise); above that is [`AtHeight::AboveTip`]. `tip + 1`
/// is the state a candidate at `tip + 1` is checked against — CEN-B5's read
/// — and the last row `connect` wrote.
pub(super) fn root_at<T: ReadTables>(
    txn: &T,
    height: BlockHeight,
) -> Result<AtHeight<CurveTreeRoot>, ReadFault> {
    let h = height.to_raw();
    if h == 0 {
        return Ok(AtHeight::Recorded(CurveTreeRoot::EMPTY));
    }
    match chain_reads::tip_of(txn)? {
        Some((tip, _)) if h <= tip.saturating_add(1) => {}
        _ => return Ok(AtHeight::AboveTip),
    }
    root_row(txn, h).map(AtHeight::Recorded)
}

/// The root row the dense range says must exist: `curve_tree_roots[key]`
/// for a `key` the caller has already classified as `1..=tip + 1`. Absent
/// is SI-7. Shared by [`root_at`] and the live-root read the digest takes
/// straight off a decoded tip, so the two cannot disagree about what a
/// missing row means.
pub(super) fn root_row<T: ReadTables>(txn: &T, key: u64) -> Result<CurveTreeRoot, ReadFault> {
    chain_reads::cell(txn, CURVE_TREE_ROOTS, key, ROOTS)?.ok_or_else(|| absent(ROOTS))
}

/// **C3.** The leaves at `range`, in position order. Bound first: a range
/// whose end is past the summary's count is [`AtIndex::BeyondCount`] and no
/// row is read — the whole range is refused, as `AboveTip` refuses a height
/// range that starts above the tip, because a caller that asked past the
/// tree has the wrong count, not a partial answer. Inside the count the
/// table is dense (SI-11): a position with no row is
/// [`StoreInvariant::LeavesNotDense`], an undecodable row SI-7. An empty
/// range inside the count is `Recorded(vec![])`.
pub(super) fn leaves<T: ReadTables>(
    txn: &T,
    range: Range<TreePosition>,
) -> Result<AtIndex<Vec<TreeLeaf>>, ReadFault> {
    let count = summary_row(txn)?.leaf_count;
    if range.end.to_raw() > count.to_raw() {
        return Ok(AtIndex::BeyondCount);
    }
    let (start, end) = (range.start.to_raw(), range.end.to_raw());
    if start >= end {
        return Ok(AtIndex::Recorded(Vec::new()));
    }
    let mut out = Vec::with_capacity(usize::try_from(end - start).unwrap_or(0));
    let table = txn.table(CURVE_TREE_LEAVES)?;
    let mut expected = start;
    for row in table.range(start..end)? {
        let (key, guard) = row?;
        if key.value() != expected {
            return Err(not_dense(TreePosition::from_raw(expected)));
        }
        out.push(
            guard
                .value()
                .decode()
                .map_err(|cause| undecodable(LEAVES, cause))?,
        );
        expected += 1;
    }
    if expected != end {
        return Err(not_dense(TreePosition::from_raw(expected)));
    }
    Ok(AtIndex::Recorded(out))
}
