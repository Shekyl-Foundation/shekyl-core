// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.A — acceptance topology (slice 1; `CHAIN_RULES_SLICE_1.md` §3).
//!
//! Only one 4.A row is a predicate `validate` can evaluate: **CEN-A2**, the
//! main-chain connect's fail-closed re-check that the candidate's `previous`
//! is the tip's hash (`blockchain.cpp:5423–5428`, `bl.prev_id != top_hash →
//! reject_block_internal`). The rest of 4.A is where a block *goes*, not
//! whether it is valid — dedup across three stores (A1), orphan marking
//! (A4), the routing decision itself (A2's other half), and the pre-parse /
//! parse bounds (A5–A7) — and is held by the C++ ingest driver or the wire
//! parser (§4 there).
//!
//! The store already holds A2's **belt**: `connect` refuses a verdict whose
//! `previous` is not the recorded tip as SI-2 `TipMismatch` — a fatal, not a
//! verdict. This rule is what stands in front of it, so a wrong-parent block
//! is refused as `InvalidBlock` and never reaches a belt.

use crate::census::CenRow;
use crate::rules::{BlockContext, BlockRule, Rule};
use crate::verdict::{refused, Locus, Verdict};
use crate::view::ChainView;
use shekyl_types::BlockHash;

/// CEN-A2: the candidate's `previous` is the recorded tip's hash — or, on
/// an empty chain, the null hash the genesis block carries.
///
/// The empty-chain arm is the C++'s: `get_tail_id()` → `top_block_hash()`
/// → `null_hash` when the store is empty (`db_lmdb.cpp:3186–3191`), so the
/// genesis block's `prev_id` is all zeros and `add_new_block` routes it to
/// the main-chain path. Written as an explicit `None` arm, not a fall-
/// through: a genesis candidate with a non-zero `previous` is refused.
pub(crate) struct A2;

impl A2 {
    /// What an empty chain's tip hash reads as: the null hash.
    const GENESIS_PREVIOUS: BlockHash = BlockHash::NULL;
}

impl Rule for A2 {
    const ROW: CenRow = CenRow::A2;
}

impl BlockRule for A2 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        let expected = match cx.tip {
            Some(tip) => tip.hash,
            None => Self::GENESIS_PREVIOUS,
        };
        if cx.candidate().block.header.previous == expected {
            Ok(Ok(()))
        } else {
            refused(Self::ROW, Locus::Block)
        }
    }
}

#[cfg(test)]
#[path = "topology_tests.rs"]
mod topology_tests;
