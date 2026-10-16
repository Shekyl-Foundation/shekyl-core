// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.B — the block header (slice 1; `CHAIN_RULES_SLICE_1.md` §3):
//! the version fields (B1, B2), the curve-tree root (B5) and the block's
//! identity (B6). B3 is surface-bound and the store's; B4 (the
//! attestation set) is `rules::attestation` (slice 8 row 10), and A3 is
//! its empty-witness arm.
//!
//! # The version pair
//!
//! A header carries two version bytes, and each has exactly one valid
//! value. `major_version` is the version the rule set admits
//! ([`RuleSet::header_major_version`], `1`): CEN-B1. `minor_version` is
//! [`HEADER_MINOR_VERSION`], `0`: CEN-B2. Both are equalities, and neither
//! is a vote or an "at least".
//!
//! The C++ holds both equalities in one predicate
//! (`header_version_is_valid`, `blockchain.cpp`), called on the main path
//! and on the alternative-chain path, against
//! `CURRENT_BLOCK_MAJOR_VERSION` and `CURRENT_BLOCK_MINOR_VERSION`. It has
//! no height schedule. `rule_set_tests` holds those two defines equal to
//! the values here.
//!
//! "The version at this height" is a property of the input, not a second
//! code path: the caller hands `validate` the rule set
//! `RuleSchedule::rules_at(height)` names, on the main chain and on an
//! alternative one alike.
//!
//! B1 reads the header and the rule set. B2 reads the header only: the
//! reserved minor byte does not depend on which rule set is in force. Both
//! are [`FormRule`]s — the
//! stateless stage's, run in `form` outside the write transaction (slice 2,
//! Q9: stage membership is view-dependence, not which slice landed the
//! rule). B5 reads the tip and a root and stays a [`BlockRule`].

use shekyl_types::BlockHash;
use shekyl_wire::block::HEADER_MINOR_VERSION;
use shekyl_wire::Block;

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::ViewRead;
use crate::rules::{BlockContext, BlockRule, FormContext, FormRule, Rule};
use crate::verdict::{refused, InvalidBlock, Locus, Verdict};
use crate::view::{AtHeight, ChainView};

/// CEN-B1: `major_version` must equal the version the rule set admits.
pub(crate) struct B1;

impl Rule for B1 {
    const ROW: CenRow = CenRow::B1;
}

impl FormRule for B1 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        if cx.candidate.block.header.major_version == cx.rule_set.header_major_version() {
            Ok(())
        } else {
            Err(InvalidBlock::new(Self::ROW, Locus::Block))
        }
    }
}

/// CEN-B2: `minor_version` must be [`HEADER_MINOR_VERSION`]. The byte is
/// reserved, and a reserved byte that validates at any value is the
/// producer's to write.
pub(crate) struct B2;

impl Rule for B2 {
    const ROW: CenRow = CenRow::B2;
}

impl FormRule for B2 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        if cx.candidate.block.header.minor_version == HEADER_MINOR_VERSION {
            Ok(())
        } else {
            Err(InvalidBlock::new(Self::ROW, Locus::Block))
        }
    }
}

/// CEN-B5: the header's `curve_tree_root` is the tree state **at the
/// connecting height** — after the parent connected, before this block
/// drains its own leaves — i.e. `root_at(tip + 1)`, the last row the parent's
/// connect wrote (SCW-19: key `h` is the state at `h`).
///
/// The C++ compares against `m_db->get_curve_tree_root()`, the tip root,
/// *after* the `prev_id == top_hash` check has made the tip the parent
/// (`blockchain.cpp:5579–5591`); here the same operand is read by height.
/// At genesis the connecting height is `0` and `root_at(0)` is the empty
/// tree, which is what the genesis header carries
/// (`shekyl-genesis-tool/src/builder.rs:185`).
///
/// `AboveTip` is unreachable against a conforming view — SI-4 keeps
/// `tip + 1` recorded — and is written as a refusal anyway: a view with no
/// state at the connecting height has nothing to compare the header to, and
/// G11 says the arm is a decision, not a fall-through.
pub(crate) struct B5;

impl Rule for B5 {
    const ROW: CenRow = CenRow::B5;
}

impl BlockRule for B5 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        view: &V,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let claimed = cx.candidate().block.header.curve_tree_root;
        match view.root_at(cx.connecting)? {
            AtHeight::Recorded(root) if root == claimed => Ok(Ok(())),
            AtHeight::Recorded(_) | AtHeight::AboveTip => refused(Self::ROW, Locus::Block),
        }
    }
}

/// CEN-B6: block identity is `keccak256(varint(len) ‖ header ‖
/// merkle(miner_tx_hash ‖ tx_hashes) ‖ varint(n_tx + 1))` — the PoW blob
/// with its length prefix (`get_block_hashing_blob`; `shekyl_wire::Block::
/// hash`, `block.rs:217–247`). **Adopted**, not re-implemented: the KAT that
/// pins it to the daemon's hashes is `shekyl-wire/tests/coinbase_hash.rs`
/// (live-oracle vectors; height 0 equals the published mainnet genesis id).
///
/// A definition, not a predicate: nothing about a candidate can fail it.
/// B6 is the identity function,
/// so it is not a check that always passes — coverage is recorded here,
/// when the identity is derived, and `implemented(rules::header::B6)`
/// names this function (slice 1, Q5). **Derived once, by `form`**: the
/// identity is stateless (a keccak over the hashing blob) and a view-bound
/// rule reads it while the rules run (CEN-E1, slice 3 F8/Q7), so `form`
/// calls [`B6::identity`] and the token carries it
/// (`StructurallyValid::hash`); `ValidatedBlock::derive` takes that value
/// and computes no second one. Slice 1 placed the derivation after the last
/// rule on the premise that no rule reads the identity — refuted, not
/// superseded.
pub(crate) struct B6;

impl Rule for B6 {
    const ROW: CenRow = CenRow::B6;
}

impl B6 {
    /// The block's identity under CEN-B6, recorded in `coverage` as this
    /// row having been applied.
    pub(crate) fn identity(block: &Block, coverage: &mut RuleCoverage) -> BlockHash {
        coverage.insert(Self::ROW);
        block.hash()
    }
}

#[cfg(test)]
#[path = "header_tests.rs"]
mod header_tests;
