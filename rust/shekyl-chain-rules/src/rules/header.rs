// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.B — the block header (slice 1; `CHAIN_RULES_SLICE_1.md` §3):
//! the version fields (B1, B2, B7), the curve-tree root (B5) and the block's
//! identity (B6). B3 is surface-bound and the store's; B4 is deferred (E4
//! S-ARCH) and A3 is subsumed into it.
//!
//! # What the C++ does, read at `dev` `3560b80c2`
//!
//! `handle_block_to_main_chain` (`blockchain.cpp:5431–5450`) first warns
//! once if `major_version > get_ideal_version()` — the **latest scheduled**
//! version, `heights.back().version` (`hardfork.cpp:366–370`), not the one
//! in force — and does **not** reject (CEN-B7), then calls `HardFork::check` → `do_check`
//! (`hardfork.cpp:109–113`): `block_version == heights[current].version &&
//! voting_version >= heights[current].version`, where `voting_version` is
//! `minor_version` with `0` read as `1` (`hardfork.cpp:41–50`). The first
//! conjunct is CEN-B1; the second is CEN-B2, unfailable at the shipped table
//! (`current.version == 1`, and the normalised vote is `>= 1` for every
//! `u8`) — which is why the census records B2's *effect* as "unconstrained".
//!
//! # What lands here
//!
//! B1 and B2 port the **predicates**, not the effects: `major_version ==`
//! and `normalised(minor_version) >=` the header version the rule set
//! admits ([`RuleSet::header_major_version`]). Under `RuleSet::GENESIS`
//! (admits `1`) B2 cannot refuse — exactly as the C++ cannot — but the
//! comparison is the C++'s comparison, so a rule set that admits `2`
//! refuses a stale vote here as the C++ would have. B7 is the no-reject
//! branch, ported as what it is: a row whose only effect is a one-time
//! `MCLOG_RED` warning, and the crate has no logging (G12). Its operand is
//! the latest *scheduled* version, which a rule cannot read — a `RuleSet` is
//! the set in force, and the schedule is the caller's (rule 71) — so the
//! condition is **not** re-computed here against the wrong operand; the rule
//! evaluates (records its row) and refuses nothing, and the header that
//! would have tripped the warning is refused by **B1**. The fixture pins both
//! halves: B7 passes such a header when called directly, and the pipeline
//! refuses it under B1, never B7.
//!
//! The alt-admission arm (`check_for_height`, ideal version *at* the block's
//! height) collapses into the same predicates: the caller hands `validate`
//! the rule set `RuleSchedule::rules_at(height)` names, so "the version at
//! this height" is a property of the input, not a second code path.
//!
//! B1, B2 and B7 read the header and the rule set and nothing else, so they
//! are [`FormRule`]s — the stateless stage's, run in `form` outside the
//! write transaction (slice 2, Q9: stage membership is view-dependence, not
//! which slice landed the rule). B5 reads the tip and a root and stays a
//! [`BlockRule`].

use shekyl_types::BlockHash;
use shekyl_wire::Block;

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
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

/// CEN-B2: the version vote (`minor_version`, `0` read as `1`) must be at
/// least the admitted version. Unfailable under `GENESIS`; ported as the
/// predicate so it stays the C++'s comparison under a later rule set.
pub(crate) struct B2;

impl B2 {
    /// `hardfork.cpp:41–50`: a `minor_version` of `0` votes for `1`.
    const fn normalised_vote(minor_version: u8) -> u8 {
        if minor_version == 0 {
            1
        } else {
            minor_version
        }
    }
}

impl Rule for B2 {
    const ROW: CenRow = CenRow::B2;
}

impl FormRule for B2 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        let vote = Self::normalised_vote(cx.candidate.block.header.minor_version);
        if vote >= cx.rule_set.header_major_version() {
            Ok(())
        } else {
            Err(InvalidBlock::new(Self::ROW, Locus::Block))
        }
    }
}

/// CEN-B7: a `major_version` above the latest scheduled version is **not**
/// a refusal on this row — the C++ (`blockchain.cpp:5431–5441`) logs once
/// and continues, and B1 then refuses. Bucket 4, ported as-is: the row's
/// whole effect is a log line the crate does not have, and its operand
/// (`get_ideal_version()`, the schedule's last entry) is not a rule's to
/// read, so nothing is computed here in its name. The row is *evaluated* —
/// it enters coverage — and passes every header.
///
/// If the R-round that judges this row ratifies a refusal instead, the
/// operand arrives as a `RuleSet` parameter with it; until then a computed
/// condition with no consumer would be a claim the code does not act on.
pub(crate) struct B7;

impl Rule for B7 {
    const ROW: CenRow = CenRow::B7;
}

impl FormRule for B7 {
    fn check(_cx: &FormContext<'_>) -> Verdict<()> {
        Ok(())
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
    ) -> Result<Verdict<()>, V::Fault> {
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
/// B7 is a no-op *policy* the C++ still evaluates, so it runs through
/// [`BlockRule`] and [`crate::rules::run`]. B6 is the identity function,
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
