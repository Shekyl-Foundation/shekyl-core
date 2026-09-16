// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.B — the block header's version fields (slice 1;
//! `CHAIN_RULES_SLICE_1.md` §3). B5 (the curve-tree root) and B6 (identity)
//! land with `ChainView::tip()`; B3 is surface-bound and the store's; B4 is
//! deferred (E4 S-ARCH).
//!
//! # What the C++ does, read at `dev` `3560b80c2`
//!
//! `handle_block_to_main_chain` (`blockchain.cpp:5431–5450`) first warns
//! once if `major_version > get_ideal_version()` and does **not** reject
//! (CEN-B7), then calls `HardFork::check` → `do_check`
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
//! branch: it evaluates the C++'s condition and refuses nothing, because the
//! row it is stated against says so; a header that trips it is refused by
//! **B1**, and the fixture pins that it is B1 and never B7. The one-time
//! `MCLOG_RED` warning is not ported (the crate has no logging, G12).
//!
//! The alt-admission arm (`check_for_height`, ideal version *at* the block's
//! height) collapses into the same predicates: the caller hands `validate`
//! the rule set `RuleSchedule::rules_at(height)` names, so "the version at
//! this height" is a property of the input, not a second code path.

use crate::census::CenRow;
use crate::rules::{BlockContext, BlockRule, Rule};
use crate::verdict::{refused, Locus, Verdict};
use crate::view::ChainView;

/// CEN-B1: `major_version` must equal the version the rule set admits.
pub(crate) struct B1;

impl Rule for B1 {
    const ROW: CenRow = CenRow::B1;
}

impl BlockRule for B1 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        if cx.candidate.block.header.major_version == cx.rule_set.header_major_version() {
            Ok(Ok(()))
        } else {
            refused(Self::ROW, Locus::Block)
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

impl BlockRule for B2 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        let vote = Self::normalised_vote(cx.candidate.block.header.minor_version);
        if vote >= cx.rule_set.header_major_version() {
            Ok(Ok(()))
        } else {
            refused(Self::ROW, Locus::Block)
        }
    }
}

/// CEN-B7: a `major_version` above the admitted one is **not** a refusal on
/// this row (the C++ logs once and continues; B1 then refuses). The rule
/// evaluates the branch condition — so the row is *evaluated*, not skipped —
/// and passes.
pub(crate) struct B7;

impl B7 {
    /// The C++'s branch condition, `blockchain.cpp:5432`. Returned rather
    /// than discarded so the fixture can pin which header trips it.
    pub(crate) const fn is_future_version(major_version: u8, admitted: u8) -> bool {
        major_version > admitted
    }
}

impl Rule for B7 {
    const ROW: CenRow = CenRow::B7;
}

impl BlockRule for B7 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        // Evaluated, never refused: the row's statement is "does not
        // reject". The refusal a future version earns is B1's.
        let _tripped = Self::is_future_version(
            cx.candidate.block.header.major_version,
            cx.rule_set.header_major_version(),
        );
        Ok(Ok(()))
    }
}

#[cfg(test)]
#[path = "header_tests.rs"]
mod header_tests;
