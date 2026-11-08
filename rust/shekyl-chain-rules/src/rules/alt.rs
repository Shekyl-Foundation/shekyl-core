// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.K's rule arms — the rows only an alternative block can be
//! judged on (`DRS_E5_POOL_ALT_PRUNE.md` §2.1, slice 9 a4).
//!
//! CEN-E2 is rejected (S1, design review 2026-11-03): no coded checkpoints,
//! so no anchor floor, and `D_max` is the switch's local limit
//! (`PopBeyondReorgCap`), not a consensus refusal. The alt tier
//! ([`crate::alt_against`]) judges a block against the chain it extends
//! rather than the recorded tip. Most of what it runs is the header-rule
//! half of `validate`'s ladder, bound on a [`HeaderView`] so the stitched,
//! unexecuted chain can answer it. The rows with no main-chain arm live
//! here:
//!
//! - **CEN-K1b** ([`K1b`]) — a block whose coinbase *claims* height 0
//!   cannot be an alternative. Stateless: it reads the claim, not the
//!   chain, so it is a [`FormRule`] the alt tier runs first — the C++'s
//!   ordering arm (`blockchain.cpp:1982`), the cheapest exit. The full
//!   rule is CEN-F5's claimed-equals-derived equality, which runs after;
//!   this arm's one job is to exit before a header is read. Not run by
//!   `form`: on the main chain a height-0 claim is genesis admission.
//! - **CEN-D5** ([`D5`]) — the alt chain's difficulty is CEN-D4's
//!   algorithm over the stitched window. The algorithm is `D4::target`
//!   unchanged; what D5 names is the window's provenance — the view the
//!   alt tier feeds it stitches the recorded prefix with the alt suffix
//!   (`AltView::header_at` in the store) — so the row records at the site
//!   that fed D4 an alt view, and the algorithm records its own.
//!
//! The tier itself is a row: **CEN-K4** ([`K4`]) — an alternative
//! block is stored only after the ladder above has run, in that order, and
//! nothing else. It has no predicate of its own; it is recorded when the
//! last step passes, and what it holds is the set and the order, pinned by
//! the tier's tests.

use shekyl_wire::Input;

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rules::{FormContext, FormRule, Rule};
use crate::verdict::{InvalidBlock, Locus, Verdict};

/// CEN-K1b: an alternative block whose coinbase claims height 0 is
/// refused before anything else is read.
///
/// The claim is the coinbase's `txin_gen.height`, producer-chosen; CEN-F5
/// holds it to the derived height later in the same ladder, and on an alt
/// chain the derived height is `≥ 1` by construction (CEN-K1a, the
/// store's `AltChain`), so every block this refuses F5 would also refuse.
/// The row is the *order*: the C++ exits here before its checkpoint walk,
/// attestation and PoW (`blockchain.cpp:1982`–`:1988`), and the census
/// pins the arm to that one job — its falsifier is the arm acquiring
/// another. The locus is the block (`reject_block_form`: a height-0 claim
/// is about the input, not the chain).
///
/// Any other input shape passes here: one `Gen` of a non-zero height is
/// F5's to compare, and anything else is CEN-F1's refusal.
pub(crate) struct K1b;

impl Rule for K1b {
    const ROW: CenRow = CenRow::K1b;
}

impl FormRule for K1b {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        match cx
            .candidate
            .block
            .miner_transaction
            .prefix
            .inputs
            .as_slice()
        {
            [Input::Gen(0)] => Err(InvalidBlock::new(Self::ROW, Locus::Block)),
            _ => Ok(()),
        }
    }
}

/// CEN-K4: an alternative block is accepted into storage after the cheap
/// tier's ladder — the version rows, linkage, the timestamp rows over the
/// stitched window, PoW at the alt target, the coinbase's prevalidate-only
/// rows — and before anything that reads
/// executed state, which is promotion's (`validate_miner_transaction`,
/// `check_tx_inputs`, the curve root, the attestation set).
///
/// The row is the tier, not a step of it. [`alt_against`](crate::alt_against)
/// records it after the last header predicate passes, so an [`AltValid`]
/// carries it iff every step ran; the set of steps is pinned by
/// `the_cheap_tier_evaluates_the_header_ladder_and_the_alt_arms_and_nothing_else`
/// and their order by `the_fork_is_judged_before_the_header_ladder`
/// (`alt_tests.rs`). A step added to the tier that reads chain state fails
/// the first pin; a step reordered fails the second. Not run by `validate`
/// — a main-chain block is not stored before it is executed — so the
/// registry status is `enforced_at` this site, outside per-block coverage,
/// as CEN-E5 is at writer open.
///
/// [`AltValid`]: crate::AltValid
pub(crate) struct K4;

impl Rule for K4 {
    const ROW: CenRow = CenRow::K4;
}

impl K4 {
    /// Record the row: the ladder ran to its end.
    pub(crate) fn record(coverage: &mut RuleCoverage) {
        coverage.insert(Self::ROW);
    }
}

/// CEN-D5: the alt chain's target is CEN-D4's LWMA-1 over the window the
/// stitched chain answers — the recorded prefix to the fork point, the alt
/// entries above it, ending at the candidate's parent.
///
/// The arithmetic is [`D4::target`](crate::rules::difficulty::D4::target)'s
/// and is not restated: D4 records its own row (and CEN-D6's, held by the
/// target's type). D5 is the fact that the window came from an
/// alternative chain, recorded by the alt tier with the target that call
/// produced. A main-chain `validate` never
/// records it.
pub(crate) struct D5;

impl Rule for D5 {
    const ROW: CenRow = CenRow::D5;
}

impl D5 {
    /// Record the row: the shared header derivation produced a target over
    /// an alternative chain.
    pub(crate) fn record(coverage: &mut RuleCoverage) {
        coverage.insert(Self::ROW);
    }
}
