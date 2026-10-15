// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.K's rule arms, and CEN-E2 — the rows only an alternative
//! block can be judged on (`DRS_E5_POOL_ALT_PRUNE.md` §2.1, slice 9 a4).
//!
//! The alt tier ([`crate::alt_against`]) judges a block against the chain it
//! extends rather than the recorded tip. Most of what it runs is the
//! header-rule half of `validate`'s ladder, bound on a [`HeaderView`] so
//! the stitched, unexecuted chain can answer it. Three rows have no
//! main-chain arm at all and live here:
//!
//! - **CEN-K1b** ([`K1b`]) — a block whose coinbase *claims* height 0
//!   cannot be an alternative. Stateless: it reads the claim, not the
//!   chain, so it is a [`FormRule`] the alt tier runs first — the C++'s
//!   ordering arm (`blockchain.cpp:1982`), the cheapest exit. The full
//!   rule is CEN-F5's claimed-equals-derived equality, which runs after;
//!   this arm's one job is to exit before a header is read. Not run by
//!   `form`: on the main chain a height-0 claim is genesis admission.
//! - **CEN-E2** ([`E2`]) — the two bands of `PDM-Q11`. The *anchor floor*:
//!   an alternative rooted below the release's current anchor would replace
//!   the anchored block, and no chain that does so can reach the anchor's
//!   hash. The *rolling cap*: an alternative that would pop more than
//!   `D_max` recorded blocks is refused, so a deep rewrite is a visible
//!   split rather than a silent reorg. Both read the **fork** — where the
//!   alternative leaves the recorded chain and how long the recorded chain
//!   is — which no [`HeaderView`] states, so the rule is a function over
//!   the [`Fork`] the alt view names (`AltChainView::fork`), recorded at
//!   its site as CEN-E5 is.
//! - **CEN-D5** ([`D5`]) — the alt chain's difficulty is CEN-D4's
//!   algorithm over the stitched window. The algorithm is `D4::target`
//!   unchanged; what D5 names is the window's provenance — the view the
//!   alt tier feeds it stitches the recorded prefix with the alt suffix
//!   (`AltView::header_at` in the store) — so the row records at the site
//!   that fed D4 an alt view, and the algorithm records its own.
//!
//! A fourth row is the tier itself: **CEN-K4** ([`K4`]) — an alternative
//! block is stored only after the ladder above has run, in that order, and
//! nothing else. It has no predicate of its own; it is recorded when the
//! last step passes, and what it holds is the set and the order, pinned by
//! the tier's tests.

use shekyl_wire::Input;

use crate::alt::Fork;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rule_set::RuleSet;
use crate::rules::{FormContext, FormRule, Rule};
use crate::trust::Trust;
use crate::verdict::{InvalidBlock, Locus, Verdict};

/// CEN-K1b: an alternative block whose coinbase claims height 0 is
/// refused before anything else is read.
///
/// The claim is the coinbase's `txin_gen.height`, producer-chosen; CEN-F5
/// holds it to the derived height later in the same ladder, and on an alt
/// chain the derived height is `≥ 1` by construction (CEN-K1a, the
/// store's `AltChain`), so every block this refuses F5 would also refuse.
/// The row is the *order*: the C++ exits here before checkpoints,
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
/// stitched window, the anchor floor, PoW at the alt target, the
/// coinbase's prevalidate-only rows — and before anything that reads
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

/// CEN-E2: the anchor floor and the rolling reorg cap (`PDM-Q11`, one
/// function, two bands), over the fork an alternative block would cause.
///
/// **Band 1 — the floor.** Refused when the fork's root is below the
/// release's current anchor (`ReleaseAnchors::current`, the last
/// checkpoint the binary carries): the alternative's first block sits at
/// `root + 1 ≤ C`, so accepting it would replace the anchored block, and
/// a chain that replaces the anchored block cannot carry the anchor's hash
/// at `C` (CEN-E1 would refuse it there). The C++
/// (`is_alternative_block_allowed`, `checkpoints.cpp:97`–`:109`) tested the
/// *candidate's claimed* height against the last checkpoint below the
/// recorded height; this tests the *fork root*, a derived fact, so a chain
/// whose earlier blocks were admitted before a release shipped the anchor
/// is refused at its next block rather than extended past it.
///
/// **Band 2 — the cap.** Refused when the recorded blocks the alternative
/// would pop — `recorded_tip − root` — exceed the rule set's
/// [`reorg_cap`](RuleSet::reorg_cap) (`D_max`; read from the rule set,
/// never the constant, so a Fakechain set and its store agree). `D_max` is
/// a detectability boundary, not a security margin: below it an adversary
/// who can afford the work reorganises silently; at it, the rewrite is a
/// split the operator can see. The cap **binds only when anchored**: a node
/// whose release carries no checkpoint has no cap (`PDM-Q11`, binding
/// condition — the anchor is the cap's precondition, not its sibling).
///
/// Neither band reads the view: the fork is the caller's derivation
/// ([`Fork`]), the anchor is the [`Trust`]'s, the cap is the rule set's.
/// So this is not a [`HeaderRule`](crate::rules::HeaderRule) — it is run
/// by the alt tier before any header is read, and records its row here.
pub(crate) struct E2;

impl Rule for E2 {
    const ROW: CenRow = CenRow::E2;
}

impl E2 {
    /// Judge `fork` under `trust`'s anchors and `rule_set`'s cap, recording
    /// the row when it passes.
    pub(crate) fn check(
        fork: &Fork,
        rule_set: &RuleSet,
        trust: &Trust,
        coverage: &mut RuleCoverage,
    ) -> Verdict<()> {
        // The floor is the last anchor the recorded chain has reached —
        // the census row's "last anchor preceding the current height"
        // (`is_alternative_block_allowed`), not the table's last entry: an
        // anchor above the tip is no floor yet, and treating it as one
        // would refuse the very alternative block it names (CEN-K6's
        // checkpoint arm, DRS-E5 a5).
        let Some(anchor) = trust.anchors().last_at_or_below(fork.recorded_tip().height) else {
            // No anchored chain: no floor to stand on and no cap to bind.
            coverage.insert(Self::ROW);
            return Ok(());
        };
        if fork.root().height < anchor.height {
            return Err(InvalidBlock::new(Self::ROW, Locus::Block));
        }
        // How many recorded blocks the alternative would pop. [`Fork::new`]
        // refused a root above the recorded tip, so the span is defined;
        // the store faults that pair as SI-7 before a `Fork` exists
        // (`AltChain::build`).
        let pops = fork.pops();
        if pops > rule_set.reorg_cap() {
            return Err(InvalidBlock::new(Self::ROW, Locus::Block));
        }
        coverage.insert(Self::ROW);
        Ok(())
    }
}

/// CEN-D5: the alt chain's target is CEN-D4's LWMA-1 over the window the
/// stitched chain answers — the recorded prefix to the fork point, the alt
/// entries above it, ending at the candidate's parent.
///
/// The arithmetic is [`D4::target`](crate::rules::difficulty::D4::target)'s
/// and is not restated: D4 records its own row (and CEN-D6's zero guard,
/// whose refusal is the C++'s height-0 sentinel made a verdict). D5 is the
/// fact that the window came from an alternative chain. It is recorded by
/// the alt tier only when that call produced a target — a D6 refusal is
/// D4's verdict, and this row did not run. A main-chain `validate` never
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
