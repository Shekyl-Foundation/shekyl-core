// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The header ladder, written once.
//!
//! `validate` and [`alt_against`](crate::alt_against) judge the same header
//! rules, in the same order, over different views. The membership of that
//! ladder used to be three lists — `validate`'s `judge_block!` subsequence,
//! `alt_against`'s `judge_header!`, and `ALT_TIER_ROWS` — and only the last
//! two were compared. A header rule added to one ladder stayed green.
//!
//! The rules are named here, in three contiguous segments, and nowhere
//! else. [`judge_header_ladder`] runs them in order for the alt tier.
//! `validate` calls the same three functions and inserts its chain-state
//! rules between them: B5 after the parent link, B4 after the clock and
//! the proof, G1 after the anchor and the coinbase. Those three are
//! `BlockRule`s; they are not members of this ladder, and a segment cannot
//! name one — [`run_header`](crate::rules::run_header) takes a
//! [`HeaderRule`](crate::rules::HeaderRule).
//!
//! [`derive`] is the shared preparation: the tip, the connecting height,
//! the seed (CEN-D3), the newest-11 window (CEN-C3), the target (CEN-D4,
//! CEN-D6 the zero guard), the cumulative difficulty after the block, the
//! comparison (CEN-D1b), and the [`BlockContext`] the predicates read. The
//! alt tier records CEN-D5 beside that target, and only when a target was
//! produced — a D6 refusal is D4's verdict, and D5 did not run. `validate`
//! does not record D5: its window is the recorded chain.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::BlockHeight;

use crate::block::StructurallyValid;
use crate::coverage::RuleCoverage;
use crate::fault::Fault;
use crate::rule_set::RuleSet;
use crate::rules::anchors::E1;
use crate::rules::difficulty::D4;
use crate::rules::miner::{F4, F5, F6};
use crate::rules::pow::{D1b, D1, D3};
use crate::rules::timestamps::{C1, C2, C3};
use crate::rules::topology::A2;
use crate::rules::{self, BlockContext};
use crate::trust::Trust;
use crate::verdict::Verdict;
use crate::view::{HeaderView, Tip};

/// What [`derive`] established for the predicates: where the block sits,
/// the work through it, and the context the header rules read.
pub(crate) struct HeaderFacts<'a> {
    /// The height the view's tip derives for the candidate.
    pub connecting: BlockHeight,
    /// The parent's cumulative difficulty plus the target the block met.
    pub cumulative_difficulty: CumulativeDifficulty,
    /// The predicates' inputs. Borrows the candidate `derive` was given.
    pub context: BlockContext<'a>,
}

/// The definitions both ladders read, over `view`.
///
/// `Ok(Err(refused))` is CEN-D6: the ratified algorithm derived zero. D4
/// (and D6, D7) are already recorded; the caller records nothing further
/// for that height. `Err` is the view's fault or a corrupt observation.
///
/// # Errors
///
/// [`Fault::View`] on the view's own fault; [`Fault::Corrupt`] on a hole
/// below the parent or a non-monotone cumulative difficulty;
/// [`Fault::Stale`] when `formed`'s seed is not this view's.
pub(crate) fn derive<'a, 'id, H: HeaderView<'id>>(
    formed: &'a StructurallyValid,
    view: &H,
    rule_set: &RuleSet,
    trust: &'a Trust,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<HeaderFacts<'a>>, Fault<H::Fault>> {
    let tip = view.tip().map_err(Fault::View)?;
    let connecting = Tip::connecting_height(tip.as_ref());
    D3::verify_seed(view, connecting, formed, coverage)?;
    let mtp_window = C3::window(view, connecting, coverage)?;
    let target = match D4::target(view, connecting, rule_set, coverage)? {
        Ok(target) => target,
        Err(refused) => return Ok(Err(refused)),
    };
    let cumulative_difficulty = D4::cumulative_after(view, connecting, target)?;
    D1b::record(coverage);
    Ok(Ok(HeaderFacts {
        connecting,
        cumulative_difficulty,
        context: BlockContext::new(formed, tip, mtp_window, target, trust),
    }))
}

/// Run the listed header rules in order. The first refusal is the verdict.
/// A [`ViewRead`](crate::ViewRead) becomes [`Fault`] through [`From`].
macro_rules! judge_header {
    ($cx:expr, $view:expr, $coverage:expr; $($rule:ty),+ $(,)?) => {
        $(
            if let Err(refused) =
                rules::run_header::<$rule, _>($cx, $view, $coverage).map_err(Fault::from)?
            {
                return Ok(Err(refused));
            }
        )+
    };
}

/// CEN-A2: the candidate's `previous` is the view's tip.
pub(crate) fn parent_link<'id, H: HeaderView<'id>>(
    cx: &BlockContext<'_>,
    view: &H,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, Fault<H::Fault>> {
    judge_header!(cx, view, coverage; A2);
    Ok(Ok(()))
}

/// CEN-C1, CEN-C2, CEN-D1: the clock against the window, and the proof
/// against the target [`derive`] put on the context.
pub(crate) fn clock_and_proof<'id, H: HeaderView<'id>>(
    cx: &BlockContext<'_>,
    view: &H,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, Fault<H::Fault>> {
    judge_header!(cx, view, coverage; C1, C2, D1);
    Ok(Ok(()))
}

/// CEN-E1, CEN-F4, CEN-F5, CEN-F6: the anchor, then the coinbase rows that
/// read only the derived height.
pub(crate) fn anchor_and_coinbase<'id, H: HeaderView<'id>>(
    cx: &BlockContext<'_>,
    view: &H,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, Fault<H::Fault>> {
    judge_header!(cx, view, coverage; E1, F4, F5, F6);
    Ok(Ok(()))
}

/// The alt tier's header predicates, in census order: the three segments
/// with nothing between them. `validate` calls the segments itself so it
/// can run B5, B4 and G1 at the C++ insertion points.
pub(crate) fn judge_header_ladder<'id, H: HeaderView<'id>>(
    cx: &BlockContext<'_>,
    view: &H,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, Fault<H::Fault>> {
    if let Err(refused) = parent_link(cx, view, coverage)? {
        return Ok(Err(refused));
    }
    if let Err(refused) = clock_and_proof(cx, view, coverage)? {
        return Ok(Err(refused));
    }
    anchor_and_coinbase(cx, view, coverage)
}
