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
//! The rules are named here, and nowhere else. The header segments are
//! [`parent_link`] (A2), [`clock`] (C1, C2) and [`anchor`] (E1). The
//! coinbase rows (F4, F5, F6) are [`coinbase_height`]: they read the miner
//! transaction, so the function takes a [`BlockContext`] and the header
//! path cannot call it. [`judge_header_ladder`] and `validate` call
//! `anchor` then `coinbase_height`, in that order. The header path calls
//! `anchor` only.
//!
//! `validate` inserts its chain-state rules between the segments: B5 after
//! the parent link, B4 after the clock (the proof, CEN-D1, is `form`'s),
//! G1 after the coinbase. Those three are `BlockRule`s; a header segment
//! cannot name one — [`run_header`](crate::rules::run_header) takes a
//! [`HeaderRule`](crate::rules::HeaderRule).
//!
//! [`derive`] is the shared preparation: the tip, the connecting height,
//! the seed (CEN-D3), the newest-11 window (CEN-C3), the target (CEN-D4,
//! CEN-D6 the zero guard) and its check against the target the caller
//! claimed ([`Stale::Target`] on a mismatch), the cumulative difficulty
//! after the block, and the comparison (CEN-D1b). The caller builds the
//! context the predicates read. The alt tier records CEN-D5 beside that
//! target, and only when a target was produced — a D6 refusal is D4's
//! verdict, and D5 did not run. `validate` does not record D5: its window
//! is the recorded chain.

use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight};

use crate::coverage::RuleCoverage;
use crate::fault::{Fault, FormAttempt, Stale};
use crate::rule_set::RuleSet;
use crate::rules::anchors::E1;
use crate::rules::difficulty::{Target, D4};
use crate::rules::miner::{F4, F5, F6};
use crate::rules::pow::{D1b, D3};
use crate::rules::timestamps::{MtpWindow, C1, C2, C3};
use crate::rules::topology::A2;
use crate::rules::{self, BlockContext, HeaderContext};
use crate::verdict::Verdict;
use crate::view::{HeaderView, Tip};

/// What [`derive`] established: where the block sits and the work through
/// it. The caller builds the context the predicates read.
pub(crate) struct Derived {
    /// The height the view's tip derives for the candidate.
    pub connecting: BlockHeight,
    /// The parent's cumulative difficulty plus the target the block met.
    pub cumulative_difficulty: CumulativeDifficulty,
    /// The recorded tip, `None` at genesis.
    pub tip: Option<Tip>,
    /// C3's window, `None` at genesis.
    pub mtp_window: Option<MtpWindow>,
    /// D4's target.
    pub target: Target,
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
/// [`Fault::Stale`] when `seed` or `claimed_target` is not this view's.
pub(crate) fn derive<'id, H: HeaderView<'id>>(
    seed: BlockHash,
    claimed_target: Target,
    attempt: FormAttempt,
    view: &H,
    rule_set: &RuleSet,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<Derived>, Fault<H::Fault>> {
    let tip = view.tip().map_err(Fault::View)?;
    let connecting = Tip::connecting_height(tip.as_ref());
    D3::verify_seed(view, connecting, seed, attempt.next(), coverage)?;
    let mtp_window = C3::window(view, connecting, coverage)?;
    let target = match D4::target(view, connecting, rule_set, coverage)? {
        Ok(target) => target,
        Err(refused) => return Ok(Err(refused)),
    };
    // The caller judged CEN-D1 against this claim; the claim must be what
    // this view's headers derive, or the block was never judged against its
    // real target. A fault, not a verdict (`Stale::Target`).
    if claimed_target != target {
        return Err(Fault::Stale(Stale::Target {
            claimed: claimed_target,
            expected: target,
            retry: attempt.next(),
        }));
    }
    let cumulative_difficulty = D4::cumulative_after(view, connecting, target)?;
    D1b::record(coverage);
    Ok(Ok(Derived {
        connecting,
        cumulative_difficulty,
        tip,
        mtp_window,
        target,
    }))
}

/// Run the listed header rules in order. The first refusal is the verdict.
/// A [`ViewRead`](crate::ViewRead) becomes [`Fault`] through [`From`].
macro_rules! judge_header {
    ($cx:expr, $view:expr, $coverage:expr; $($rule:ty),+ $(,)?) => {
        $(
            if let Err(refused) =
                rules::run_header::<$rule, _, _>($cx, $view, $coverage).map_err(Fault::from)?
            {
                return Ok(Err(refused));
            }
        )+
    };
}

/// CEN-A2: the candidate's `previous` is the view's tip.
pub(crate) fn parent_link<'id, P, H: HeaderView<'id>>(
    cx: &HeaderContext<'_, P>,
    view: &H,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, Fault<H::Fault>> {
    judge_header!(cx, view, coverage; A2);
    Ok(Ok(()))
}

/// CEN-C1, CEN-C2: the clock against the window. CEN-D1, the proof against
/// the target, is `form`'s: it runs before any body work, against the
/// claim [`derive`] verifies.
pub(crate) fn clock<'id, P, H: HeaderView<'id>>(
    cx: &HeaderContext<'_, P>,
    view: &H,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, Fault<H::Fault>> {
    judge_header!(cx, view, coverage; C1, C2);
    Ok(Ok(()))
}

/// CEN-E1: the anchor at the connecting height.
pub(crate) fn anchor<'id, P, H: HeaderView<'id>>(
    cx: &HeaderContext<'_, P>,
    view: &H,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, Fault<H::Fault>> {
    judge_header!(cx, view, coverage; E1);
    Ok(Ok(()))
}

/// CEN-F4, CEN-F5, CEN-F6. The context is a [`BlockContext`]: these rows
/// read the coinbase, and a header-only context cannot name this function.
/// The `Result` is the ladder's shape, shared with [`anchor`] and
/// [`clock`], so `validate` calls it with `?`. These three rows do not
/// produce a view fault.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn coinbase_height<'id, H: HeaderView<'id>>(
    cx: &BlockContext<'_>,
    view: &H,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, Fault<H::Fault>> {
    if let Err(refused) = rules::run_coinbase::<F4, _>(cx, view, coverage) {
        return Ok(Err(refused));
    }
    if let Err(refused) = rules::run_coinbase::<F5, _>(cx, view, coverage) {
        return Ok(Err(refused));
    }
    if let Err(refused) = rules::run_coinbase::<F6, _>(cx, view, coverage) {
        return Ok(Err(refused));
    }
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
    let header = cx.as_header();
    if let Err(refused) = parent_link(&header, view, coverage)? {
        return Ok(Err(refused));
    }
    if let Err(refused) = clock(&header, view, coverage)? {
        return Ok(Err(refused));
    }
    if let Err(refused) = anchor(&header, view, coverage)? {
        return Ok(Err(refused));
    }
    coinbase_height(cx, view, coverage)
}
