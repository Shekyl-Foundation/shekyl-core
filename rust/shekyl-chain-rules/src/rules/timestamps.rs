// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.C — timestamps (slice 2; `CHAIN_RULES_SLICE_2.md` §2): the
//! future-time limit (C1), the strict median-time-past bound (C2), and the
//! genesis-padded window that bound is taken over (C3).
//!
//! # One implementation, adopted
//!
//! The bodies are `shekyl-difficulty`'s — `check_timestamp_rule`
//! (`timestamp.rs:146`) is the **one** implementation of the C2-R3 rule,
//! ratified 2026-09-01, and the C++ already consumes it through the FFI
//! (`blockchain.cpp:5167`–`:5205`, a marshaling shim that "decides
//! nothing"). This module is the same shim in the validator's shape: it
//! assembles the window the way the C++ does (`:5207`–`:5240`), calls the
//! one function, and reads its verdict arm by arm. Nothing about the bound
//! is restated here — the strict `>` has one site (`is_above_mtp`), the
//! saturating FTL one site (`is_timestamp_below_ftl`), the padding one arm.
//!
//! # Three rows, two predicates and a definition
//!
//! C1 and C2 are predicates, each on its own half of the one function: C1
//! is `is_timestamp_below_ftl` (the FTL half's one site, `:67`), C2 is
//! `check_timestamp_rule` with the clock set to the candidate itself so the
//! FTL arm cannot fire — the same neutralisation the shared vectors
//! (`docs/test_vectors/MTP_BOUNDARY_V1.json`) use for "the MTP half only".
//! Each row's verdict therefore depends on its own operand and no other,
//! and `validate`'s list orders C1 before C2 as the function orders its
//! arms, so a candidate that fails both is refused on C1 — as the C++ is.
//! C3 is a **definition**: *which*
//! timestamps the median is over (the up-to-eleven preceding, right-padded
//! with the genesis timestamp; no bootstrap carve-out). It records at the
//! derivation site, [`C3::window`], where `validate` builds the window once
//! for both predicates — the B6 shape (slice 1 Q5): a gate that could never
//! fail is never run as one.
//!
//! # Genesis
//!
//! At connecting height `0` there is no predecessor, no window, and no
//! genesis timestamp to pad with. The C++ returns before **either** arm
//! (`:5224`–`:5228`: *"not a carve-out: there is no window to check"*), so
//! block 0 is exempt from the FTL leg as well as the MTP leg — F3, ruled a
//! census amendment on CEN-C1. All three rows **record as applied** at
//! genesis (Q3): each ran, checked its premise — a predecessor exists —
//! and found it false; that is a decision, not a fall-through (G11), and
//! complete coverage at genesis is what `connect` demands. [`C3::window`]
//! returns `None` there, and both predicates pass on it.
//!
//! # The clock
//!
//! C1's operand is the wall clock **at `form`**, carried on the
//! `StructurallyValid` (`judged_at`) — read once, outside the write
//! transaction, so the FTL leg is judged against one instant a consumer can
//! see. The comparison itself is here, view-bound, because the genesis
//! exemption is `connecting.is_zero()` on the context — the height, not
//! "the MTP window was absent".

use shekyl_difficulty::{
    check_timestamp_rule, is_timestamp_below_ftl, TimestampRuleVerdict, MTP_WINDOW_USIZE,
};
use shekyl_types::{BlockHeight, Timestamp};

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, ViewRead};
use crate::rules::{recorded, BlockContext, BlockRule, Rule};
use crate::verdict::{refused, Locus, Verdict};
use crate::view::ChainView;

/// The median-time-past window at a connecting height, as C3 defines it:
/// the up-to-eleven preceding timestamps and the genesis timestamp the
/// rule pads with. `None` at genesis (no predecessor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MtpWindow {
    /// The timestamps of the blocks at `connecting − k` for
    /// `k ∈ 1..=min(connecting, MTP_WINDOW)`, oldest first. Order is
    /// immaterial to the median; it is the C++'s (`:5231`–`:5236`).
    preceding: Vec<Timestamp>,
    /// Block 0's timestamp — the padding value below eleven blocks of
    /// history (`check_timestamp_rule`'s third operand).
    genesis: Timestamp,
}

impl MtpWindow {
    /// The padded median itself — `check_timestamp_rule`'s second return,
    /// read with the candidate as its own clock so neither leg can fire.
    fn median(&self) -> Timestamp {
        let (_verdict, median) =
            check_timestamp_rule(self.genesis, &self.preceding, self.genesis, self.genesis);
        median
    }

    /// Whether `candidate_ts` is strictly above this window's padded median
    /// — the MTP half of the one implementation, the FTL half neutralised by
    /// passing the candidate as its own clock (`ts − ts = 0 ≤ FTL`).
    fn is_above_median(&self, candidate_ts: Timestamp) -> bool {
        let (verdict, _median) =
            check_timestamp_rule(candidate_ts, &self.preceding, self.genesis, candidate_ts);
        match verdict {
            TimestampRuleVerdict::Ok => true,
            TimestampRuleVerdict::NotAboveMedian => false,
            // FTL cannot fire with the candidate as its own clock, and the
            // window is built with at most `MTP_WINDOW` entries
            // (`C3::window`), so neither arm has a producer here.
            TimestampRuleVerdict::AboveFtl | TimestampRuleVerdict::WindowTooWide => {
                unreachable!("MtpWindow neutralises FTL and is at most MTP_WINDOW wide")
            }
        }
    }
}

/// CEN-C3: the median window is the up-to-eleven preceding timestamps,
/// **right-padded with the genesis timestamp** below eleven blocks of
/// history — the same rule from block 1, no bootstrap carve-out.
///
/// A definition, not a predicate: nothing about a candidate can fail
/// "which timestamps the median is over". Coverage is recorded here, when
/// the window is derived, and `implemented(rules::timestamps::C3)` names
/// this type.
pub(crate) struct C3;

impl Rule for C3 {
    const ROW: CenRow = CenRow::C3;
}

impl C3 {
    /// The window at `connecting`, recorded in `coverage` as this row
    /// having been applied. `None` at genesis.
    pub(crate) fn window<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        coverage: &mut RuleCoverage,
    ) -> Result<Option<MtpWindow>, ViewRead<V::Fault>> {
        coverage.insert(Self::ROW);
        let c = connecting.to_raw();
        if c == 0 {
            return Ok(None);
        }
        // `connecting ≥ 1` means block 0 and every height below `c` are
        // recorded on a conforming view. The shared parent-side read
        // (`recorded`) makes a hole there the halting fault, not a panic.
        let genesis = Timestamp::from_raw(recorded(view, BlockHeight::ZERO)?.header.timestamp);
        let window_len = u64::try_from(MTP_WINDOW_USIZE).expect("MTP_WINDOW fits u64");
        let oldest = c.saturating_sub(window_len);
        let mut preceding = Vec::with_capacity(MTP_WINDOW_USIZE);
        for h in oldest..c {
            let block = recorded(view, BlockHeight::from_raw(h))?;
            preceding.push(Timestamp::from_raw(block.header.timestamp));
        }
        Ok(Some(MtpWindow { preceding, genesis }))
    }
}

/// CEN-C2's operand at `connecting`: the padded median of the CEN-C3
/// window, `None` at genesis. **Public for one reason** (E6 slice 6,
/// `CHAIN_RULES_SLICE_6.md` §5.3): the block producer claims the least
/// timestamp the chain admits, `max(now, median + 1)`, and the median it
/// claims against is *this one* — read here, not from a second copy of the
/// right-padded eleven-block definition. Coverage stays with [`C3`]; this
/// is the definition alone.
///
/// Two positions, as [`crate::tx_volume_window`]: the outer `Err` is the
/// view's fault; the inner is [`Corrupt::HoleBelowTip`] — a height the
/// window spans is not recorded.
///
/// # Errors
///
/// The view's fault on a read (outer).
pub fn mtp_median_at<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
) -> Result<Result<Option<Timestamp>, Corrupt>, V::Fault> {
    // The producer's read is not a rule evaluation; the coverage it would
    // record is discarded here rather than lying about a judgement.
    let mut unrecorded = RuleCoverage::EMPTY;
    match C3::window(view, connecting, &mut unrecorded) {
        Ok(window) => Ok(Ok(window.map(|window| window.median()))),
        Err(ViewRead::View(fault)) => Err(fault),
        Err(ViewRead::Corrupt(corrupt)) => Ok(Err(corrupt)),
    }
}

/// CEN-C1: the candidate's timestamp is at most `clock + FTL` — the
/// saturating bound `is_timestamp_below_ftl` holds, the clock being the
/// reading `form` took. Exempt at genesis (module docs).
pub(crate) struct C1;

impl Rule for C1 {
    const ROW: CenRow = CenRow::C1;
}

impl BlockRule for C1 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        if cx.connecting.is_zero() {
            return Ok(Ok(()));
        }
        let ts = Timestamp::from_raw(cx.candidate().block.header.timestamp);
        if is_timestamp_below_ftl(ts, cx.formed.judged_at()) {
            Ok(Ok(()))
        } else {
            refused(Self::ROW, Locus::Block)
        }
    }
}

/// CEN-C2: the candidate's timestamp is **strictly greater** than the
/// median (sorted index 5) of the C3 window. Exempt at genesis (module
/// docs).
pub(crate) struct C2;

impl Rule for C2 {
    const ROW: CenRow = CenRow::C2;
}

impl BlockRule for C2 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        if cx.connecting.is_zero() {
            return Ok(Ok(()));
        }
        let Some(window) = cx.mtp_window.as_ref() else {
            unreachable!("C3 yields a window at every height above genesis");
        };
        let ts = Timestamp::from_raw(cx.candidate().block.header.timestamp);
        if window.is_above_median(ts) {
            Ok(Ok(()))
        } else {
            refused(Self::ROW, Locus::Block)
        }
    }
}

#[cfg(test)]
#[path = "timestamps_tests.rs"]
mod timestamps_tests;
