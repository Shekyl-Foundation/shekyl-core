// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.G — the block-weight medians (`CHAIN_RULES_SLICE_7.md` §4,
//! the `judge_emission` definition chain's first two rows).
//!
//! Two **definition rows**, the CEN-D4 shape: nothing about a candidate can
//! fail them, they yield the values the 4.F consumers refuse or price on
//! (F14 refuses over the limit, F14b prices the penalty, `connect` records
//! the long-term weight), and they record their rows where they yield.
//!
//! - **CEN-G6** — the bounds: the long-term effective median `LTEM` is the
//!   median of `long_term_weight` over the `min(W_long, h)` recorded blocks
//!   below the connecting height `h`, floored at the penalty-free zone;
//!   `W_long` and the short window `W_short` are the two generated windows
//!   (`shekyl_economics::params`, Q6). Recorded by [`Medians::derive`].
//! - **CEN-G6b** — the remainder: the effective median is the short-term
//!   median over the last `min(W_short, h)` weights clamped to
//!   `[LTEM, S · LTEM]` (`shekyl_economics::effective_median`, the ratified
//!   `S = 4`); the block-weight limit is twice it; and the connecting
//!   block's **long-term weight** is its weight clamped to
//!   `[LTEM · 10/17, LTEM · 1.7]` (`shekyl_economics::long_term_weight`).
//!   Recorded by [`Weights::derive`], which needs the block's weight and so
//!   runs once every transaction has been judged.
//!
//! # The C++ this is at parity with
//!
//! `Blockchain::update_next_cumulative_weight_limit` (`blockchain.cpp:
//! 6067–6107`): both medians are over the blocks **below** `db_height`,
//! which is the height the next block connects at — so the window's end
//! is the connecting height and the candidate's own weight is never in
//! its own median. The C++ floors the clamped median at the zone a second
//! time (`:6096`); with `LTEM ≥ zone` the clamp's lower arm already holds
//! that, and the redundancy is recorded rather than copied. Since
//! `1c8594049` both languages take `S` from one key (§3.8): this is a
//! parity landing, not a divergence — the census cells that still say
//! "×50" are corrected in commit 10.
//!
//! **The median's even-count arm is the C++'s.** `epee::misc_utils::median`
//! and `rolling_median_t::median` both return, for an even count, the
//! floor of the mean of the two middle elements
//! (`get_mid`: `a/2 + b/2 + ((a%2) + (b%2))/2`, overflow-safe). A median
//! that took the lower middle element would agree with the C++ on every
//! odd window and disagree on every even one — the short window is 100.
//! [`cxx_median`] is that definition, pinned against a sorted reference
//! in `block_weight_tests`.
//!
//! # The early-chain arm
//!
//! Below `W_long` the window **is** the chain: `min(W_long, h) = h`, so
//! every block since genesis is in the long-term median and nothing has
//! aged out. C2-R2 Q2 records the governor as structurally weak there —
//! for the first ~100 000 blocks `S` is the only bound on weight growth —
//! and that regime is the *whole* regime any test chain runs in, so the
//! fixtures exercise this arm by necessity. It is pinned **deliberately**
//! (`the_long_window_is_the_chain_below_its_length`), not left to be the
//! arm the fixtures happened to reach: a chain of `h < W_long` blocks
//! whose median moves when its first block is changed is the evidence
//! nothing aged out; the same edit on a chain one block past `W_long`
//! would not move it.
//!
//! # Two readers of one median
//!
//! [`effective_median_at`] is public for the block producer (Q4, I17's
//! shape one row over): `shekyl-block-template` prices its coinbase and
//! bounds its body against the median the validator will judge by, read
//! here and not from a second copy of the two-window definition or from
//! the store's recorded `long_term_effective_median(tip)` (SCR-19's
//! one-block staleness). Coverage stays with the rows; the public function
//! is the definition alone.
//!
//! # What the read costs
//!
//! One `ChainView::weights_window` over `W_long` rows (Q2, ruled (b) on the
//! Pi 4 floor: 36.6 ms against 598 ms for per-height point reads, 0.5 % of
//! the zone-point verify) and two `O(n)` selections. No rolling cache: an
//! index that exists to make a consensus computation fast is a second
//! place the answer lives (§3.6), and the floor said it is not needed.

use shekyl_economics::params::{BLOCK_WEIGHT_LONG_TERM_WINDOW, BLOCK_WEIGHT_SHORT_TERM_WINDOW};
use shekyl_economics::{effective_median, long_term_weight, FULL_REWARD_ZONE};
use shekyl_types::{BlockCount, BlockHeight, BlockWeight, LongTermWeight};
use shekyl_wire::Transaction;

use crate::block::Candidate;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, PerHeightRecord, ViewRead};
use crate::rules::Rule;
use crate::view::{AtHeight, ChainView, RecordedWeights};

/// CEN-G6: the frozen bounds — the two windows and the surge factor — and
/// the long-term effective median they yield. A definition row.
pub(crate) struct G6;

impl Rule for G6 {
    const ROW: CenRow = CenRow::G6;
}

/// CEN-G6b: the effective median (the short-term median clamped to
/// `[LTEM, S · LTEM]`), the limit (twice it), and the connecting block's
/// long-term weight (its weight clamped to `[LTEM/1.7, LTEM·1.7]`). A
/// definition row.
pub(crate) struct G6b;

impl Rule for G6b {
    const ROW: CenRow = CenRow::G6b;
}

/// The two medians in force for a connecting height — what the validator
/// judges the block's weight against and what the producer builds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectiveMedian {
    /// `LTEM`: the long-term median floored at the zone (CEN-G6). The
    /// operand of the connecting block's long-term weight, and what the
    /// store records beside it.
    pub long_term_effective_median: LongTermWeight,
    /// The short-term median clamped to `[LTEM, S · LTEM]` (CEN-G6b). The
    /// block-weight limit is twice this; the penalty (F14b) prices against
    /// it.
    pub effective_median: BlockWeight,
}

impl EffectiveMedian {
    /// The block-weight limit: twice the effective median (`blockchain.cpp:
    /// 6100`). Saturating — a limit that wrapped would refuse every block.
    #[must_use]
    pub const fn limit(&self) -> BlockWeight {
        BlockWeight::from_raw(self.effective_median.to_raw().saturating_mul(2))
    }
}

/// What the medians were derived from: the window read, once.
///
/// Wraps [`EffectiveMedian`] with the row-recording constructor `validate`
/// calls; the public definition is [`effective_median_at`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Medians(pub(crate) EffectiveMedian);

impl Medians {
    /// Derive both medians for a candidate connecting at `connecting`,
    /// recording CEN-G6 as evaluated. Runs before the slot loop beside the
    /// other definitions: it reads only the view.
    pub(crate) fn derive<'id, V: ChainView<'id>>(
        view: &V,
        connecting: BlockHeight,
        coverage: &mut RuleCoverage,
    ) -> Result<Self, ViewRead<V::Fault>> {
        let medians = effective_median_at(view, connecting)?;
        coverage.insert(G6::ROW);
        Ok(Self(medians))
    }
}

/// What CEN-G6b established for a validated block: the medians it was
/// judged under, its weight, and the long-term weight `connect` records
/// for it. Carried on the verdict (`ValidatedBlock`) because every value
/// here is one the validator had to compute (Q5): the store persists what
/// it is handed, and the ingest reads them off the verdict rather than
/// composing a second copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Weights {
    /// The medians in force for this block (CEN-G6/G6b).
    pub medians: EffectiveMedian,
    /// The block's weight: the coinbase's `Transaction::weight` plus every
    /// listed body's (`blockchain.cpp:5445`'s `coinbase_weight + Σ
    /// td.weight`). Saturating: each term is bounded by CEN-H1 and a
    /// saturated sum is over any limit, so the direction is a refusal
    /// (F14), never an acceptance.
    pub weight: BlockWeight,
    /// The block's long-term weight — its weight clamped to
    /// `[LTEM · 10/17, LTEM · 1.7]` — the value the store records and the
    /// next long-term median reads (CEN-G6b).
    pub long_term_weight: LongTermWeight,
}

impl Weights {
    /// Derive the block's weight and long-term weight under `medians`,
    /// recording CEN-G6b as evaluated. Runs after the slot loop: every
    /// transaction has passed `tx_form`, so `Transaction::weight` is the
    /// wire's measure of a parsed value and not a panic a hand-built one
    /// could reach.
    pub(crate) fn derive(
        medians: Medians,
        candidate: &Candidate,
        coverage: &mut RuleCoverage,
    ) -> Self {
        let weight = block_weight(candidate);
        let long_term = long_term_weight(
            medians.0.long_term_effective_median.to_raw(),
            weight.to_raw(),
        );
        coverage.insert(G6b::ROW);
        Self {
            medians: medians.0,
            weight,
            long_term_weight: LongTermWeight::from_raw(long_term),
        }
    }
}

/// The wire weight of a candidate: the coinbase plus every listed body.
fn block_weight(candidate: &Candidate) -> BlockWeight {
    let weight_of = |tx: &Transaction| u64::try_from(tx.weight()).unwrap_or(u64::MAX);
    let coinbase = weight_of(&candidate.block.miner_transaction);
    let total = candidate
        .transactions
        .iter()
        .fold(coinbase, |acc, tx| acc.saturating_add(weight_of(tx)));
    BlockWeight::from_raw(total)
}

/// CEN-G6/G6b's definition at `connecting`: the long-term effective median
/// over the `min(W_long, connecting)` recorded long-term weights below it,
/// floored at the zone, and the short-term median over the last
/// `min(W_short, connecting)` weights clamped to `[LTEM, S · LTEM]`.
///
/// **Public for one reason** (Q4; the shape of [`crate::mtp_median_at`] and
/// [`crate::tx_volume_window`]): the block producer prices and bounds
/// against the median the validator judges by, read here. Coverage stays
/// with [`G6`] and [`G6b`]; this is the definition alone.
///
/// One read: [`ChainView::weights_window`] over the long window, the
/// short window its suffix. At genesis (`connecting = 0`) the window is
/// empty and both medians are the zone — the C++'s `nblocks > 0 ? … :
/// ZONE` arm and its `median(empty) = 0` clamped up.
///
/// # Errors
///
/// [`ViewRead::View`] on a view fault (a hole inside the window is the
/// store's SI-7, reported as its own fault before this arm);
/// [`ViewRead::Corrupt`] when a view answers `AboveTip` for the height it
/// itself reported as the tip's successor — a store that does not hold
/// what it claims, never a shorter window.
pub fn effective_median_at<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
) -> Result<EffectiveMedian, ViewRead<V::Fault>> {
    let window = match view
        .weights_window(
            connecting,
            BlockCount::from_raw(BLOCK_WEIGHT_LONG_TERM_WINDOW),
        )
        .map_err(ViewRead::View)?
    {
        AtHeight::Recorded(window) => window,
        // `connecting` is the tip's successor, read from this same view;
        // `AboveTip` here is the tip's own `block_info` row missing.
        AtHeight::AboveTip => {
            return Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                at: BlockHeight::from_raw(connecting.to_raw().saturating_sub(1)),
                record: PerHeightRecord::Block,
            }))
        }
    };
    Ok(medians_over(&window))
}

/// The two medians over a window of recorded weights in height order —
/// the whole long window, the short window its last `W_short` rows.
/// Pure: the arithmetic the store read feeds, held on its own in
/// `block_weight_tests` at the clamps' boundaries.
pub(crate) fn medians_over(window: &[RecordedWeights]) -> EffectiveMedian {
    let mut long_term: Vec<u64> = window.iter().map(|w| w.long_term_weight.to_raw()).collect();
    // Total: a window longer than the address space is the whole slice.
    let short_len = usize::try_from(BLOCK_WEIGHT_SHORT_TERM_WINDOW)
        .unwrap_or(usize::MAX)
        .min(window.len());
    let mut short_term: Vec<u64> = window[window.len() - short_len..]
        .iter()
        .map(|w| w.weight.to_raw())
        .collect();
    let long_term_effective = cxx_median(&mut long_term).max(FULL_REWARD_ZONE);
    let effective = effective_median(long_term_effective, cxx_median(&mut short_term));
    EffectiveMedian {
        long_term_effective_median: LongTermWeight::from_raw(long_term_effective),
        effective_median: BlockWeight::from_raw(effective),
    }
}

/// The C++'s median (`epee::misc_utils::median`, `rolling_median_t::
/// median`): `0` of nothing, the element of one, the middle of an odd
/// count, and for an even count the floor of the mean of the two middle
/// elements (`get_mid`). Reorders `values`; `O(n)` by selection.
pub(crate) fn cxx_median(values: &mut [u64]) -> u64 {
    let n = values.len();
    if n == 0 {
        return 0;
    }
    let mid = n / 2;
    let (below, upper, _) = values.select_nth_unstable(mid);
    let upper = *upper;
    if n % 2 == 1 {
        return upper;
    }
    // An even `n ≥ 2` has `mid ≥ 1` elements below; the fallback is the
    // total form of the same value (the mean of `upper` with itself).
    let lower = below.iter().copied().max().unwrap_or(upper);
    // `get_mid`: (a + b) / 2 without the sum, so two weights near `u64::MAX`
    // cannot wrap into a small median.
    lower / 2 + upper / 2 + (lower % 2 + upper % 2) / 2
}

#[cfg(test)]
#[path = "block_weight_tests.rs"]
mod block_weight_tests;
