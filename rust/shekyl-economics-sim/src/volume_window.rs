// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The volume operand the validator prices a block at, over a fold's own
//! blocks (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`, ESR-4).
//!
//! The burn fraction, the release multiplier and the fee correction all
//! read CEN-F20's window: the transactions in the `min(h, 720)` blocks
//! before the one being priced. The validator reads it from two prefix sums
//! in its store ([`shekyl_chain_rules::tx_volume_window`]). A fold has no
//! store, so it keeps the prefix sums the window can reach and asks the
//! validator's own span ([`shekyl_chain_rules::tx_volume_span`]) which two
//! to subtract. Which heights the window covers is never restated here.
//!
//! Heights are the fold's own: its first block is height 0. A scenario that
//! starts mid-chain (`genesis_height_offset`) therefore starts with an empty
//! window, as the chain does at genesis — a scenario-layer simplification,
//! declared in §4 of the design document, not a claim about that chain's
//! history.

use std::collections::{BTreeMap, VecDeque};

use shekyl_chain_rules::tx_volume_span_of;
use shekyl_economics::params::TX_VOLUME_WINDOW;
use shekyl_economics::TxVolume;
use shekyl_types::BlockHeight;

/// What a fold prices its blocks at from the volume window
/// (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.33, J's arms).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VolumeSignal {
    /// The window's transaction sum (CEN-F20): production.
    #[default]
    Sum,
    /// The lower middle of the window's per-block counts, as the sum of
    /// that many blocks at it (J's arm 1). A declared arm.
    Median,
    /// The median read against the baseline restated in median terms
    /// ([`crate::rng::geometric_median`] of the baseline: 35 at the shipped
    /// 50), so honest geometric traffic reads 1.0 where blocks have room
    /// (§5.34). Passed as the median scaled by the shipped baseline over
    /// the restated one, which release, the burn and `C` read exactly as
    /// the median against the restated baseline: each reads the operand
    /// only through its ratio to the baseline. A declared arm.
    MedianRestated,
    /// The baseline, whatever the window holds: release, the burn and `C`
    /// cut off from volume together (J's arm 5, §5.34). A declared arm.
    Fixed,
}

/// The prefix sums of a fold's transaction counts, as far back as CEN-F20's
/// window can reach, and the height of the next block to be priced.
#[derive(Debug, Clone, Default)]
pub(crate) struct VolumeFold<const W: u64> {
    /// `prefix[i]` is the cumulative transaction count through height
    /// `next - prefix.len() + i`. At most `W + 1` entries: the window's
    /// upper term and its lower term are `W` apart. Wider than the chain's
    /// `u64` because a fold's lifetime sum is not the chain's operand: C2
    /// sums scaled fee units, whose lifetime passes `u64` on a growth fold
    /// while its window still fits, and a saturated prefix would read that
    /// window as empty.
    prefix: VecDeque<u128>,
    /// The height the next [`Self::operand`] prices.
    next: u64,
    /// The per-block counts of the window's blocks, the differences of the
    /// prefix sums, oldest first: at most `W`.
    counts: VecDeque<u64>,
    /// The same counts as a multiset, count → blocks, for the median.
    sorted: BTreeMap<u64, u64>,
}

/// The shipped window. EUP-5's window-length stress builds [`VolumeFold`]
/// at another length (`ECONOMICS_SIM_PHASE0.md`, the const-generic window).
pub(crate) type VolumeWindow = VolumeFold<{ TX_VOLUME_WINDOW }>;

impl<const W: u64> VolumeFold<W> {
    /// The validator's operand for the block at the next height.
    ///
    /// A window whose own sum passes `u64` reads as `u64::MAX`. Only C2's
    /// scaled fee units get there, and C2's burn reads them through
    /// [`TxVolume::ratio_scaled_squared`], which has already saturated at
    /// that sum, so the clamp changes no figure
    /// (`economy::tests::a_fee_window_past_u64_burns_as_its_true_sum`).
    pub(crate) fn operand(&self) -> TxVolume {
        let span = tx_volume_span_of::<W>(BlockHeight::from_raw(self.next));
        let Some(upper) = span.upper else {
            return TxVolume::window(0, 0);
        };
        let upper_sum = self.prefix_at(upper);
        let lower_sum = span.lower.map_or(0, |at| self.prefix_at(at));
        let window_sum = upper_sum
            .checked_sub(lower_sum)
            .expect("a fold's prefix sums only grow");
        span.volume(u64::try_from(window_sum).unwrap_or(u64::MAX), 0)
            .expect("a sum less nothing does not fall")
    }

    /// The operand `signal` prices the next block at: [`Self::operand`] for
    /// the production sum, [`Self::median_operand`] for the median arms, and
    /// `baseline` a block for the arm that reads no volume.
    pub(crate) fn signal_operand(&self, signal: VolumeSignal, baseline: u64) -> TxVolume {
        match signal {
            VolumeSignal::Sum => self.operand(),
            VolumeSignal::Median => self.median_operand(),
            VolumeSignal::MedianRestated => {
                let median = self.median_operand();
                let restated = crate::rng::geometric_median(baseline);
                // Widened, so a product past u64 is a stop, not a wrap.
                let scaled = |count: u64, by: u64| {
                    u64::try_from(u128::from(count) * u128::from(by))
                        .expect("the restated operand fits the chain's u64 volume")
                };
                TxVolume::window(
                    scaled(median.tx_count_sum(), baseline),
                    scaled(median.blocks(), restated),
                )
            }
            VolumeSignal::Fixed => TxVolume::per_block(baseline),
        }
    }

    /// J's arm 1: the lower middle of the per-block counts of the blocks
    /// the production operand sums, passed as that many blocks at it, so
    /// the release multiplier, the burn and `C` read it as they read the
    /// sum. A block count's median moves only when over half the window's
    /// blocks move it.
    pub(crate) fn median_operand(&self) -> TxVolume {
        let blocks = self.counts.len() as u64;
        if blocks == 0 {
            return TxVolume::window(0, 0);
        }
        debug_assert_eq!(
            self.operand(),
            TxVolume::window(self.counts.iter().sum(), blocks),
            "the counts are the blocks the production operand sums"
        );
        let rank = (blocks - 1) / 2;
        let mut seen = 0;
        for (&count, &at) in &self.sorted {
            seen += at;
            if seen > rank {
                return TxVolume::window(count * blocks, blocks);
            }
        }
        unreachable!("the multiset holds every counted block")
    }

    /// Record the block at the next height carrying `txs` transactions.
    pub(crate) fn push(&mut self, txs: u64) {
        let cumulative = self.prefix.back().copied().unwrap_or(0) + u128::from(txs);
        self.prefix.push_back(cumulative);
        if self.prefix.len() as u64 > W + 1 {
            self.prefix.pop_front();
        }
        self.counts.push_back(txs);
        *self.sorted.entry(txs).or_insert(0) += 1;
        if self.counts.len() as u64 > W {
            let gone = self.counts.pop_front().expect("over W entries");
            let left = self.sorted.get_mut(&gone).expect("a counted block");
            *left -= 1;
            if *left == 0 {
                self.sorted.remove(&gone);
            }
        }
        self.next += 1;
    }

    fn prefix_at(&self, at: BlockHeight) -> u128 {
        let oldest = self.next - self.prefix.len() as u64;
        let index = at
            .to_raw()
            .checked_sub(oldest)
            .expect("the span never reaches below the kept prefix sums");
        self.prefix[usize::try_from(index).expect("at most W + 1 entries")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fold whose lifetime sum passes `u64` still reads its window: the
    /// sum of the last `W` blocks, which fits. A saturated prefix read this
    /// as zero, and C2's burn fell to nothing on the growth folds (§5.37.2).
    #[test]
    fn a_lifetime_past_u64_keeps_the_window() {
        let per_block = u64::MAX / (TX_VOLUME_WINDOW + 1);
        let mut fold = VolumeWindow::default();
        for _ in 0..3 * (TX_VOLUME_WINDOW + 1) {
            fold.push(per_block);
        }
        assert_eq!(
            fold.operand(),
            TxVolume::window(per_block * TX_VOLUME_WINDOW, TX_VOLUME_WINDOW)
        );
    }

    /// A window past `u64` reads the largest operand, and once those blocks
    /// leave it the window reads its true sum again.
    #[test]
    fn a_window_past_u64_saturates_and_recovers() {
        let mut fold = VolumeWindow::default();
        for _ in 0..TX_VOLUME_WINDOW {
            fold.push(u64::MAX);
        }
        assert_eq!(fold.operand(), TxVolume::window(u64::MAX, TX_VOLUME_WINDOW));
        for _ in 0..TX_VOLUME_WINDOW {
            fold.push(7);
        }
        assert_eq!(
            fold.operand(),
            TxVolume::window(7 * TX_VOLUME_WINDOW, TX_VOLUME_WINDOW)
        );
    }

    /// Against a prefix sum held in full: the window is the transactions of
    /// the `min(h, W)` blocks before `h`, which is CEN-F20's definition read
    /// the long way. Traffic varies by block so a misplaced edge shows.
    #[test]
    fn the_window_is_the_transactions_of_the_blocks_before() {
        let w = TX_VOLUME_WINDOW;
        let txs = |h: u64| (h * 7 + 3) % 11;
        let mut window = VolumeWindow::default();
        let mut all = Vec::new();
        for h in 0..(3 * w) {
            let n = h.min(w);
            let expected: u64 = all[usize::try_from(h - n).unwrap()..].iter().sum();
            assert_eq!(
                window.operand(),
                TxVolume::window(expected, n),
                "height {h}"
            );
            window.push(txs(h));
            all.push(txs(h));
        }
    }

    /// J's arm 1 against a sort of the window's counts held in full: the
    /// lower middle of the `min(h, W)` blocks before `h`, as many blocks at
    /// it. Traffic varies by block so a misplaced rank shows.
    #[test]
    fn the_median_is_the_lower_middle_of_the_blocks_before() {
        let w = TX_VOLUME_WINDOW;
        let txs = |h: u64| (h * 7 + 3) % 11 + (h / 500) % 4;
        let mut window = VolumeWindow::default();
        let mut all = Vec::new();
        for h in 0..(3 * w) {
            let n = h.min(w);
            let expected = if n == 0 {
                TxVolume::window(0, 0)
            } else {
                let mut last: Vec<u64> = all[usize::try_from(h - n).unwrap()..].to_vec();
                last.sort_unstable();
                TxVolume::window(last[usize::try_from((n - 1) / 2).unwrap()] * n, n)
            };
            assert_eq!(window.median_operand(), expected, "height {h}");
            assert_eq!(
                window.signal_operand(VolumeSignal::Sum, 50),
                window.operand()
            );
            assert_eq!(
                window.signal_operand(VolumeSignal::Median, 50),
                window.median_operand()
            );
            assert_eq!(
                window.signal_operand(VolumeSignal::Fixed, 50),
                TxVolume::per_block(50),
                "arm 5 reads the baseline whatever the window holds"
            );
            window.push(txs(h));
            all.push(txs(h));
        }
    }

    /// Under half the window cannot move the median of a constant count;
    /// over half moves it all the way.
    #[test]
    fn the_median_moves_at_half_the_window() {
        let w = TX_VOLUME_WINDOW;
        let mut window = VolumeWindow::default();
        for _ in 0..w {
            window.push(50);
        }
        for _ in 0..(w / 2) {
            window.push(80);
        }
        assert_eq!(
            window.median_operand(),
            TxVolume::window(50 * w, w),
            "half the window"
        );
        window.push(80);
        assert_eq!(
            window.median_operand(),
            TxVolume::window(80 * w, w),
            "over half"
        );
    }

    /// The block being priced is not in its own window: a step in traffic
    /// reaches the operand one block later, and fully after `W` blocks.
    #[test]
    fn a_step_reaches_the_operand_over_the_window() {
        let w = TX_VOLUME_WINDOW;
        let mut window = VolumeWindow::default();
        for _ in 0..w {
            window.push(10);
        }
        assert_eq!(window.operand(), TxVolume::window(10 * w, w));
        window.push(100);
        assert_eq!(window.operand(), TxVolume::window(10 * (w - 1) + 100, w));
        for _ in 1..w {
            window.push(100);
        }
        assert_eq!(window.operand(), TxVolume::window(100 * w, w));
    }
}
