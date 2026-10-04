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

use std::collections::VecDeque;

use shekyl_chain_rules::tx_volume_span;
use shekyl_economics::params::TX_VOLUME_WINDOW;
use shekyl_economics::TxVolume;
use shekyl_types::BlockHeight;

/// The prefix sums of a fold's transaction counts, as far back as CEN-F20's
/// window can reach, and the height of the next block to be priced.
#[derive(Debug, Clone, Default)]
pub(crate) struct VolumeWindow {
    /// `prefix[i]` is the cumulative transaction count through height
    /// `next - prefix.len() + i`. At most `W + 1` entries: the window's
    /// upper term and its lower term are `W` apart.
    prefix: VecDeque<u64>,
    /// The height the next [`Self::operand`] prices.
    next: u64,
}

impl VolumeWindow {
    /// The validator's operand for the block at the next height.
    pub(crate) fn operand(&self) -> TxVolume {
        let span = tx_volume_span(BlockHeight::from_raw(self.next));
        let Some(upper) = span.upper else {
            return TxVolume::window(0, 0);
        };
        let upper_sum = self.prefix_at(upper);
        let lower_sum = span.lower.map_or(0, |at| self.prefix_at(at));
        span.volume(upper_sum, lower_sum)
            .expect("a fold's prefix sums only grow")
    }

    /// Record the block at the next height carrying `txs` transactions.
    pub(crate) fn push(&mut self, txs: u64) {
        let cumulative = self.prefix.back().copied().unwrap_or(0).saturating_add(txs);
        self.prefix.push_back(cumulative);
        if self.prefix.len() as u64 > TX_VOLUME_WINDOW + 1 {
            self.prefix.pop_front();
        }
        self.next += 1;
    }

    fn prefix_at(&self, at: BlockHeight) -> u64 {
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
