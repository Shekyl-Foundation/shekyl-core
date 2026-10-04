// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block-weight medians the validator prices a block against, over a
//! fold's own blocks (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`,
//! ESR-6).
//!
//! CEN-G6/G6b: the long-term effective median is the median of the last
//! 100 000 blocks' long-term weights, floored at the penalty-free zone; the
//! effective median is the median of the last 100 weights, clamped to
//! `[LTEM, S · LTEM]`. The validator selects both from its store at every
//! block ([`shekyl_chain_rules::medians_over`]). A fold of sixty years cannot
//! afford a 100 000-row selection per block, so [`RollingMedian`] keeps each
//! window split into a lower and an upper half as blocks arrive and leave,
//! and hands the middle pair to the validator's own
//! [`even_pair_median`](shekyl_chain_rules::even_pair_median) — the
//! even-count rule stays production's — and the result to [`medians_from`]
//! for the composition. The tests hold the per-block result equal to
//! [`shekyl_chain_rules::medians_over`] over the same window, and the
//! rolling median itself equal to [`shekyl_chain_rules::median`] over the
//! explicit window.

use std::collections::{BTreeMap, VecDeque};

use shekyl_chain_rules::{even_pair_median, medians_from, EffectiveMedian};
use shekyl_economics::block_weight::long_term_weight;
use shekyl_economics::params::{BLOCK_WEIGHT_LONG_TERM_WINDOW, BLOCK_WEIGHT_SHORT_TERM_WINDOW};

/// The last `capacity` values pushed, with the median of them kept as it
/// goes: every value in `low` is at most every value in `high`, and `low`
/// holds the same count as `high` or one more.
#[derive(Debug, Clone)]
pub(crate) struct RollingMedian {
    capacity: usize,
    arrival: VecDeque<u64>,
    low: Multiset,
    high: Multiset,
}

impl RollingMedian {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "a median over no values has no window");
        Self {
            capacity,
            arrival: VecDeque::with_capacity(capacity.min(1 << 20)),
            low: Multiset::default(),
            high: Multiset::default(),
        }
    }

    /// The median of the values held, by the validator's rule: the middle
    /// value of an odd count, [`even_pair_median`] of the middle pair of an
    /// even one, `0` of none.
    pub(crate) fn median(&self) -> u64 {
        match (self.low.max(), self.high.min()) {
            (None, _) => 0,
            (Some(lower), Some(upper)) if self.low.len == self.high.len => {
                even_pair_median(lower, upper)
            }
            (Some(lower), _) => lower,
        }
    }

    /// Add `value`; the oldest leaves once the window is full.
    pub(crate) fn push(&mut self, value: u64) {
        if self.arrival.len() == self.capacity {
            let oldest = self
                .arrival
                .pop_front()
                .expect("a full window is not empty");
            // A value below `low`'s maximum is held in `low`, one above it
            // in `high`; one equal to it may be in either, and removing a
            // copy from whichever holds one keeps the halves ordered.
            let removed = (self.low.max().is_some_and(|m| oldest <= m) && self.low.remove(oldest))
                || self.high.remove(oldest);
            assert!(removed, "the evicted value is held");
        }
        self.arrival.push_back(value);
        if self.low.max().is_none_or(|m| value <= m) {
            self.low.insert(value);
        } else {
            self.high.insert(value);
        }
        self.rebalance();
    }

    fn rebalance(&mut self) {
        while self.low.len > self.high.len + 1 {
            let moved = self.low.pop_max();
            self.high.insert(moved);
        }
        while self.high.len > self.low.len {
            let moved = self.high.pop_min();
            self.low.insert(moved);
        }
    }
}

/// A multiset of `u64` with its size.
#[derive(Debug, Clone, Default)]
struct Multiset {
    counts: BTreeMap<u64, u32>,
    len: usize,
}

impl Multiset {
    fn insert(&mut self, value: u64) {
        *self.counts.entry(value).or_insert(0) += 1;
        self.len += 1;
    }

    /// Remove one copy of `value`; `false` if none is held.
    fn remove(&mut self, value: u64) -> bool {
        match self.counts.get_mut(&value) {
            None => false,
            Some(count) => {
                *count -= 1;
                if *count == 0 {
                    self.counts.remove(&value);
                }
                self.len -= 1;
                true
            }
        }
    }

    fn max(&self) -> Option<u64> {
        self.counts.keys().next_back().copied()
    }

    fn min(&self) -> Option<u64> {
        self.counts.keys().next().copied()
    }

    fn pop_max(&mut self) -> u64 {
        let value = self.max().expect("pop from a non-empty half");
        self.remove(value);
        value
    }

    fn pop_min(&mut self) -> u64 {
        let value = self.min().expect("pop from a non-empty half");
        self.remove(value);
        value
    }
}

/// CEN-G6/G6b over a fold's blocks: the long window of long-term weights
/// and the short window of weights, and the medians the next block is
/// judged under.
#[derive(Debug, Clone)]
pub(crate) struct MedianWindow {
    long_term: RollingMedian,
    short_term: RollingMedian,
}

impl Default for MedianWindow {
    fn default() -> Self {
        Self {
            long_term: RollingMedian::new(window_len(BLOCK_WEIGHT_LONG_TERM_WINDOW)),
            short_term: RollingMedian::new(window_len(BLOCK_WEIGHT_SHORT_TERM_WINDOW)),
        }
    }
}

impl MedianWindow {
    /// The medians the next block is priced and bounded against. At a
    /// fold's first block both windows are empty and both medians are the
    /// zone, as at the chain's genesis.
    pub(crate) fn medians(&self) -> EffectiveMedian {
        medians_from(self.long_term.median(), self.short_term.median())
    }

    /// Record a block of `weight` bytes judged under `medians` — the value
    /// [`Self::medians`] returned for it. Its long-term weight is the
    /// production clamp at that block's own long-term effective median.
    pub(crate) fn push(&mut self, medians: EffectiveMedian, weight: u64) {
        let long_term = long_term_weight(medians.long_term_effective_median.to_raw(), weight);
        self.long_term.push(long_term);
        self.short_term.push(weight);
    }
}

fn window_len(blocks: u64) -> usize {
    usize::try_from(blocks).expect("a median window fits the address space")
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_chain_rules::{median, medians_over, RecordedWeights};
    use shekyl_types::{BlockWeight, LongTermWeight};

    /// A deterministic stream with repeats, so the even-count rule and
    /// duplicate eviction are both exercised.
    fn stream(seed: u64, n: usize, modulus: u64) -> Vec<u64> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (x >> 33) % modulus
            })
            .collect()
    }

    /// Against the validator's own median over the explicit window, at
    /// every step: small capacities so the window fills, evicts and churns
    /// through odd and even counts many times.
    #[test]
    fn the_rolling_median_is_the_validators_median_over_the_window() {
        for (capacity, modulus) in [(1usize, 5u64), (2, 3), (7, 10), (64, 50), (101, 1_000_000)] {
            let mut rolling = RollingMedian::new(capacity);
            let mut window: VecDeque<u64> = VecDeque::new();
            for (step, value) in stream(capacity as u64, 4_000, modulus)
                .into_iter()
                .enumerate()
            {
                rolling.push(value);
                window.push_back(value);
                if window.len() > capacity {
                    window.pop_front();
                }
                let explicit: Vec<u64> = window.iter().copied().collect();
                assert_eq!(
                    rolling.median(),
                    median(&explicit),
                    "capacity {capacity}, step {step}"
                );
            }
        }
        assert_eq!(RollingMedian::new(3).median(), 0, "the median of nothing");
    }

    /// The whole of CEN-G6/G6b, block by block, against
    /// `shekyl_chain_rules::medians_over` over the same recorded weights:
    /// a stream long enough to evict from the 100 000-row long window,
    /// with weights that cross the zone and the clamps. `medians_over` is
    /// an `O(window)` selection, so it is asked at every step for the first
    /// 3 000 blocks, every 4 999th step to the window's fill, and every
    /// 997th after it, where eviction runs.
    #[test]
    fn the_window_is_medians_over_at_every_checked_block() {
        let long = window_len(BLOCK_WEIGHT_LONG_TERM_WINDOW);
        let weights = stream(7, long + 30_000, 1_500_000);
        let mut rolling = MedianWindow::default();
        let mut recorded: VecDeque<RecordedWeights> = VecDeque::new();
        let mut checks = 0usize;
        for (step, weight) in weights.into_iter().enumerate() {
            let medians = rolling.medians();
            let checked = step < 3_000 || step % 4_999 == 0 || (step >= long && step % 997 == 0);
            if checked {
                let window: Vec<_> = recorded.iter().copied().collect();
                assert_eq!(medians, medians_over(&window), "block {step}");
                checks += 1;
            }
            rolling.push(medians, weight);
            recorded.push_back(RecordedWeights {
                weight: BlockWeight::from_raw(weight),
                long_term_weight: LongTermWeight::from_raw(long_term_weight(
                    medians.long_term_effective_median.to_raw(),
                    weight,
                )),
            });
            if recorded.len() > long {
                recorded.pop_front();
            }
        }
        assert!(
            checks > 3_000 + 30,
            "the eviction regime was checked ({checks} checks)"
        );
    }
}
