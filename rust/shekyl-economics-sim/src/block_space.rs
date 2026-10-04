// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transactions waiting for a block, and the producer's fill of one.
//!
//! [`BlockSpace`] offers the waiting transactions, oldest first, then the
//! block's own demand, to [`Fill`](shekyl_block_template::Fill) at the
//! effective median [`MedianWindow`](crate::median_window::MedianWindow)
//! holds. What the rule refuses stays until it is older than the mempool
//! livetime. The two departures from the chain — bodies-only weight, and a
//! waiting transaction paying the fee of the block it is offered to — are
//! declared on [`BlockSpace`].

use std::collections::VecDeque;

use shekyl_block_template::Fill;
use shekyl_chain_rules::EffectiveMedian;

use crate::fee_model::{FeePoint, OrdinaryTx};
use crate::median_window::MedianWindow;

/// `CRYPTONOTE_MEMPOOL_TX_LIVETIME`: how long, in seconds, the daemon keeps
/// a transaction no block has taken. The pool has no Rust owner yet
/// (`DRS_E1_SPOOL.md`), so this is the C++ define restated, pinned to it by
/// a test that reads the header; it moves to the pool's owner when the pool
/// does.
const MEMPOOL_TX_LIVETIME_SECS: u64 = 86_400 * 3;

/// The transactions waiting for a block, the medians they wait under, and
/// the rule that decides how many a block takes.
///
/// Each block offers the waiting transactions, oldest first, and then the
/// block's own demand to the producer's fill rule ([`Fill`],
/// `shekyl-block-template`) at the effective median, admits until the rule
/// refuses, and leaves the rest waiting; a transaction older than the pool's
/// livetime is dropped before the block is filled. The transactions are
/// identical, so a refusal leaves the fill unchanged and every later offer
/// would be refused the same way: the rule's own batch offer
/// ([`Fill::admit_up_to`]) is the producer's walk over this pool, not a
/// shortcut of it. Two departures from the chain, declared in §4 of the
/// design document: the block's weight is its
/// bodies' — the coinbase's few hundred bytes are neither priced nor
/// recorded — and every waiting transaction pays the fee of the block it is
/// offered to, not the fee it was built with.
#[derive(Debug, Clone, Default)]
pub(crate) struct BlockSpace {
    medians: MedianWindow,
    /// `(height it arrived at, count)`, oldest first.
    waiting: VecDeque<(u64, u64)>,
    /// The sum of `waiting`'s counts, kept as it changes: the queue holds a
    /// livetime of entries while blocks are full.
    waiting_total: u64,
}

/// What one block took.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Filled {
    /// Transactions the block lists.
    pub(crate) included: u64,
    /// Transactions dropped unserved before this block, for age.
    pub(crate) expired: u64,
    /// The penalised gross reward at the block's weight
    /// ([`Fill::reward`]), before the split.
    pub(crate) paid_reward: u64,
    /// The listed bodies' weight.
    pub(crate) bodies_weight: u64,
    /// The listed bodies' fees.
    pub(crate) fees: u64,
}

impl BlockSpace {
    /// The medians the next block is judged under.
    pub(crate) fn medians(&self) -> EffectiveMedian {
        self.medians.medians()
    }

    /// Transactions waiting after the last block.
    pub(crate) fn waiting(&self) -> u64 {
        self.waiting_total
    }

    /// Build the block at `height` under `medians` — what [`Self::medians`]
    /// returned for it — from the waiting transactions and `demand` new ones,
    /// each the ordinary transaction `tx` priced at `at`, then record it.
    pub(crate) fn fill(
        &mut self,
        height: u64,
        medians: EffectiveMedian,
        demand: u64,
        tx: OrdinaryTx,
        at: &FeePoint<'_>,
    ) -> Filled {
        let livetime_blocks = MEMPOOL_TX_LIVETIME_SECS / at.params.daa_target_seconds;
        let mut expired = 0;
        while let Some(&(arrived, count)) = self.waiting.front() {
            if height - arrived <= livetime_blocks {
                break;
            }
            expired += count;
            self.waiting.pop_front();
        }
        if demand > 0 {
            self.waiting.push_back((height, demand));
        }
        self.waiting_total = self.waiting_total + demand - expired;

        let effective = medians.effective_median.to_raw();
        let offered = self.waiting();
        let mut fill = Fill::empty(effective, at.already_generated, at.volume, at.params)
            .expect("sim trajectory stays within the reward's arithmetic domain");
        let included = fill.admit_up_to(tx.weight, tx.fee_atomic, offered);
        let mut taken = included;
        while taken > 0 {
            let front = self
                .waiting
                .front_mut()
                .expect("taken never exceeds offered");
            let from_front = front.1.min(taken);
            front.1 -= from_front;
            taken -= from_front;
            if front.1 == 0 {
                self.waiting.pop_front();
            }
        }
        self.waiting_total -= included;

        let weight = fill.bodies_weight();
        self.medians.push(medians, weight);
        Filled {
            included,
            expired,
            paid_reward: fill.reward(),
            bodies_weight: fill.bodies_weight(),
            fees: fill.fees(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_economics::{EconomicParams, TxVolume};

    /// The livetime is the C++ define's, read from the header.
    #[test]
    fn the_pool_livetime_is_the_cxx_define() {
        let config_h = include_str!("../../../src/cryptonote_config.h");
        let value = config_h
            .lines()
            .find_map(|l| {
                let mut words = l.split_whitespace();
                (words.next() == Some("#define")
                    && words.next() == Some("CRYPTONOTE_MEMPOOL_TX_LIVETIME"))
                .then(|| words.next())
                .flatten()
            })
            .expect("cryptonote_config.h defines CRYPTONOTE_MEMPOOL_TX_LIVETIME");
        assert_eq!(value, "(86400*3)", "the define's expression");
        assert_eq!(MEMPOOL_TX_LIVETIME_SECS, 86_400 * 3);
    }

    /// The running total against the queue it stands for.
    fn assert_total_is_the_queue(space: &BlockSpace) {
        let queued: u64 = space.waiting.iter().map(|&(_, count)| count).sum();
        assert_eq!(
            space.waiting(),
            queued,
            "the running total is the queue's sum"
        );
    }

    fn baseline_tx() -> OrdinaryTx {
        OrdinaryTx {
            fee_atomic: 3_000_000_000,
            weight: 14_643,
        }
    }

    /// Below the median a block takes all it is offered; what the rule
    /// refuses waits, oldest first, and is dropped once older than the
    /// livetime.
    #[test]
    fn the_block_takes_what_the_rule_admits_and_the_rest_waits_then_expires() {
        let params = EconomicParams::default();
        let at = FeePoint {
            already_generated: 0,
            volume: TxVolume::per_block(params.tx_volume_baseline),
            long_term_median: params.full_reward_zone,
            sigma_scaled: 0,
            burn_pct_scaled: 0,
            chain_leaves: 1,
            params: &params,
        };
        let mut space = BlockSpace::default();
        let small = space.fill(0, space.medians(), 5, baseline_tx(), &at);
        assert_eq!(
            (small.included, space.waiting()),
            (5, 0),
            "five fit under the zone"
        );

        // More than a livetime of blocks can take, so some of it expires.
        let demand = 1_000_000;
        let full = space.fill(1, space.medians(), demand, baseline_tx(), &at);
        assert!(full.included < demand, "the rule refuses past the median");
        assert_total_is_the_queue(&space);
        assert_eq!(space.waiting(), demand - full.included);

        let livetime = MEMPOOL_TX_LIVETIME_SECS / params.daa_target_seconds;
        let mut drained = full.included;
        for height in 2..=livetime + 1 {
            let block = space.fill(height, space.medians(), 0, baseline_tx(), &at);
            assert_eq!(
                block.expired, 0,
                "nothing is older than the livetime at {height}"
            );
            drained += block.included;
            assert_total_is_the_queue(&space);
        }
        let last = space.fill(livetime + 2, space.medians(), 0, baseline_tx(), &at);
        assert!(last.expired > 0, "the rest is older than the livetime");
        assert_eq!(last.included, 0, "dropped before the block is filled");
        assert_eq!(
            drained + last.expired,
            demand,
            "every transaction is served or dropped"
        );
        assert_eq!(space.waiting(), 0);
        assert_total_is_the_queue(&space);
    }
}
