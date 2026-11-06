// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One burned, shard-closing chain for the staker-pool coinbase.
//!
//! CEN-F17 / F18 and the block template price the same record: an
//! accumulator a third of the way up the curve, truncated to a multiple of
//! the chain length, forty listed transactions a block, three archival
//! shards closed through the parent, and a tenth of that accumulator
//! burned. The chain's columns and the economics priced over them are
//! functions of that one accumulator. Callers pass the asymptote and the
//! first block's timestamp; the spacing is the consensus target
//! ([`shekyl_difficulty::T_SECONDS`]).

use shekyl_difficulty::{CumulativeDifficulty, GENESIS_DIFFICULTY, T_SECONDS};
use shekyl_types::{ArchivalLength, SHARD_LENGTH};
use shekyl_units::AtomicUnits;

use super::fixture::{recorded_with_work, root};
use super::MockChain;
use crate::view::RecordedBlock;

/// Blocks in the staker-pool record.
const STAKER_POOL_BLOCKS: u64 = 4;

/// Listed transactions recorded on each block.
const STAKER_POOL_TRANSACTIONS_PER_BLOCK: u64 = 40;

/// Archival shards closed through the parent.
const STAKER_POOL_CLOSED_SHARDS: u64 = 3;

/// `total_burned` is the accumulator divided by this.
const STAKER_POOL_BURN_DIVISOR: u64 = 10;

/// The chain, and the figures its tip records. `coins_generated` at height
/// `h` is [`Self::accumulator`]` / 4 * (h + 1)`, so the tip holds the
/// accumulator whole.
pub struct StakerPoolChain {
    /// Four recorded blocks and the planted burn.
    pub chain: MockChain,
    /// Tip `coins_generated`: `asymptote / 3` truncated to a multiple of
    /// the block count. Truncating before the per-block split is what
    /// makes the tip and a price over this chain name one number.
    pub accumulator: u64,
    /// Planted `total_burned`: a tenth of [`Self::accumulator`].
    pub burned: u64,
    /// Shards the archival-length column closes through the parent.
    pub closed_shards: u64,
}

/// The staker-pool record (module docs). `first_timestamp` is block 0's;
/// later blocks step by [`T_SECONDS`].
#[must_use]
pub fn burned_staker_chain(asymptote: u64, first_timestamp: u64) -> StakerPoolChain {
    let blocks = STAKER_POOL_BLOCKS;
    let accumulator = asymptote / 3 / blocks * blocks;
    let burned = accumulator / STAKER_POOL_BURN_DIVISOR;
    let chain = (0..blocks).fold(MockChain::default(), |chain, h| {
        let step = h + 1;
        chain.push(
            RecordedBlock {
                coins_generated: AtomicUnits::from_raw(accumulator / blocks * step),
                cumulative_tx_count: STAKER_POOL_TRANSACTIONS_PER_BLOCK * step,
                cumulative_archival_len: ArchivalLength::from_raw(
                    STAKER_POOL_CLOSED_SHARDS * SHARD_LENGTH.to_raw() * step / blocks,
                ),
                ..recorded_with_work(
                    first_timestamp + h * T_SECONDS,
                    CumulativeDifficulty::from_raw(u128::from(step) * GENESIS_DIFFICULTY),
                )
            },
            root(u8::try_from(h).expect("four blocks fit a byte") + 1),
        )
    });
    StakerPoolChain {
        chain: chain.with_total_burned(AtomicUnits::from_raw(burned)),
        accumulator,
        burned,
        closed_shards: STAKER_POOL_CLOSED_SHARDS,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        burned_staker_chain, STAKER_POOL_BLOCKS, STAKER_POOL_BURN_DIVISOR,
        STAKER_POOL_CLOSED_SHARDS, STAKER_POOL_TRANSACTIONS_PER_BLOCK,
    };
    use crate::view::{AtHeight, ChainView};
    use shekyl_difficulty::T_SECONDS;
    use shekyl_economics::EconomicParams;
    use shekyl_types::BlockHeight;
    use shekyl_units::AtomicUnits;

    /// The tip holds the truncated accumulator, the burn is its tenth, and
    /// the blocks are `T_SECONDS` apart. Red edit: record `asymptote / 3`
    /// without the truncation, or space the timestamps by a literal.
    #[test]
    fn the_tip_holds_the_truncated_accumulator_and_a_tenth_is_burned() {
        let asymptote = EconomicParams::default().emission_curve_asymptote;
        let first_timestamp = 1_000;
        let built = burned_staker_chain(asymptote, first_timestamp);
        let tip_height = built.chain.tip().expect("the chain has a tip").height;
        let (first, tip, burned) = built.chain.with_view(|view| {
            let recorded = |height| match view.block_at(height).expect("the mock does not fault") {
                AtHeight::Recorded(block) => block,
                AtHeight::AboveTip => panic!("a pushed height is recorded"),
            };
            (
                recorded(BlockHeight::ZERO),
                recorded(tip_height),
                view.total_burned().expect("the mock does not fault"),
            )
        });
        assert_eq!(
            built.accumulator,
            asymptote / 3 / STAKER_POOL_BLOCKS * STAKER_POOL_BLOCKS
        );
        assert_eq!(
            tip.coins_generated,
            AtomicUnits::from_raw(built.accumulator)
        );
        assert_eq!(
            first.coins_generated,
            AtomicUnits::from_raw(built.accumulator / STAKER_POOL_BLOCKS)
        );
        assert_eq!(burned, AtomicUnits::from_raw(built.burned));
        assert_eq!(built.burned, built.accumulator / STAKER_POOL_BURN_DIVISOR);
        assert_eq!(built.closed_shards, STAKER_POOL_CLOSED_SHARDS);
        assert_eq!(
            tip.cumulative_tx_count,
            STAKER_POOL_TRANSACTIONS_PER_BLOCK * STAKER_POOL_BLOCKS
        );
        assert_eq!(
            tip.header.header.timestamp - first.header.header.timestamp,
            (STAKER_POOL_BLOCKS - 1) * T_SECONDS
        );
        assert_eq!(first.header.header.timestamp, first_timestamp);
    }
}
