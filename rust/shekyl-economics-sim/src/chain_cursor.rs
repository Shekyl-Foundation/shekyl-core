// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One step of the honest chain, shared by every scenario fold
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`, ESR-4 and ESR-6).
//!
//! The engine, the budget and the stage-2 fold each accumulate something
//! different after a block. They price the block the same way: CEN-F20's
//! volume window and CEN-G6's medians are read before the block joins
//! them, the burn reads the net supply, and the producer's fill rule
//! decides how many of the offered transactions the block lists. The
//! block the fill made is then priced by production's own composition,
//! [`price_emission`]: the paid reward, its split and the fee burn come
//! back as one [`PaidEmission`], and no fold assembles them from parts.
//! That step lives here, so a later change to the operand order lands once.

use shekyl_chain_rules::EffectiveMedian;
use shekyl_economics::{
    burn::calc_burn_pct_at, emission_share_at, price_emission, CirculatingSupply, ClosedShardCount,
    EconomicParams, EmissionInputs, PaidEmission, TxVolume,
};

use crate::block_space::{BlockSpace, Filled};
use crate::engine::{net_supply, SimParams};
use crate::fee_model::{FeePoint, OrdinaryTx};
use crate::volume_window::VolumeWindow;

/// The chain state a fold carries from block to block: the volume window
/// and the pool whose fill the medians price.
#[derive(Debug, Clone, Default)]
pub(crate) struct ChainCursor {
    window: VolumeWindow,
    space: BlockSpace,
}

/// What one block offers the cursor. Heights are a pair: `fold_height` is
/// the cursor's own count, from the fold's first block, and `chain_height`
/// is the consensus height the emission share reads (a scenario that starts
/// mid-chain adds its genesis offset here, and nowhere else).
pub(crate) struct ChainStep {
    pub(crate) fold_height: u64,
    pub(crate) chain_height: u64,
    /// Transactions the scenario offers this block.
    pub(crate) demand: u64,
    /// Outputs in the curve tree the fee is built against, before this
    /// block's own outputs accrue.
    pub(crate) leaves: u64,
    /// Coins generated and destroyed through the parent block. The folds
    /// keep both in `u128`; the chain records them as `u64`.
    pub(crate) already_generated: u128,
    pub(crate) total_burned: u128,
    /// Closed transaction shards through the parent block, the operand the
    /// burn's staker share escalates on. A fold with no corpus trajectory
    /// passes zero, where the share is its floor under any parameter set.
    pub(crate) closed_shards: ClosedShardCount,
}

/// The block [`ChainCursor::price`] built, and the operands it was built at.
pub(crate) struct PricedBlock<'a> {
    pub(crate) volume: TxVolume,
    pub(crate) medians: EffectiveMedian,
    pub(crate) supply: CirculatingSupply,
    pub(crate) burn_pct: u64,
    pub(crate) emission_share: u64,
    pub(crate) fee_point: FeePoint<'a>,
    pub(crate) tx: OrdinaryTx,
    pub(crate) filled: Filled,
    /// The block as production prices it, at the bodies' weight: the fill
    /// lists no coinbase, so its bytes are not in the weight the penalty
    /// reads (§4 of the design document). The ledger advances by
    /// [`Self::paid_reward`]; the fill's own copy of that figure is checked
    /// against it in [`ChainCursor::price`] and is not what a fold accumulates.
    pub(crate) paid: PaidEmission,
}

impl PricedBlock<'_> {
    /// The paid reward the ledger advances by: [`PaidEmission::paid`].
    #[must_use]
    pub(crate) fn paid_reward(&self) -> u64 {
        self.paid.paid.to_raw()
    }
}

impl ChainCursor {
    /// The medians the next block is judged under. After [`Self::price`],
    /// this includes the block just priced.
    pub(crate) fn medians(&self) -> EffectiveMedian {
        self.space.medians()
    }

    /// Price `step` and record the block the fill listed.
    ///
    /// The volume window and the medians are the blocks before this one.
    /// The block joins them only after the fill has decided what it lists.
    pub(crate) fn price<'a>(
        &mut self,
        step: ChainStep,
        params: &SimParams,
        economic: &'a EconomicParams,
    ) -> PricedBlock<'a> {
        let volume = self.window.operand();
        let medians = self.space.medians();
        let supply = net_supply(step.already_generated, step.total_burned);
        let share = emission_share_at(step.chain_height);
        let burn_pct = calc_burn_pct_at(volume, supply, economic);
        let generated = u64::try_from(step.already_generated.min(u128::from(u64::MAX)))
            .expect("clamped to the chain's u64 supply rail");
        let fee_point = FeePoint {
            already_generated: generated,
            volume,
            long_term_median: medians.long_term_effective_median.to_raw(),
            sigma_scaled: share,
            burn_pct_scaled: burn_pct,
            chain_leaves: step.leaves,
            params: economic,
        };
        let tx = params.fee.ordinary_tx(&fee_point);
        let filled = self
            .space
            .fill(step.fold_height, medians, step.demand, tx, &fee_point);
        self.window.push(filled.included);
        let paid = price_emission(&EmissionInputs {
            height: step.chain_height,
            median_weight: medians.effective_median.to_raw(),
            block_weight: filled.bodies_weight,
            already_generated: generated,
            tx_volume: volume,
            total_fees: filled.fees,
            supply,
            closed_shards: step.closed_shards,
            params: economic,
        })
        .expect("the fill priced this block at this weight");
        assert_eq!(
            paid.paid.to_raw(),
            filled.paid_reward,
            "the fill and the composition price one block"
        );
        PricedBlock {
            volume,
            medians,
            supply,
            burn_pct,
            emission_share: share,
            fee_point,
            tx,
            filled,
            paid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The operand is the blocks before this one: an empty window at the
    /// fold's first block, then that block's listed transactions.
    #[test]
    fn the_operand_is_read_before_the_block_joins_the_window() {
        let params = SimParams::default();
        let economic = params.economic();
        let mut chain = ChainCursor::default();
        let first = chain.price(
            ChainStep {
                fold_height: 0,
                chain_height: 0,
                demand: 5,
                leaves: 0,
                already_generated: 0,
                total_burned: 0,
                closed_shards: ClosedShardCount::ZERO,
            },
            &params,
            &economic,
        );
        assert_eq!(first.volume, TxVolume::window(0, 0));
        assert_eq!(first.filled.included, 5, "five fit under the zone");
        let second = chain.price(
            ChainStep {
                fold_height: 1,
                chain_height: 1,
                demand: 5,
                leaves: 0,
                already_generated: u128::from(first.paid_reward()),
                total_burned: 0,
                closed_shards: ClosedShardCount::ZERO,
            },
            &params,
            &economic,
        );
        assert_eq!(second.volume, TxVolume::window(5, 1));
    }
}
