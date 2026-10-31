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
    burn::calc_burn_pct_at, price_emission, CirculatingSupply, ClosedShardCount, EconomicParams,
    EmissionInputs, PaidEmission, TxVolume,
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
    /// The block as production prices it, at the weight the fill reports:
    /// the bodies and the coinbase reserve, which the node's template passes
    /// too (`shekyl_block_template::Fill`). The ledger advances by
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
    pub(crate) fn medians(&self, params: &EconomicParams) -> EffectiveMedian {
        self.space.medians(params)
    }

    /// Price `step` and record the block the fill listed.
    ///
    /// The volume window and the medians are the blocks before this one.
    /// The block joins them only after the fill has decided what it lists.
    pub(crate) fn price<'a>(
        &mut self,
        step: ChainStep,
        params: &'a SimParams,
        economic: &'a EconomicParams,
    ) -> PricedBlock<'a> {
        let volume = self.window.operand();
        let medians = self.space.medians(economic);
        let supply = net_supply(step.already_generated, step.total_burned);
        let share = economic.emission_schedule().share_at(step.chain_height);
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
            relay: params.relay(),
        };
        let tx = params.fee.ordinary_tx(&fee_point);
        let filled = self
            .space
            .fill(step.fold_height, medians, step.demand, tx, &fee_point);
        self.window.push(filled.included);
        let paid = price_emission(&EmissionInputs {
            height: step.chain_height,
            median_weight: medians.effective_median.to_raw(),
            block_weight: filled.block_weight,
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
    use shekyl_economics::FEE_QUANTIZATION_MASK;

    /// E15-1. One baseline year, every block's ordinary fee on the lattice.
    /// Red: price the block with the unrounded product.
    #[test]
    fn a_baseline_years_fees_are_lattice_multiples() {
        let params = SimParams::default();
        let economic = params.economic();
        let mut cursor = ChainCursor::default();
        let mut generated = 0u128;
        let mut burned = 0u128;
        let mut leaves = 0u64;
        for block in 0..params.blocks_per_year() {
            let priced = cursor.price(
                ChainStep {
                    fold_height: block,
                    chain_height: block,
                    demand: params.economic().tx_volume_baseline,
                    leaves,
                    already_generated: generated,
                    total_burned: burned,
                    closed_shards: ClosedShardCount::new(0),
                },
                &params,
                economic,
            );
            assert_eq!(
                priced.tx.fee_atomic % FEE_QUANTIZATION_MASK,
                0,
                "block {block} fee {} is off the lattice",
                priced.tx.fee_atomic
            );
            generated = generated.saturating_add(u128::from(priced.paid_reward()));
            burned = burned.saturating_add(u128::from(priced.paid.fee_burn.actually_destroyed));
            leaves = leaves.saturating_add(priced.filled.included.saturating_mul(2));
        }
    }

    /// E16-9. At `relay.fee_decimal_places = 8` every production-arm fee in
    /// one baseline year is a multiple of 10 atomic, and the run's admission
    /// accepts every one at that block's Economy rung. Some fee is off the
    /// shipped 1 000-atomic lattice, so the run's lattice, not the shipped
    /// one, is what priced it: a pricer that ignored the override would pass
    /// the first two checks and fail this one.
    #[test]
    fn a_finer_lattice_reaches_the_fee_and_admission_takes_it() {
        let params = SimParams::with_overrides(vec![crate::baseline::Override::parse(
            "relay.fee_decimal_places=8",
        )
        .expect("well-formed")])
        .expect("eight decimals pass the relay validator");
        assert_eq!(params.relay().quantization_mask(), Some(10));
        let economic = params.economic();
        let mut cursor = ChainCursor::default();
        let (mut generated, mut burned, mut leaves) = (0u128, 0u128, 0u64);
        let mut off_the_shipped_lattice = 0u64;
        for block in 0..params.blocks_per_year() {
            let priced = cursor.price(
                ChainStep {
                    fold_height: block,
                    chain_height: block,
                    demand: economic.tx_volume_baseline,
                    leaves,
                    already_generated: generated,
                    total_burned: burned,
                    closed_shards: ClosedShardCount::new(0),
                },
                &params,
                economic,
            );
            let fee = priced.tx.fee_atomic;
            assert_eq!(
                fee % 10,
                0,
                "block {block} fee {fee} is off the run's lattice"
            );
            let economy = params.fee.admission_rate(&priced.fee_point).atomic();
            assert!(
                params.relay().admits(fee, priced.tx.weight, &[economy]),
                "block {block}: fee {fee} at weight {} refused at Economy {economy}",
                priced.tx.weight
            );
            if fee % FEE_QUANTIZATION_MASK != 0 {
                off_the_shipped_lattice += 1;
            }
            generated = generated.saturating_add(u128::from(priced.paid_reward()));
            burned = burned.saturating_add(u128::from(priced.paid.fee_burn.actually_destroyed));
            leaves = leaves.saturating_add(priced.filled.included.saturating_mul(2));
        }
        assert!(
            off_the_shipped_lattice > 0,
            "every fee sat on the shipped lattice: the override did not reach the pricer"
        );
    }

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
            economic,
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
            economic,
        );
        assert_eq!(second.volume, TxVolume::window(5, 1));
    }
}
