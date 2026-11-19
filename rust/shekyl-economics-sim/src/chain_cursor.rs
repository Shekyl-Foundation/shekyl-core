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

use crate::block_space::{Arrival, BlockSpace, Filled, OwnBodies};
use crate::engine::{net_supply, SimParams};
use crate::fee_model::{FeePoint, OrdinaryTx, MILLI};
use crate::rung_mix::{FeePriority, PerRung, RungMix, RungSplit, ADMISSION};
use crate::volume_window::VolumeWindow;

/// The chain state a fold carries from block to block: the volume window,
/// the pool whose fill the medians price, and the split of demand across
/// the fee ladder's rungs.
#[derive(Debug, Clone, Default)]
pub(crate) struct ChainCursor {
    window: VolumeWindow,
    space: BlockSpace,
    split: RungSplit,
    /// High's fee at the fold's first block, which an elastic mix's
    /// High demand is measured against
    /// ([`crate::rung_mix::RungMix::high_at`]).
    high_reference_fee: Option<u64>,
}

/// What one block offers the cursor. `chain_height` is the consensus height
/// the emission share, the pool's reference window and its received hour
/// read (a scenario that starts mid-chain adds its genesis offset here, and
/// nowhere else).
pub(crate) struct ChainStep {
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

/// What each block is offered (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.34,
/// §5.35).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Traffic {
    /// The scenario's demand every block, split across the rungs by the
    /// mix. The control arm: the edge case and the regression anchor.
    Steady,
    /// Standard traffic under a seed: each block's interval is drawn
    /// exponential around the target spacing ([`crate::rng::block_interval`]),
    /// and each rung's arrivals over it are Poisson around its share of the
    /// scenario's demand ([`crate::rng::rung_arrivals`]). Their sum is the
    /// geometric count of §5.34. What a block does not list waits in the
    /// pool, as on the chain.
    Variable(u64),
}

/// The sim's standard traffic: drawn, at the canonical seed (§5.35). Every
/// [`SimParams`] constructor starts here; `steady` is named where a run
/// asks for the control.
pub const STANDARD_TRAFFIC: Traffic = Traffic::Variable(crate::rng::HONEST_SEEDS[0]);

impl Traffic {
    /// The line a report opens with on standard traffic, naming the draw
    /// and its seed. `None` on the `steady` control, whose reports print as
    /// they did before standard traffic (§5.35, STD-2).
    pub(crate) fn report_line(self) -> Option<String> {
        match self {
            Self::Steady => None,
            Self::Variable(seed) => Some(format!(
                "Traffic: standard, at seed {seed} (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.35): each block's interval \
                 drawn exponential around the target spacing, each fee rung's arrivals Poisson over it; the pool \
                 carries what a block does not list. --control-steady-traffic offers every block its demand."
            )),
        }
    }

    /// The transactions each rung is offered at `height` when the scenario
    /// asks for `demand` under `mix`. Steady traffic splits the demand
    /// through `split`, which carries the rungs' remainders from block to
    /// block; standard traffic draws each rung's arrivals over the block's
    /// interval, keyed on the seed and the height, and leaves `split` alone.
    pub(crate) fn arrivals(
        self,
        split: &mut RungSplit,
        mix: RungMix,
        demand: u64,
        height: u64,
    ) -> PerRung<u64> {
        match self {
            Self::Steady => split.split(mix, demand),
            Self::Variable(seed) => {
                let interval = crate::rng::block_interval(seed, height);
                PerRung::from_fn(|rung| {
                    #[allow(clippy::cast_precision_loss)]
                    let share = demand as f64 * mix.milli(rung) as f64 / MILLI as f64;
                    crate::rng::rung_arrivals(seed, height, rung, share * interval)
                })
            }
        }
    }
}

/// What a producer's own bodies pay ([`ChainCursor::price_with_own`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnFee {
    /// The relay floor, the Economy rung: the chain once the floor applies
    /// to a block's own bodies (C2-R2 Q9's fix).
    RelayFloor,
    /// Nothing: the chain as it stands, where the floor is relay policy and
    /// a producer's own bodies never pass a relay.
    None,
}

/// The block [`ChainCursor::price`] built, and the operands it was built at.
pub(crate) struct PricedBlock<'a> {
    pub(crate) volume: TxVolume,
    pub(crate) medians: EffectiveMedian,
    pub(crate) supply: CirculatingSupply,
    pub(crate) burn_pct: u64,
    pub(crate) emission_share: u64,
    pub(crate) fee_point: FeePoint<'a>,
    /// The Standard rung's ordinary transaction at this block: the one the
    /// growth gate reads.
    pub(crate) tx: OrdinaryTx,
    /// The block's fill, its traffic on each rung, demand included.
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

    /// Bodies listed since the last call, per rung, by age at inclusion in
    /// blocks (index = age), and start counting again.
    pub(crate) fn take_ages(&mut self) -> PerRung<Vec<u64>> {
        self.space.take_ages()
    }

    /// The last block's listing, cohort by cohort.
    pub(crate) fn listed(&self) -> &[crate::block_space::ListedBodies] {
        self.space.listed()
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
        self.price_with_own(step, None, params, economic)
    }

    /// [`Self::price`], with the producer listing bodies of its own after
    /// the pool's when `own` names them: one `own` transaction, priced on
    /// the Economy rung at this block, paying its fee or none.
    pub(crate) fn price_with_own<'a>(
        &mut self,
        step: ChainStep,
        own: Option<OwnFee>,
        params: &'a SimParams,
        economic: &'a EconomicParams,
    ) -> PricedBlock<'a> {
        let volume = self
            .window
            .signal_operand(params.volume_signal, economic.tx_volume_baseline);
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
        let txs = params.fee.rung_txs(&fee_point);
        let tx = txs[FeePriority::Standard].expect("every arm prices the Standard rung");
        let mix = params.fee.mix();
        let mix = match txs[FeePriority::High] {
            Some(high) if mix.is_high_elastic() => {
                let reference = *self.high_reference_fee.get_or_insert(high.fee_atomic);
                mix.high_at(reference, high.fee_atomic)
            }
            _ => mix,
        };
        let demand = params
            .traffic
            .arrivals(&mut self.split, mix, step.demand, step.chain_height);
        let arrivals: Vec<Arrival> = ADMISSION
            .into_iter()
            .filter(|&rung| demand[rung] > 0)
            .map(|rung| Arrival {
                rung,
                count: demand[rung],
                tx: txs[rung].expect("a rung the mix sends demand to is priced"),
            })
            .collect();
        // The pool's heights are the chain's: the reference window and the
        // received hour read them.
        let own = own.map(|own| {
            let economy = params
                .fee
                .rung_tx(FeePriority::Economy, &fee_point)
                .expect("a producer's own body is priced on the Economy rung");
            OwnBodies {
                tx: match own {
                    OwnFee::RelayFloor => economy,
                    OwnFee::None => crate::fee_model::tx_paying(0, &fee_point),
                },
            }
        });
        let filled =
            self.space
                .fill_with_own(step.chain_height, medians, &arrivals, &fee_point, own);
        self.window.push(filled.carried_txs());
        let paid = price_emission(&EmissionInputs {
            height: step.chain_height,
            median_weight: medians.effective_median.to_raw(),
            block_weight: filled.block_weight,
            already_generated: generated,
            tx_volume: volume,
            total_fees: filled.fees_atomic(),
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
    use crate::volume_window::VolumeSignal;
    use shekyl_economics::FEE_QUANTIZATION_MASK;

    /// The operand, burn and `C` a cursor prices its next block at after
    /// `blocks` blocks offered `demand` each, on `signal`.
    fn priced_after(signal: VolumeSignal, demand: u64, blocks: u64) -> (TxVolume, u64, u64) {
        let mut params = SimParams::default();
        params.volume_signal = signal;
        let economic = params.economic();
        let mut cursor = ChainCursor::default();
        let step = |h: u64, demand: u64| ChainStep {
            chain_height: h,
            demand,
            leaves: 0,
            already_generated: 0,
            total_burned: 0,
            closed_shards: ClosedShardCount::new(0),
        };
        for h in 0..blocks {
            cursor.price(step(h, demand), &params, economic);
        }
        let priced = cursor.price(step(blocks, demand), &params, economic);
        let c = shekyl_economics::fee_correction(
            priced.volume,
            priced.emission_share,
            priced.burn_pct,
            economic,
        );
        (priced.volume, priced.burn_pct, c.as_scaled())
    }

    /// Arm 5 (§5.34): with the baseline in place of volume, a busy window
    /// and an empty one price the same operand, burn and `C`. On the sum
    /// they differ, so the comparison has something to find.
    #[test]
    fn the_baseline_arm_reads_no_volume() {
        let quiet = priced_after(VolumeSignal::Fixed, 0, 60);
        let busy = priced_after(VolumeSignal::Fixed, 20, 60);
        assert_eq!(quiet, busy);
        assert_eq!(
            quiet.0,
            TxVolume::per_block(SimParams::default().economic().tx_volume_baseline)
        );
        assert_ne!(
            priced_after(VolumeSignal::Sum, 0, 60),
            priced_after(VolumeSignal::Sum, 20, 60)
        );
    }

    /// The restated median (§5.34) prices exactly as the median against the
    /// baseline restated to 35: release, the burn and `C` each read the
    /// operand only through its ratio to the baseline.
    #[test]
    fn the_restated_median_is_the_median_against_the_restated_baseline() {
        use crate::baseline::Override;
        use shekyl_economics::{calc_release_multiplier, fee_correction};
        let shipped = SimParams::default();
        let restated =
            SimParams::with_overrides(vec![
                Override::parse("economic.tx_volume_baseline=35").expect("well-formed")
            ])
            .expect("a restated baseline passes the validators");
        let (a, b) = (shipped.economic(), restated.economic());
        assert_eq!(
            crate::rng::geometric_median(a.tx_volume_baseline),
            b.tx_volume_baseline
        );
        let supply = net_supply(u128::from(a.emission_curve_asymptote) / 3, 0);
        let mut window = VolumeWindow::default();
        let mut read = 0;
        for h in 0..3_000u64 {
            window.push((h * 37 + 11) % 97);
            if h % 61 != 0 {
                continue;
            }
            read += 1;
            let scaled = window.signal_operand(VolumeSignal::MedianRestated, a.tx_volume_baseline);
            let median = window.median_operand();
            assert_eq!(
                calc_release_multiplier(scaled, a.tx_volume_baseline, a.release_min, a.release_max),
                calc_release_multiplier(median, b.tx_volume_baseline, b.release_min, b.release_max),
                "height {h}"
            );
            let burn = calc_burn_pct_at(scaled, supply, a);
            assert_eq!(burn, calc_burn_pct_at(median, supply, b), "height {h}");
            for share in [0, 400_000, 1_000_000] {
                assert_eq!(
                    fee_correction(scaled, share, burn, a).as_scaled(),
                    fee_correction(median, share, burn, b).as_scaled(),
                    "height {h}"
                );
            }
        }
        assert!(read > 40);
    }

    /// Steady traffic splits the scenario's demand by the mix; standard
    /// traffic offers each rung its draw over the block's interval.
    #[test]
    fn standard_traffic_offers_each_rung_its_draw() {
        let mix = RungMix::DEFAULTED;
        let steady = Traffic::Steady.arrivals(&mut RungSplit::default(), mix, 50, 9);
        assert_eq!(steady.sum(|&n| n), 50);
        let mut split = RungSplit::default();
        for h in 0..100 {
            let drawn = Traffic::Variable(2).arrivals(&mut split, mix, 50, h);
            let interval = crate::rng::block_interval(2, h);
            for rung in FeePriority::ALL {
                #[allow(clippy::cast_precision_loss)]
                let mean = 50.0 * mix.milli(rung) as f64 / MILLI as f64 * interval;
                assert_eq!(drawn[rung], crate::rng::rung_arrivals(2, h, rung, mean));
            }
        }
        assert!((0..100).any(|h| {
            Traffic::Variable(2)
                .arrivals(&mut RungSplit::default(), mix, 50, h)
                .sum(|&n| n)
                != 50
        }));
    }

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
            leaves = leaves.saturating_add(priced.filled.carried_txs().saturating_mul(2));
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
            leaves = leaves.saturating_add(priced.filled.carried_txs().saturating_mul(2));
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
        // Steady: the test pins the counts it offers.
        let params = SimParams::default().on_steady();
        let economic = params.economic();
        let mut chain = ChainCursor::default();
        let first = chain.price(
            ChainStep {
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
        assert_eq!(first.filled.carried_txs(), 5, "five fit under the zone");
        let second = chain.price(
            ChainStep {
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
