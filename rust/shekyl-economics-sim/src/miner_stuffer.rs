// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The cheapest archival byte: what each stuffer pays to add one shard to
//! the corpus, at a block the honest fold built
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.10, ESR-7).
//!
//! The chain does not care which adversary stuffs; the burden model consumes
//! the minimum. Three attackers, each priced only through production:
//!
//! - **Relay stuffer.** He reaches blocks through the pool, which offers
//!   bodies by fee per byte. At the relay floor (the Economy rung) the
//!   producer's fill rule ([`Fill`]) admits him only where the honest bodies
//!   leave room. Otherwise he has to outrank them, at one atomic unit per
//!   byte above the honest rate. He pays the campaign at whichever rate gets
//!   him in ([`stuffer_cost_per_shard_atomic`]).
//! - **Miner, floor unenforced.** The chain today: a miner lists its own
//!   transactions at no fee (the relay floor does not apply to a block's own
//!   bodies), in the block the honest fold built, and pays the cheapest of
//!   three placements:
//!   - **free room**, under the emission's full weight, which costs nothing;
//!   - the **penalty** the reward takes past it;
//!   - the miner's share of the honest fees it **displaces**.
//! - **Miner, floor enforced** (C2-R2 Q9's fix, a declared divergence). The
//!   same placements, and every transaction also pays the relay floor. The
//!   miner gets its own miner leg back, so the floor costs it the burned part.
//!   As a self-archiver it also recovers a share `q` of the staker pool's
//!   part.
//!
//! The penalty is quadratic in a block's overshoot, but an overshoot is whole
//! transactions. So the miner's cheapest byte is one stuffing transaction a
//! block, and patience buys that floor, not zero. A hashrate share and a time
//! budget then set how many shards a miner can stuff at that price, not the
//! price.

use shekyl_block_template::Fill;
use shekyl_economics::{
    compute_burn_split_at, penalty_free_weight, ClosedShardCount, EconomicParams,
    PrePenaltyEmission,
};
use shekyl_tx_weight::predict_weight;
use shekyl_types::SHARD_LENGTH;

use crate::calibration::{
    all_shapes, stuffer_cost_per_shard_atomic, stuffer_shape, tree_depth_for_leaves, PerByteRate,
};
use crate::engine::SimParams;
use crate::fee_model::FeePoint;
use crate::stage2::LastBlock;

/// How a miner placed its stuffing, at its cheapest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Under the emission's full weight, beside the honest bodies.
    FreeRoom,
    /// Past it: the reward pays the penalty.
    Penalty,
    /// In place of honest bodies, whose fees the miner forgoes.
    Displacement,
}

/// A miner's cheapest shard at one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MinerShard {
    /// Atomic units per shard.
    pub(crate) cost_atomic: u128,
    /// Blocks the miner must mine to land one shard at that price.
    pub(crate) blocks: u64,
    pub(crate) placement: Placement,
}

/// What each attacker pays for one shard at one block.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Envelope {
    /// The relay stuffer's rate, and whether it is the floor.
    pub(crate) relay_rate: PerByteRate,
    pub(crate) relay_at_floor: bool,
    pub(crate) relay_atomic: u128,
    pub(crate) unenforced: MinerShard,
    pub(crate) enforced: MinerShard,
    /// The enforced miner as one of [`CO_HOLDERS`] holders of its shards.
    pub(crate) self_archiving_one_of_many: MinerShard,
    /// The enforced miner as the whole holder set (a Sybil).
    pub(crate) self_archiving_whole_set: MinerShard,
}

impl Envelope {
    /// The cheapest shard on the chain as it stands: relay or unenforced miner.
    pub(crate) fn today_atomic(&self) -> u128 {
        self.relay_atomic.min(self.unenforced.cost_atomic)
    }

    /// The cheapest shard once the floor applies to a block's own bodies.
    pub(crate) fn after_fix_atomic(&self) -> u128 {
        self.relay_atomic.min(self.enforced.cost_atomic)
    }
}

/// The holders a shard's staker-pool share divides among, for the one-of-many
/// self-archiving bound (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`, "~100
/// co-holders").
pub(crate) const CO_HOLDERS: u64 = 100;

/// The block the honest fold built, and the operands an attacker prices it
/// at.
struct Block<'a> {
    at: FeePoint<'a>,
    economic: &'a EconomicParams,
    depth: u8,
    median: u64,
    emission: PrePenaltyEmission,
    honest: Fill<'a>,
    /// Weight the honest bodies leave under the emission's full weight.
    room: u64,
    burn_pct: u64,
    closed_shards: ClosedShardCount,
    honest_weight: u64,
    honest_fee: u64,
}

impl<'a> Block<'a> {
    fn new(last: &LastBlock, economic: &'a EconomicParams) -> Self {
        let at = FeePoint {
            already_generated: last.already_generated,
            volume: last.volume,
            long_term_median: last.medians.long_term_effective_median.to_raw(),
            sigma_scaled: last.sigma_scaled,
            burn_pct_scaled: last.burn_pct_scaled,
            chain_leaves: last.chain_leaves,
            params: economic,
        };
        let median = last.medians.effective_median.to_raw();
        let emission = PrePenaltyEmission::of(last.already_generated, last.volume, economic)
            .expect("the fold priced this block");
        let mut honest = Fill::empty(median, last.already_generated, last.volume, economic)
            .expect("the fold priced this block");
        honest.admit_up_to(
            last.honest_tx.weight,
            last.honest_tx.fee_atomic,
            last.honest_offered,
        );
        let room = penalty_free_weight(median, economic)
            .min(honest.bodies_weight_bound())
            .saturating_sub(honest.bodies_weight());
        Self {
            at,
            economic,
            depth: tree_depth_for_leaves(last.chain_leaves),
            median,
            emission,
            honest,
            room,
            burn_pct: last.burn_pct_scaled,
            closed_shards: ClosedShardCount::new(last.closed_shards),
            honest_weight: last.honest_tx.weight,
            honest_fee: last.honest_tx.fee_atomic,
        }
    }

    /// What the miner keeps of a fee it is paid, and what the staker pool
    /// takes, under the block's own burn split.
    fn split(&self, fee: u64) -> (u64, u64) {
        let split = compute_burn_split_at(fee, self.burn_pct, self.closed_shards, self.economic);
        (split.miner_fee_income, split.staker_pool_amount)
    }

    /// The relay stuffer: the rate that gets his bodies listed, and his
    /// campaign's cost for one shard at it.
    fn relay(&self, floor: PerByteRate) -> (PerByteRate, bool, u128) {
        let shape = stuffer_shape(self.depth, floor);
        let mut after_honest = self.honest;
        let at_floor = after_honest.admit(
            shape.tx_weight(self.depth, floor),
            shape.tx_fee_atomic(self.depth, floor),
        );
        let rate = if at_floor {
            floor
        } else {
            // Outrank the honest bodies: one atomic unit per byte above their
            // rate, which the pool offers first and the fill rule lists under
            // the median in their place.
            PerByteRate::from_atomic(self.honest_fee / self.honest_weight.max(1) + 1)
        };
        (
            rate,
            at_floor,
            stuffer_cost_per_shard_atomic(self.at.chain_leaves, rate),
        )
    }

    /// A miner's cheapest shard. `floor` is the relay floor its own bodies
    /// pay when it is enforced; `pool_recovered` is the part of the staker
    /// pool's share a self-archiver recovers, as `(num, den)`.
    fn miner(&self, floor: Option<PerByteRate>, pool_recovered: (u64, u64)) -> MinerShard {
        let (miner_keeps_honest, _) = self.split(self.honest_fee);
        let mut best: Option<(MinerShard, u128, u64)> = None;
        for shape in all_shapes() {
            let fee = floor.map_or(0, |r| shape.tx_fee_atomic(self.depth, r));
            let weight = predict_weight(shape.n_in, shape.n_out, self.depth, fee) as u64;
            let archival = shape.archival_bytes(self.depth).max(1);
            // The floor costs the miner what it does not get back.
            let self_dealing = if fee == 0 {
                0
            } else {
                let (keeps, pool) = self.split(fee);
                let recovered =
                    u128::from(pool) * u128::from(pool_recovered.0) / u128::from(pool_recovered.1);
                u128::from(fee - keeps) - recovered
            };
            for (placement, per_tx, per_block) in self.placements(weight, miner_keeps_honest) {
                let per_tx_total = per_tx + self_dealing;
                let candidate = (per_tx_total, archival);
                let cheaper = best.is_none_or(|(_, total, bytes)| {
                    per_tx_total * u128::from(bytes) < total * u128::from(archival)
                });
                if cheaper {
                    let txs = u128::from(SHARD_LENGTH.to_raw()).div_ceil(u128::from(archival));
                    let blocks = txs.div_ceil(u128::from(per_block.max(1)));
                    best = Some((
                        MinerShard {
                            cost_atomic: txs * per_tx_total,
                            blocks: u64::try_from(blocks).unwrap_or(u64::MAX),
                            placement,
                        },
                        candidate.0,
                        candidate.1,
                    ));
                }
            }
        }
        best.expect("the shape space is non-empty").0
    }

    /// The ways one stuffing transaction of `weight` fits this block:
    /// placement, its cost per transaction, and how many fit a block that
    /// way.
    fn placements(&self, weight: u64, miner_keeps_honest: u64) -> Vec<(Placement, u128, u64)> {
        let mut out = Vec::new();
        if weight <= self.room {
            out.push((Placement::FreeRoom, 0, self.room / weight.max(1)));
        }
        let past = self.honest.bodies_weight() + weight;
        if past <= self.honest.bodies_weight_bound() {
            let after = self
                .emission
                .penalised(self.median, past, self.economic)
                .expect("within twice the median");
            out.push((
                Placement::Penalty,
                u128::from(self.honest.reward() - after),
                1,
            ));
        }
        let listed = self.honest.bodies_weight() / self.honest_weight.max(1);
        if listed > 0 && weight <= self.honest.bodies_weight() + self.room {
            // In bulk: the honest weight it clears carries its stuffing, so
            // each stuffing transaction forgoes the miner's share of
            // `weight / honest_weight` honest fees.
            let forgone = u128::from(miner_keeps_honest) * u128::from(weight)
                / u128::from(self.honest_weight.max(1));
            let per_block = (self.honest.bodies_weight() + self.room) / weight.max(1);
            out.push((Placement::Displacement, forgone, per_block));
        }
        out
    }
}

/// Where the report samples the envelope: three eras of the baseline, and a
/// chain whose demand sits below the zone, where free room exists (§5.10).
const ROWS: [(&str, u64, &str); 4] = [
    ("baseline_steady_state", 5, "constrained"),
    ("baseline_steady_state", 20, "carried"),
    ("baseline_steady_state", 45, "tail"),
    ("high_history_low_activity", 50, "below zone"),
];

/// Hashrate shares and time budgets (blocks) the shard counts are read at.
const SHARES_PCT: [u64; 2] = [10, 33];

/// Print the envelope (§5.10). SKL per shard; the last two columns are the
/// minimum on the chain as it stands and once the floor is enforced on a
/// block's own bodies.
pub(crate) fn print_envelope(
    out: &mut impl core::fmt::Write,
    params: &SimParams,
) -> core::fmt::Result {
    let budgets = [
        ("epoch", shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS),
        ("year", params.blocks_per_year),
        ("decade", 10 * params.blocks_per_year),
    ];
    writeln!(
        out,
        "\nESR-7 — THE CHEAPEST ARCHIVAL BYTE: SKL to add one shard at a block the honest fold built.\n\
         relay = through the pool at the rate that gets listed (floor, or one atomic/B above the\n\
         honest rate); miner U = own bodies at no fee (today: the relay floor does not apply to them),\n\
         cheapest of free room / penalty / displaced fees; miner E = the same paying the floor\n\
         (C2-R2 Q9's fix, a declared divergence); self = E recovering the staker pool's part as one of\n\
         {CO_HOLDERS} holders, and as the whole holder set. 'today' / 'fixed' = the minimum over the\n\
         attackers on each chain."
    )?;
    writeln!(
        out,
        "{:<12} {:>3} {:<11} {:>7} {:>6} {:>11} {:>12} {:>13} {:>11} {:>11} {:>11} {:>11} {:>11}",
        "scenario",
        "y",
        "era",
        "M (KB)",
        "room",
        "relay",
        "miner U",
        "(placement)",
        "miner E",
        "self 1/100",
        "self all",
        "today",
        "fixed"
    )?;
    let skl = |atomic: u128| atomic as f64 / crate::burden::COIN as f64;
    let mut shard_rows = Vec::new();
    for (name, year, era) in ROWS {
        let config = crate::onset::at_horizon(
            crate::scenarios::all_scenarios(params)
                .into_iter()
                .find(|c| c.name == name)
                .expect("the scenario exists"),
        );
        let aggs = crate::stage2::a1_year_aggs(params, &config);
        let Some(agg) = aggs.iter().find(|a| a.year == year) else {
            continue;
        };
        let last = agg.last_block;
        let e = envelope_at(&last, params);
        let economic = params.economic();
        let block = Block::new(&last, &economic);
        writeln!(
            out,
            "{:<12} {:>3} {:<11} {:>7.0} {:>6.0} {:>11.4} {:>12.4} {:>13} {:>11.4} {:>11.4} {:>11.4} {:>11.4} {:>11.4}",
            crate::stage2::trunc(name, 12),
            year,
            era,
            block.median as f64 / 1.0e3,
            block.room as f64 / 1.0e3,
            skl(e.relay_atomic),
            skl(e.unenforced.cost_atomic),
            format!("{:?}", e.unenforced.placement),
            skl(e.enforced.cost_atomic),
            skl(e.self_archiving_one_of_many.cost_atomic),
            skl(e.self_archiving_whole_set.cost_atomic),
            skl(e.today_atomic()),
            skl(e.after_fix_atomic()),
        )?;
        shard_rows.push((
            name,
            year,
            e.unenforced.blocks,
            e.relay_at_floor,
            e.relay_rate,
        ));
    }
    writeln!(
        out,
        "  -> Shards a miner stuffs at the U price within a budget: share x budget / blocks per shard.\n\
         Hashrate and time set a rate, not a price; a larger campaign raises the overshoot and the price."
    )?;
    for (name, year, blocks, at_floor, rate) in shard_rows {
        let cells: Vec<String> = SHARES_PCT
            .iter()
            .flat_map(|&pct| {
                budgets.iter().map(move |&(label, n)| {
                    format!("{pct}%/{label} {}", n * pct / 100 / blocks.max(1))
                })
            })
            .collect();
        writeln!(
            out,
            "       {:<12} y{year:<3} {blocks:>5} blocks/shard; relay at {} atomic/B{}: {}",
            crate::stage2::trunc(name, 12),
            rate.atomic(),
            if at_floor {
                " (the floor)"
            } else {
                " (outranking honest)"
            },
            cells.join(", ")
        )?;
    }
    Ok(())
}

/// Every attacker at the block a fold ended a year on.
pub(crate) fn envelope_at(last: &LastBlock, params: &SimParams) -> Envelope {
    let economic = params.economic();
    let block = Block::new(last, &economic);
    let floor = params.fee.admission_rate(&block.at);
    let (relay_rate, relay_at_floor, relay_atomic) = block.relay(floor);
    Envelope {
        relay_rate,
        relay_at_floor,
        relay_atomic,
        unenforced: block.miner(None, (0, 1)),
        enforced: block.miner(Some(floor), (0, 1)),
        self_archiving_one_of_many: block.miner(Some(floor), (1, CO_HOLDERS)),
        self_archiving_whole_set: block.miner(Some(floor), (1, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_chain_rules::medians_from;
    use shekyl_economics::{paid_block_reward, TxVolume};

    use crate::fee_model::OrdinaryTx;

    fn block_at(offered: u64, params: &SimParams) -> LastBlock {
        let economic = params.economic();
        let zone = economic.full_reward_zone;
        let volume = TxVolume::per_block(params.tx_volume_baseline);
        let at = FeePoint {
            already_generated: economic.emission_curve_asymptote / 3,
            volume,
            long_term_median: zone,
            sigma_scaled: 100_000,
            burn_pct_scaled: 200_000,
            chain_leaves: 50_000_000,
            params: &economic,
        };
        let honest_tx: OrdinaryTx = params.fee.ordinary_tx(&at);
        LastBlock {
            already_generated: at.already_generated,
            volume,
            sigma_scaled: at.sigma_scaled,
            burn_pct_scaled: at.burn_pct_scaled,
            chain_leaves: at.chain_leaves,
            closed_shards: 1_000,
            medians: medians_from(zone, zone),
            honest_offered: offered,
            honest_tx,
        }
    }

    /// Where honest demand leaves room under the median, the relay stuffer
    /// gets in at the floor and the unenforced miner stuffs for nothing;
    /// where it fills the block, the relay stuffer must outrank the honest
    /// bodies and the miner pays.
    #[test]
    fn free_room_is_free_and_a_full_block_is_not() {
        let params = SimParams::default();
        let roomy = envelope_at(&block_at(5, &params), &params);
        assert!(
            roomy.relay_at_floor,
            "admitted at the floor beside 5 bodies"
        );
        assert_eq!(roomy.unenforced.cost_atomic, 0);
        assert_eq!(roomy.unenforced.placement, Placement::FreeRoom);

        let full = envelope_at(&block_at(1_000, &params), &params);
        assert!(!full.relay_at_floor, "a full block refuses the floor rate");
        assert!(full.unenforced.cost_atomic > 0);
        assert_ne!(full.unenforced.placement, Placement::FreeRoom);
    }

    /// Paying the floor can only add to the miner's cost, and recovering
    /// part of the staker pool can only lower it again.
    #[test]
    fn enforcement_adds_cost_and_self_archiving_recovers_part_of_it() {
        let params = SimParams::default();
        for offered in [5, 22, 1_000] {
            let e = envelope_at(&block_at(offered, &params), &params);
            assert!(
                e.enforced.cost_atomic >= e.unenforced.cost_atomic,
                "offered {offered}"
            );
            assert!(e.self_archiving_one_of_many.cost_atomic <= e.enforced.cost_atomic);
            assert!(
                e.self_archiving_whole_set.cost_atomic <= e.self_archiving_one_of_many.cost_atomic
            );
            assert!(e.today_atomic() <= e.relay_atomic);
        }
    }

    /// The penalty leg is the reward the owner takes away: for a full block
    /// at the zone, one more transaction of the miner's costs exactly
    /// `paid(c) − paid(c + x)`.
    #[test]
    fn the_penalty_leg_is_the_owners_reward_difference() {
        let params = SimParams::default();
        let last = block_at(1_000, &params);
        let economic = params.economic();
        let block = Block::new(&last, &economic);
        let weight = 20_000;
        let c = block.honest.bodies_weight();
        let m = block.median;
        let owed = |w| paid_block_reward(m, w, last.already_generated, last.volume, &economic);
        let expected = owed(c).expect("priced") - owed(c + weight).expect("priced");
        let penalty = block
            .placements(weight, 0)
            .into_iter()
            .find(|(p, _, _)| *p == Placement::Penalty)
            .expect("one more transaction fits under the limit");
        assert_eq!(penalty.1, u128::from(expected));
    }
}
