// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which bodies a template lists under the ruled fill
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`, ESR-6).
//!
//! [`Fill`] is the reward-aware policy. It is not the scan
//! `tx_memory_pool::fill_block_template` runs. That scan lists bodies in
//! fee order, lets one body cross the median, refuses a body that would
//! pass 13/10 of the median less the coinbase reserve, and then stops.
//! This rule admits a body only when listing it does not lower the gross
//! coinbase, and keeps the block — bodies plus the coinbase weight it was
//! given — within twice the effective median. The C++ scan deletes with
//! `tx_pool.cpp` at the DRS-X flip. The economics sim and the node's
//! template both pass `shekyl_wire::transaction::COINBASE_RESERVE` as the
//! coinbase weight.
//!
//! A producer offers pool bodies to a [`Fill`] in its own order — the
//! daemon offers them by fee, then by receive time — and lists those this
//! rule admits. The penalty is the only thing that can make a fee-paying
//! body lower the gross coinbase, so the rule is where the fee a
//! transaction pays meets the block size it buys: below the median every
//! body is admitted; past it, one is admitted only while its fee covers
//! the reward it costs. The rule is mempool policy, not consensus — the
//! validator admits any block under its limit.
//!
//! - The comparison is on the **gross** coinbase: the reward before the
//!   staker split and the fees before the burn. A producer paid net of
//!   both would weigh a body differently; that is a question for the fee
//!   design, not something this rule settles.
//! - The weight stored is the block's. It starts at the coinbase weight
//!   the caller passed and grows by each admitted body. The sim and the
//!   node's template pass `COINBASE_RESERVE`, which is at least any
//!   coinbase the grammar can build. [`crate::build`] prices the listing
//!   it is given and does not drop a body from it.
//! - The comparison is exact. An earlier C++ copy of this rule rounded
//!   through a float threshold of 1.0; that copy left with the hard-fork
//!   mechanism and is not what the daemon runs.

use shekyl_economics::{
    penalty_free_weight, EconomicParams, EmissionError, PrePenaltyEmission, TxVolume,
};

/// A template priced so far, and what admitting one more body would do.
///
/// The stored weight is the block's: the coinbase the caller passed, plus
/// the bodies admitted since. Body weight is that total less the coinbase,
/// which holds because every constructor and [`Self::admit`] build the
/// total with a checked add.
#[derive(Clone, Copy, Debug)]
pub struct Fill<'a> {
    median_weight: u64,
    /// The coinbase this block is priced at. Bodies sit on top of it.
    coinbase_weight: u64,
    emission: PrePenaltyEmission,
    params: &'a EconomicParams,
    /// Bodies plus [`Self::coinbase_weight`]. The weight [`Self::reward`]
    /// was penalised at.
    block_weight: u64,
    fees: u64,
    reward: u64,
}

impl<'a> Fill<'a> {
    /// A template with no bodies, at the effective median `median_weight`
    /// (CEN-G6), priced at `coinbase_weight`, the parent's
    /// `already_generated` and the volume window (CEN-F20) — the operands
    /// [`crate::EmissionOperands`] carries, plus the coinbase.
    ///
    /// # Errors
    ///
    /// The reward's own error when the empty block cannot be priced.
    pub fn empty(
        median_weight: u64,
        coinbase_weight: u64,
        already_generated: u64,
        tx_volume: TxVolume,
        params: &'a EconomicParams,
    ) -> Result<Self, EmissionError> {
        // The emission does not depend on the bodies; it is priced once here
        // and penalised at each block weight an offer would make.
        let emission = PrePenaltyEmission::of(already_generated, tx_volume, params)?;
        let reward = emission.penalised(median_weight, coinbase_weight, params)?;
        Ok(Self {
            median_weight,
            coinbase_weight,
            emission,
            params,
            block_weight: coinbase_weight,
            fees: 0,
            reward,
        })
    }

    /// A template whose bodies are already listed. `bodies_weight` and
    /// `fees` are that listing's outcome; the reward is the penalty at the
    /// weight. A fold that kept the outcome rebuilds the template in one
    /// pricing, then offers the next body to [`Self::admit`].
    ///
    /// # Errors
    ///
    /// [`EmissionError::BlockTooBig`] above twice the median;
    /// [`EmissionError::Overflow`] when the emission overflows or the
    /// reward and the fees do not fit in one coinbase.
    pub fn listed(
        median_weight: u64,
        coinbase_weight: u64,
        already_generated: u64,
        tx_volume: TxVolume,
        params: &'a EconomicParams,
        bodies_weight: u64,
        fees: u64,
    ) -> Result<Self, EmissionError> {
        let emission = PrePenaltyEmission::of(already_generated, tx_volume, params)?;
        let Some(block_weight) = bodies_weight.checked_add(coinbase_weight) else {
            return Err(EmissionError::Overflow);
        };
        let reward = emission.penalised(median_weight, block_weight, params)?;
        if reward.checked_add(fees).is_none() {
            return Err(EmissionError::Overflow);
        }
        Ok(Self {
            median_weight,
            coinbase_weight,
            emission,
            params,
            block_weight,
            fees,
            reward,
        })
    }

    /// Twice the median: the block limit this fill admits under.
    fn block_limit(&self) -> u64 {
        self.median_weight.saturating_mul(2)
    }

    /// The coinbase weight the block is priced at.
    #[must_use]
    pub fn coinbase_weight(&self) -> u64 {
        self.coinbase_weight
    }

    /// The most the listed bodies may weigh: the block limit less the coinbase.
    ///
    /// Zero when the coinbase alone is at or past the limit.
    #[must_use]
    pub fn bodies_weight_bound(&self) -> u64 {
        self.block_limit().saturating_sub(self.coinbase_weight)
    }

    /// The most the bodies may weigh while the block stays inside
    /// [`penalty_free_weight`], and not past [`Self::bodies_weight_bound`].
    #[must_use]
    pub fn penalty_free_bodies(&self) -> u64 {
        let free_block = penalty_free_weight(self.median_weight, self.params);
        let under_free = free_block.saturating_sub(self.coinbase_weight);
        under_free.min(self.bodies_weight_bound())
    }

    /// Body bytes still inside [`Self::penalty_free_bodies`]. Zero once the
    /// listed bodies are already past that ceiling.
    #[must_use]
    pub fn penalty_free_body_room(&self) -> u64 {
        self.penalty_free_bodies()
            .saturating_sub(self.bodies_weight())
    }

    /// The block weight: the bodies plus the coinbase.
    #[must_use]
    pub fn block_weight(&self) -> u64 {
        self.block_weight
    }

    /// Offer a body of `weight` paying `fee`. Admitted — and counted — when
    /// the block stays within [`Self::block_limit`] and the body does not
    /// lower the gross coinbase; otherwise refused and nothing changes, so
    /// a producer goes on to the next body.
    pub fn admit(&mut self, weight: u64, fee: u64) -> bool {
        let Some(block_weight) = self.block_weight.checked_add(weight) else {
            return false;
        };
        if block_weight > self.block_limit() {
            return false;
        }
        let Ok(reward) = self
            .emission
            .penalised(self.median_weight, block_weight, self.params)
        else {
            return false;
        };
        let Some(fees) = self.fees.checked_add(fee) else {
            return false;
        };
        let Some(coinbase) = reward.checked_add(fees) else {
            return false;
        };
        if coinbase < self.coinbase() {
            return false;
        }
        self.block_weight = block_weight;
        self.fees = fees;
        self.reward = reward;
        true
    }

    /// Offer `count` identical bodies, each of `weight` paying `fee`, one
    /// after another; the number admitted. Exactly what `count` calls of
    /// [`Self::admit`] admit, stopping at the first refusal — identical
    /// bodies refused once are refused again, since a refusal changes
    /// nothing.
    ///
    /// The bodies that keep the block within [`penalty_free_weight`] and the
    /// bound leave the reward where it is and add a fee each, so every one
    /// of them is admitted; they are admitted together, and the walk resumes
    /// past them. A block of millions of transactions below its median costs
    /// one step, not millions.
    pub fn admit_up_to(&mut self, weight: u64, fee: u64, count: u64) -> u64 {
        let ceiling = self.penalty_free_bodies();
        let free = match ceiling.checked_sub(self.bodies_weight()) {
            None => 0,
            Some(_) if weight == 0 => count,
            Some(room) => (room / weight).min(count),
        };
        let mut admitted = 0;
        let batch_fees = free
            .checked_mul(fee)
            .and_then(|added| self.fees.checked_add(added))
            .filter(|&fees| self.reward.checked_add(fees).is_some());
        let batch_weight = free
            .checked_mul(weight)
            .and_then(|added| self.block_weight.checked_add(added));
        if let (Some(fees), Some(block_weight)) = (batch_fees, batch_weight) {
            // Within the penalty-free weight the reward is the whole
            // emission, which is what it already is.
            self.block_weight = block_weight;
            self.fees = fees;
            admitted = free;
        }
        while admitted < count && self.admit(weight, fee) {
            admitted += 1;
        }
        admitted
    }

    /// The admitted bodies' weight: the block weight less the coinbase.
    #[must_use]
    pub fn bodies_weight(&self) -> u64 {
        debug_assert!(self.block_weight >= self.coinbase_weight);
        self.block_weight - self.coinbase_weight
    }

    /// The admitted bodies' fees.
    #[must_use]
    pub fn fees(&self) -> u64 {
        self.fees
    }

    /// The penalised reward at `bodies_weight` under this template's median.
    /// The listed bodies stay where they are: a producer asks what one more
    /// placement would pay.
    ///
    /// # Errors
    ///
    /// [`Self::admit`]'s reward error at that weight.
    pub fn reward_at(&self, bodies_weight: u64) -> Result<u64, EmissionError> {
        let block_weight = bodies_weight
            .checked_add(self.coinbase_weight)
            .ok_or(EmissionError::Overflow)?;
        self.emission
            .penalised(self.median_weight, block_weight, self.params)
    }

    /// The penalised reward at the bodies' weight
    /// ([`shekyl_economics::paid_block_reward`]), before the split.
    #[must_use]
    pub fn reward(&self) -> u64 {
        self.reward
    }

    /// The gross coinbase: [`Self::reward`] plus the bodies' fees. The sum
    /// was checked when the last body was admitted.
    #[must_use]
    pub fn coinbase(&self) -> u64 {
        self.reward + self.fees
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_economics::paid_block_reward;

    /// `admit_up_to` against the walk it stands for, `count` single offers
    /// stopping at the first refusal: the same count and the same fill
    /// after, from fills that start below, at, across and past the full
    /// weight, with fees from nothing to enough to buy the whole penalty
    /// zone, and counts that end inside and beyond the run.
    #[test]
    fn admit_up_to_is_the_single_offer_walk() {
        let p = params();
        let v = volume(&p);
        let zone = p.full_reward_zone;
        let mut cases = 0;
        for median in [zone, zone + 77_777, 3 * zone] {
            for already_generated in [0, p.emission_curve_asymptote / 2] {
                let empty = Fill::empty(median, coinbase_weight(), already_generated, v, &p)
                    .expect("priced");
                let full = median.max(zone);
                for start in [0, full / 3, full - 5_000, full, full + 9_000] {
                    for weight in [0u64, 1, 2_999, 12_595, 15_283, 70_001] {
                        for fee in [0u64, 1, 1_000_000, 3_000_000_000, 400_000_000_000] {
                            for count in [0u64, 1, 7, 23, 24, 25, 500, 100_000] {
                                let mut base = empty;
                                // A start past the full weight is bought with
                                // a fee that covers its penalty.
                                assert!(
                                    start == 0 || base.admit(start, 1_000_000_000_000_000),
                                    "the start is admitted"
                                );
                                let mut walked = base;
                                let mut walk = 0;
                                while walk < count && walked.admit(weight, fee) {
                                    walk += 1;
                                }
                                let mut batched = base;
                                let batch = batched.admit_up_to(weight, fee, count);
                                let at = format!(
                                    "median {median} ag {already_generated} start {start} \
                                     weight {weight} fee {fee} count {count}"
                                );
                                assert_eq!(batch, walk, "count, {at}");
                                assert_eq!(batched.bodies_weight(), walked.bodies_weight(), "{at}");
                                assert_eq!(batched.fees(), walked.fees(), "{at}");
                                assert_eq!(batched.reward(), walked.reward(), "{at}");
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(cases > 4_000, "the grid ran ({cases} cases)");
    }

    fn params() -> EconomicParams {
        EconomicParams::default()
    }

    fn volume(params: &EconomicParams) -> TxVolume {
        TxVolume::per_block(params.tx_volume_baseline)
    }

    fn coinbase_weight() -> u64 {
        u64::try_from(shekyl_wire::transaction::COINBASE_RESERVE).expect("the reserve fits")
    }

    /// Below the penalty-free weight the reward does not move, so a body
    /// paying nothing is admitted; the bound is twice the median less the
    /// coinbase, and a body crossing it is refused however much it pays.
    #[test]
    fn below_the_median_everything_fits_and_the_bound_refuses_regardless_of_fee() {
        let p = params();
        let m = p.full_reward_zone;
        let coinbase = coinbase_weight();
        let mut fill = Fill::empty(m, coinbase, 0, volume(&p), &p).expect("priced");
        let empty = fill.coinbase();
        assert!(
            fill.admit(m - coinbase, 0),
            "a body filling the penalty-free weight"
        );
        assert_eq!(fill.block_weight(), m);
        assert_eq!(fill.coinbase(), empty, "no penalty at the free weight");
        assert_eq!(fill.bodies_weight_bound(), 2 * m - coinbase);
        let room = fill.bodies_weight_bound() - fill.bodies_weight();
        let mut tight = fill;
        assert!(
            !tight.admit(room + 1, u64::MAX / 4),
            "one byte over the bound"
        );
        assert_eq!(
            tight.bodies_weight(),
            m - coinbase,
            "a refusal changes nothing"
        );
    }

    /// Past the median a body is admitted exactly when its fee covers the
    /// reward it costs: the boundary pair is the fee one atomic unit short
    /// of the penalty and the fee equal to it.
    #[test]
    fn past_the_median_the_fee_must_cover_the_reward_the_body_costs() {
        let p = params();
        let m = p.full_reward_zone;
        let v = volume(&p);
        let body = 13_000;
        let coinbase = coinbase_weight();
        let mut base = Fill::empty(m, coinbase, 0, v, &p).expect("priced");
        let under = m - coinbase - 1_000;
        assert!(base.admit(under, 0));
        let before = paid_block_reward(m, under + coinbase, 0, v, &p).expect("priced");
        let after = paid_block_reward(m, under + coinbase + body, 0, v, &p).expect("priced");
        let cost = before - after;
        assert!(cost > 0, "the body crosses the median");

        let mut short = base;
        assert!(!short.admit(body, cost - 1), "one atomic unit short");
        assert_eq!(short.bodies_weight(), under);
        let mut covered = base;
        assert!(covered.admit(body, cost), "the fee equals the cost");
        assert_eq!(covered.coinbase(), before);
        assert_eq!(covered.reward(), after, "the reward at the new weight");
        assert_eq!(covered.fees(), cost);
    }

    /// Rebuilding a listed template is the fill the offers produced: the
    /// same weight, fees, reward and coinbase, below the median and past it.
    #[test]
    fn listed_is_the_fill_the_offers_built() {
        let p = params();
        let v = volume(&p);
        let median = p.full_reward_zone;
        for (weight, fee, count) in [(2_000u64, 0u64, 40u64), (20_000, 50_000_000_000, 12)] {
            let mut offered = Fill::empty(median, coinbase_weight(), 0, v, &p).expect("priced");
            let admitted = offered.admit_up_to(weight, fee, count);
            assert!(admitted > 0, "the case lists something");
            let listed = Fill::listed(
                median,
                coinbase_weight(),
                0,
                v,
                &p,
                offered.bodies_weight(),
                offered.fees(),
            )
            .expect("the offers' outcome is a template");
            assert_eq!(listed.bodies_weight(), offered.bodies_weight());
            assert_eq!(listed.fees(), offered.fees());
            assert_eq!(listed.reward(), offered.reward());
            assert_eq!(listed.coinbase(), offered.coinbase());
            assert_eq!(
                listed.reward_at(listed.bodies_weight()).expect("priced"),
                listed.reward()
            );
        }
    }
}
