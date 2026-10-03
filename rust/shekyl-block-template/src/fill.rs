// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which bodies a template lists: the fill rule
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`, ESR-6).
//!
//! A producer offers pool bodies to a [`Fill`] in its own order — the C++
//! offers them by fee, then by receive time — and lists those it admits.
//! The rule is one comparison: a body is admitted when listing it does not
//! lower what the coinbase would carry, the penalised reward at the bodies'
//! new weight plus every listed fee, and when the bodies stay within twice
//! the effective median less the coinbase reserve. The penalty is the only
//! thing that can make a fee-paying body lower that sum, so the rule is
//! where the fee a transaction pays meets the block size it buys: below the
//! median every body is admitted; past it, one is admitted only while its
//! fee covers the reward it costs.
//!
//! The rule is mempool policy, not consensus — the validator admits any
//! block under its limit — and its first implementation is
//! `tx_memory_pool::fill_block_template` (`tx_pool.cpp`), whose comparison
//! this module owns from here on. Two facts of the C++ are kept, one is not:
//!
//! - **Kept:** the comparison is on the **gross** coinbase — the reward
//!   before the staker split and the fees before the burn. A producer
//!   paid net of both would weigh a body differently; that is a question
//!   for the fee design, not something a lift may settle silently.
//! - **Kept:** the weight priced is the **bodies'** weight. The coinbase's
//!   own bytes are reserved in the bound, not priced here; [`crate::build`]
//!   prices the block the bodies make, coinbase included.
//! - **Not kept:** the C++ compares against `best · ACCEPT_THRESHOLD` with
//!   the threshold a `float` of `1.0`, so `best` is rounded to the nearest
//!   24-bit-mantissa value first, and within that rounding it can admit a
//!   body that lowers the coinbase or refuse one that raises it. This rule
//!   compares exactly.

use shekyl_economics::{EconomicParams, EmissionError, PrePenaltyEmission, TxVolume};
use shekyl_wire::transaction::COINBASE_BLOB_RESERVED_SIZE;

/// The bytes a block holds back for its coinbase when bodies are admitted.
const COINBASE_RESERVE: u64 = COINBASE_BLOB_RESERVED_SIZE as u64;

/// A template's bodies so far, and what admitting one more would do.
#[derive(Clone, Copy, Debug)]
pub struct Fill<'a> {
    median_weight: u64,
    emission: PrePenaltyEmission,
    params: &'a EconomicParams,
    bodies_weight: u64,
    fees: u64,
    reward: u64,
}

impl<'a> Fill<'a> {
    /// A template with no bodies, at the effective median `median_weight`
    /// (CEN-G6), the parent's `already_generated` and the volume window
    /// (CEN-F20) — the operands [`crate::EmissionOperands`] carries.
    ///
    /// # Errors
    ///
    /// The reward's own error when the empty block cannot be priced.
    pub fn empty(
        median_weight: u64,
        already_generated: u64,
        tx_volume: TxVolume,
        params: &'a EconomicParams,
    ) -> Result<Self, EmissionError> {
        // The emission does not depend on the bodies; it is priced once here
        // and penalised at each weight an offer would make.
        let emission = PrePenaltyEmission::of(already_generated, tx_volume, params)?;
        let reward = emission.penalised(median_weight, 0, params)?;
        Ok(Self {
            median_weight,
            emission,
            params,
            bodies_weight: 0,
            fees: 0,
            reward,
        })
    }

    /// The most the listed bodies may weigh: twice the median, less the
    /// coinbase reserve.
    #[must_use]
    pub fn bodies_weight_bound(&self) -> u64 {
        self.median_weight
            .saturating_mul(2)
            .saturating_sub(COINBASE_RESERVE)
    }

    /// Offer a body of `weight` paying `fee`. Admitted — and counted — when
    /// it fits under [`Self::bodies_weight_bound`] and does not lower the
    /// gross coinbase; otherwise refused and nothing changes, so a producer
    /// goes on to the next body.
    pub fn admit(&mut self, weight: u64, fee: u64) -> bool {
        let Some(bodies_weight) = self.bodies_weight.checked_add(weight) else {
            return false;
        };
        if bodies_weight > self.bodies_weight_bound() {
            return false;
        }
        let Ok(reward) = self
            .emission
            .penalised(self.median_weight, bodies_weight, self.params)
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
        self.bodies_weight = bodies_weight;
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
    /// The bodies that keep the block within the emission's full weight
    /// ([`PrePenaltyEmission::full_weight`]) and the bound leave the reward
    /// where it is and add a fee each, so every one of them is admitted;
    /// they are admitted together, and the walk resumes past them. A block
    /// of millions of transactions below its median costs one step, not
    /// millions.
    pub fn admit_up_to(&mut self, weight: u64, fee: u64, count: u64) -> u64 {
        let ceiling = self
            .emission
            .full_weight(self.median_weight, self.params)
            .min(self.bodies_weight_bound());
        let free = match ceiling.checked_sub(self.bodies_weight) {
            None => 0,
            Some(_) if weight == 0 => count,
            Some(room) => (room / weight).min(count),
        };
        let mut admitted = 0;
        let batch_fees = free
            .checked_mul(fee)
            .and_then(|added| self.fees.checked_add(added))
            .filter(|&fees| self.reward.checked_add(fees).is_some());
        if let Some(fees) = batch_fees {
            // Within the full weight the reward is the whole emission, which
            // is what it already is: `bodies_weight` is at or below it.
            self.bodies_weight += free * weight;
            self.fees = fees;
            admitted = free;
        }
        while admitted < count && self.admit(weight, fee) {
            admitted += 1;
        }
        admitted
    }

    /// The admitted bodies' weight.
    #[must_use]
    pub fn bodies_weight(&self) -> u64 {
        self.bodies_weight
    }

    /// The admitted bodies' fees.
    #[must_use]
    pub fn fees(&self) -> u64 {
        self.fees
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
                let empty = Fill::empty(median, already_generated, v, &p).expect("priced");
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

    /// Below the median the reward does not move, so a body paying nothing
    /// is admitted; the bound is twice the median less the reserve, and a
    /// body crossing it is refused however much it pays.
    #[test]
    fn below_the_median_everything_fits_and_the_bound_refuses_regardless_of_fee() {
        let p = params();
        let m = p.full_reward_zone;
        let mut fill = Fill::empty(m, 0, volume(&p), &p).expect("priced");
        let empty = fill.coinbase();
        assert!(fill.admit(m, 0), "a body filling the median exactly");
        assert_eq!(fill.coinbase(), empty, "no penalty at the median");
        assert_eq!(fill.bodies_weight_bound(), 2 * m - 600);
        let room = fill.bodies_weight_bound() - fill.bodies_weight();
        let mut tight = fill;
        assert!(
            !tight.admit(room + 1, u64::MAX / 4),
            "one byte over the bound"
        );
        assert_eq!(tight.bodies_weight(), m, "a refusal changes nothing");
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
        let mut base = Fill::empty(m, 0, v, &p).expect("priced");
        assert!(base.admit(m - 1_000, 0));
        let before = paid_block_reward(m, m - 1_000, 0, v, &p).expect("priced");
        let after = paid_block_reward(m, m - 1_000 + body, 0, v, &p).expect("priced");
        let cost = before - after;
        assert!(cost > 0, "the body crosses the median");

        let mut short = base;
        assert!(!short.admit(body, cost - 1), "one atomic unit short");
        assert_eq!(short.bodies_weight(), m - 1_000);
        let mut covered = base;
        assert!(covered.admit(body, cost), "the fee equals the cost");
        assert_eq!(covered.coinbase(), before);
        assert_eq!(covered.reward(), after, "the reward at the new weight");
        assert_eq!(covered.fees(), cost);
    }
}
