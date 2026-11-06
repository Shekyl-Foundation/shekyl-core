// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Which bodies a template lists under the ruled fill
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md`, ESR-6).
//!
//! [`Fill`] is the reward-aware policy, and the only fill the node runs.
//! It admits a body only when listing it does not lower the gross
//! coinbase, and keeps the block — bodies plus the coinbase weight it was
//! given — within twice the effective median. It is not the inherited
//! scan, which listed bodies in fee order, let one body cross the median,
//! refused a body that would pass 13/10 of the median less the coinbase
//! reserve, and then stopped; that scan left with the C++ pool at the
//! DRS-X flip. The economics sim and the node's template both pass `shekyl_wire::transaction::COINBASE_RESERVE` as the
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
    block_weight_limit, penalty_free_weight, EconomicParams, EmissionError, PrePenaltyEmission,
    TxVolume,
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
    /// the block stays within the block limit, twice the median weight, and
    /// the body does not lower the gross coinbase; otherwise refused and nothing changes, so
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
    /// nothing. It costs a bounded number of reward pricings, not one per
    /// body (`ECONOMY_UMBRELLA_PLAN.md` §3.2 b).
    ///
    /// 1. **The reward does not move.** Bodies that keep the block within
    ///    [`penalty_free_weight`] and the bound, or that weigh nothing, add
    ///    a fee each and leave the reward where it is. Every one is admitted
    ///    until the fees would overflow the coinbase, which is a quotient.
    /// 2. **The body that crosses the penalty-free weight** is offered
    ///    alone, so that from here the block is past it and the penalty's
    ///    product has been formed at the smallest excess the run will see.
    ///    The product only falls as the excess grows, so it cannot overflow
    ///    later in the run.
    /// 3. **The penalty zone.** `admit`'s exits that only depend on the
    ///    weight or the fees are monotone in the number of bodies, and each
    ///    is a quotient: the fill's block limit, the penalty's own limit
    ///    ([`block_weight_limit`], its `BlockTooBig`), the fees' overflow,
    ///    and `count`. Within them, the bodies whose fee covers the
    ///    real-valued penalty are all admitted
    ///    ([`PrePenaltyEmission::bodies_the_fee_covers`] proves it), so the
    ///    first refusal is at or past that root. Past the root, write
    ///    `h_j = c·x_j² − fee·j` (the economics helper's notation). Each body
    ///    there costs more than its fee, so `h` rises and `⌈h⌉` never falls;
    ///    a body is admitted exactly when `⌈h⌉` stays level. "Every body
    ///    from the root to `j` is admitted" is then one test,
    ///    `R(root) − R(j) ≤ fee·(j − root)`, and it is monotone in `j`. So is
    ///    "the coinbase still fits", because the coinbase does not fall
    ///    along an admitted run. The last admitted body is found by
    ///    bisection on the two, with [`PrePenaltyEmission::penalised`] at
    ///    each probe.
    ///
    /// **The bound `B`: how far past the root the first refusal can lie.**
    /// Let `T = (e·M)² / (A·s²·w²) = 1/(c·w²)`. Past the root, body
    /// `root + i` costs `δ − fee > 2·c·w²·(i − 1)`, because `δ` rises by
    /// `2·c·w²` a body and the first past the root already exceeds the fee.
    /// After `t` bodies, `h` has risen by more than `c·w²·t·(t − 1)`. Once
    /// that reaches 1, `⌈h⌉` has risen, and the body where it rose was
    /// refused. So at most `B = t − 1` bodies are admitted past the root,
    /// `t` the least integer with `t·(t − 1) ≥ T`. That is about
    /// `e·M / (s·w·√A)`. It is not a constant: it grows with the median and
    /// shrinks with the reward and the body
    /// (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.28 evaluates it on the sim's
    /// schedules). The bisection's cost is logarithmic in `count` whatever
    /// `B` is. `B` bounds where the refusal lies, and the tests check it on
    /// every case they draw.
    ///
    /// Where the economics helper cannot count the root (its products leave
    /// `u128`, past the penalty's own arithmetic), the bodies are offered
    /// one at a time, as before.
    pub fn admit_up_to(&mut self, weight: u64, fee: u64, count: u64) -> u64 {
        let mut admitted = self.admit_unpenalised(weight, fee, count);
        if weight > 0 {
            let free_weight = penalty_free_weight(self.median_weight, self.params);
            while admitted < count && self.block_weight <= free_weight {
                if !self.admit(weight, fee) {
                    return admitted;
                }
                admitted += 1;
            }
            if admitted < count {
                admitted += self.admit_penalised(weight, fee, count - admitted);
            }
        }
        // After the closed form this offer is refused, or `count` is met.
        // Where the helper could not count the root it is the whole walk.
        while admitted < count && self.admit(weight, fee) {
            admitted += 1;
        }
        admitted
    }

    /// Step 1 of [`Self::admit_up_to`]: the bodies that leave the reward
    /// where it is, admitted together. A zero-weight body never moves the
    /// reward. A weighted one does not move it while the bodies stay within
    /// [`Self::penalty_free_bodies`]. Both are refused only past the block
    /// limit, or where the fees would overflow the coinbase.
    fn admit_unpenalised(&mut self, weight: u64, fee: u64, count: u64) -> u64 {
        let steady = if weight == 0 {
            if self.block_weight <= self.block_limit() {
                count
            } else {
                0
            }
        } else {
            match self.penalty_free_bodies().checked_sub(self.bodies_weight()) {
                None => 0,
                Some(room) => (room / weight).min(count),
            }
        };
        // The reward is fixed, so body `i` fits while `coinbase + i·fee`
        // does. That also keeps the fees alone in range.
        let admitted = match (u64::MAX - self.coinbase()).checked_div(fee) {
            Some(fits) => steady.min(fits),
            None => steady,
        };
        // In range: `admitted·weight` is at most the room, and
        // `admitted·fee` at most the coinbase's headroom.
        self.block_weight += admitted * weight;
        self.fees += admitted * fee;
        admitted
    }

    /// Step 3 of [`Self::admit_up_to`], from a block past the penalty-free
    /// weight with `weight > 0`: the bodies admitted before the first
    /// refusal, admitted together. Zero where the economics helper cannot
    /// count the root, and the caller walks.
    fn admit_penalised(&mut self, weight: u64, fee: u64, count: u64) -> u64 {
        let params = self.params;
        let median = self.median_weight;
        let start_weight = self.block_weight;
        let start_fees = self.fees;
        // `admit`'s exits in its order: the weight's overflow and the fill's
        // limit, the penalty's limit, the fees' overflow. Each is monotone in
        // the bodies, so the run stops at the least of them.
        let limit = self.block_limit().min(block_weight_limit(median, params));
        let Some(room) = limit.checked_sub(start_weight) else {
            return 0;
        };
        let mut most = (room / weight).min(count);
        if let Some(fits) = (u64::MAX - start_fees).checked_div(fee) {
            most = most.min(fits);
        }
        let Some(covered) =
            self.emission
                .bodies_the_fee_covers(median, start_weight, weight, fee, params)
        else {
            return 0;
        };
        let root = covered.min(most);
        // In range for every `j ≤ most`, by the caps above.
        let weight_at = |j: u64| start_weight + j * weight;
        let fees_at = |j: u64| start_fees + j * fee;
        let reward_at = |j: u64| self.emission.penalised(median, weight_at(j), params).ok();
        let Some(root_reward) = reward_at(root) else {
            return 0;
        };
        // Bodies `1..=j` are all admitted. Up to the root the penalty never
        // refuses, and past it the cumulative test stands for the per-body
        // one. The coinbase must fit.
        let admitted_through = |j: u64| -> Option<u64> {
            let reward = reward_at(j)?;
            reward.checked_add(fees_at(j))?;
            if j > root {
                // The reward only falls with the weight, so the cost is not
                // negative; the comparison is in `u128` to say so.
                let paid = u128::from(fee) * u128::from(j - root) + u128::from(reward);
                if u128::from(root_reward) > paid {
                    return None;
                }
            }
            Some(reward)
        };
        let (mut low, mut high) = (0, most);
        let reward = match admitted_through(most) {
            Some(reward) => {
                low = most;
                reward
            }
            None => {
                // `low` is admitted and `high` is not.
                while high - low > 1 {
                    let mid = low + (high - low) / 2;
                    if admitted_through(mid).is_some() {
                        low = mid;
                    } else {
                        high = mid;
                    }
                }
                match admitted_through(low) {
                    Some(reward) => reward,
                    None => return 0,
                }
            }
        };
        self.block_weight = weight_at(low);
        self.fees = fees_at(low);
        self.reward = reward;
        low
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
    use shekyl_economics::block_weight::MAX_BLOCK_WEIGHT_LIMIT_MULTIPLE;
    use shekyl_economics::paid_block_reward;
    use shekyl_economics::params::SCALE;

    /// The longest walk a parity case runs as its reference. Counts the
    /// walk does not reach within it are not checked, and are counted, so a
    /// grid that checks nothing fails its count.
    const WALK_CAP: u64 = 1 << 18;

    /// `count` single offers of `admit`, stopping at the first refusal: the
    /// reference `admit_up_to` is held to. One walk serves every count in
    /// `counts` (ascending): the fill after `min(count, run)` admissions,
    /// for each count the walk settles within [`WALK_CAP`] offers.
    fn walk<'a>(base: Fill<'a>, weight: u64, fee: u64, counts: &[u64]) -> Vec<(u64, Fill<'a>)> {
        let mut fill = base;
        let mut admitted = 0;
        let mut out = Vec::with_capacity(counts.len());
        for &count in counts {
            while admitted < count {
                if admitted == WALK_CAP {
                    return out;
                }
                if !fill.admit(weight, fee) {
                    break;
                }
                admitted += 1;
            }
            out.push((admitted, fill));
        }
        out
    }

    /// `admit_up_to` from `base` equals the walk for every count the walk
    /// settles: the admitted number and the fill after, field by field.
    /// True when every count was checked.
    fn parity(base: Fill<'_>, weight: u64, fee: u64, counts: &[u64], at: &str) -> bool {
        let walked = walk(base, weight, fee, counts);
        let all = walked.len() == counts.len();
        for (&count, (walk, after)) in counts.iter().zip(walked) {
            let mut batched = base;
            let batch = batched.admit_up_to(weight, fee, count);
            let at = format!("{at} weight {weight} fee {fee} count {count}");
            assert_eq!(batch, walk, "admitted, {at}");
            assert_eq!(batched.block_weight(), after.block_weight(), "weight, {at}");
            assert_eq!(batched.fees(), after.fees(), "fees, {at}");
            assert_eq!(batched.reward(), after.reward(), "reward, {at}");
        }
        all
    }

    /// The set at limit multiple `multiple` ([`SCALE`] units), validated.
    fn params_at(multiple: u64) -> EconomicParams {
        let p = EconomicParams {
            block_weight_limit_multiple: multiple,
            ..EconomicParams::default()
        };
        p.validate().expect("a valid multiple");
        p
    }

    /// `admit_up_to` against the walk it stands for, `count` single offers
    /// stopping at the first refusal: the same count and the same fill
    /// after. The fills start below, at, across and past the penalty-free
    /// weight. Medians run from below the zone to past 8 GB. The reward is
    /// on the curve's start, its middle, and the tail. The limit multiple is
    /// the shipped 2, 1.5 (the penalty's limit inside the fill's, so its
    /// `BlockTooBig` is an exit) and the validator's maximum. Fees run from
    /// nothing, through enough to buy the whole penalty zone, to an
    /// overflow within four bodies. Counts end inside and beyond the run.
    #[test]
    fn admit_up_to_is_the_single_offer_walk() {
        let counts = [0u64, 1, 7, 23, 24, 25, 500, 100_000, 1 << 40, u64::MAX];
        let (mut cases, mut skipped) = (0u64, 0u64);
        for multiple in [2 * SCALE, 15 * SCALE / 10, MAX_BLOCK_WEIGHT_LIMIT_MULTIPLE] {
            let p = params_at(multiple);
            let v = volume(&p);
            let zone = p.full_reward_zone;
            for median in [zone / 3, zone, zone + 77_777, 3 * zone, 40 * zone, 1 << 33] {
                for already_generated in [
                    0,
                    p.emission_curve_asymptote / 2,
                    p.emission_curve_asymptote + 1,
                ] {
                    let empty = Fill::empty(median, coinbase_weight(), already_generated, v, &p)
                        .expect("priced");
                    let full = median.max(zone);
                    for start in [
                        0,
                        full / 3,
                        full - 5_000,
                        full,
                        full + 9_000,
                        full + full / 2,
                    ] {
                        let mut base = empty;
                        // A start past the full weight is bought with a fee
                        // that covers its penalty; one past the limit is not
                        // admitted, and the case starts empty.
                        if start > 0 && !base.admit(start, 1_000_000_000_000_000) {
                            base = empty;
                        }
                        // A one-byte body is walked only where the median
                        // keeps its reference walk short.
                        let one = if median <= 3 * zone { 1 } else { 2_999 };
                        for weight in [0u64, one, 2_999, 12_595, 15_283, 70_001] {
                            for fee in [
                                0u64,
                                1,
                                1_000_000,
                                3_000_000_000,
                                400_000_000_000,
                                1_000_000_000_000_000,
                                u64::MAX / 3,
                            ] {
                                let at = format!(
                                    "multiple {multiple} median {median} ag {already_generated} \
                                     start {start}"
                                );
                                if parity(base, weight, fee, &counts, &at) {
                                    cases += 1;
                                } else {
                                    skipped += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(
            cases > 10_000,
            "the grid ran ({cases} cases whole, {skipped} with long counts unchecked)"
        );
    }

    /// Every case on a small block: a 64-byte zone, so a walk is at most
    /// 128 bodies and every weight, fee and count can be enumerated. The
    /// tail is small enough (6, 100 and 12 346 atomic) that the penalty's
    /// floor moves by single units, which is where the integer walk and the
    /// real curve part.
    #[test]
    fn admit_up_to_is_the_walk_on_every_small_case() {
        let counts = [0u64, 1, 2, 3, 5, 8, 13, 34, 63, 64, 65, 128, u64::MAX];
        // A body that weighs nothing is admitted until the fees overflow,
        // which no reference walk reaches: its counts stop at 128.
        let weightless = &counts[..counts.len() - 1];
        let mut cases = 0u64;
        for multiple in [
            2 * SCALE,
            15 * SCALE / 10,
            25 * SCALE / 10,
            MAX_BLOCK_WEIGHT_LIMIT_MULTIPLE,
        ] {
            for per_minute in [3u64, 50, 6_173] {
                let p = EconomicParams {
                    block_weight_limit_multiple: multiple,
                    full_reward_zone: 64,
                    final_subsidy_per_minute: per_minute,
                    ..EconomicParams::default()
                };
                let v = volume(&p);
                let tail = p.emission_curve_asymptote + 1;
                for coinbase in [0u64, 5] {
                    let empty = Fill::empty(64, coinbase, tail, v, &p).expect("priced");
                    let amount = empty.reward();
                    // Every fee up to one past the reward, which no body costs
                    // more than; the largest tail's to 600, past the steepest
                    // body the 64-byte zone holds.
                    let fees: Vec<u64> = (0..=(amount + 1).min(600))
                        .chain([amount - 1, amount, amount + 1])
                        .collect();
                    for start in [0u64, 30, 59, 95] {
                        let mut base = empty;
                        // A start past the penalty's limit is refused, and
                        // the case starts empty.
                        if start > 0 && !base.admit(start, u64::MAX / 4) {
                            base = empty;
                        }
                        for weight in 0..=40 {
                            for &fee in &fees {
                                let at = format!(
                                    "multiple {multiple} tail {amount} coinbase {coinbase} \
                                     start {start}"
                                );
                                let counts = if weight == 0 { weightless } else { &counts };
                                assert!(parity(base, weight, fee, counts, &at), "{at}");
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(cases > 400_000, "every case ran ({cases})");
    }

    /// The exits `admit` takes that a grid reaches rarely, each reached:
    /// fees at the edge of `u64` below and past the median, a body that
    /// overflows the block's weight, the penalty's `BlockTooBig` inside the
    /// fill's limit, and the penalty's product leaving `u128`.
    #[test]
    fn admit_up_to_takes_every_exit_admit_takes() {
        let counts = [0u64, 1, 2, 3, 1_000, 1 << 30, u64::MAX];
        let p = params();
        let v = volume(&p);
        let zone = p.full_reward_zone;
        let cb = coinbase_weight();

        // Fees: the coinbase's headroom is a few bodies' fees, below the
        // median and in the penalty zone.
        for bodies in [0, zone - cb - 40_000, zone - cb + 20_000] {
            for headroom in [0u64, 1, 999, 100_000] {
                let reward = Fill::listed(zone, cb, 0, v, &p, bodies, 0)
                    .expect("listed")
                    .reward();
                let fees = u64::MAX - reward - headroom;
                let base = Fill::listed(zone, cb, 0, v, &p, bodies, fees).expect("listed");
                for (weight, fee) in [(1_000, 1), (1_000, 7), (0, 3), (13_000, 100)] {
                    let at = format!("bodies {bodies} headroom {headroom}");
                    assert!(parity(base, weight, fee, &counts, &at), "{at}");
                }
            }
        }

        // A body whose weight overflows the block, and one that only just
        // passes the limit: neither is admitted, whatever it pays.
        let empty = Fill::empty(zone, cb, 0, v, &p).expect("priced");
        for weight in [u64::MAX, u64::MAX - cb + 1, 2 * zone - cb + 1] {
            let mut tried = empty;
            assert_eq!(tried.admit_up_to(weight, u64::MAX / 2, u64::MAX), 0);
            assert!(parity(empty, weight, u64::MAX / 2, &counts, "overflow"));
        }

        // At 1.5 the penalty ends at 1.5 medians, inside the fill's two: the
        // run stops at the penalty's limit, refused by `BlockTooBig`.
        let p15 = params_at(15 * SCALE / 10);
        let empty = Fill::empty(zone, cb, 0, v, &p15).expect("priced");
        let mut run = empty;
        let admitted = run.admit_up_to(1_000, 1_000_000_000_000_000, u64::MAX);
        assert!(admitted > 0);
        assert!(run.block_weight() <= zone * 3 / 2);
        assert!(
            run.block_weight() + 1_000 > zone * 3 / 2,
            "stopped at the limit"
        );
        assert_eq!(
            run.reward_at(run.bodies_weight() + 1_000),
            Err(EmissionError::BlockTooBig)
        );
        assert!(parity(
            empty,
            1_000,
            1_000_000_000_000_000,
            &counts,
            "BlockTooBig"
        ));

        // A median of 2⁵⁰ on the curve's first reward: the penalty's
        // product leaves `u128` at the first excess byte, so the penalty
        // zone is refused and the run stops at the median.
        let huge = 1u64 << 50;
        let empty = Fill::empty(huge, cb, 0, v, &p).expect("priced");
        let mut run = empty;
        let admitted = run.admit_up_to(1 << 33, 0, u64::MAX);
        assert_eq!(run.block_weight(), cb + admitted * (1 << 33));
        assert!(run.block_weight() <= huge);
        assert_eq!(
            run.reward_at(run.bodies_weight() + (1 << 33)),
            Err(EmissionError::Overflow),
            "the next body's reward cannot be priced"
        );
        assert!(parity(empty, 1 << 33, 0, &counts, "Overflow"));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(2_048))]

        /// `admit_up_to` equals `count` single offers on a clone, for the
        /// count and the fill after, over random operands: the median, the
        /// coinbase weight, the reward (any supply and volume), the limit
        /// multiple on the validator's grain, a start already listed, and the
        /// body. A case whose walk is too long to run is discarded.
        #[test]
        fn admit_up_to_is_the_walk_on_random_operands(
            median in 0u64..1 << 36,
            coinbase in 0u64..1 << 18,
            already_generated in proptest::prelude::any::<u64>(),
            volume in 0u64..10_000,
            tenths in 11u64..=40,
            start in 0u64..1 << 37,
            start_fee in proptest::prop_oneof![0u64..1 << 40, proptest::prelude::any::<u64>()],
            weight in proptest::prop_oneof![0u64..64, 0u64..1 << 16, 0u64..1 << 30],
            fee in proptest::prop_oneof![0u64..1 << 20, 0u64..1 << 42, proptest::prelude::any::<u64>()],
            count in proptest::prop_oneof![0u64..1 << 12, 0u64..1 << 22, proptest::prelude::Just(u64::MAX)],
        ) {
            let p = params_at(tenths * SCALE / 10);
            let v = TxVolume::per_block(volume);
            let Ok(empty) = Fill::empty(median, coinbase, already_generated, v, &p) else {
                return Err(proptest::test_runner::TestCaseError::reject("not priced"));
            };
            let mut base = empty;
            if !base.admit(start, start_fee) {
                base = empty;
            }
            proptest::prop_assume!(parity(base, weight, fee, &[count], "random"));
        }
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
