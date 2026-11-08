// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transactions waiting for a block, and the producer's fill of one.
//!
//! [`BlockSpace`] is the pool the Rust daemon holds (`shekyl-mempool`,
//! CEN-M10), kept as cohorts: the transactions built at one block, each
//! keeping the fee and weight it was built with. Each block it
//!
//! 1. drops the cohorts whose reference has left CEN-I11's window at the
//!    connecting height (the reconcile at the new tip);
//! 2. admits the block's demand, built on the tip below it, making room
//!    under CEN-M10's limit from strictly cheaper entries and refusing what
//!    it cannot make room for. Demand arrives on the fee ladder's rungs
//!    ([`Rung`]), richest first ([`Rung::ADMISSION`]);
//! 3. offers the cohorts to the producer's fill rule
//!    ([`Fill`](shekyl_block_template::Fill)) in the template's order, at the
//!    effective median [`MedianWindow`](crate::median_window::MedianWindow)
//!    holds;
//! 4. trims the pool to its limit, passing over the bodies the block lists;
//! 5. drops the listed bodies, which the block carries.
//!
//! The limit, both orders and both eviction walks are `shekyl-mempool`'s
//! [`policy`](shekyl_mempool::policy), called. The wallet's reference is
//! `shekyl_curve_tree::select_reference_height`, and the window is
//! `shekyl_chain_rules::admissible_references`. The block's recorded weight
//! includes the coinbase reserve, the maximum coinbase.
//!
//! Each cohort keeps the rung it was built on, so the pool counts what each
//! rung carries and drops. The rung orders nothing: the daemon cannot see
//! it, and the template's order by fee per weight is the rung order on the
//! shipped ladder (§5.29 of the design document).

use core::cmp::Ordering;

use shekyl_block_template::Fill;
use shekyl_chain_rules::{admissible_references, EffectiveMedian};
use shekyl_curve_tree::select_reference_height;
use shekyl_mempool::policy::{make_room, template_order, trim_to, FeeRate, Limits};
use shekyl_types::BlockHeight;
use shekyl_wire::transaction::COINBASE_RESERVE;

use crate::fee_model::{FeePoint, OrdinaryTx};
use crate::median_window::MedianWindow;
use crate::rung_mix::{PerRung, Rung};

/// Seconds in the pool's received key: `ReceivedHour::of` is Unix seconds
/// over this (`shekyl-chain-store`, `codec/pool.rs`), pinned by
/// `the_received_key_is_the_pools_hour`.
const SECONDS_PER_RECEIVED_KEY: u64 = 3_600;

/// The transactions one block's demand built: `count` of them, each paying
/// `fee` at `weight`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cohort {
    /// The first block that can list it. It was built on the tip below.
    arrived: u64,
    /// The height of its reference block: the wallet's anchor at that tip.
    reference: u64,
    /// The hour the pool first held it, the tie both orders break on.
    hour: u64,
    fee: u64,
    weight: u64,
    count: u64,
    /// The rung it was priced on. Counted, never ordered on.
    rung: Rung,
}

impl Cohort {
    fn rate(&self) -> FeeRate {
        FeeRate::new(self.fee, self.weight)
    }

    fn key(&self) -> (FeeRate, u64) {
        (self.rate(), self.hour)
    }
}

/// Bodies a block listed from one cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListedBodies {
    pub(crate) fee: u64,
    pub(crate) weight: u64,
    pub(crate) count: u64,
}

/// The pool the Rust daemon holds, and the medians it fills under (module
/// docs).
///
/// Two of the pool's orders end on the transaction hash: the template's
/// (the richest per weight, then the earliest hour, then the hash) and
/// eviction's (the cheapest, then the newest hour, then the hash). Which of
/// a user's transactions has the lesser hash is not knowable, so where an
/// order reaches a group of equal rate and hour and takes only part of it,
/// the part is shared across the group's cohorts in proportion to their
/// counts, by largest remainder: the expected value of a uniform hash
/// order. Within such a group, cohorts of different weight (an equal rate
/// at a different weight) are offered lightest first and evicted heaviest
/// first.
///
/// The pool is kept in the template's order, so a block walks it without
/// sorting; eviction walks the same groups backwards.
///
/// A scenario's first blocks are before the chain is deep enough for a
/// wallet to anchor (`select_reference_height` is `None`) or for CEN-I11 to
/// admit any reference. The scenario's demand starts at its first block,
/// as if users had outputs to spend there. Those transactions anchor at
/// genesis, and no window drops anything until one exists: a scenario
/// boundary, declared in §4 of the design document.
#[derive(Debug, Clone, Default)]
pub(crate) struct BlockSpace {
    medians: MedianWindow,
    /// The pool, in the template's order ([`template_cmp`]).
    waiting: Vec<Cohort>,
    /// The sum of `waiting`'s counts, kept as it changes.
    waiting_total: u64,
    /// The pool's weight, kept as it changes.
    weight_total: u128,
    /// Bodies listed since the last [`Self::take_ages`], per rung, by age
    /// at inclusion: the listing height less the cohort's arrival.
    ages: PerRung<Vec<u64>>,
    /// The last block's listing, group by group, in the order offered.
    listed: Vec<ListedBodies>,
    /// This block's listing per entry of `waiting`, for the trim.
    taken: Vec<u64>,
}

/// One rung's part of a block: what it listed, and what of it left the pool
/// unserved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RungBlock {
    /// Transactions the block lists.
    pub(crate) included: u64,
    /// Transactions whose reference left CEN-I11's window before this block.
    pub(crate) expired: u64,
    /// Transactions CEN-M10 evicted at this block: to make room for an
    /// arrival paying more per weight, or to bring the pool within its limit.
    pub(crate) evicted: u64,
    /// Arrivals the pool refused: no strictly cheaper entries freed room.
    pub(crate) refused: u64,
    /// The listed bodies' fees.
    pub(crate) fees: u64,
}

/// What one block took, and what left the pool unserved.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Filled {
    /// Each rung's listing and drops.
    pub(crate) rungs: PerRung<RungBlock>,
    /// Transactions waiting after the block.
    pub(crate) waiting: u64,
    /// The penalised gross reward at the block's weight
    /// ([`Fill::reward`]), before the split.
    pub(crate) paid_reward: u64,
    /// The block's weight: bodies plus the coinbase reserve.
    pub(crate) block_weight: u64,
    /// The listed bodies' weight.
    pub(crate) bodies_weight: u64,
    /// The listed bodies' fees.
    pub(crate) fees: u64,
}

impl Filled {
    fn sum(&self, field: impl Fn(&RungBlock) -> u64) -> u64 {
        self.rungs.iter().map(field).sum()
    }

    /// Transactions the block lists, every rung.
    pub(crate) fn included(&self) -> u64 {
        self.sum(|r| r.included)
    }
}

/// One rung's demand at a block: `count` transactions, each `tx`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    pub(crate) rung: Rung,
    pub(crate) count: u64,
    pub(crate) tx: OrdinaryTx,
}

/// `k` shared across `counts` in proportion, by largest remainder; an equal
/// remainder goes to the earlier entry. Each share is at most its count when
/// `k` is at most their sum.
fn pro_rata(counts: &[u64], k: u64) -> Vec<u64> {
    let total: u128 = counts.iter().map(|&count| u128::from(count)).sum();
    if total == 0 {
        return vec![0; counts.len()];
    }
    let k = u128::from(k).min(total);
    let mut shares: Vec<u64> = Vec::with_capacity(counts.len());
    let mut remainders: Vec<(u128, usize)> = Vec::with_capacity(counts.len());
    let mut given: u128 = 0;
    for (index, &count) in counts.iter().enumerate() {
        let scaled = k * u128::from(count);
        let share = scaled / total;
        given += share;
        shares.push(u64::try_from(share).expect("a share is at most its count"));
        remainders.push((scaled % total, index));
    }
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let leftover = usize::try_from(k - given).expect("fewer than the entries");
    for &(_, index) in remainders.iter().take(leftover) {
        shares[index] += 1;
    }
    shares
}

/// The pool's order: the template's ([`template_order`]), then the lighter,
/// then the cheaper, then build order, then the rung (which only places
/// interchangeable cohorts). Eviction's order is this one's groups read
/// backwards: [`eviction_order`](shekyl_mempool::policy::eviction_order)
/// reverses the template's rate and hour.
fn template_cmp(a: &Cohort, b: &Cohort) -> Ordering {
    template_order(a.key(), b.key())
        .then(a.weight.cmp(&b.weight))
        .then(a.fee.cmp(&b.fee))
        .then(a.arrived.cmp(&b.arrived))
        .then(a.rung.cmp(&b.rung))
}

/// Whether two cohorts are one group: tied by the order, at one fee and
/// weight. Their transactions are then interchangeable but for age, whatever
/// rung each was priced on.
fn same_group(a: &Cohort, b: &Cohort) -> bool {
    template_order(a.key(), b.key()) == Ordering::Equal && a.weight == b.weight && a.fee == b.fee
}

impl BlockSpace {
    /// A pool holding `cohorts`, kept in the pool's order.
    #[cfg(test)]
    fn holding(cohorts: &[Cohort]) -> Self {
        let mut waiting = cohorts.to_vec();
        waiting.sort_by(template_cmp);
        Self {
            waiting_total: waiting.iter().map(|cohort| cohort.count).sum(),
            weight_total: waiting
                .iter()
                .map(|cohort| u128::from(cohort.weight) * u128::from(cohort.count))
                .sum(),
            waiting,
            ..Self::default()
        }
    }

    /// The medians the next block is judged under.
    pub(crate) fn medians(&self, params: &shekyl_economics::EconomicParams) -> EffectiveMedian {
        self.medians.medians(params)
    }

    /// Transactions waiting after the last block ([`Filled::waiting`] is
    /// the fold's read).
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> u64 {
        self.waiting_total
    }

    /// Bodies listed since the last call, per rung, by age at inclusion
    /// (index = age in blocks), and start counting again.
    pub(crate) fn take_ages(&mut self) -> PerRung<Vec<u64>> {
        core::mem::take(&mut self.ages)
    }

    /// The last block's listing, group by group.
    pub(crate) fn listed(&self) -> &[ListedBodies] {
        &self.listed
    }

    /// The end of the group that starts at `start`.
    fn group_end(&self, start: usize) -> usize {
        let head = &self.waiting[start];
        let mut end = start + 1;
        while end < self.waiting.len() && same_group(head, &self.waiting[end]) {
            end += 1;
        }
        end
    }

    /// Every group, in the template's order, as index ranges.
    fn groups(&self) -> Vec<core::ops::Range<usize>> {
        let mut out = Vec::new();
        let mut start = 0;
        while start < self.waiting.len() {
            let end = self.group_end(start);
            out.push(start..end);
            start = end;
        }
        out
    }

    fn group_count(&self, group: &core::ops::Range<usize>) -> u64 {
        self.waiting[group.clone()]
            .iter()
            .map(|cohort| cohort.count)
            .sum()
    }

    /// Take `k` from the cohorts of `group`, in proportion, counting each
    /// taken transaction against its rung in `taken`.
    fn take_from(&mut self, group: core::ops::Range<usize>, k: u64, taken: &mut PerRung<u64>) {
        if k == 0 {
            return;
        }
        let weight = self.waiting[group.start].weight;
        if group.len() == 1 {
            self.waiting[group.start].count -= k;
            taken[self.waiting[group.start].rung] += k;
        } else {
            let counts: Vec<u64> = self.waiting[group.clone()]
                .iter()
                .map(|c| c.count)
                .collect();
            for (index, share) in group.zip(pro_rata(&counts, k)) {
                self.waiting[index].count -= share;
                taken[self.waiting[index].rung] += share;
            }
        }
        self.waiting_total -= k;
        self.weight_total -= u128::from(weight) * u128::from(k);
    }

    fn drop_empty(&mut self) {
        self.waiting.retain(|cohort| cohort.count > 0);
    }

    /// Step 1: the reconcile at the tip below `connecting`. Returns what
    /// expired, per rung.
    fn expire(&mut self, connecting: u64) -> PerRung<u64> {
        let mut expired = PerRung::<u64>::default();
        let Some((oldest, _)) = admissible_references(BlockHeight::from_raw(connecting)) else {
            return expired;
        };
        let oldest = oldest.to_raw();
        let mut expired_weight: u128 = 0;
        self.waiting.retain(|cohort| {
            let keep = cohort.reference >= oldest;
            if !keep {
                expired[cohort.rung] += cohort.count;
                expired_weight += u128::from(cohort.weight) * u128::from(cohort.count);
            }
            keep
        });
        self.waiting_total -= expired.iter().sum::<u64>();
        self.weight_total -= expired_weight;
        expired
    }

    /// Add `k` to the cohort at `index`.
    fn add(&mut self, index: usize, k: u64) {
        let cohort = &mut self.waiting[index];
        cohort.count += k;
        self.waiting_total += k;
        self.weight_total += u128::from(cohort.weight) * u128::from(k);
    }

    /// Step 2: admit `arrival`'s transactions, built on the tip below
    /// `connecting`, under `limit`. Evictions are counted against the
    /// evicted entries' rungs in `evicted`; returns the arrivals refused.
    ///
    /// Each arrival is [`make_room`]'s question: the entries paying
    /// strictly less per weight, the cheapest first, until it fits. An
    /// arrival refused once leaves the pool as it was, so every identical
    /// arrival after it is refused too. Where the next victim has the
    /// arrival's weight and one victim covers the excess, each arrival
    /// takes exactly one, which is what [`make_room`] returns for it; those
    /// arrivals are admitted together.
    fn admit(
        &mut self,
        connecting: u64,
        arrival: Arrival,
        limit: u64,
        daa: u64,
        evicted: &mut PerRung<u64>,
    ) -> u64 {
        let Arrival {
            rung,
            count: demand,
            tx,
        } = arrival;
        if demand == 0 {
            return 0;
        }
        let tip = connecting.saturating_sub(1);
        let reference =
            select_reference_height(BlockHeight::from_raw(tip)).map_or(0, BlockHeight::to_raw);
        let arrival = Cohort {
            arrived: connecting,
            reference,
            hour: tip.saturating_mul(daa) / SECONDS_PER_RECEIVED_KEY,
            fee: tx.fee_atomic,
            weight: tx.weight,
            count: 0,
            rung,
        };
        let rate = arrival.rate();
        let new = self
            .waiting
            .partition_point(|cohort| template_cmp(cohort, &arrival) == Ordering::Less);
        self.waiting.insert(new, arrival);

        let mut remaining = demand;
        while remaining > 0 {
            let free = u128::from(limit).saturating_sub(self.weight_total);
            let fits = if tx.weight == 0 {
                u128::from(remaining)
            } else {
                free / u128::from(tx.weight)
            };
            let fits = u64::try_from(fits.min(u128::from(remaining))).expect("at most remaining");
            if fits > 0 {
                self.add(new, fits);
                remaining -= fits;
                continue;
            }
            // The groups paying strictly less, the cheapest first.
            let victims: Vec<core::ops::Range<usize>> = self
                .groups()
                .into_iter()
                .rev()
                .filter(|group| {
                    self.waiting[group.start].rate().cmp_rate(rate) == Ordering::Less
                        && self.group_count(group) > 0
                })
                .collect();
            let over =
                (self.weight_total + u128::from(tx.weight)).saturating_sub(u128::from(limit));
            if let Some(first) = victims.first() {
                if self.waiting[first.start].weight == tx.weight && over <= u128::from(tx.weight) {
                    let batch = self.group_count(first).min(remaining);
                    self.take_from(first.clone(), batch, evicted);
                    self.add(new, batch);
                    remaining -= batch;
                    continue;
                }
            }
            // One arrival, through the pool's own walk over every entry.
            let units = victims.iter().enumerate().flat_map(|(at, group)| {
                let head = self.waiting[group.start];
                (0..self.group_count(group)).map(move |_| (at, head.rate(), head.weight))
            });
            let Some(taken) = make_room(self.weight_total, tx.weight, limit, rate, units) else {
                break;
            };
            let mut per_group = vec![0u64; victims.len()];
            for at in taken {
                per_group[at] += 1;
            }
            for (group, n) in victims.iter().zip(per_group) {
                self.take_from(group.clone(), n, evicted);
            }
            self.add(new, 1);
            remaining -= 1;
        }
        // Nothing above removes an entry, so `new` held; drop the empties now.
        self.drop_empty();
        remaining
    }

    /// Step 3: offer the pool to `fill` in the template's order; the bodies
    /// listed are recorded in `self.listed` (per group), `self.taken` (per
    /// entry), `self.ages` and `rungs` (per rung), and taken from the pool.
    ///
    /// **The stop rule.** A group is offered with [`Fill::admit_up_to`], and
    /// a refusal ends it. It also ends every later group of the same weight:
    /// `Fill::admit` refuses `(w, f)` at block weight `W` exactly when
    /// `W + w` passes the block limit or `f` is less than
    /// `penalised(W) − penalised(W + w)`, and a refusal leaves `W` where it
    /// was. A later group of weight `w` pays `f' ≤ f`, because the order is
    /// by fee per weight, so both conditions refuse it as well. A group of
    /// another weight faces a different penalty and limit test and is still
    /// offered, as the template walks every candidate.
    fn offer(&mut self, fill: &mut Fill<'_>, height: u64, rungs: &mut PerRung<RungBlock>) {
        self.listed.clear();
        self.taken.clear();
        self.taken.resize(self.waiting.len(), 0);
        let mut closed: Vec<u64> = Vec::new();
        let mut start = 0;
        while start < self.waiting.len() {
            let end = self.group_end(start);
            let head = self.waiting[start];
            let group = start..end;
            start = end;
            if closed.contains(&head.weight) {
                continue;
            }
            let offered = self.group_count(&group);
            if offered == 0 {
                continue;
            }
            let taken = fill.admit_up_to(head.weight, head.fee, offered);
            if taken < offered {
                closed.push(head.weight);
            }
            if taken == 0 {
                continue;
            }
            let shares = if group.len() == 1 {
                vec![taken]
            } else {
                let counts: Vec<u64> = self.waiting[group.clone()]
                    .iter()
                    .map(|c| c.count)
                    .collect();
                pro_rata(&counts, taken)
            };
            for (index, share) in group.clone().zip(shares) {
                if share == 0 {
                    continue;
                }
                let cohort = self.waiting[index];
                let age = usize::try_from(height - cohort.arrived).expect("small");
                let ages = &mut self.ages[cohort.rung];
                if ages.len() <= age {
                    ages.resize(age + 1, 0);
                }
                ages[age] += share;
                rungs[cohort.rung].included += share;
                rungs[cohort.rung].fees += share * cohort.fee;
                self.taken[index] += share;
                self.waiting[index].count -= share;
            }
            self.waiting_total -= taken;
            self.weight_total -= u128::from(head.weight) * u128::from(taken);
            self.listed.push(ListedBodies {
                fee: head.fee,
                weight: head.weight,
                count: taken,
            });
        }
    }

    /// Step 4: bring the pool within `limit`, the bodies this block listed
    /// (`self.taken`) counting toward the weight and never chosen
    /// ([`trim_to`]). Evictions are counted per rung in `evicted`.
    fn trim(&mut self, limit: u64, evicted: &mut PerRung<u64>) {
        let listed_weight: u128 = self
            .waiting
            .iter()
            .zip(&self.taken)
            .map(|(cohort, &taken)| u128::from(cohort.weight) * u128::from(taken))
            .sum();
        if self.weight_total + listed_weight <= u128::from(limit) {
            return;
        }
        // Units in eviction order: per group, the listed ones (never chosen)
        // and the ones still waiting.
        let order: Vec<core::ops::Range<usize>> = self.groups().into_iter().rev().collect();
        let units: Vec<(Option<usize>, u64)> = order
            .iter()
            .enumerate()
            .flat_map(|(at, group)| {
                let weight = self.waiting[group.start].weight;
                let listed: u64 = self.taken[group.clone()].iter().sum();
                let waiting = self.group_count(group);
                (0..listed)
                    .map(move |_| (None, weight))
                    .chain((0..waiting).map(move |_| (Some(at), weight)))
            })
            .collect();
        let trimmed = trim_to(limit, units, |key| key.is_none());
        let mut per_group = vec![0u64; order.len()];
        for key in trimmed {
            per_group[key.expect("only waiting units are chosen")] += 1;
        }
        for (group, n) in order.into_iter().zip(per_group) {
            self.take_from(group, n, evicted);
        }
    }

    /// Build the block at `height` under `medians` — what [`Self::medians`]
    /// returned for it — from the pool and the block's `arrivals`, each
    /// rung's ordinary transaction priced at `at`, admitted in the order
    /// given, then record it.
    pub(crate) fn fill(
        &mut self,
        height: u64,
        medians: EffectiveMedian,
        arrivals: &[Arrival],
        at: &FeePoint<'_>,
    ) -> Filled {
        let limit = Limits::of_block_limit(medians.limit(at.params).to_raw()).max_weight;
        let expired = self.expire(height);
        let mut evicted = PerRung::<u64>::default();
        let mut refused = PerRung::<u64>::default();
        for &arrival in arrivals {
            refused[arrival.rung] += self.admit(
                height,
                arrival,
                limit,
                at.params.daa_target_seconds,
                &mut evicted,
            );
        }

        let effective = medians.effective_median.to_raw();
        let coinbase = u64::try_from(COINBASE_RESERVE).expect("the reserve fits");
        let mut fill = Fill::empty(
            effective,
            coinbase,
            at.already_generated,
            at.volume,
            at.params,
        )
        .expect("sim trajectory stays within the reward's arithmetic domain");
        let mut rungs = PerRung::<RungBlock>::default();
        self.offer(&mut fill, height, &mut rungs);
        self.trim(limit, &mut evicted);
        self.drop_empty();
        for rung in Rung::ALL {
            rungs[rung].expired = expired[rung];
            rungs[rung].evicted = evicted[rung];
            rungs[rung].refused = refused[rung];
        }
        assert_eq!(
            rungs.iter().map(|r| r.fees).sum::<u64>(),
            fill.fees(),
            "every listed fee is some rung's"
        );

        let weight = fill.block_weight();
        self.medians.push(medians, weight, at.params);
        Filled {
            rungs,
            waiting: self.waiting_total,
            paid_reward: fill.reward(),
            block_weight: weight,
            bodies_weight: fill.bodies_weight(),
            fees: fill.fees(),
        }
    }
}

#[cfg(test)]
#[path = "block_space_tests.rs"]
mod tests;
