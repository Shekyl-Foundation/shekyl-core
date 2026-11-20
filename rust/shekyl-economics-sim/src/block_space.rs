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
//!    ([`FeePriority`]), richest first ([`ADMISSION`](crate::rung_mix::ADMISSION));
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

use shekyl_block_template::{Fill, Refusal};
use shekyl_chain_rules::{admissible_references, EffectiveMedian};
use shekyl_curve_tree::select_reference_height;
use shekyl_economics::{EconomicParams, EmissionError, TxVolume};
use shekyl_mempool::policy::{template_order, FeeRate, Limits};
use shekyl_types::BlockHeight;
use shekyl_wire::transaction::COINBASE_RESERVE;

use crate::economy::TemplateRule;
use crate::fee_model::{FeePoint, OrdinaryTx};
use crate::median_window::MedianWindow;
use crate::rung_mix::{FeePriority, PerRung, RungTraffic};

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
    rung: FeePriority,
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

/// What one block took, and what left the pool unserved.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Filled {
    /// Each rung's traffic at this block: its arrivals, its listing, and its
    /// drops (an expiry is of a reference that left CEN-I11's window before
    /// this block).
    pub(crate) rungs: PerRung<RungTraffic<u64>>,
    /// Transactions waiting after the block.
    pub(crate) waiting: u64,
    /// Cohorts waiting after the block: what the pool's walks cost in.
    pub(crate) cohorts_waiting: usize,
    /// The penalised gross reward at the block's weight
    /// ([`Fill::reward`]), before the split.
    pub(crate) paid_reward: u64,
    /// The block's weight: bodies plus the coinbase reserve.
    pub(crate) block_weight: u64,
    /// The listed bodies' weight.
    pub(crate) bodies_weight: u64,
    /// The producer's own bodies, listed after the pool's
    /// ([`OwnBodies`]). Zero unless the fold offers some.
    pub(crate) own: OwnListing,
    /// Why the fill ended (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.36).
    pub(crate) stop: FillStop,
    /// The bodies listed past the penalty-free weight, and the penalty
    /// the block pays for them (§5.36).
    pub(crate) past_free: PastFree,
}

/// Why a block's fill stopped listing (`ECONOMICS_SIM_PRODUCTION_REBASE.md`
/// §5.36), or [`Self::Drained`] when every offered body was listed.
///
/// The template walks cohorts from the richest fee per weight. A refusal
/// ends that weight and the walk continues at the next. The reason kept is
/// the last refusal: the marginal body, the cheapest cohort the template
/// did not finish. On one weight that is the only refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FillStop {
    /// Every body the pool offered was listed.
    Drained,
    /// The marginal body's fee is under the penalty it would add
    /// ([`Refusal::Penalty`], the gross coinbase).
    Penalty,
    /// The marginal body would pass the block's limit ([`Refusal::Limit`]).
    Limit,
}

/// [`FillStop`] for one offer's refusal. A refusal outside the reward's
/// domain is a defect in the trajectory, the same class as an unpriceable
/// empty block: the fold does not call it a penalty.
fn stop_of(refusal: Refusal) -> FillStop {
    match refusal {
        Refusal::Penalty => FillStop::Penalty,
        Refusal::Limit => FillStop::Limit,
        Refusal::Unpriced | Refusal::Overflow => {
            panic!("the fill refused a body outside the reward's domain: {refusal:?}")
        }
    }
}

/// Production's empty fill for a block judged under `medians`: the coinbase
/// reserve, its emission priced once ([`Fill::empty`]).
fn empty_fill<'a>(
    medians: EffectiveMedian,
    already_generated: u64,
    volume: TxVolume,
    params: &'a EconomicParams,
) -> Fill<'a> {
    let coinbase = u64::try_from(COINBASE_RESERVE).expect("the reserve fits");
    Fill::empty(
        medians.effective_median.to_raw(),
        coinbase,
        already_generated,
        volume,
        params,
    )
    .expect("sim trajectory stays within the reward's arithmetic domain")
}

/// Whether a block judged under `medians` can price a body past its
/// penalty-free weight: production's penalty, one byte past it, stays
/// inside `u128`. The penalty's product only falls as the excess grows, so
/// one byte decides every weight. Where it does not, production's template
/// refuses every body past the median as [`Refusal::Unpriced`]: the
/// reward's domain edge (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.37.1),
/// which only a median of terabytes reaches.
pub(crate) fn penalty_zone_prices(
    medians: EffectiveMedian,
    already_generated: u64,
    volume: TxVolume,
    params: &EconomicParams,
) -> bool {
    let fill = empty_fill(medians, already_generated, volume, params);
    fill.reward_at(fill.penalty_free_bodies().saturating_add(1)) != Err(EmissionError::Overflow)
}

/// The bodies a block lists past the penalty-free weight
/// (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.36). Only they pay a penalty.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PastFree {
    /// Bodies whose place in the block ends past the penalty-free weight.
    pub(crate) bodies: u64,
    /// Their fees.
    pub(crate) fees_atomic: u64,
    /// The block's penalty: the reward it would have paid within the
    /// penalty-free weight less the reward it paid.
    pub(crate) penalty_atomic: u64,
}

impl PastFree {
    /// Those bodies' fees less the penalty they added: what listing them
    /// left the producer. The fill lists a body only when the coinbase
    /// does not fall, so the fees cover the penalty.
    pub(crate) fn surplus_atomic(&self) -> u64 {
        self.fees_atomic
            .checked_sub(self.penalty_atomic)
            .expect("the fill lists no body that lowers the coinbase")
    }
}

/// The pool offer's record: the marginal refusal, and the bodies listed
/// past the penalty-free weight. The penalty is priced after the producer's
/// own bodies join the fill.
#[derive(Debug, Clone, Copy, Default)]
struct PoolOffer {
    marginal: Option<FillStop>,
    past_bodies: u64,
    past_fees_atomic: u64,
    /// The fees the fill was offered for the bodies it listed: the bodies'
    /// own under the gross rule, each scaled under the miner's net
    /// ([`TemplateRule::offered_fee`]).
    offered_fees_atomic: u64,
}

impl Filled {
    /// Transactions the block lists: every rung's, and the producer's own.
    pub(crate) fn carried_txs(&self) -> u64 {
        self.rungs.sum(|rung| rung.carried_txs) + self.own.txs
    }

    /// The listed bodies' fees: every rung's, and the producer's own.
    pub(crate) fn fees_atomic(&self) -> u64 {
        self.rungs.sum(|rung| rung.fees_atomic) + self.own.fees_atomic
    }
}

/// Bodies a block's producer lists of its own, after the pool's: each one
/// `tx`, as many as fit inside the penalty-free weight that the pool's
/// listing leaves, so the producer takes no penalty. They are not in the
/// pool and no rung's traffic: they enter the block's weight, its fees,
/// the medians and the volume window. The window-edge stuffer
/// (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.32, EI-3) is their one user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnBodies {
    pub(crate) tx: OrdinaryTx,
}

/// The producer's own bodies one block listed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OwnListing {
    pub(crate) txs: u64,
    pub(crate) fees_atomic: u64,
}

/// One rung's demand at a block: `count` transactions, each `tx`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    pub(crate) rung: FeePriority,
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
    /// Each arrival is [`make_room`](shekyl_mempool::policy::make_room)'s
    /// question: the entries paying strictly less per weight, the cheapest
    /// first, until it fits; an arrival refused leaves the pool as it was,
    /// so every identical arrival after it is refused too. The arrivals are
    /// answered together. After `j` of them, the pool's walk has evicted
    /// the shortest cheapest-first run of strictly cheaper entries whose
    /// weight covers `total + j·weight − limit`: each arrival extends the
    /// run before it by the fewest entries that cover its own excess, and
    /// nothing it admits is a victim (its rate is not strictly less). So
    /// the `j`-th is admitted exactly when that excess is at most the
    /// cheaper entries' whole weight, and the admitted arrivals evict that
    /// run, group by group. Pinned against the pool's own walk, one arrival
    /// at a time, by `admission_makes_room_as_the_pool_does`.
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
        let cheaper: u128 = victims
            .iter()
            .map(|group| {
                u128::from(self.waiting[group.start].weight) * u128::from(self.group_count(group))
            })
            .sum();
        let room = (u128::from(limit) + cheaper).saturating_sub(self.weight_total);
        let admitted = if tx.weight == 0 {
            demand
        } else {
            u64::try_from((room / u128::from(tx.weight)).min(u128::from(demand)))
                .expect("at most the demand")
        };
        let mut over = (self.weight_total + u128::from(admitted) * u128::from(tx.weight))
            .saturating_sub(u128::from(limit));
        for group in victims {
            if over == 0 {
                break;
            }
            let weight = u128::from(self.waiting[group.start].weight);
            let held = u128::from(self.group_count(&group));
            let taken = if weight == 0 {
                held
            } else {
                held.min(over.div_ceil(weight))
            };
            over = over.saturating_sub(taken * weight);
            self.take_from(
                group,
                u64::try_from(taken).expect("at most the group"),
                evicted,
            );
        }
        debug_assert_eq!(over, 0, "the cheaper entries cover the admitted arrivals");
        let new = self
            .waiting
            .partition_point(|cohort| template_cmp(cohort, &arrival) == Ordering::Less);
        self.waiting.insert(new, arrival);
        self.add(new, admitted);
        // Nothing above removes an entry; drop the empties now.
        self.drop_empty();
        demand - admitted
    }

    /// Step 3: offer the pool to `fill` in the template's order; the bodies
    /// listed are recorded in `self.listed` (per group), `self.taken` (per
    /// entry), `self.ages` and `rungs` (per rung: carried and fees), and
    /// taken from the pool.
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
    fn offer(
        &mut self,
        fill: &mut Fill<'_>,
        height: u64,
        rungs: &mut PerRung<RungTraffic<u64>>,
        offered_fee: &impl Fn(u64) -> u64,
    ) -> PoolOffer {
        let mut record = PoolOffer::default();
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
            let count = self.group_count(&group);
            if count == 0 {
                continue;
            }
            let admission = fill.admit_up_to(head.weight, offered_fee(head.fee), count);
            let taken = admission.taken;
            record.offered_fees_atomic = taken
                .checked_mul(offered_fee(head.fee))
                .and_then(|fees| record.offered_fees_atomic.checked_add(fees))
                .expect("the offered fees of a listing fit the fill's u64 fees");
            if let Some(refusal) = admission.refusal {
                closed.push(head.weight);
                // A later weight can still be listed. The last refusal is
                // the marginal body.
                record.marginal = Some(stop_of(refusal));
            }
            let past = taken
                .checked_sub(admission.within_free)
                .expect("the bodies inside the penalty-free weight are a prefix of those listed");
            let past_fees = past
                .checked_mul(head.fee)
                .expect("a listed body's fee fits");
            record.past_bodies += past;
            record.past_fees_atomic = record
                .past_fees_atomic
                .checked_add(past_fees)
                .expect("the fees past the penalty-free weight fit");
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
                rungs[cohort.rung].carried_txs += share;
                rungs[cohort.rung].fees_atomic += share * cohort.fee;
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
        record
    }

    /// Step 4: bring the pool within `limit`, the bodies this block listed
    /// (`self.taken`) counting toward the weight and never chosen. Evictions
    /// are counted per rung in `evicted`.
    ///
    /// [`trim_to`](shekyl_mempool::policy::trim_to)'s walk in the eviction
    /// order, group by group: a group's waiting entries are taken until the
    /// excess is covered, the fewest that cover it, and the walk ends there.
    /// Pinned against `trim_to` over every entry by
    /// `the_trim_passes_over_the_listing_as_the_pool_does`.
    fn trim(&mut self, limit: u64, evicted: &mut PerRung<u64>) {
        let listed_weight: u128 = self
            .waiting
            .iter()
            .zip(&self.taken)
            .map(|(cohort, &taken)| u128::from(cohort.weight) * u128::from(taken))
            .sum();
        let mut over = (self.weight_total + listed_weight).saturating_sub(u128::from(limit));
        for group in self.groups().into_iter().rev() {
            if over == 0 {
                break;
            }
            let weight = u128::from(self.waiting[group.start].weight);
            let waiting = u128::from(self.group_count(&group));
            let taken = if weight == 0 {
                waiting
            } else {
                waiting.min(over.div_ceil(weight))
            };
            over = over.saturating_sub(taken * weight);
            self.take_from(
                group,
                u64::try_from(taken).expect("at most the group"),
                evicted,
            );
        }
    }

    /// Build the block at `height` under `medians` — what [`Self::medians`]
    /// returned for it — from the pool and the block's `arrivals`, each
    /// rung's ordinary transaction priced at `at`, admitted in the order
    /// given ([`ADMISSION`](crate::rung_mix::ADMISSION)), then record it.
    #[cfg(test)]
    pub(crate) fn fill(
        &mut self,
        height: u64,
        medians: EffectiveMedian,
        arrivals: &[Arrival],
        at: &FeePoint<'_>,
    ) -> Filled {
        self.fill_with_own(height, medians, arrivals, at, None)
    }

    /// [`Self::fill`], then the producer's `own` bodies, when it lists any,
    /// in the penalty-free room the pool's listing leaves.
    #[cfg(test)]
    pub(crate) fn fill_with_own(
        &mut self,
        height: u64,
        medians: EffectiveMedian,
        arrivals: &[Arrival],
        at: &FeePoint<'_>,
        own: Option<OwnBodies>,
    ) -> Filled {
        self.fill_ruled(height, medians, arrivals, at, own, TemplateRule::Gross)
    }

    /// [`Self::fill_with_own`] under the template `rule`
    /// (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.37). Production's fill is
    /// offered each body at [`TemplateRule::offered_fee`] at this block's
    /// σ and burn: its own fee under the gross rule, the scaled fee that
    /// makes the gross test the miner's-net test under the other. The
    /// bodies' own fees are what the block records and pays.
    pub(crate) fn fill_ruled(
        &mut self,
        height: u64,
        medians: EffectiveMedian,
        arrivals: &[Arrival],
        at: &FeePoint<'_>,
        own: Option<OwnBodies>,
        rule: TemplateRule,
    ) -> Filled {
        let offered = |fee: u64| rule.offered_fee(fee, at.sigma_scaled, at.burn_pct_scaled);
        let limit = Limits::of_block_limit(medians.limit(at.params).to_raw()).max_weight;
        let expired = self.expire(height);
        let mut evicted = PerRung::<u64>::default();
        let mut rungs = PerRung::<RungTraffic<u64>>::default();
        for &arrival in arrivals {
            let rung = &mut rungs[arrival.rung];
            rung.demand_txs += arrival.count;
            rung.refused_txs += self.admit(
                height,
                arrival,
                limit,
                at.params.daa_target_seconds,
                &mut evicted,
            );
        }

        let mut fill = empty_fill(medians, at.already_generated, at.volume, at.params);
        let pool = self.offer(&mut fill, height, &mut rungs, &offered);
        self.trim(limit, &mut evicted);
        self.drop_empty();
        let own_offered_fee = own.map_or(0, |own| offered(own.tx.fee_atomic));
        let own = own.map_or_else(OwnListing::default, |own| {
            let room = fill.penalty_free_body_room() / own.tx.weight.max(1);
            let txs = fill
                .admit_up_to(own.tx.weight, offered(own.tx.fee_atomic), room)
                .taken;
            OwnListing {
                txs,
                fees_atomic: txs * own.tx.fee_atomic,
            }
        });
        for rung in FeePriority::ALL {
            rungs[rung].expired_txs = expired[rung];
            rungs[rung].evicted_txs = evicted[rung];
        }

        let weight = fill.block_weight();
        self.medians.push(medians, weight, at.params);
        // The producer's own bodies sit inside the penalty-free room, so the
        // penalty is the pool's bodies' alone.
        let penalty_atomic = if fill.bodies_weight() > fill.penalty_free_bodies() {
            fill.reward_at(0)
                .expect("the reward prices an empty block")
                .checked_sub(fill.reward())
                .expect("a heavier block is not paid more")
        } else {
            0
        };
        let filled = Filled {
            rungs,
            waiting: self.waiting_total,
            cohorts_waiting: self.waiting.len(),
            paid_reward: fill.reward(),
            block_weight: weight,
            bodies_weight: fill.bodies_weight(),
            own,
            stop: pool.marginal.unwrap_or(FillStop::Drained),
            past_free: PastFree {
                bodies: pool.past_bodies,
                fees_atomic: pool.past_fees_atomic,
                penalty_atomic,
            },
        };
        let own_offered = filled
            .own
            .txs
            .checked_mul(own_offered_fee)
            .expect("the own bodies' offered fees fit");
        assert_eq!(
            pool.offered_fees_atomic + own_offered,
            fill.fees(),
            "every fee the fill was offered is a listed body's"
        );
        if rule == TemplateRule::Gross {
            assert_eq!(
                filled.fees_atomic(),
                fill.fees(),
                "every listed fee is some rung's"
            );
        }
        filled
    }
}

#[cfg(test)]
#[path = "block_space_tests.rs"]
mod tests;
